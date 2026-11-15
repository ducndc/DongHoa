// SPDX-License-Identifier: MIT
// MEASURE phase of a steering transaction (source AP): the candidate pool,
// the 11k beacon requests and air-monitor requests that measure it, the
// stored levels and the events that end the phase. The state machine is in
// steer.cpp.
#include "daemon/daemon.hpp"
#include "base/log.hpp"
#include "core/policy.hpp"
#include "daemon/steer_util.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};
constexpr Millis MEAS_FRESH_MS = 10000U;
constexpr Millis BCN_QUIET_BASE_MS = 200U;    // + 2 channel times: no new beacon report -> 11k over

const Measurement *measLookup(const Sta &s, const Mac &bssid, MeasSrc src) noexcept
{
	const Millis now = os::nowMs();
	const Measurement *r = nullptr;
	for (std::size_t i = 0U; (i < s.nMeas) && (r == nullptr); i++) {
		const Measurement &m = s.meas[i];
		if ((m.src == src) && (m.bssid == bssid) && ((now - m.ts) < MEAS_FRESH_MS)) {
			r = &m;
		}
	}
	return r;
}

bool freshSince(const Measurement *m, Millis since) noexcept
{
	return (m != nullptr) && (m->ts >= since);
}

} // namespace

namespace steer {

// STA-measured (11k beacon report) level of bssid.
const Measurement *bcnLookup(const Sta &s, const Mac &bssid) noexcept
{
	return measLookup(s, bssid, MeasSrc::STA_11K);
}

// Best available level: the STA's own report, else an air monitor's.
const Measurement *levelLookup(const Sta &s, const Mac &bssid) noexcept
{
	const Measurement *m = measLookup(s, bssid, MeasSrc::STA_11K);
	return (m != nullptr) ? m : measLookup(s, bssid, MeasSrc::AIR_MONITOR);
}

} // namespace steer

Measurement &Daemon::storeMeasurement(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
				      std::uint8_t opClass, std::uint8_t channel, Millis ts) noexcept
{
	Measurement *e = nullptr;
	for (std::size_t i = 0U; (i < s.nMeas) && (e == nullptr); i++) {
		if ((s.meas[i].src == src) && (s.meas[i].bssid == bssid)) {
			e = &s.meas[i];
		}
	}
	if (e == nullptr) {
		if (s.nMeas < s.meas.size()) {
			e = &s.meas[s.nMeas];
			s.nMeas++;
		} else {
			e = &s.meas[0U];
			for (std::size_t i = 1U; i < s.nMeas; i++) {
				if (s.meas[i].ts < e->ts) {
					e = &s.meas[i];
				}
			}
		}
	}
	e->bssid = bssid;
	e->src = src;
	e->rcpi = rcpi;
	e->opClass = opClass;
	e->channel = channel;
	e->ts = ts;
	e->ulDbm = 0;
	e->paired = false; // a new value: usable for calibration again
	// A level on a band proves the STA can use it.
	const std::uint8_t bit = rrm::opClassBandBit(opClass);
	s.bandsSeen = static_cast<std::uint8_t>(s.bandsSeen | bit);
	if ((bit & (rrm::BANDS_5G | rrm::BANDS_6G)) != 0U) {
		s.bandEmpty = 0;
	}
	return *e;
}

// ---- candidate pool and measurement requests ----

void Daemon::buildPool(SteerTxn &t) noexcept
{
	const arcp::BssInfo &cur = mBss[t.bss].info;
	Sta *const s = findSta(t.sta);
	const Millis now = os::nowMs();
	// Skip bands the STA does not advertise (unless measured there) and
	// 6 GHz for a WPA2-PSK STA; a manual steer goes where the operator says.
	// An MLD STA never goes to another link of its own AP MLD: link
	// selection inside the AP MLD is the MLD's job, not BTM's.
	const auto usable = [&t, s, &cur](const arcp::BssInfo &bi) {
		const bool ownMld = (s != nullptr) && s->mld && arcp::isSameMld(bi, cur);
		return !ownMld &&
		       ((t.reason == arcp::SteerReason::MANUAL) || (s == nullptr) ||
			policy::isBandUsable(policy::StaBands{s->bandsAdv, s->bandsSeen, s->bandsBlocked},
					     bi.band));
	};
	// Best level the STA was measured at for bssid in the last
	// POOL_HINT_MS (11k or AP-side): a hint for the pool order only.
	const auto hint = [s, now](const Mac &bssid) {
		int r = policy::NO_HINT;
		for (std::size_t i = 0U; (s != nullptr) && (i < s->nMeas); i++) {
			const Measurement &m = s->meas[i];
			if ((m.bssid == bssid) && (m.rcpi <= 220U) && ((now - m.ts) < steer::POOL_HINT_MS) &&
			    (static_cast<int>(m.rcpi) > r)) {
				r = static_cast<int>(m.rcpi);
			}
		}
		return r;
	};
	// The pool holds MAX_CAND BSSes. When more qualify, a new one replaces
	// the lowest-ranked entry if it ranks strictly higher (the last added
	// of equal rank goes first), so with nothing known the peers visited
	// first stay. firstDrop: visit position of the first unknown remote
	// BSS left out, where the next steer of this STA starts.
	std::size_t firstDrop = MAX_PEERS;
	const auto add = [&t, &usable, &hint, &firstDrop](const arcp::BssInfo &bi, const Mac &ap, bool local,
							  std::size_t pos) {
		if ((!t.forcedTarget.isZero() && (t.forcedTarget != bi.bssid)) || !usable(bi)) {
			return;
		}
		Candidate c;
		c.bssid = bi.bssid;
		c.ap = ap;
		c.local = local;
		c.info = bi;
		c.poolRank = policy::candidatePoolRank(local, hint(bi.bssid));
		c.poolPos = pos;
		if (t.nCand < t.cand.size()) {
			t.cand[t.nCand] = c;
			t.nCand++;
			return;
		}
		std::size_t worst = 0U;
		for (std::size_t i = 1U; i < t.nCand; i++) {
			if (t.cand[i].poolRank <= t.cand[worst].poolRank) {
				worst = i;
			}
		}
		const Candidate *out = &c; // the BSS left out
		if (c.poolRank > t.cand[worst].poolRank) {
			const Candidate evicted = t.cand[worst];
			t.cand[worst] = c;
			out = &evicted;
			if (!out->local && (out->poolRank == 0) && (out->poolPos < firstDrop)) {
				firstDrop = out->poolPos;
			}
		} else if (!out->local && (out->poolRank == 0) && (out->poolPos < firstDrop)) {
			firstDrop = out->poolPos;
		} else {
			// a ranked BSS that did not fit
		}
	};
	const bool band = t.reason == arcp::SteerReason::BAND;
	const std::size_t start = (s != nullptr) ? (s->poolStart % MAX_PEERS) : 0U;

	t.nCand = 0U;
	for (std::size_t i = 0U; i < mNBss; i++) {
		if ((i != t.bss) && mBss[i].up && arcp::isSameEss(mBss[i].info, cur) &&
		    (!band || (mBss[i].info.band > cur.band))) {
			add(mBss[i].info, mApId, true, 0U);
		}
	}
	for (std::size_t k = 0U; k < MAX_PEERS; k++) {
		const Peer &p = mPeers[(start + k) % MAX_PEERS];
		if (!p.used) {
			continue;
		}
		for (const RemoteBss &rb : p.bss) {
			if (rb.used && arcp::isSameEss(rb.info, cur) && (!band ||
									 (rb.info.band > cur.band))) {
				add(rb.info, p.id, false, k);
			}
		}
	}
	// Measure the most promising first (requestBeacons takes channels in
	// pool order); evaluate() sorts by score afterwards.
	for (std::size_t i = 1U; i < t.nCand; i++) {
		const Candidate c = t.cand[i];
		std::size_t j = i;
		while ((j > 0U) && (t.cand[j - 1U].poolRank < c.poolRank)) {
			t.cand[j] = t.cand[j - 1U];
			j--;
		}
		t.cand[j] = c;
	}
	if ((s != nullptr) && (firstDrop < MAX_PEERS)) {
		s->poolStart = (start + firstDrop) % MAX_PEERS;
		logging::info(LOG_MODULE,
			      "steer #{} {}: more BSSes than the {} the pool holds, next pool starts at peer "
			      "slot {}", t.id, t.sta, MAX_CAND, s->poolStart);
	}
}

bool Daemon::requestBeacons(SteerTxn &t, Sta &s) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	LocalBss &src = mBss[t.bss];
	rrm::OpChanList chans{};
	std::size_t n = 0U;
	FixedString<256U> hexreq;
	FixedString<320U> cmd;
	hapd::Reply reply;

	// The tput model also measures the serving channel (first).
	const bool serving = p.scoreModel == ScoreModel::TPUT;
	for (std::size_t i = 0U; (i < (t.nCand + (serving ? 1U : 0U))) && (n < chans.size()); i++) {
		const arcp::BssInfo &bi = (serving &&
					   (i == 0U)) ? src.info : t.cand[serving ? (i - 1U) : i].info;
		bool dup = false;
		for (std::size_t k = 0U; k < n; k++) {
			dup = dup || ((chans[k].opClass == bi.opClass) && (chans[k].channel == bi.channel));
		}
		if (!dup) {
			chans[n] = rrm::OpChan{bi.opClass, bi.channel};
			n++;
		}
	}
	// One request for all channels: a STA refuses a second beacon
	// measurement while the first runs. hostapd refuses (FAIL, nothing
	// sent) a mode the STA did not advertise in its RM Enabled
	// Capabilities, which the control interface does not expose: try the
	// configured mode, then active, then passive, and remember the first
	// accepted. Table mode only repeats cached results: not a fallback.
	std::array<rrm::BeaconMode, 3U> modes{p.beaconMode, rrm::BeaconMode::ACTIVE,
						       rrm::BeaconMode::PASSIVE};
	std::size_t nModes = modes.size();
	if (s.bcnMode.has_value()) {
		modes[0U] = *s.bcnMode;
		nModes = 1U;
	}
	for (std::size_t i = 0U; i < nModes; i++) {
		const rrm::BeaconMode mode = modes[i];
		bool tried = false;
		for (std::size_t k = 0U; k < i; k++) {
			tried = tried || (modes[k] == mode);
		}
		if (tried) {
			continue;
		}
		std::uint16_t dur = static_cast<std::uint16_t>(p.beaconDuration);
		if ((mode == rrm::BeaconMode::PASSIVE) && (dur < rrm::PASSIVE_MIN_TU)) {
			dur = rrm::PASSIVE_MIN_TU;
		}
		// Reports may come per channel: allow two channel times of silence.
		t.bcnQuietMs = BCN_QUIET_BASE_MS + ((2U * static_cast<Millis>(dur) * 1024U) / 1000U);
		if (!rrm::buildBcnReqHex(chans, n, mode, dur, nullptr, src.info.ssidView(), hexreq)) {
			return false;
		}
		cmd.clear();
		formatTo(cmd, "REQ_BEACON {} {}", s.addr, hexreq);
		if (!src.hapd.runCommand(cmd.view(), reply)) {
			return false;
		}
		if (!startsWith(reply.view(), "FAIL")) {
			if (!(s.bcnMode.has_value() && (*s.bcnMode == mode))) {
				logging::info(LOG_MODULE, "sta {}: {} beacon reports", s.addr,
					      rrm::beaconModeName(mode));
			}
			s.bcnMode = mode;
			return true;
		}
	}
	logging::info(LOG_MODULE, "sta {}: beacon report not supported (no active or passive mode)", s.addr);
	s.bcnMode.reset();
	s.bcnUnsupported = true;
	s.flags = static_cast<std::uint8_t>(s.flags & static_cast<std::uint8_t>(~arcp::STA_F11K));
	return false;
}

// Ask every candidate owner that has an air monitor to listen for the STA.
// Step 1 of an AP-side measurement: multicast STA_MONITOR_REQ to every
// peer, and start this AP's own watch when one of its BSSes is a candidate.
// MEASURE then waits for a STA_MONITOR_STATUS from this AP and from each
// peer that owns a candidate (others may answer too). Returns the number of
// APs waited for.
std::size_t Daemon::requestMonitors(SteerTxn &t, const Sta &s) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const arcp::BssInfo &src = mBss[t.bss].info;
	bool anyPeer = false;

	t.nMonWait = 0U;
	if (!p.amonRequest) {
		return 0U;
	}
	for (std::size_t i = 0U; i < t.nCand; i++) {
		const Candidate &c = t.cand[i];
		const Mac ap = c.local ? mApId : c.ap;
		bool dup = false;
		for (std::size_t k = 0U; k < t.nMonWait; k++) {
			dup = dup || (t.monWait[k] == ap);
		}
		if (dup) {
			continue;
		}
		if (c.local) {
			const arcp::MonitorStatus st =
				startAmonWatch(s.addr, mApId, t.id, p.amonDurationMs, src.opClass,
					       src.channel);
			if (st != arcp::MonitorStatus::MEASURED) {
				continue;
			}
		} else if (findPeer(c.ap) == nullptr) {
			continue;
		} else {
			anyPeer = true;
		}
		t.monWait[t.nMonWait] = ap;
		t.nMonWait++;
	}
	if (anyPeer) {
		arcp::StaMonitorReq r;
		r.txn = t.id;
		r.sta = s.addr;
		r.durationMs = static_cast<std::uint16_t>(p.amonDurationMs);
		r.opClass = src.opClass;
		r.channel = src.channel;
		arcp::Message m;
		beginMsg(m, arcp::MsgType::STA_MONITOR_REQ, 0U);
		(void)m.add(r);
		multicast(m);
	}
	if (t.nMonWait > 0U) {
		logging::info(LOG_MODULE, "steer #{} {}: measurement requested, waiting for {} AP(s)", t.id,
			      s.addr, t.nMonWait);
	}
	return t.nMonWait;
}

// ---- events that end MEASURE ----

// True when MEASURE can end before its deadline.
bool Daemon::isMeasureComplete(const SteerTxn &t, const Sta &s) const noexcept
{
	bool all11k = true;
	bool allAny = true;

	for (std::size_t i = 0U; i < t.nCand; i++) {
		all11k = all11k && freshSince(steer::bcnLookup(s, t.cand[i].bssid), t.started);
		allAny = allAny && freshSince(steer::levelLookup(s, t.cand[i].bssid), t.started);
	}
	// The tput model also needs the STA's own level of the serving BSS.
	if ((mCfg.pol.scoreModel == ScoreModel::TPUT) && t.bcnOutstanding &&
	    !freshSince(steer::bcnLookup(s, mBss[t.bss].info.bssid), t.started)) {
		all11k = false;
	}
	// STA-measured levels win; monitor levels only once 11k is over.
	return all11k || (!t.bcnOutstanding && allAny);
}

void Daemon::onBeaconReport(Sta &s, const std::optional<rrm::BeaconReport> &r) noexcept
{
	SteerTxn *const t = findTxnBySta(s.addr);

	if (r.has_value()) {
		(void)storeMeasurement(s, r->bssid, MeasSrc::STA_11K, r->rcpi, r->opClass, r->channel,
				       os::nowMs());
		pairUlDl(s, r->bssid);
	}
	if ((t == nullptr) || (t->state != SteerState::MEASURE)) {
		return;
	}
	if (!r.has_value()) {
		// Refused or empty report: the one 11k measurement is over.
		// Without monitor reports to wait for, evaluate now.
		t->bcnOutstanding = false;
		if (!t->amonPending || isMeasureComplete(*t, s)) {
			evaluate(*t);
		}
	} else if (isMeasureComplete(*t, s)) {
		evaluate(*t);
	} else {
		// More may come; tickSteer ends the 11k part after a quiet period.
		t->bcnQuietUntil = os::nowMs() + t->bcnQuietMs;
	}
}

void Daemon::onMonitorResult(Sta &s) noexcept
{
	SteerTxn *const t = findTxnBySta(s.addr);
	if ((t != nullptr) && (t->state == SteerState::MEASURE) && isMeasureComplete(*t, s)) {
		evaluate(*t);
	}
}

} // namespace donghoa
