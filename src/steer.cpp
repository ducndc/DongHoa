// SPDX-License-Identifier: MIT
// Steering transaction state machine (source AP) and admission control
// (target AP). See docs/SDD.md section 6.6.
//
//   IDLE -> MEASURE (11k beacon request + air monitors) -> NEGOTIATE
//   (STEER_REQ/RESP with the target AP; skipped for local BSSes) -> BTM
//   (11v BSS TM Request) -> ROAM (wait for the association) -> done
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};
constexpr Millis MEAS_FRESH_MS = 10000U;
constexpr Millis REMOTE_HOLD_SLACK_MS = 1500U; // covers ARCP retransmissions
constexpr Millis AMON_REPORT_SLACK_MS = 500U;  // monitor report delivery after the watch
constexpr std::uint8_t NO_STATUS = 0xffU;

std::string_view reasonName(arcp::SteerReason r) noexcept
{
	std::string_view n = "?";
	switch (r) {
	case arcp::SteerReason::RSSI: n = "rssi"; break;
	case arcp::SteerReason::LOAD: n = "load"; break;
	case arcp::SteerReason::BAND: n = "band"; break;
	case arcp::SteerReason::MANUAL: n = "manual"; break;
	default: break;
	}
	return n;
}

std::string_view reasonNameRaw(std::uint8_t r) noexcept
{
	return ((r >= 1U) && (r <= 4U)) ? reasonName(static_cast<arcp::SteerReason>(r)) : "?";
}

constexpr std::array<std::string_view, 6U> OUTCOME_NAMES{"success",      "btm-reject",   "btm-timeout",
							"roam-timeout", "wrong-target", "aborted"};

std::string_view outcomeName(std::uint8_t o) noexcept
{
	std::string_view name{"?"};
	if (o < OUTCOME_NAMES.size()) {
		name = OUTCOME_NAMES[o];
	}
	return name;
}

std::uint8_t raw(arcp::SteerOutcome o) noexcept
{
	return static_cast<std::uint8_t>(o);
}

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

bool freshSince(const Measurement *m, Millis since) noexcept
{
	return (m != nullptr) && (m->ts >= since);
}

// Best score first. Insertion sort: at most MAX_CAND entries, stable, and
// no comparator subtraction that could overflow.
void sortCandidates(std::array<Candidate, MAX_CAND> &c, std::size_t n) noexcept
{
	for (std::size_t i = 1U; i < n; i++) {
		const Candidate key = c[i];
		std::size_t j = i;
		while ((j > 0U) && (c[j - 1U].score < key.score)) {
			c[j] = c[j - 1U];
			j--;
		}
		c[j] = key;
	}
}

} // namespace

std::string_view steerStateName(SteerState s) noexcept
{
	std::string_view n = "?";
	switch (s) {
	case SteerState::IDLE: n = "IDLE"; break;
	case SteerState::MEASURE: n = "MEASURE"; break;
	case SteerState::NEGOTIATE: n = "NEGOTIATE"; break;
	case SteerState::BTM: n = "BTM"; break;
	case SteerState::ROAM: n = "ROAM"; break;
	default: break;
	}
	return n;
}

SteerTxn *Daemon::findTxnBySta(const Mac &sta) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : mTxn) {
		if ((r == nullptr) && t.used && (t.sta == sta)) {
			r = &t;
		}
	}
	return r;
}

SteerTxn *Daemon::findTxnById(std::uint32_t id) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : mTxn) {
		if ((r == nullptr) && t.used && (t.id == id)) {
			r = &t;
		}
	}
	return r;
}

int Daemon::countReservations(std::size_t bss, Millis now) const noexcept
{
	int n = 0;
	for (const Reservation &r : mResv) {
		if (r.used && (r.bss == bss) && (r.expiry > now)) {
			n++;
		}
	}
	return n;
}

void Daemon::storeMeasurement(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
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
	// A level on a band proves the STA can use it.
	const std::uint8_t bit = rrm::opClassBandBit(opClass);
	s.bandsSeen = static_cast<std::uint8_t>(s.bandsSeen | bit);
	if ((bit & (rrm::BANDS_5G | rrm::BANDS_6G)) != 0U) {
		s.bandEmpty = 0;
	}
}

// ---- transaction end ----

void Daemon::sendResult(const SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus) noexcept
{
	if ((t.cur < t.nCand) && !t.cand[t.cur].local && (t.state >= SteerState::BTM)) {
		arcp::SteerResult r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.outcome = raw(outcome);
		r.btmStatus = btmStatus;
		beginMsg(m, arcp::MsgType::STEER_RESULT, arcp::FLAG_ACK_REQ);
		(void)m.add(r);
		(void)unicast(t.cand[t.cur].ap, m);
	}
}

void Daemon::endTxn(SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus,
		     bool countFailure) noexcept
{
	Sta *const s = findSta(t.sta);
	const Millis now = os::nowMs();

	logging::info(LOG_MODULE, "steer #{} {} ({}) finished: {} after {} ms", t.id, t.sta, reasonName(t.reason),
		      outcomeName(raw(outcome)), now - t.started);
	sendResult(t, outcome, btmStatus);
	if (s != nullptr) {
		if ((outcome == arcp::SteerOutcome::SUCCESS) || (outcome == arcp::SteerOutcome::WRONG_TARGET)) {
			s->steerFailures = 0;
			s->nextSteerMs = now + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		} else {
			if (countFailure) {
				s->steerFailures++;
			}
			s->nextSteerMs = now + static_cast<Millis>(policy::backoffMs(mCfg.pol, s->steerFailures));
		}
	}
	t.used = false;
}

// No candidate at all: wait a cooldown; not a STA failure. A band steer
// in which no candidate was measured at all says nothing about the STA's
// bands, but repeating it every cooldown wastes airtime: back off
// exponentially until a higher-band level shows up.
void Daemon::failTxnNoCandidate(SteerTxn &t) noexcept
{
	Sta *const s = findSta(t.sta);
	const Millis now = os::nowMs();

	logging::info(LOG_MODULE, "steer #{} {} ({}): no suitable candidate", t.id, t.sta, reasonName(t.reason));
	if (s != nullptr) {
		s->nextSteerMs = now + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		if (t.reason == arcp::SteerReason::BAND) {
			if (!t.anyMeasured) {
				s->bandEmpty++;
			}
			const int wait = policy::backoffMs(mCfg.pol, s->bandEmpty);
			s->nextBandMs = now + static_cast<Millis>(wait);
			if (!t.anyMeasured) {
				logging::info(LOG_MODULE, "sta {}: no higher-band level ({} in a row), next band steer in {} ms",
					      t.sta, s->bandEmpty, wait);
			}
		}
	}
	t.used = false;
}

// ---- 11v BSS Transition Management Request ----

void Daemon::sendBtm(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	LocalBss &src = mBss[t.bss];
	const Candidate &c = t.cand[t.cur];
	FixedString<512U> cmd;
	hapd::Reply reply;
	std::uint32_t bi = c.info.bssidInfo;

	if ((c.info.mdid != 0U) && (c.info.mdid == src.info.mdid)) {
		bi |= rrm::BI_MOBILITY_DOMAIN;
	}
	formatTo(cmd, "BSS_TM_REQ {} pref=1 abridged=1 valid_int={}", t.sta, p.btmValidInt);
	if (p.disassocImminent) {
		formatTo(cmd, " disassoc_imminent=1 disassoc_timer={}", p.disassocTimer);
	}
	// neighbor=<BSSID>,<BSSID Info>,<Op Class>,<Channel>,<PHY type>[,<subelems>]
	// Subelement 3 = BSS Transition Candidate Preference (255 = best).
	formatTo(cmd, " neighbor={},0x{},{},{},{},0301ff", c.bssid, hex(bi, 8U), c.info.opClass,
		  c.info.channel, c.info.phyType);
	if (!src.hapd.runCommand(cmd.view(), reply) || !startsWith(reply.view(), "OK")) {
		logging::warn(LOG_MODULE, "steer #{}: BSS_TM_REQ rejected by hostapd (bss_transition=1?)", t.id);
		t.state = SteerState::BTM; // so the target gets a STEER_RESULT
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, true);
		return;
	}
	logging::info(LOG_MODULE, "steer #{} {}: BTM request -> {} ch {} (score {})", t.id, t.sta, c.bssid,
		      c.info.channel, c.score);
	t.state = SteerState::BTM;
	t.deadline = os::nowMs() + static_cast<Millis>(p.btmTimeoutMs);
}

// ---- candidate walk ----

void Daemon::advance(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;

	for (; t.cur < t.nCand; t.cur++) {
		const Candidate &c = t.cand[t.cur];
		const Sta *const s = findSta(t.sta);

		if (c.local) {
			const std::optional<std::size_t> b = findLocalBss(c.bssid);
			if (b.has_value() &&
			    (policy::admit(p, policy::utilToPct(mBss[*b].load.util), mBss[*b].load.staCount,
					   countReservations(*b, os::nowMs()), mBss[*b].cfg->maxSta) ==
			     arcp::SteerStatus::ACCEPT)) {
				sendBtm(t);
				return;
			}
			continue;
		}
		arcp::SteerReq r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.srcBssid = mBss[t.bss].info.bssid;
		r.tgtBssid = c.bssid;
		r.reason = static_cast<std::uint8_t>(t.reason);
		r.rcpi = c.rcpi;
		r.staFlags = (s != nullptr) ? s->flags : 0U;
		r.curRssi = static_cast<std::int8_t>((s != nullptr) ? s->rssi : 0);
		beginMsg(m, arcp::MsgType::STEER_REQ, arcp::FLAG_ACK_REQ);
		(void)m.add(r);
		if (!unicast(c.ap, m)) {
			continue;
		}
		logging::info(LOG_MODULE, "steer #{} {}: asking AP {} for {}", t.id, t.sta, c.ap, c.bssid);
		t.state = SteerState::NEGOTIATE;
		t.deadline = os::nowMs() + static_cast<Millis>(p.steerRespTimeoutMs) + REMOTE_HOLD_SLACK_MS;
		return;
	}
	if (t.state == SteerState::MEASURE) {
		failTxnNoCandidate(t);
	} else {
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
	}
}

void Daemon::evaluate(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Sta *const s = findSta(t.sta);
	policy::SteerCtx ctx;
	std::size_t n = 0U;

	if (s == nullptr) {
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
		return;
	}
	const LocalBss &src = mBss[t.bss];
	ctx.reason = t.reason;
	ctx.curRssi = s->rssi;
	ctx.curBand = src.info.band;
	ctx.curUtilPct = policy::utilToPct(src.load.util);
	ctx.curPeakMbps = policy::computePeakMbps(src.info.caps, src.info.bw, p.staNss);
	if (p.scoreModel == ScoreModel::TPUT) {
		// Compare like with like: the STA's own downlink measurement of
		// the serving BSS, as for the candidates, when it has one.
		const Measurement *const cur = bcnLookup(*s, src.info.bssid);
		if (cur != nullptr) {
			ctx.curRssi = rrm::rcpiToDbm(cur->rcpi);
		}
	}
	for (std::size_t i = 0U; i < t.nCand; i++) {
		Candidate &c = t.cand[i];
		const Measurement *const be = levelLookup(*s, c.bssid);
		policy::CandInput in;
		bool known = true;

		in.band = c.info.band;
		in.peakMbps = policy::computePeakMbps(c.info.caps, c.info.bw, p.staNss);
		in.estRssi = (be != nullptr) ? rrm::rcpiToDbm(be->rcpi) : policy::RSSI_UNKNOWN;
		t.anyMeasured = t.anyMeasured || (be != nullptr);
		c.rcpi = (be != nullptr) ? be->rcpi : 255U;
		if (in.estRssi == policy::RSSI_UNKNOWN) {
			if (t.reason == arcp::SteerReason::MANUAL) {
				in.estRssi = p.rssiMinTarget; // operator decided
			} else if ((t.reason == arcp::SteerReason::RSSI) &&
				   ((s->bandsAdv & rrm::bandBit(c.info.band)) != 0U)) {
				// The current band is already known bad (that is why this
				// steer started) and the STA advertised this candidate's
				// band in its Supported Operating Classes element. Trust
				// that capability rather than refuse for lack of a fresh
				// 11k/air monitor measurement, which a STA at the edge of
				// range often never answers in time. Floor, not a real
				// estimate: the lowest level that still clears score()'s
				// eligibility checks, so a measured candidate always wins.
				const int floor = ctx.curRssi + p.rssiHysteresis;
				in.estRssi = (floor > p.rssiMinTarget) ? floor : p.rssiMinTarget;
			}
		}
		if (c.local) {
			const std::optional<std::size_t> b = findLocalBss(c.bssid);
			known = b.has_value();
			if (known) {
				in.utilPct = policy::utilToPct(mBss[*b].load.util);
				in.staCount = static_cast<int>(mBss[*b].load.staCount) + countReservations(*b, os::nowMs());
				in.maxSta = mBss[*b].cfg->maxSta;
			}
		} else {
			const RemoteBss *const rb = lookupRemoteBss(c.bssid, nullptr);
			known = rb != nullptr;
			if (known && rb->hasLoad) {
				in.utilPct = policy::utilToPct(rb->load.util);
				in.staCount = static_cast<int>(rb->load.staCount);
				in.maxSta = static_cast<int>(rb->load.maxSta);
				in.accepting = (rb->load.flags & arcp::LOAD_ACCEPTING) != 0U;
			}
		}
		if (!known) {
			continue;
		}
		c.score = policy::score(p, ctx, in);
		logging::dbg(LOG_MODULE, "steer #{} cand {} rssi {} ({}) util {}% -> {}", t.id, c.bssid, in.estRssi,
			     (be == nullptr) ? "unmeasured"
					     : ((be->src == MeasSrc::STA_11K) ? "11k" : "air monitor"),
			     in.utilPct, (c.score == policy::INELIGIBLE) ? -9999 : c.score);
		if (c.score != policy::INELIGIBLE) {
			t.cand[n] = c;
			n++;
		}
	}
	t.nCand = n;
	sortCandidates(t.cand, n);
	t.cur = 0U;
	advance(t);
}

// ---- start ----

void Daemon::buildPool(SteerTxn &t) noexcept
{
	const arcp::BssInfo &cur = mBss[t.bss].info;
	const Sta *const s = findSta(t.sta);
	// Skip bands the STA does not advertise (unless measured there) and
	// 6 GHz for a WPA2-PSK STA; a manual steer goes where the operator says.
	const auto usable = [&t, s](const arcp::BssInfo &bi) {
		return (t.reason == arcp::SteerReason::MANUAL) || (s == nullptr) ||
		       policy::isBandUsable(policy::StaBands{s->bandsAdv, s->bandsSeen, s->bandsBlocked}, bi.band);
	};
	const auto add = [&t, &usable](const arcp::BssInfo &bi, const Mac &ap, bool local) {
		if ((t.nCand < t.cand.size()) && (t.forcedTarget.isZero() || (t.forcedTarget == bi.bssid)) &&
		    usable(bi)) {
			Candidate &c = t.cand[t.nCand];
			c = Candidate{};
			c.bssid = bi.bssid;
			c.ap = ap;
			c.local = local;
			c.info = bi;
			t.nCand++;
		}
	};
	const bool band = t.reason == arcp::SteerReason::BAND;

	t.nCand = 0U;
	for (std::size_t i = 0U; i < mNBss; i++) {
		if ((i != t.bss) && mBss[i].up && arcp::isSameEss(mBss[i].info, cur) &&
		    (!band || (mBss[i].info.band > cur.band))) {
			add(mBss[i].info, mApId, true);
		}
	}
	for (const Peer &p : mPeers) {
		if (!p.used) {
			continue;
		}
		for (const RemoteBss &rb : p.bss) {
			if (rb.used && arcp::isSameEss(rb.info, cur) && (!band || (rb.info.band > cur.band))) {
				add(rb.info, p.id, false);
			}
		}
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
		const arcp::BssInfo &bi = (serving && (i == 0U)) ? src.info : t.cand[serving ? (i - 1U) : i].info;
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
	std::array<rrm::BeaconMode, 3U> modes{p.beaconMode, rrm::BeaconMode::ACTIVE, rrm::BeaconMode::PASSIVE};
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
				logging::info(LOG_MODULE, "sta {}: {} beacon reports", s.addr, rrm::beaconModeName(mode));
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
// Returns the number of requests (local watch included).
std::size_t Daemon::requestMonitors(const SteerTxn &t, const Sta &s) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const arcp::BssInfo &src = mBss[t.bss].info;
	std::array<Mac, MAX_CAND> asked{};
	std::size_t nAsked = 0U;
	std::size_t sent = 0U;

	if (!p.amonRequest) {
		return 0U;
	}
	arcp::StaMonitorReq r;
	r.txn = t.id;
	r.sta = s.addr;
	r.durationMs = static_cast<std::uint16_t>(p.amonDurationMs);
	r.opClass = src.opClass;
	r.channel = src.channel;
	for (std::size_t i = 0U; i < t.nCand; i++) {
		const Candidate &c = t.cand[i];
		bool dup = false;
		for (std::size_t k = 0U; k < nAsked; k++) {
			dup = dup || (asked[k] == c.ap);
		}
		if (dup) {
			continue;
		}
		asked[nAsked] = c.ap;
		nAsked++;
		if (c.local) {
			if (startAmonWatch(s.addr, mApId, t.id, p.amonDurationMs)) {
				sent++;
			}
			continue;
		}
		const Peer *const pe = findPeer(c.ap);
		if ((pe == nullptr) || ((pe->flags & arcp::AP_FLAG_AIR_MONITOR) == 0U)) {
			continue;
		}
		arcp::Message m;
		beginMsg(m, arcp::MsgType::STA_MONITOR_REQ, arcp::FLAG_ACK_REQ);
		(void)m.add(r);
		if (unicast(c.ap, m)) {
			sent++;
		}
	}
	if (sent > 0U) {
		logging::info(LOG_MODULE, "steer #{} {}: {} air monitor request(s)", t.id, s.addr, sent);
	}
	return sent;
}

bool Daemon::startSteer(Sta &s, arcp::SteerReason reason, const Mac *target) noexcept
{
	SteerTxn *t = nullptr;

	if ((findTxnBySta(s.addr) != nullptr) || !mBss[s.bss].up) {
		return false;
	}
	for (SteerTxn &x : mTxn) {
		if ((t == nullptr) && !x.used) {
			t = &x;
		}
	}
	if (t == nullptr) {
		return false;
	}
	*t = SteerTxn{};
	mNextTxn++;
	t->id = mNextTxn;
	t->sta = s.addr;
	t->bss = s.bss;
	t->reason = reason;
	t->started = os::nowMs();
	if (target != nullptr) {
		t->forcedTarget = *target;
	}
	buildPool(*t);
	if (t->nCand == 0U) {
		s.nextSteerMs = os::nowMs() + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		return false;
	}
	t->used = true;
	t->state = SteerState::MEASURE;
	logging::info(LOG_MODULE, "steer #{} {} start: reason {}, rssi {}, {} candidate BSS", t->id, s.addr,
		      reasonName(reason), s.rssi, t->nCand);

	// 11k (STA-measured) and air monitors (AP-measured) in parallel: a STA
	// without 11k, or too busy to answer, is still measured.
	if (((s.flags & arcp::STA_F11K) != 0U) && requestBeacons(*t, s)) {
		t->bcnOutstanding = true;
		t->deadline = os::nowMs() + static_cast<Millis>(mCfg.pol.beaconReqTimeoutMs);
	}
	if (requestMonitors(*t, s) > 0U) {
		const Millis dl = os::nowMs() + static_cast<Millis>(mCfg.pol.amonDurationMs) + AMON_REPORT_SLACK_MS;
		t->amonPending = true;
		if (dl > t->deadline) {
			t->deadline = dl;
		}
	}
	if (!t->bcnOutstanding && !t->amonPending) {
		evaluate(*t);
	}
	return true;
}

// ---- triggers ----

void Daemon::onStaPoll(Sta &s) noexcept
{
	const PolicyConfig &p = mCfg.pol;

	if (s.away || (os::nowMs() < s.nextSteerMs) || ((s.flags & arcp::STA_F11V) == 0U) ||
	    (findTxnBySta(s.addr) != nullptr)) {
		return;
	}
	const std::uint8_t band = mBss[s.bss].info.band;
	if (policy::isRssiTriggered(p, s.rssi, s.lowCount)) {
		(void)startSteer(s, arcp::SteerReason::RSSI, nullptr);
	} else if (policy::isBandTriggered(p, band, s.rssi) && (os::nowMs() >= s.nextBandMs) &&
		   policy::hasHigherBand(policy::StaBands{s.bandsAdv, s.bandsSeen, s.bandsBlocked}, band)) {
		(void)startSteer(s, arcp::SteerReason::BAND, nullptr);
	} else {
		// no trigger
	}
}

void Daemon::runLbRound() noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Millis now = os::nowMs();

	for (std::size_t b = 0U; b < mNBss; b++) {
		const LocalBss &lb = mBss[b];
		Sta *pick = nullptr;

		if (!lb.up || !policy::isBssOverloaded(p, policy::utilToPct(lb.load.util), lb.load.staCount,
						       lb.cfg->maxSta)) {
			continue;
		}
		// Weakest eligible STA first: it costs the most airtime per bit.
		for (Sta &s : mSta) {
			const bool eligible = s.used && !s.away && (s.bss == b) && (s.rssi != 0) &&
					      (now >= s.nextSteerMs) && ((s.flags & arcp::STA_F11V) != 0U) &&
					      (findTxnBySta(s.addr) == nullptr) &&
					      policy::isLbStaEligible(p, s.tputKbps);
			if (eligible && ((pick == nullptr) || (s.rssi < pick->rssi))) {
				pick = &s;
			}
		}
		if (pick != nullptr) {
			logging::info(LOG_MODULE, "bss {} overloaded (util {}%, {} STA): offloading {}", lb.cfg->ifname,
				      policy::utilToPct(lb.load.util), lb.load.staCount, pick->addr);
			(void)startSteer(*pick, arcp::SteerReason::LOAD, nullptr);
		}
	}
}

// ---- events into the source-side state machine ----

// True when MEASURE can end before its deadline.
bool Daemon::isMeasureComplete(const SteerTxn &t, const Sta &s) const noexcept
{
	bool all11k = true;
	bool allAny = true;

	for (std::size_t i = 0U; i < t.nCand; i++) {
		all11k = all11k && freshSince(bcnLookup(s, t.cand[i].bssid), t.started);
		allAny = allAny && freshSince(levelLookup(s, t.cand[i].bssid), t.started);
	}
	// The tput model also needs the STA's own level of the serving BSS.
	if ((mCfg.pol.scoreModel == ScoreModel::TPUT) && t.bcnOutstanding &&
	    !freshSince(bcnLookup(s, mBss[t.bss].info.bssid), t.started)) {
		all11k = false;
	}
	// STA-measured levels win; monitor levels only once 11k is over.
	return all11k || (!t.bcnOutstanding && allAny);
}

void Daemon::onBeaconReport(Sta &s, const std::optional<rrm::BeaconReport> &r) noexcept
{
	SteerTxn *const t = findTxnBySta(s.addr);

	if (r.has_value()) {
		storeMeasurement(s, r->bssid, MeasSrc::STA_11K, r->rcpi, r->opClass, r->channel, os::nowMs());
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
		// wait for more reports
	}
}

void Daemon::onMonitorResult(Sta &s) noexcept
{
	SteerTxn *const t = findTxnBySta(s.addr);
	if ((t != nullptr) && (t->state == SteerState::MEASURE) && isMeasureComplete(*t, s)) {
		evaluate(*t);
	}
}

void Daemon::onBtmResp(const hapd::BtmResp &r) noexcept
{
	SteerTxn *const t = findTxnBySta(r.addr);

	if ((t == nullptr) || (t->state != SteerState::BTM)) {
		return;
	}
	if (r.status != 0) {
		// 802.11v status: 1 reject, 2 insufficient beacons, 3 capacity,
		// 5 delay requested, 6 candidate list provided, 7 no candidates
		logging::info(LOG_MODULE, "steer #{} {}: BTM rejected, status {}", t->id, r.addr, r.status);
		if ((t->cur + 1U) < t->nCand) {
			// This candidate said no; try the next one before giving up.
			sendResult(*t, arcp::SteerOutcome::BTM_REJECT, static_cast<std::uint8_t>(r.status));
			t->cur++;
			advance(*t);
		} else {
			endTxn(*t, arcp::SteerOutcome::BTM_REJECT, static_cast<std::uint8_t>(r.status), true);
		}
		return;
	}
	if (r.hasTarget && (t->cur < t->nCand) && (r.target != t->cand[t->cur].bssid)) {
		logging::info(LOG_MODULE, "steer #{}: STA chose {} instead", t->id, r.target);
	}
	t->state = SteerState::ROAM;
	t->deadline = os::nowMs() + static_cast<Millis>(mCfg.pol.roamTimeoutMs);
}

void Daemon::onStaEvent(const Mac &ap, const arcp::StaEvent &e) noexcept
{
	if (e.event != static_cast<std::uint8_t>(arcp::StaEventType::ASSOC)) {
		return;
	}
	// Target side: a reservation for this STA is consumed.
	for (Reservation &r : mResv) {
		if (r.used && (r.sta == e.sta) && (ap == mApId)) {
			r.used = false;
		}
	}
	// After a roam (esp. FT) the old hostapd keeps the STA until its
	// inactivity timer fires: stop reporting and steering it meanwhile.
	if (ap != mApId) {
		Sta *const s = findSta(e.sta);
		if ((s != nullptr) && !s->away) {
			logging::info(LOG_MODULE, "sta {} now served by AP {}", e.sta, ap);
			s->away = true;
		}
	}
	SteerTxn *const t = findTxnBySta(e.sta);
	if ((t == nullptr) || ((t->state != SteerState::BTM) && (t->state != SteerState::ROAM)) ||
	    (t->cur >= t->nCand)) {
		return;
	}
	if (e.bssid == mBss[t->bss].info.bssid) {
		return; // reassociated to the source
	}
	endTxn(*t, (e.bssid == t->cand[t->cur].bssid) ? arcp::SteerOutcome::SUCCESS : arcp::SteerOutcome::WRONG_TARGET,
		0U, false);
}

void Daemon::onLocalDisassoc(const Mac &sta) noexcept
{
	SteerTxn *const t = findTxnBySta(sta);
	// In BTM/ROAM the STA leaving is expected; wait for its association.
	if ((t != nullptr) && ((t->state == SteerState::MEASURE) || (t->state == SteerState::NEGOTIATE))) {
		endTxn(*t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
	}
}

void Daemon::onSteerResp(const Peer &from, const arcp::SteerResp &r) noexcept
{
	SteerTxn *const t = findTxnById(r.txn);

	if ((t == nullptr) || (t->state != SteerState::NEGOTIATE) || (t->cur >= t->nCand) ||
	    (t->cand[t->cur].ap != from.id)) {
		return;
	}
	if (r.status == static_cast<std::uint8_t>(arcp::SteerStatus::ACCEPT)) {
		sendBtm(*t);
		return;
	}
	logging::info(LOG_MODULE, "steer #{}: AP {} refused (status {})", t->id, from.id, r.status);
	t->cur++;
	advance(*t);
}

void Daemon::onPeerLost(const Peer &p) noexcept
{
	for (SteerTxn &t : mTxn) {
		if (t.used && (t.state == SteerState::NEGOTIATE) && (t.cur < t.nCand) && (t.cand[t.cur].ap == p.id)) {
			t.cur++;
			advance(t);
		}
	}
	for (Reservation &r : mResv) {
		if (r.used && (r.srcAp == p.id)) {
			r.used = false;
		}
	}
}

// ---- target side ----

void Daemon::onSteerReq(const Peer &from, const arcp::SteerReq &r) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Millis now = os::nowMs();
	const std::optional<std::size_t> b = findLocalBss(r.tgtBssid);
	arcp::SteerStatus status = arcp::SteerStatus::ACCEPT;
	arcp::SteerResp resp;
	arcp::Message m;

	resp.txn = r.txn;
	if (!b.has_value()) {
		status = arcp::SteerStatus::UNKNOWN_BSS;
	} else if (findTxnBySta(r.sta) != nullptr) {
		status = arcp::SteerStatus::BUSY;
	} else {
		status = policy::admit(p, policy::utilToPct(mBss[*b].load.util), mBss[*b].load.staCount,
				       countReservations(*b, now), mBss[*b].cfg->maxSta);
	}
	if (status == arcp::SteerStatus::ACCEPT) {
		Reservation *rv = nullptr;
		for (Reservation &x : mResv) {
			if ((rv == nullptr) && (!x.used || (x.expiry <= now))) {
				rv = &x;
			}
		}
		if (rv == nullptr) {
			status = arcp::SteerStatus::BUSY;
		} else {
			rv->used = true;
			rv->sta = r.sta;
			rv->srcAp = from.id;
			rv->bss = *b;
			rv->txn = r.txn;
			rv->expiry = now + static_cast<Millis>(p.reserveHoldMs);
			resp.holdMs = static_cast<std::uint16_t>(p.reserveHoldMs);
		}
	}
	resp.status = static_cast<std::uint8_t>(status);
	logging::info(LOG_MODULE, "steer-in request #{} from {}: sta {} -> {} ({}, rcpi {}): {}", r.txn, from.id,
		      r.sta, r.tgtBssid, reasonNameRaw(r.reason), r.rcpi,
		      (status == arcp::SteerStatus::ACCEPT) ? "accept" : "reject");
	beginMsg(m, arcp::MsgType::STEER_RESP, arcp::FLAG_ACK_REQ);
	(void)m.add(resp);
	(void)unicast(from.id, m);
}

void Daemon::onSteerResult(const Peer &from, const arcp::SteerResult &r) noexcept
{
	for (Reservation &rv : mResv) {
		if (rv.used && (rv.txn == r.txn) && (rv.srcAp == from.id)) {
			rv.used = false;
		}
	}
	logging::info(LOG_MODULE, "steer #{} from {} sta {}: {}", r.txn, from.id, r.sta, outcomeName(r.outcome));
}

// ---- timers ----

void Daemon::tickSteer(Millis now) noexcept
{
	for (SteerTxn &t : mTxn) {
		if (!t.used || (now < t.deadline)) {
			continue;
		}
		switch (t.state) {
		case SteerState::MEASURE:
			evaluate(t);
			break;
		case SteerState::NEGOTIATE:
			logging::info(LOG_MODULE, "steer #{}: no STEER_RESP from {}", t.id,
				      (t.cur < t.nCand) ? t.cand[t.cur].ap : Mac{});
			t.cur++;
			advance(t);
			break;
		case SteerState::BTM:
			if ((t.cur + 1U) < t.nCand) {
				// No BTM response from this candidate; try the next one
				// before giving up on the whole steer.
				logging::info(LOG_MODULE, "steer #{}: no BTM response from {}, trying next candidate",
					      t.id, t.cand[t.cur].bssid);
				sendResult(t, arcp::SteerOutcome::BTM_TIMEOUT, NO_STATUS);
				t.cur++;
				advance(t);
			} else {
				endTxn(t, arcp::SteerOutcome::BTM_TIMEOUT, NO_STATUS, true);
			}
			break;
		case SteerState::ROAM:
			endTxn(t, arcp::SteerOutcome::ROAM_TIMEOUT, 0U, true);
			break;
		default:
			t.used = false;
			break;
		}
	}
	for (Reservation &r : mResv) {
		if (r.used && (r.expiry <= now)) {
			r.used = false;
		}
	}
}

} // namespace donghoa
