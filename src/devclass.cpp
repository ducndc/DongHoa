// SPDX-License-Identifier: MIT
// Low-power (IoT) device classification from traffic behaviour, and the
// device class records shared between APs.
//
// Each poll of a local STA gives one uplink and one downlink rate. Over the
// connection the AP keeps their standard deviations and the behaviour score
// S = alpha(band) x sigma_up / sigma_down: a sensor or camera pushes data up
// in bursts and receives little, so S > 1 adds one to the STA's score
// theta, S <= 1 takes one away. theta > lp_threshold classifies the STA as
// low-power (policy.cpp holds the arithmetic).
//
// A change of class is sent (STA_CLASS, reliable) to every peer, which
// keeps it in its table; when the STA later associates to another AP, or an
// AP restarts, the record comes back from the peers instead of being
// learned again. There is no master AP: every AP holds the table.
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "text.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::CLASS};
// A local disassociation and a peer's association report this close make an own roam.
constexpr Millis OWN_ROAM_WINDOW_MS = 5000U;

std::uint64_t perSecond(std::uint64_t bytes, Millis dtMs) noexcept
{
	return (dtMs == 0U) ? 0U : ((bytes * 1000U) / dtMs);
}

} // namespace

void formatScore(FixedString<16U> &out, int s100) noexcept
{
	if (s100 == policy::LP_NO_EVIDENCE) {
		formatTo(out, "-");
	} else if (s100 >= policy::LP_S_MAX) {
		formatTo(out, "inf");
	} else {
		formatTo(out, "{}.{}{}", s100 / 100, (s100 % 100) / 10, s100 % 10);
	}
}

const DevClassRec *Daemon::findDevClass(const Mac &sta) const noexcept
{
	const DevClassRec *r = nullptr;
	for (const DevClassRec &d : mDevClass) {
		if ((r == nullptr) && d.used && (d.sta == sta)) {
			r = &d;
		}
	}
	return r;
}

// The record of sta, or a new one (a free slot, else the oldest record,
// reset): one record per STA holds its class and its roaming threshold.
DevClassRec &Daemon::devClassSlot(const Mac &sta) noexcept
{
	DevClassRec *slot = nullptr;
	DevClassRec *spare = nullptr; // a free slot, else the oldest record
	for (DevClassRec &d : mDevClass) {
		if (d.used && (d.sta == sta)) {
			slot = &d;
		} else if ((spare != nullptr) && !spare->used) {
			// keep the free slot
		} else if ((spare == nullptr) || !d.used || (d.ts < spare->ts)) {
			spare = &d;
		} else {
			// an older record is already the spare
		}
	}
	if (slot == nullptr) {
		slot = spare;
		*slot = DevClassRec{};
		slot->used = true;
		slot->sta = sta;
	}
	return *slot;
}

// Updates or adds the class of sta.
DevClassRec &Daemon::storeDevClass(const Mac &sta, bool lowPower, int score, std::uint32_t samples,
				   const Mac &source) noexcept
{
	const bool existed = findDevClass(sta) != nullptr;
	DevClassRec &slot = devClassSlot(sta);
	slot.corrected = existed && !lowPower && (slot.lowPower || slot.corrected);
	slot.lowPower = lowPower;
	slot.score = score;
	slot.samples = samples;
	slot.source = source;
	slot.ts = os::nowMs();
	return slot;
}

void Daemon::storeRoamRec(const Mac &sta, int thresholdDbm, std::uint32_t events, const Mac &source) noexcept
{
	DevClassRec &slot = devClassSlot(sta);
	slot.roamThr = thresholdDbm;
	slot.roamEvents = events;
	if (slot.samples == 0U) {
		slot.source = source; // no class evidence: the threshold's AP
	}
	slot.ts = os::nowMs();
}

void Daemon::sendStaRoam(const Mac &peer, const DevClassRec &r) noexcept
{
	arcp::Message m;
	arcp::StaRoam c;

	c.sta = r.sta;
	c.thresholdDbm = static_cast<std::int8_t>(r.roamThr);
	c.events = r.roamEvents;
	beginMsg(m, arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ);
	(void)m.add(c);
	(void)unicast(peer, m);
}

void Daemon::shareRoamThr(const Mac &sta, int oldDbm, int newDbm, std::uint32_t events,
			   std::string_view why) noexcept
{
	if (newDbm == oldDbm) {
		logging::dbg(LOG_MODULE, "sta {}: roaming threshold stays {} dBm ({}, {} events)", sta,
			     oldDbm, why, events);
		return;
	}
	logging::info(LOG_MODULE, "sta {}: roaming threshold {} -> {} dBm ({}, {} events)", sta, oldDbm,
		      newDbm, why, events);
	storeRoamRec(sta, newDbm, events, mApId);
	const DevClassRec *const r = findDevClass(sta);
	for (const Peer &peer : mPeers) {
		if (peer.used && (r != nullptr)) {
			sendStaRoam(peer.id, *r);
		}
	}
}

void Daemon::noteRoamThr(Sta &s, int thresholdDbm, std::string_view why) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	if (!p.roamThrLearn) {
		return;
	}
	const int old = policy::roamThreshold(p, s.roamThr);
	s.roamThr = thresholdDbm;
	s.roamEvents++;
	s.roamThrTs = os::nowMs();
	shareRoamThr(s.addr, old, thresholdDbm, s.roamEvents, why);
}

void Daemon::noteOwnRoamFromRecord(const Mac &sta) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	DevClassRec *r = nullptr;
	for (DevClassRec &d : mDevClass) {
		if ((r == nullptr) && d.used && (d.sta == sta)) {
			r = &d;
		}
	}
	if (!p.roamThrLearn || (r == nullptr) || (r->leftTs == 0U) || (r->leftRssi == 0) ||
	    ((os::nowMs() - r->leftTs) > OWN_ROAM_WINDOW_MS)) {
		return;
	}
	const int old = policy::roamThreshold(p, r->roamThr);
	const int thr = policy::updateRoamThrSelf(p, r->roamThr, r->leftRssi);
	const std::uint32_t events = r->roamEvents + 1U;
	r->leftTs = 0U; // used once
	r->roamThr = thr;
	r->roamEvents = events;
	shareRoamThr(sta, old, thr, events, "own roam");
}

void Daemon::onStaRoam(const Peer &from, const arcp::StaRoam &c) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const int lo = (p.roamThrMin <= p.roamThrMax) ? p.roamThrMin : p.roamThrMax;
	const int hi = (p.roamThrMin <= p.roamThrMax) ? p.roamThrMax : p.roamThrMin;
	const int thr = (c.thresholdDbm < lo) ? lo : ((c.thresholdDbm > hi) ? hi :
						      static_cast<int>(c.thresholdDbm));
	const DevClassRec *const known = findDevClass(c.sta);

	// events only grow along a STA's history: the larger count is newer
	if ((known == nullptr) || (c.events > known->roamEvents)) {
		storeRoamRec(c.sta, thr, c.events, from.id);
	}
	Sta *const s = findSta(c.sta);
	if ((s != nullptr) && !s->away && (c.events > s->roamEvents)) {
		if (s->roamThr != thr) {
			logging::info(LOG_MODULE, "sta {}: roaming threshold {} dBm ({} events, from AP {})",
				      c.sta, thr, c.events, from.id);
		}
		s->roamThr = thr;
		s->roamEvents = c.events;
		s->roamThrTs = os::nowMs();
	}
}

void Daemon::sendStaClass(const Mac &peer, const DevClassRec &r) noexcept
{
	arcp::Message m;
	arcp::StaClass c;

	c.sta = r.sta;
	c.devClass = static_cast<std::uint8_t>(r.lowPower ? arcp::DevClass::LOW_POWER :
					       arcp::DevClass::NORMAL);
	c.score = static_cast<std::int32_t>(r.score);
	c.samples = r.samples;
	beginMsg(m, arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ);
	(void)m.add(c);
	(void)unicast(peer, m);
}

void Daemon::sampleTraffic(Sta &s, std::uint64_t upBytes, std::uint64_t downBytes, Millis dtMs) noexcept
{
	const PolicyConfig &p = mCfg.pol;

	if (!p.lpClassify || (dtMs == 0U)) {
		return;
	}
	// A PHY that lp_exclude_vht/he/eht rules out (by default VHT and EHT,
	// rare on battery devices): such a STA is never low-power, whatever its
	// traffic looks like. A STA already (mis)classified before this
	// capability was known is corrected immediately, not just frozen.
	if (policy::isLpExcludedPhy(p, s.phyCaps)) {
		if (s.lowPower) {
			s.lowPower = false;
			s.lpScore = 0;
			s.lpS100 = policy::LP_NO_EVIDENCE;
			// onStaClass only accepts a record with a strictly larger
			// sample count (that is how it tells a correction from the
			// same stale record coming back); bump it so the correction
			// is not silently dropped by a peer holding the old count.
			s.lpSamples++;
			logging::info(LOG_MODULE,
				      "sta {} classified normal (its PHY overrides the traffic shape)",
				      s.addr);
			const DevClassRec &r = storeDevClass(s.addr, false, 0, s.lpSamples, mApId);
			for (const Peer &peer : mPeers) {
				if (peer.used) {
					sendStaClass(peer.id, r);
				}
			}
		}
		return;
	}
	const std::uint8_t band = mBss[s.bss].info.band;
	const std::uint64_t upBps = perSecond(upBytes, dtMs);
	const std::uint64_t downBps = perSecond(downBytes, dtMs);
	policy::addTrafficSample(s.traffic, upBps, downBps);
	s.lpS100 = policy::lpBehaviourScore(p, s.traffic, band);
	logging::dbg(LOG_MODULE,
		     "sta {}: up={}Bps down={}Bps meanUp={}Bps meanDown={}Bps sigmaUp={} sigmaDown={} n={} "
		     "s100={} "
		     "score={}", s.addr, upBps, downBps, s.traffic.up.mean16 / 16, s.traffic.down.mean16 / 16,
		     policy::isqrt(s.traffic.up.m2), policy::isqrt(s.traffic.down.m2), s.traffic.n, s.lpS100,
		     s.lpScore);
	if (s.lpS100 == policy::LP_NO_EVIDENCE) {
		return;
	}
	s.lpScore = policy::updateLpScore(p, s.lpScore, s.lpS100);
	s.lpSamples++;
	const bool low = policy::isLowPower(p, s.lpScore, s.lowPower);
	if (low == s.lowPower) {
		return;
	}
	s.lowPower = low;
	FixedString<16U> sText;
	formatScore(sText, s.lpS100);
	logging::info(LOG_MODULE, "sta {} classified {} (score {}/{}, S {}, {} samples)", s.addr,
		      low ? "low-power" : "normal", s.lpScore, p.lpThreshold, sText, s.lpSamples);
	const DevClassRec &r = storeDevClass(s.addr, s.lowPower, s.lpScore, s.lpSamples, mApId);
	for (const Peer &peer : mPeers) {
		if (peer.used) {
			sendStaClass(peer.id, r);
		}
	}
}

void Daemon::restoreDevClass(Sta &s) noexcept
{
	const DevClassRec *const r = findDevClass(s.addr);
	if (r != nullptr) {
		s.lowPower = r->lowPower;
		s.lpScore = r->score;
		s.lpSamples = r->samples;
		s.roamThr = r->roamThr;
		s.roamEvents = r->roamEvents;
		s.roamThrTs = os::nowMs();
		logging::dbg(LOG_MODULE, "sta {}: known {} (score {}, {} samples, from {})", s.addr,
			     r->lowPower ? "low-power" : "normal", r->score, r->samples, r->source);
	}
}

void Daemon::saveDevClass(const Sta &s) noexcept
{
	const DevClassRec *const known = findDevClass(s.addr);
	if ((s.roamEvents > 0U) && ((known == nullptr) || (known->roamEvents <= s.roamEvents))) {
		storeRoamRec(s.addr, s.roamThr, s.roamEvents, mApId);
	}
	const DevClassRec *const r = findDevClass(s.addr);
	// Keep what was learned here, unless a peer already holds more. A tied
	// count alone does not mean someone else still owns it: if the STA is
	// genuinely associated here right now (not just leaving, the case this
	// is called for from onPeerStaAssoc), this AP is the current authority
	// for it regardless of not having produced fresh evidence yet.
	if ((s.lpSamples > 0U) && ((r == nullptr) || (r->samples <= s.lpSamples))) {
		const bool tie = (r != nullptr) && (r->samples == s.lpSamples);
		(void)storeDevClass(s.addr, s.lowPower, s.lpScore, s.lpSamples,
				    (tie && s.away) ? r->source : mApId);
	}
}

void Daemon::onStaClass(const Peer &from, const arcp::StaClass &c) noexcept
{
	const bool low = c.devClass == static_cast<std::uint8_t>(arcp::DevClass::LOW_POWER);
	const int lim = (mCfg.pol.lpScoreMax > 0) ? mCfg.pol.lpScoreMax : 0;
	const int score = (c.score < 0) ? 0 : ((c.score > lim) ? lim : static_cast<int>(c.score));
	const DevClassRec *const known = findDevClass(c.sta);

	// samples only grow along a STA's history: the larger count is newer
	// (an equal count is the same record coming back, e.g. from a peer's sync).
	if ((known == nullptr) || (c.samples > known->samples)) {
		(void)storeDevClass(c.sta, low, score, c.samples, from.id);
	}
	Sta *const s = findSta(c.sta);
	if ((s != nullptr) && !s->away && (c.samples > s->lpSamples)) {
		if (s->lowPower != low) {
			logging::info(LOG_MODULE, "sta {} is {} (score {}, {} samples, from AP {})", c.sta,
				      low ? "low-power" : "normal", score, c.samples, from.id);
		}
		s->lowPower = low;
		s->lpScore = score;
		s->lpSamples = c.samples;
	}
}

void Daemon::onPeerStaAssoc(const Mac &ap, const Mac &sta) noexcept
{
	if (ap == mApId) {
		return;
	}
	const Sta *const s = findSta(sta);
	if ((s != nullptr) && ((s->lpSamples > 0U) || (s->roamEvents > 0U))) {
		saveDevClass(*s);
	}
	const DevClassRec *const r = findDevClass(sta);
	if (r != nullptr) {
		logging::dbg(LOG_MODULE, "sta {} joined AP {}: sending its class", sta, ap);
		sendStaClass(ap, *r);
		if (r->roamEvents > 0U) {
			sendStaRoam(ap, *r);
		}
	}
}

void Daemon::syncDevClass(const Mac &peer) noexcept
{
	arcp::Message m;
	std::size_t n = 0U;
	std::size_t total = 0U;

	// Live local STAs first, so the table holds their latest state.
	for (const Sta &s : mSta) {
		if (s.used && !s.away && ((s.lpSamples > 0U) || (s.roamEvents > 0U))) {
			saveDevClass(s);
		}
	}
	for (const DevClassRec &r : mDevClass) {
		// Low-power records, and corrections back to normal: a peer that
		// rejoins after missing the one-shot correction (its own restart
		// raced the broadcast) must learn "normal now", or it keeps a stale
		// flag forever. Other normal records tell a peer nothing, and
		// sending them all could fill the retransmission queue.
		// Also any learned roaming threshold, so it follows the STA.
		const bool cls = r.lowPower || r.corrected;
		const bool roam = r.roamEvents > 0U;
		if (!r.used || (!cls && !roam)) {
			continue;
		}
		if ((n > 0U) && (m.room() < ((arcp::TLV_HDR_LEN + 15U) + (arcp::TLV_HDR_LEN + 11U)))) {
			(void)unicast(peer, m);
			n = 0U;
		}
		if (n == 0U) {
			beginMsg(m, arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ);
		}
		if (cls) {
			arcp::StaClass c;
			c.sta = r.sta;
			c.devClass = static_cast<std::uint8_t>(r.lowPower ? arcp::DevClass::LOW_POWER :
							       arcp::DevClass::NORMAL);
			c.score = static_cast<std::int32_t>(r.score);
			c.samples = r.samples;
			(void)m.add(c);
		}
		if (roam) {
			arcp::StaRoam c;
			c.sta = r.sta;
			c.thresholdDbm = static_cast<std::int8_t>(r.roamThr);
			c.events = r.roamEvents;
			(void)m.add(c);
		}
		n++;
		total++;
	}
	if (n > 0U) {
		(void)unicast(peer, m);
	}
	if (total > 0U) {
		logging::dbg(LOG_MODULE, "sent {} class / roaming records to AP {}", total, peer);
	}
}

} // namespace donghoa
