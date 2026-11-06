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

// Updates or adds the record of sta; a full table drops its oldest record.
DevClassRec &Daemon::storeDevClass(const Mac &sta, bool lowPower, int score, std::uint32_t samples,
				   const Mac &source) noexcept
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
	}
	slot->used = true;
	slot->sta = sta;
	slot->lowPower = lowPower;
	slot->score = score;
	slot->samples = samples;
	slot->source = source;
	slot->ts = os::nowMs();
	return *slot;
}

void Daemon::sendStaClass(const Mac &peer, const DevClassRec &r) noexcept
{
	arcp::Message m;
	arcp::StaClass c;

	c.sta = r.sta;
	c.devClass = static_cast<std::uint8_t>(r.lowPower ? arcp::DevClass::LOW_POWER : arcp::DevClass::NORMAL);
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
	const std::uint8_t band = mBss[s.bss].info.band;
	policy::addTrafficSample(s.traffic, perSecond(upBytes, dtMs), perSecond(downBytes, dtMs));
	s.lpS100 = policy::lpBehaviourScore(p, s.traffic, band);
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
		logging::dbg(LOG_MODULE, "sta {}: known {} (score {}, {} samples, from {})", s.addr,
			     r->lowPower ? "low-power" : "normal", r->score, r->samples, r->source);
	}
}

void Daemon::saveDevClass(const Sta &s) noexcept
{
	const DevClassRec *const r = findDevClass(s.addr);
	// Keep what was learned here, unless a peer already holds more.
	if ((s.lpSamples > 0U) && ((r == nullptr) || (r->samples <= s.lpSamples))) {
		(void)storeDevClass(s.addr, s.lowPower, s.lpScore, s.lpSamples,
				    ((r != nullptr) && (r->samples == s.lpSamples)) ? r->source : mApId);
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
	if ((s != nullptr) && (s->lpSamples > 0U)) {
		saveDevClass(*s);
	}
	const DevClassRec *const r = findDevClass(sta);
	if (r != nullptr) {
		logging::dbg(LOG_MODULE, "sta {} joined AP {}: sending its class", sta, ap);
		sendStaClass(ap, *r);
	}
}

void Daemon::syncDevClass(const Mac &peer) noexcept
{
	arcp::Message m;
	std::size_t n = 0U;
	std::size_t total = 0U;

	// Live local STAs first, so the table holds their latest state.
	for (const Sta &s : mSta) {
		if (s.used && !s.away && (s.lpSamples > 0U)) {
			saveDevClass(s);
		}
	}
	for (const DevClassRec &r : mDevClass) {
		if (!r.used || !r.lowPower) {
			continue;
		}
		if ((n > 0U) && (m.room() < (arcp::TLV_HDR_LEN + 15U))) {
			(void)unicast(peer, m);
			n = 0U;
		}
		if (n == 0U) {
			beginMsg(m, arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ);
		}
		arcp::StaClass c;
		c.sta = r.sta;
		c.devClass = static_cast<std::uint8_t>(arcp::DevClass::LOW_POWER);
		c.score = static_cast<std::int32_t>(r.score);
		c.samples = r.samples;
		(void)m.add(c);
		n++;
		total++;
	}
	if (n > 0U) {
		(void)unicast(peer, m);
	}
	if (total > 0U) {
		logging::dbg(LOG_MODULE, "sent {} low-power records to AP {}", total, peer);
	}
}

} // namespace donghoa
