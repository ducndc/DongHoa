// SPDX-License-Identifier: MIT
// Unit tests: triggers, scoring, admission, backoff (src/core/policy).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "unit.hpp"

#include "core/config.hpp"
#include "core/policy.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"

using namespace donghoa;

void testPolicy()
{
	Config c;
	const PolicyConfig &p = c.pol;
	policy::SteerCtx ctx;
	policy::CandInput in;

	ctx.reason = arcp::SteerReason::RSSI;
	ctx.curRssi = -80;
	ctx.curBand = arcp::BAND_5G;
	in.band = arcp::BAND_5G;
	in.estRssi = -65;
	in.utilPct = 20;
	CHECK(policy::score(p, ctx, in) == (-65 + 5 - ((2 * 20) / 10)));
	in.estRssi = -75; // only 5 dB better: below hysteresis
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.estRssi = policy::RSSI_UNKNOWN;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.estRssi = -60;
	in.utilPct = 85; // target too busy
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.utilPct = 20;
	in.maxSta = 10;
	in.staCount = 10;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.maxSta = 0;

	// Load balancing tolerates a small RSSI loss but needs a quiet target.
	ctx.reason = arcp::SteerReason::LOAD;
	ctx.curRssi = -60;
	in.estRssi = -64;
	in.utilPct = 30;
	CHECK(policy::score(p, ctx, in) != policy::INELIGIBLE);
	in.utilPct = 60; // > util_high - lb_margin = 55
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.utilPct = 30;
	in.estRssi = -68; // 8 dB loss > tolerance
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);

	// Band steering only towards a higher band
	ctx.reason = arcp::SteerReason::BAND;
	ctx.curBand = arcp::BAND_2G;
	ctx.curRssi = -50;
	in.band = arcp::BAND_5G;
	in.estRssi = -62;
	CHECK(policy::score(p, ctx, in) != policy::INELIGIBLE);
	in.band = arcp::BAND_2G;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);

	CHECK(policy::isRssiTriggered(p, -80, 3, p.rssiLow) && !policy::isRssiTriggered(p, -80, 2, p.rssiLow));
	CHECK(!policy::isRssiTriggered(p, -70, 5, p.rssiLow) && !policy::isRssiTriggered(p, 0, 5, p.rssiLow));
	CHECK(!policy::isRssiTriggered(p, -80, 5, -82)); // a STA with a lower threshold hangs on
	CHECK(policy::isRssiTriggered(p, -70, 5, -65));  // a higher one roams earlier

	// contextual bandit for the target choice
	{
		std::array<bool, policy::BANDIT_CTX> seen{};
		bool unique = true;
		const std::array<int, 4U> lv{{-50, -58, -66, -75}};
		const std::array<int, 3U> ut{{10, 40, 70}};
		for (const int l : lv) {
			for (int bd = -1; bd <= 1; bd++) {
				for (int lo = 0; lo < 2; lo++) {
					for (const int u : ut) {
						for (int sr = 0; sr < 3; sr++) {
							policy::BanditFeatures f;
							f.levelDbm = l;
							f.bandDelta = bd;
							f.local = lo == 1;
							f.utilPct = u;
							f.src = static_cast<policy::BanditSrc>(sr);
							const std::size_t ci = policy::banditCtx(f);
							unique = unique && (ci < policy::BANDIT_CTX) && !seen[ci];
							if (ci < policy::BANDIT_CTX) {
								seen[ci] = true;
							}
						}
					}
				}
			}
		}
		CHECK(unique);
		policy::BanditFeatures unk;
		unk.utilPct = -1;
		policy::BanditFeatures low;
		low.utilPct = 10;
		CHECK(policy::banditCtx(unk) == policy::banditCtx(low)); // unknown load counts as light
		// prior: what a success would earn
		CHECK((policy::banditPriorDb(10) == 18) && (policy::banditPriorDb(40) == 32) && (policy::banditPriorDb(-5) == 8));
		policy::BanditTable t;
		CHECK(policy::banditValue(t, 7U, 20) == (20 * policy::RL_ONE)); // nothing learned: the prior
		policy::banditUpdate(t, 7U, policy::RL_R_REFUSED);
		CHECK((t.n[7] == 1U) && (t.q[7] == (policy::RL_R_REFUSED * policy::RL_ONE)));
		CHECK(policy::banditValue(t, 7U, 20) == ((-10 + (20 * 3)) * policy::RL_ONE) / 4); // 1 sample vs prior x3
		for (int i = 0; i < 30; i++) {
			policy::banditUpdate(t, 7U, policy::RL_R_REFUSED);
		}
		CHECK(policy::banditValue(t, 7U, 20) < 0); // evidence outweighs the prior
		CHECK(policy::banditValue(t, policy::BANDIT_CTX, 5) == (5 * policy::RL_ONE)); // out of range: prior
		Config cfg;
		CHECK(cfg.pol.banditTarget == 0); // off by default
		CHECK(parseConfigLine(cfg, "bandit_target 2") && (cfg.pol.banditTarget == 2) && !parseConfigLine(cfg, "bandit_target 3"));
		CHECK(parseConfigLine(cfg, "bandit_epsilon_pct 0") && (cfg.pol.banditEpsilonPct == 0));
	}
	// Q-learning of when to roam
	{
		// state encoding: every combination maps to a distinct index
		std::array<bool, policy::RL_STATES> seen{};
		bool unique = true;
		const std::array<int, 6U> rssis{{-55, -62, -68, -73, -78, -85}};
		for (const int r : rssis) {
			for (int sl = -1; sl <= 1; sl++) {
				for (int g = 0; g < 4; g++) {
					for (int rf = 0; rf < 3; rf++) {
						for (int k = 0; k < 2; k++) {
							policy::RlFeatures f;
							f.rssi = r;
							f.slope = sl;
							f.gapKnown = g != 0;
							f.gapDb = (g == 1) ? -3 : ((g == 2) ? 4 : 12);
							f.refusals = rf;
							f.lowStreak = k == 1;
							const std::size_t i = policy::rlState(f);
							unique = unique && (i < policy::RL_STATES) && !seen[i];
							if (i < policy::RL_STATES) {
								seen[i] = true;
							}
						}
					}
				}
			}
		}
		CHECK(unique);
		// the prior reproduces the rule: steer below -75 dBm with a low streak
		policy::RlTable t;
		policy::rlInit(t);
		bool explored = false;
		policy::RlFeatures w;
		w.rssi = -78;
		w.lowStreak = true;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::STEER);
		w.lowStreak = false;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::WAIT);
		w.rssi = -72;
		w.lowStreak = true;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::WAIT);
		// exploration: STEER only where safe (below -65, neighbour not known worse)
		w.rssi = -72;
		CHECK((policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::STEER) && explored);
		w.gapKnown = true;
		w.gapDb = -4;
		CHECK((policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::WAIT) && !explored);
		w.rssi = -62;
		w.gapKnown = false;
		CHECK(policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::WAIT);
		CHECK(policy::rlChoose(t, policy::rlState(w), 1, 50U, explored) == policy::RlAction::WAIT); // rnd 50 >= 1%
		// learning: a STA that refuses at -78 makes STEER worse than WAIT there
		policy::RlFeatures r78;
		r78.rssi = -78;
		r78.lowStreak = true;
		const std::size_t s78 = policy::rlState(r78);
		policy::rlUpdate(t, s78, policy::RlAction::STEER, policy::RL_R_REFUSED, true, 0U);
		CHECK(t.q[s78][1U] == (policy::RL_R_REFUSED * policy::RL_ONE)); // alpha 1 on the first visit
		CHECK(policy::rlChoose(t, s78, 0, 0U, explored) == policy::RlAction::WAIT);
		for (int i = 0; i < 40; i++) {
			policy::rlUpdate(t, s78, policy::RlAction::STEER, 20, true, 0U); // later: big successes
		}
		CHECK((t.q[s78][1U] > (18 * policy::RL_ONE)) && (t.n[s78][1U] == 41U));
		CHECK(policy::rlChoose(t, s78, 0, 0U, explored) == policy::RlAction::STEER);
		// non-terminal: discounted best of the next state
		policy::RlTable u;
		policy::rlInit(u);
		u.q[3][1U] = 10 * policy::RL_ONE;
		policy::rlUpdate(u, 1U, policy::RlAction::WAIT, -2, false, 3U);
		CHECK(u.q[1][0U] == ((-2 * policy::RL_ONE) + ((10 * policy::RL_ONE * policy::RL_GAMMA) / policy::RL_ONE)));
		// rewards
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::SUCCESS, 30) == (policy::RL_R_SUCCESS + policy::RL_R_GAIN_MAX));
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::BTM_REJECT, 0) == policy::RL_R_REFUSED);
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::ABORTED, 0) == 0);
		CHECK((policy::rlRewardWait(-65) == 0) && (policy::rlRewardWait(-82) == -3) && (policy::rlRewardWait(0) == 0));
		Config cfg;
		CHECK(cfg.pol.rlRoam == 0); // off by default; rl_roam or RL mode enables it
		CHECK(parseConfigLine(cfg, "rl_roam 2") && (cfg.pol.rlRoam == 2) && !parseConfigLine(cfg, "rl_roam 3"));
	}
	// per-STA roaming threshold
	{
		PolicyConfig q; // rssi_low -75, range -82..-65, learning on
		CHECK(policy::roamThreshold(q, 0) == -75);             // not learned: rssi_low
		CHECK(policy::roamThreshold(q, -79) == -79);
		CHECK(policy::roamThreshold(q, -90) == -82);           // clamped
		CHECK(policy::updateRoamThrOutcome(q, 0, policy::RoamOutcome::REFUSED, 0) == -77);
		CHECK(policy::updateRoamThrOutcome(q, -77, policy::RoamOutcome::ROAM_TIMEOUT, 0) == -78);
		CHECK(policy::updateRoamThrOutcome(q, -78, policy::RoamOutcome::SUCCESS, 20) == -77); // big gain: earlier
		CHECK(policy::updateRoamThrOutcome(q, -78, policy::RoamOutcome::SUCCESS, 10) == -78); // modest: kept
		int t = 0;
		for (int i = 0; i < 10; i++) {
			t = policy::updateRoamThrOutcome(q, t, policy::RoamOutcome::REFUSED, 0);
		}
		CHECK(t == -82);                                        // floor
		CHECK(policy::updateRoamThrSelf(q, -75, -67) == -73);   // quarter of the way
		CHECK(policy::updateRoamThrSelf(q, -75, -77) == -76);   // at least 1 dB
		CHECK(policy::updateRoamThrSelf(q, -75, -75) == -75);
		CHECK(policy::updateRoamThrSelf(q, -66, -40) == -65);   // ceiling
		CHECK((policy::decayRoamThr(q, -80) == -79) && (policy::decayRoamThr(q, -70) == -71) &&
		      (policy::decayRoamThr(q, -75) == -75));
		q.roamThrLearn = false;
		CHECK(policy::roamThreshold(q, -80) == -75);            // learning off: rssi_low
		Config cfg;
		CHECK(parseConfigLine(cfg, "roam_thr_min -85") && (cfg.pol.roamThrMin == -85));
		CHECK(parseConfigLine(cfg, "roam_thr_learn 0") && !cfg.pol.roamThrLearn);
		// STA_ROAM TLV round trip; a longer TLV from a newer peer decodes
		arcp::StaRoam r;
		r.sta = mac("02:00:00:00:02:09");
		r.thresholdDbm = -79;
		r.events = 7U;
		arcp::Message m;
		m.begin(arcp::MsgType::STA_CLASS, 0U, r.sta, 1U, 1U);
		CHECK(m.add(r) && m.finish(ByteView()));
		const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
		if (h.has_value()) {
			arcp::TlvReader rd(m.bytes(), *h);
			std::uint8_t ty = 0U;
			ByteView v;
			arcp::StaRoam o;
			CHECK(rd.next(ty, v) && (ty == arcp::raw(arcp::Tlv::STA_ROAM)) && arcp::decode(v, o));
			CHECK((o.sta == r.sta) && (o.thresholdDbm == -79) && (o.events == 7U));
			CHECK(!arcp::decode(v.first(10U), o));
		}
		CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::STA_ROAM)) == "STA_ROAM");
	}
	CHECK(policy::isBandTriggered(p, arcp::BAND_2G, -50) && policy::isBandTriggered(p, arcp::BAND_5G, -50));
	CHECK(!policy::isBandTriggered(p, arcp::BAND_5G, -60) && !policy::isBandTriggered(p, arcp::BAND_6G, -40));
	{
		Config c6;
		c6.pol.bandSteer6g = false;
		CHECK(policy::isBandTriggered(c6.pol, arcp::BAND_2G, -50) &&
		      !policy::isBandTriggered(c6.pol, arcp::BAND_5G, -50));
	}
	CHECK(policy::isBssOverloaded(p, 75, 1, 0) && !policy::isBssOverloaded(p, 50, 1, 0));
	CHECK(policy::isBssOverloaded(p, -1, 32, 32));
	CHECK(policy::admit(p, 50, 5, 0, 0) == arcp::SteerStatus::ACCEPT);
	CHECK(policy::admit(p, 50, 9, 1, 10) == arcp::SteerStatus::CAPACITY);
	CHECK(policy::admit(p, 90, 1, 0, 0) == arcp::SteerStatus::LOAD);
	// Band usability: unknown counts as usable; seen overrides advertised;
	// blocked (6 GHz, WPA2-PSK) always wins
	using B = policy::StaBands;
	constexpr std::uint8_t ALL = rrm::BANDS_2G | rrm::BANDS_5G | rrm::BANDS_6G;
	CHECK(policy::isBandUsable(B{0U, 0U, 0U}, arcp::BAND_6G));
	CHECK(!policy::isBandUsable(B{rrm::BANDS_2G, rrm::BANDS_2G, 0U}, arcp::BAND_5G));
	CHECK(policy::isBandUsable(B{rrm::BANDS_2G, rrm::BANDS_5G, 0U}, arcp::BAND_5G));
	CHECK(!policy::isBandUsable(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_6G));
	CHECK(!policy::isBandUsable(B{0U, 0U, rrm::BANDS_6G}, arcp::BAND_6G));
	CHECK(policy::isBandUsable(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{rrm::BANDS_2G, rrm::BANDS_2G, 0U}, arcp::BAND_2G));
	CHECK(policy::hasHigherBand(B{rrm::BANDS_2G | rrm::BANDS_6G, 0U, 0U}, arcp::BAND_2G));
	CHECK(policy::hasHigherBand(B{0U, 0U, 0U}, arcp::BAND_2G));
	// From 5 GHz only with 6 GHz advertised or seen, and not blocked
	CHECK(policy::hasHigherBand(B{ALL, 0U, 0U}, arcp::BAND_5G));
	CHECK(policy::hasHigherBand(B{0U, rrm::BANDS_6G, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{0U, 0U, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{rrm::BANDS_2G | rrm::BANDS_5G, 0U, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{ALL, 0U, 0U}, arcp::BAND_6G));
	CHECK(policy::backoffMs(p, 0) == 30000 && policy::backoffMs(p, 2) == 120000);
	CHECK(policy::backoffMs(p, 20) == p.steerBackoffMaxMs);
	CHECK(policy::utilToPct(255) == -1 && policy::utilToPct(128) == 50 && policy::utilToPct(0) == 0);
}

// Expected-throughput model: the scenarios of the design note.
void testPolicyTput()
{
	Config c;
	PolicyConfig &p = c.pol;
	const std::uint16_t ht = arcp::CAP_HT;
	const std::uint16_t vht = arcp::CAP_HT | arcp::CAP_VHT;

	p.scoreModel = ScoreModel::TPUT;

	// Sigmoid quality: 500 at the midpoint, monotonic, saturating
	CHECK(policy::computeLinkQuality(p, -72) == 500);
	CHECK(policy::computeLinkQuality(p, -80) == 83 && policy::computeLinkQuality(p, -55) == 994);
	CHECK(policy::computeLinkQuality(p, -120) == 0 && policy::computeLinkQuality(p, -20) == 1000);
	CHECK(policy::computeLinkQuality(p, 0) == 0 && policy::computeLinkQuality(p, policy::RSSI_UNKNOWN) == 0);
	for (int r = -105; r < -35; r++) {
		CHECK(policy::computeLinkQuality(p, r) <= policy::computeLinkQuality(p, r + 1));
	}

	// Peak PHY rate: top MCS, short GI, x streams
	CHECK(policy::computePeakMbps(ht, arcp::BW20, 2) == 144);
	CHECK(policy::computePeakMbps(vht, arcp::BW80, 2) == 866);
	CHECK(policy::computePeakMbps(vht | arcp::CAP_HE, arcp::BW80, 2) == 1202);
	CHECK(policy::computePeakMbps(0U, arcp::BW20, 2) == 54);
	CHECK(policy::computeExpectedKbps(p, -60, 866, 40) == ((973 * 866 * 60) / 100));
	CHECK(policy::computeExpectedKbps(p, -60, 866, -1) == (973 * 866));

	policy::SteerCtx ctx;
	policy::CandInput a;
	policy::CandInput b;

	// 1. Weak 5 GHz STA: the louder 2.4 GHz BSS loses to a fast 5 GHz one
	ctx.reason = arcp::SteerReason::RSSI;
	ctx.curRssi = -80;
	ctx.curBand = arcp::BAND_5G;
	ctx.curUtilPct = 30;
	ctx.curPeakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	a.band = arcp::BAND_5G;
	a.estRssi = -60;
	a.utilPct = 40;
	a.peakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	b.band = arcp::BAND_2G;
	b.estRssi = -55;
	b.utilPct = 20;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, a) > policy::score(p, ctx, b));
	CHECK(policy::score(p, ctx, b) != policy::INELIGIBLE);
	p.scoreModel = ScoreModel::LINEAR;
	CHECK(policy::score(p, ctx, a) < policy::score(p, ctx, b));
	p.scoreModel = ScoreModel::TPUT;

	// 2. A louder but slower target that would cut throughput is refused
	ctx.curRssi = -77;
	ctx.curUtilPct = 10;
	b.estRssi = -69;
	b.utilPct = 50;
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	p.scoreModel = ScoreModel::LINEAR;
	CHECK(policy::score(p, ctx, b) != policy::INELIGIBLE);
	p.scoreModel = ScoreModel::TPUT;

	// 3/4. Band steering only when 5 GHz is really faster
	ctx.reason = arcp::SteerReason::BAND;
	ctx.curRssi = -50;
	ctx.curBand = arcp::BAND_2G;
	ctx.curUtilPct = 20;
	ctx.curPeakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	a.estRssi = -58;
	a.utilPct = 30;
	CHECK(policy::score(p, ctx, a) != policy::INELIGIBLE);
	b = policy::CandInput{};
	b.band = arcp::BAND_5G;
	b.estRssi = -58;
	b.utilPct = 70;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	ctx.curRssi = -45;
	ctx.curUtilPct = 0;
	b.estRssi = -50;
	b.utilPct = 0; // same width, idle: < tput_gain_pct
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);

	// 5. Load balancing: the STA must not lose throughput
	ctx = policy::SteerCtx{};
	ctx.reason = arcp::SteerReason::LOAD;
	ctx.curRssi = -60;
	ctx.curBand = arcp::BAND_5G;
	ctx.curUtilPct = 90;
	ctx.curPeakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	a.estRssi = -64;
	a.utilPct = 30;
	CHECK(policy::score(p, ctx, a) != policy::INELIGIBLE);
	b = policy::CandInput{};
	b.band = arcp::BAND_2G;
	b.estRssi = -62;
	b.utilPct = 40;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	a.utilPct = 60; // still needs a quiet target
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);

	// Hard gates apply in both models
	ctx.reason = arcp::SteerReason::MANUAL;
	a.utilPct = 30;
	a.estRssi = -75; // below rssi_min_target
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
	a.estRssi = -60;
	a.accepting = false;
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
	a.accepting = true;
	a.utilPct = 85; // >= util_admit_max
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
}
