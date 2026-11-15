// SPDX-License-Identifier: MIT
// Unit tests: low-power classification arithmetic, record TLV, config keys.
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "unit.hpp"

#include "core/config.hpp"
#include "core/policy.hpp"
#include "core/proto.hpp"

using namespace donghoa;

// Low-power (IoT) classification: integer statistics, score, theta, class
// record TLV and config keys.
void testLowPower()
{
	CHECK(policy::isqrt(0U) == 0U);
	CHECK(policy::isqrt(15U) == 3U);
	CHECK(policy::isqrt(16U) == 4U);
	CHECK(policy::isqrt(static_cast<std::uint64_t>(1U) << 62U) == (1U << 31U));
	CHECK(policy::isqrt(~static_cast<std::uint64_t>(0U)) == 0xffffffffU);

	// Welford: down alternates 0 / 1000 B/s (mean 500, variance 250000),
	// up stays 0.
	policy::TrafficStats t;
	for (int i = 0; i < 200; i++) {
		policy::addTrafficSample(t, 0U, ((i % 2) == 0) ? 0U : 1000U);
	}
	CHECK(t.n == 200U);
	CHECK((t.down.mean16 / 16) == 500);
	const std::uint64_t var = t.down.m2 / t.n;
	CHECK((var > 247500U) && (var < 252500U));
	CHECK(t.up.m2 == 0U);
	// past the window n halves and the variance stays
	for (int i = 0; i < 5000; i++) {
		policy::addTrafficSample(t, 0U, ((i % 2) == 0) ? 0U : 1000U);
	}
	CHECK(t.n <= policy::TRAFFIC_WINDOW);
	const std::uint64_t var2 = t.down.m2 / t.n;
	CHECK((var2 > 247500U) && (var2 < 252500U));
	// a slow device (0 / 10 B/s) does not truncate to zero
	policy::TrafficStats slow;
	for (int i = 0; i < 100; i++) {
		policy::addTrafficSample(slow, ((i % 2) == 0) ? 0U : 10U, 0U);
	}
	CHECK((slow.up.m2 / slow.n) >= 20U);
	// rates above TRAFFIC_RATE_MAX are clamped
	policy::TrafficStats big;
	policy::addTrafficSample(big, ~static_cast<std::uint64_t>(0U), 0U);
	CHECK((big.up.mean16 / 16) == static_cast<std::int64_t>(policy::TRAFFIC_RATE_MAX));

	// S = alpha x sigma_up / sigma_down
	PolicyConfig p;
	policy::TrafficStats u;
	for (int i = 0; i < 100; i++) {
		const bool odd = (i % 2) != 0;
		policy::addTrafficSample(u, odd ? 1000U : 0U, odd ? 500U : 0U); // sigma 500 / 250
	}
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_2G) == 200);
	p.lpAlpha2g = 40;
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_2G) == 80);
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_5G) == 200); // alpha per band
	p.lpAlpha2g = 100;
	// no evidence: too few samples, or nothing varies (idle)
	policy::TrafficStats few;
	policy::addTrafficSample(few, 0U, 0U);
	policy::addTrafficSample(few, 1000U, 0U);
	CHECK(policy::lpBehaviourScore(p, few, arcp::BAND_2G) == policy::LP_NO_EVIDENCE);
	policy::TrafficStats idle;
	for (int i = 0; i < 50; i++) {
		policy::addTrafficSample(idle, 0U, 0U);
	}
	CHECK(policy::lpBehaviourScore(p, idle, arcp::BAND_2G) == policy::LP_NO_EVIDENCE);
	// only the uplink varies
	policy::TrafficStats uponly;
	for (int i = 0; i < 50; i++) {
		policy::addTrafficSample(uponly, ((i % 2) == 0) ? 0U : 300U, 100U);
	}
	CHECK(policy::lpBehaviourScore(p, uponly, arcp::BAND_2G) == policy::LP_S_MAX);
	// Found on the QEMU testbed: a STA idle after one small uplink burst.
	// The window still has sigma_up > 0 and sigma_down = 0, but an idle
	// poll is no evidence, so theta does not climb while nothing is sent.
	policy::TrafficStats quiet;
	int thQ = 0;
	policy::addTrafficSample(quiet, 4000U, 0U);
	for (int i = 0; i < 300; i++) {
		policy::addTrafficSample(quiet, 0U, 0U);
		thQ = policy::updateLpScore(p, thQ, policy::lpBehaviourScore(p, quiet, arcp::BAND_2G));
	}
	CHECK((quiet.up.m2 > 0U) && (quiet.down.m2 == 0U) && !quiet.lastActive);
	CHECK(thQ == 0);
	policy::addTrafficSample(quiet, 40U, 0U); // the next real frame counts again
	CHECK(policy::lpBehaviourScore(p, quiet, arcp::BAND_2G) == policy::LP_S_MAX);

	// load-balancing feedback: utilisation must drop by lb_min_drop_pct (3)
	{
		PolicyConfig q;
		CHECK(policy::isLbMoveEffective(q, 90, 87));
		CHECK(!policy::isLbMoveEffective(q, 90, 88));
		CHECK(!policy::isLbMoveEffective(q, 90, 95));
		CHECK(policy::isLbMoveEffective(q, -1, 95)); // unknown: no judgement
		CHECK(policy::isLbMoveEffective(q, 90, -1));
		Config c;
		CHECK(parseConfigLine(c, "lb_max_futile 3") && (c.pol.lbMaxFutile == 3));
		CHECK(parseConfigLine(c, "lb_hold_ms 60000") && (c.pol.lbHoldMs == 60000));
		CHECK(parseConfigLine(c, "lb_min_drop_pct 5") && (c.pol.lbMinDropPct == 5));
	}
	// uplink -> downlink offset learning
	{
		PolicyConfig q; // learn on, 3 samples, amon_rssi_offset 0
		policy::UlDlOffset o;
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);     // nothing learned: global offset
		q.amonRssiOffset = 2;
		CHECK(policy::uplinkToDownlink(q, nullptr, -70) == -68);
		q.amonRssiOffset = 0;
		CHECK(policy::addUlDlSample(q, o, -55, -63)); // +8
		CHECK(policy::addUlDlSample(q, o, -56, -63)); // +7
		CHECK(!policy::isUlDlCalibrated(q, o));
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);     // 2 samples: not used yet
		CHECK(policy::addUlDlSample(q, o, -54, -63)); // +9
		CHECK(policy::isUlDlCalibrated(q, o) && (o.n == 3U));
		CHECK(o.offset16 == 128);                               // cumulative mean +8.0
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -62);
		CHECK(!policy::addUlDlSample(q, o, -40, -63));          // +23: 15 dB from the mean, outlier
		CHECK(o.n == 3U);
		CHECK(!policy::addUlDlSample(q, o, -20, -60));          // +40: not one link
		CHECK(!policy::addUlDlSample(q, o, 0, -60));            // no level
		policy::UlDlOffset neg;
		for (int i = 0; i < 20; i++) {
			(void)policy::addUlDlSample(q, neg, -66, -62);  // -4
		}
		CHECK((neg.offset16 == -64) && (policy::uplinkToDownlink(q, &neg, -60) == -64));
		q.amonOffsetLearn = false;                               // learning off: global offset
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);
		Config c;
		CHECK(parseConfigLine(c, "amon_offset_learn 0") && !c.pol.amonOffsetLearn);
		CHECK(parseConfigLine(c, "amon_offset_min_samples 5") && (c.pol.amonOffsetMinSamples == 5));
	}
	// signal freshness: only a frame within the last poll counts
	CHECK(policy::isSignalFresh(0U, 1000));     // hostapd gave no inactive_msec
	CHECK(policy::isSignalFresh(999U, 1000));
	CHECK(!policy::isSignalFresh(1000U, 1000));
	CHECK(!policy::isSignalFresh(30000U, 1000)); // idle STA: old value
	// candidate pool order: measured (by level) > own BSS > unknown remote
	CHECK(policy::candidatePoolRank(false, 150) > policy::candidatePoolRank(false, 100));
	CHECK(policy::candidatePoolRank(false, 0) > policy::candidatePoolRank(true, policy::NO_HINT));
	CHECK(policy::candidatePoolRank(true, policy::NO_HINT) > policy::candidatePoolRank(false, policy::NO_HINT));
	CHECK(policy::candidatePoolRank(false, 255) == policy::candidatePoolRank(false, policy::NO_HINT)); // RCPI unknown

	// theta: +1 / -1, clamped to 0..lp_score_max, unchanged without evidence
	CHECK(policy::updateLpScore(p, 0, 50) == 0);
	CHECK(policy::updateLpScore(p, 5, 100) == 4); // S = 1 is not > 1
	CHECK(policy::updateLpScore(p, 5, 101) == 6);
	CHECK(policy::updateLpScore(p, 120, 300) == 120);
	CHECK(policy::updateLpScore(p, 7, policy::LP_NO_EVIDENCE) == 7);
	// class with hysteresis: in above 60, out below 50
	CHECK(!policy::isLowPower(p, 60, false));
	CHECK(policy::isLowPower(p, 61, false));
	CHECK(policy::isLowPower(p, 50, true));
	CHECK(!policy::isLowPower(p, 49, true));

	// End to end on synthetic traffic, one sample per second: a sensor
	// (bursty upload, little download) becomes low-power after
	// lp_min_samples + lp_threshold samples; a phone (bursty download) never.
	policy::TrafficStats sensor;
	policy::TrafficStats phone;
	int thS = 0;
	int thP = 0;
	bool lowS = false;
	bool lowP = false;
	int when = -1;
	for (int i = 0; i < 300; i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(sensor, burst ? 4000U : 40U, burst ? 200U : 20U);
		policy::addTrafficSample(phone, burst ? 2000U : 100U, burst ? 900000U : 3000U);
		thS = policy::updateLpScore(p, thS, policy::lpBehaviourScore(p, sensor, arcp::BAND_2G));
		thP = policy::updateLpScore(p, thP, policy::lpBehaviourScore(p, phone, arcp::BAND_2G));
		const bool l = policy::isLowPower(p, thS, lowS);
		if (l && !lowS && (when < 0)) {
			when = i + 1;
		}
		lowS = l;
		lowP = policy::isLowPower(p, thP, lowP);
	}
	CHECK(lowS && !lowP && (thP == 0));
	CHECK(when == (p.lpMinSamples - 1) + p.lpThreshold + 1);

	// A big, bursty upload (device backup, AirDrop) has the same shape as
	// the sensor above (bursty up, quiet down, S > 1 on every burst) but
	// moves 500x the data: never low-power, because lp_max_mean_bps gates
	// on the mean uplink rate actually seen, not just its shape.
	policy::TrafficStats bigUpload;
	int thU = 0;
	bool lowU = false;
	for (int i = 0; i < 300; i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(bigUpload, burst ? 2000000U : 1000U, burst ? 200U : 20U);
		thU = policy::updateLpScore(p, thU, policy::lpBehaviourScore(p, bigUpload, arcp::BAND_2G));
		lowU = policy::isLowPower(p, thU, lowU);
	}
	CHECK(!lowU && (thU == 0));
	// The gate follows the recent rate: once the upload stops and the STA
	// is back to sensor-sized traffic, S counts again within a few polls
	// (a whole-window mean would hold the 2 MB/s bursts for minutes).
	int firstEvidence = -1;
	for (int i = 0; (i < 100) && (firstEvidence < 0); i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(bigUpload, burst ? 4000U : 0U, burst ? 200U : 20U);
		if (policy::lpBehaviourScore(p, bigUpload, arcp::BAND_2G) != policy::LP_NO_EVIDENCE) {
			firstEvidence = i;
		}
	}
	CHECK((firstEvidence > 5) && (firstEvidence < 40)); // not at once, not minutes

	// PHY exclusion: VHT and EHT by default, not HE (Wi-Fi 6 IoT uses TWT)
	CHECK(policy::isLpExcludedPhy(p, arcp::CAP_VHT));
	CHECK(policy::isLpExcludedPhy(p, arcp::CAP_EHT));
	CHECK(!policy::isLpExcludedPhy(p, arcp::CAP_HE));
	CHECK(!policy::isLpExcludedPhy(p, 0U));
	PolicyConfig pHe = p;
	pHe.lpExcludeHe = true;
	pHe.lpExcludeVht = false;
	CHECK(policy::isLpExcludedPhy(pHe, arcp::CAP_HE) && !policy::isLpExcludedPhy(pHe, arcp::CAP_VHT));

	// STA_CLASS TLV round trip; a longer TLV from a newer peer decodes
	arcp::StaClass c;
	c.sta = mac("02:00:00:00:02:07");
	c.devClass = static_cast<std::uint8_t>(arcp::DevClass::LOW_POWER);
	c.score = 77;
	c.samples = 123456U;
	arcp::Message m;
	m.begin(arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ, mac("02:00:00:00:00:01"), 1U, 1U);
	CHECK(m.add(c) && m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value() && (h->type == arcp::raw(arcp::MsgType::STA_CLASS)));
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t ty = 0U;
	ByteView v;
	CHECK(rd.next(ty, v) && (ty == arcp::raw(arcp::Tlv::STA_CLASS)) && (v.size() == 15U));
	arcp::StaClass o;
	CHECK(arcp::decode(v, o) && (o.sta == c.sta) && (o.devClass == c.devClass) && (o.score == 77) &&
	      (o.samples == 123456U));
	std::array<std::uint8_t, 20U> longer{};
	for (std::size_t i = 0U; i < v.size(); i++) {
		longer[i] = v[i];
	}
	arcp::StaClass o2;
	CHECK(arcp::decode(viewOf(longer), o2) && (o2.samples == 123456U));
	CHECK(!arcp::decode(v.first(14U), o2));
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::STA_CLASS)) == "STA_CLASS");
	CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::STA_CLASS)) == "STA_CLASS");

	// config keys
	Config cfg;
	CHECK(cfg.pol.lpClassify && cfg.pol.lpNoSteer && (cfg.pol.lpThreshold == 60));
	CHECK(parseConfigLine(cfg, "lp_threshold 30") && (cfg.pol.lpThreshold == 30));
	CHECK(parseConfigLine(cfg, "lp_no_steer 0") && !cfg.pol.lpNoSteer);
	CHECK(parseConfigLine(cfg, "lp_classify 0") && !cfg.pol.lpClassify);
	CHECK(parseConfigLine(cfg, "lp_alpha_5g 80") && (cfg.pol.lpAlpha5g == 80));
	CHECK(parseConfigLine(cfg, "lp_min_samples 5") && (cfg.pol.lpMinSamples == 5));
	CHECK(!parseConfigLine(cfg, "lp_threshold x"));
}
