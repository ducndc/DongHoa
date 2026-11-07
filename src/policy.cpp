// SPDX-License-Identifier: MIT
#include "policy.hpp"

#include <array>

#include "rrm.hpp"

namespace donghoa {
namespace policy {

namespace {

// 1000 / (1 + exp(-0.3 * d)) for d = -30..30 dB around the midpoint
constexpr std::array<std::uint16_t, 61U> QUALITY{
	0U,    0U,    0U,    0U,    0U,    1U,    1U,    1U,    1U,    2U,
	2U,    3U,    4U,    6U,    8U,    11U,   15U,   20U,   27U,   36U,
	47U,   63U,   83U,   109U,  142U,  182U,  231U,  289U,  354U,  426U,
	500U,  574U,  646U,  711U,  769U,  818U,  858U,  891U,  917U,  937U,
	953U,  964U,  973U,  980U,  985U,  989U,  992U,  994U,  996U,  997U,
	998U,  998U,  999U,  999U,  999U,  999U,  1000U, 1000U, 1000U, 1000U,
	1000U,
};

// Top MCS, short GI, one stream, per width BW20..BW320
constexpr std::array<int, 5U> HT{72, 150, 150, 150, 150};
constexpr std::array<int, 5U> VHT{87, 200, 433, 867, 867};
constexpr std::array<int, 5U> HE{143, 287, 601, 1201, 2402};

int bandBonus(const PolicyConfig &p, std::uint8_t band) noexcept
{
	int b = 0;
	if (band == arcp::BAND_5G) {
		b = p.bandBonus5g;
	} else if (band == arcp::BAND_6G) {
		b = p.bandBonus6g;
	} else {
		// 2.4 GHz: no bonus
	}
	return b;
}

// Throughput model: compare expected throughput at the target with what
// the STA gets now. The caller has applied the hard gates.
int scoreTput(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept
{
	const std::int64_t tgt = computeExpectedKbps(p, c.estRssi, c.peakMbps, c.utilPct);
	const std::int64_t cur = computeExpectedKbps(p, ctx.curRssi, ctx.curPeakMbps, ctx.curUtilPct);
	bool eligible = true;

	switch (ctx.reason) {
	case arcp::SteerReason::RSSI:
		eligible = (tgt * 100) >= (cur * p.tputGainPct);
		break;
	case arcp::SteerReason::LOAD:
		eligible = !((c.utilPct >= 0) && (c.utilPct > (p.utilHigh - p.lbMargin))) &&
			   (tgt >= cur); // the STA must not lose throughput
		break;
	case arcp::SteerReason::BAND:
		eligible = (c.band > ctx.curBand) && ((tgt * 100) >= (cur * p.tputGainPct));
		break;
	default: // manual: any eligible candidate
		break;
	}
	return eligible ? static_cast<int>(tgt) : INELIGIBLE;
}

} // namespace

int computeLinkQuality(const PolicyConfig &p, int rssi) noexcept
{
	int q = 0;
	if ((rssi != 0) && (rssi != RSSI_UNKNOWN)) {
		const int d = rssi - p.tputRssiMid;
		if (d > 30) {
			q = 1000;
		} else if (d >= -30) {
			q = static_cast<int>(QUALITY[static_cast<std::size_t>(d + 30)]);
		} else {
			// far below the midpoint: no link
		}
	}
	return q;
}

int computePeakMbps(std::uint16_t caps, std::uint8_t bw, int nss) noexcept
{
	const std::size_t w = (bw > arcp::BW320) ? static_cast<std::size_t>(arcp::BW320)
						 : static_cast<std::size_t>(bw);
	const int n = (nss < 1) ? 1 : nss;
	int r = 54;

	if ((caps & (arcp::CAP_HE | arcp::CAP_EHT)) != 0U) {
		r = HE[w] * n;
	} else if ((caps & arcp::CAP_VHT) != 0U) {
		r = VHT[w] * n;
	} else if ((caps & arcp::CAP_HT) != 0U) {
		r = HT[w] * n;
	} else {
		// legacy OFDM
	}
	return r;
}

int computeExpectedKbps(const PolicyConfig &p, int rssi, int peak, int utilPct) noexcept
{
	// Unknown utilisation: assume the airtime is free, like the linear
	// model, which then applies no load penalty.
	const int util = (utilPct > 100) ? 100 : utilPct;
	const std::int64_t freePct = (utilPct < 0) ? 100 : (100 - util);
	return static_cast<int>((static_cast<std::int64_t>(computeLinkQuality(p, rssi)) * peak * freePct) /
				100);
}

int score(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept
{
	int r = INELIGIBLE;
	const bool gated = (!c.accepting) || (c.estRssi == RSSI_UNKNOWN) ||
			   ((c.maxSta != 0) && (c.staCount >= c.maxSta)) ||
			   ((c.utilPct >= 0) && (c.utilPct >= p.utilAdmitMax)) ||
			   (c.estRssi < p.rssiMinTarget);

	if (gated) {
		r = INELIGIBLE;
	} else if (p.scoreModel == ScoreModel::TPUT) {
		r = scoreTput(p, ctx, c);
	} else {
		int floor = p.rssiMinTarget;
		bool eligible = true;

		switch (ctx.reason) {
		case arcp::SteerReason::RSSI:
			floor = ctx.curRssi + p.rssiHysteresis;
			break;
		case arcp::SteerReason::LOAD:
			eligible = !((c.utilPct >= 0) && (c.utilPct > (p.utilHigh - p.lbMargin)));
			floor = ctx.curRssi - p.lbRssiTolerance;
			break;
		case arcp::SteerReason::BAND:
			eligible = c.band > ctx.curBand;
			break;
		default: // manual: any eligible candidate
			break;
		}
		if (eligible && (c.estRssi >= floor)) {
			r = c.estRssi + bandBonus(p, c.band);
			if (c.utilPct >= 0) {
				r -= (p.utilWeight * c.utilPct) / 10;
			}
		}
	}
	return r;
}

bool isRssiTriggered(const PolicyConfig &p, int rssi, int lowCount, int thresholdDbm) noexcept
{
	return p.rssiSteering && (rssi != 0) && (rssi < thresholdDbm) && (lowCount >= p.rssiLowCount);
}

namespace {

int clampRoamThr(const PolicyConfig &p, int v) noexcept
{
	const int lo = (p.roamThrMin <= p.roamThrMax) ? p.roamThrMin : p.roamThrMax;
	const int hi = (p.roamThrMin <= p.roamThrMax) ? p.roamThrMax : p.roamThrMin;
	return (v < lo) ? lo : ((v > hi) ? hi : v);
}

} // namespace

int roamThreshold(const PolicyConfig &p, int learnedDbm) noexcept
{
	return clampRoamThr(p, (p.roamThrLearn && (learnedDbm != 0)) ? learnedDbm : p.rssiLow);
}

int updateRoamThrOutcome(const PolicyConfig &p, int learnedDbm, RoamOutcome o, int gainDb) noexcept
{
	int t = roamThreshold(p, learnedDbm);
	if (o == RoamOutcome::REFUSED) {
		t += ROAM_THR_REFUSED_DB;
	} else if (o == RoamOutcome::ROAM_TIMEOUT) {
		t += ROAM_THR_TIMEOUT_DB;
	} else if (gainDb >= ROAM_THR_BIG_GAIN_DB) {
		t += ROAM_THR_EARLIER_DB;
	} else {
		// a success with a modest gain: the threshold was right
	}
	return clampRoamThr(p, t);
}

int updateRoamThrSelf(const PolicyConfig &p, int learnedDbm, int leftAtDbm) noexcept
{
	const int t = roamThreshold(p, learnedDbm);
	int r = t;
	if (leftAtDbm < 0) {
		const int d = leftAtDbm - t;
		// at least 1 dB per roam towards the level it left at
		const int step = (d / 4 != 0) ? (d / 4) : ((d > 0) ? 1 : ((d < 0) ? -1 : 0));
		r = t + step;
	}
	return clampRoamThr(p, r);
}

int decayRoamThr(const PolicyConfig &p, int learnedDbm) noexcept
{
	const int t = roamThreshold(p, learnedDbm);
	const int base = clampRoamThr(p, p.rssiLow);
	return (t < base) ? (t + 1) : ((t > base) ? (t - 1) : t);
}

bool isSignalFresh(std::uint32_t inactiveMs, int pollMs) noexcept
{
	return (pollMs <= 0) || (inactiveMs < static_cast<std::uint32_t>(pollMs));
}

bool isUlDlCalibrated(const PolicyConfig &p, const UlDlOffset &o) noexcept
{
	const std::uint32_t need = (p.amonOffsetMinSamples < 1) ? 1U : static_cast<std::uint32_t>(p.amonOffsetMinSamples);
	return p.amonOffsetLearn && (o.n >= need);
}

bool addUlDlSample(const PolicyConfig &p, UlDlOffset &o, int downlinkDbm, int uplinkDbm) noexcept
{
	const int delta = downlinkDbm - uplinkDbm;
	bool ok = (downlinkDbm < 0) && (uplinkDbm < 0) && (delta <= ULDL_MAX_DELTA) && (delta >= -ULDL_MAX_DELTA);
	if (ok && isUlDlCalibrated(p, o)) {
		const int dev = (16 * delta) - o.offset16;
		ok = (dev <= (16 * ULDL_OUTLIER)) && (dev >= -(16 * ULDL_OUTLIER));
	}
	if (ok) {
		const std::uint32_t div = (o.n < ULDL_AVG_N) ? (o.n + 1U) : ULDL_AVG_N;
		o.offset16 += ((16 * delta) - o.offset16) / static_cast<int>(div);
		o.n++;
	}
	return ok;
}

int uplinkToDownlink(const PolicyConfig &p, const UlDlOffset *o, int uplinkDbm) noexcept
{
	int off = p.amonRssiOffset;
	if ((o != nullptr) && isUlDlCalibrated(p, *o)) {
		// round x16 to the nearest dB, symmetric around 0
		off = (o->offset16 >= 0) ? ((o->offset16 + 8) / 16) : -(((-o->offset16) + 8) / 16);
	}
	return uplinkDbm + off;
}

bool isBandTriggered(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept
{
	const bool from2g = (band == arcp::BAND_2G) && (rssi >= p.bandSteerRssi);
	const bool from5g = p.bandSteer6g && (band == arcp::BAND_5G) && (rssi >= p.bandSteer6gRssi);
	return p.bandSteering && (rssi != 0) && (from2g || from5g);
}

bool isBssOverloaded(const PolicyConfig &p, int utilPct, int staCount, int maxSta) noexcept
{
	return p.loadBalancing && (((utilPct >= 0) && (utilPct >= p.utilHigh)) ||
				    ((maxSta != 0) && (staCount >= maxSta)));
}

bool isLbStaEligible(const PolicyConfig &p, std::uint32_t tputKbps) noexcept
{
	return (!p.lbOnlyIdle) || (tputKbps < static_cast<std::uint32_t>(p.idleKbps));
}

bool isLbMoveEffective(const PolicyConfig &p, int utilBeforePct, int utilNowPct) noexcept
{
	return (utilBeforePct < 0) || (utilNowPct < 0) || (utilNowPct <= (utilBeforePct - p.lbMinDropPct));
}

arcp::SteerStatus admit(const PolicyConfig &p, int utilPct, int staCount, int reserved,
			int maxSta) noexcept
{
	arcp::SteerStatus s = arcp::SteerStatus::ACCEPT;
	if ((maxSta != 0) && ((staCount + reserved) >= maxSta)) {
		s = arcp::SteerStatus::CAPACITY;
	} else if ((utilPct >= 0) && (utilPct >= p.utilAdmitMax)) {
		s = arcp::SteerStatus::LOAD;
	} else {
		// admitted
	}
	return s;
}

bool isBandUsable(const StaBands &b, std::uint8_t band) noexcept
{
	const std::uint8_t bit = rrm::bandBit(band);
	bool ok = true;
	if (bit == 0U) {
		ok = true;
	} else if ((b.blocked & bit) != 0U) {
		ok = false;
	} else {
		ok = (b.advertised == 0U) || ((static_cast<std::uint8_t>(b.advertised | b.seen) & bit) != 0U);
	}
	return ok;
}

bool hasHigherBand(const StaBands &b, std::uint8_t curBand) noexcept
{
	bool r = false;
	if (curBand < arcp::BAND_5G) {
		r = isBandUsable(b, arcp::BAND_5G) || isBandUsable(b, arcp::BAND_6G);
	} else if (curBand == arcp::BAND_5G) {
		const std::uint8_t known = static_cast<std::uint8_t>(b.advertised | b.seen);
		r = ((known & rrm::BANDS_6G) != 0U) && ((b.blocked & rrm::BANDS_6G) == 0U);
	} else {
		r = false; // 6 GHz is the top band
	}
	return r;
}

int candidatePoolRank(bool local, int hintRcpi) noexcept
{
	int r = 0;
	if ((hintRcpi >= 0) && (hintRcpi <= 220)) {
		r = 2000 + hintRcpi;
	} else if (local) {
		r = 1000;
	} else {
		// unknown, remote
	}
	return r;
}

int backoffMs(const PolicyConfig &p, int failures) noexcept
{
	std::int64_t ms = p.steerCooldownMs;
	for (int i = 0; (i < failures) && (ms < p.steerBackoffMaxMs); i++) {
		ms *= 2;
	}
	if (ms > p.steerBackoffMaxMs) {
		ms = p.steerBackoffMaxMs;
	}
	return static_cast<int>(ms);
}

namespace {

void addRate(RateStats &r, std::uint32_t n, std::uint64_t bps) noexcept
{
	const std::int64_t x16 = static_cast<std::int64_t>(((bps < TRAFFIC_RATE_MAX) ? bps : TRAFFIC_RATE_MAX) * 16U);
	const std::int64_t delta = x16 - r.mean16;
	r.mean16 += delta / static_cast<std::int64_t>(n);
	// delta and (x - new mean) have the same sign: the product is >= 0.
	const std::int64_t prod = (delta * (x16 - r.mean16)) / 256;
	r.m2 += (prod > 0) ? static_cast<std::uint64_t>(prod) : 0U;
}

int lpAlpha(const PolicyConfig &p, std::uint8_t band) noexcept
{
	int a = p.lpAlpha2g;
	if (band == arcp::BAND_5G) {
		a = p.lpAlpha5g;
	} else if (band == arcp::BAND_6G) {
		a = p.lpAlpha6g;
	} else {
		// 2.4 GHz
	}
	return (a < 0) ? 0 : ((a > 10000) ? 10000 : a);
}

} // namespace

bool isLpExcludedPhy(const PolicyConfig &p, std::uint8_t phyCaps) noexcept
{
	std::uint8_t mask = 0U;
	if (p.lpExcludeVht) {
		mask = static_cast<std::uint8_t>(mask | arcp::CAP_VHT);
	}
	if (p.lpExcludeHe) {
		mask = static_cast<std::uint8_t>(mask | arcp::CAP_HE);
	}
	if (p.lpExcludeEht) {
		mask = static_cast<std::uint8_t>(mask | arcp::CAP_EHT);
	}
	return (phyCaps & mask) != 0U;
}

std::uint32_t isqrt(std::uint64_t v) noexcept
{
	std::uint64_t r = 0U;
	std::uint64_t bit = static_cast<std::uint64_t>(1U) << 62U;
	while (bit > v) {
		bit >>= 2U;
	}
	while (bit != 0U) {
		if (v >= (r + bit)) {
			v -= r + bit;
			r = (r >> 1U) + bit;
		} else {
			r >>= 1U;
		}
		bit >>= 2U;
	}
	return static_cast<std::uint32_t>(r);
}

void addTrafficSample(TrafficStats &t, std::uint64_t upBps, std::uint64_t downBps) noexcept
{
	if (t.n >= TRAFFIC_WINDOW) {
		t.n /= 2U;
		t.up.m2 /= 2U;
		t.down.m2 /= 2U;
	}
	t.n++;
	addRate(t.up, t.n, upBps);
	addRate(t.down, t.n, downBps);
	t.lastActive = (upBps > 0U) || (downBps > 0U);
	const std::int64_t up16 =
		static_cast<std::int64_t>(((upBps > TRAFFIC_RATE_MAX) ? TRAFFIC_RATE_MAX : upBps) * 16U);
	t.upRecent16 = (t.n == 1U) ? up16 : (t.upRecent16 + ((up16 - t.upRecent16) / TRAFFIC_RECENT_DIV));
}

int lpBehaviourScore(const PolicyConfig &p, const TrafficStats &t, std::uint8_t band) noexcept
{
	int r = LP_NO_EVIDENCE;
	// n cancels in sigma_up / sigma_down: compare the square roots of m2.
	const std::uint64_t su = isqrt(t.up.m2);
	const std::uint64_t sd = isqrt(t.down.m2);
	const bool enough = (p.lpMinSamples <= 1) || (t.n >= static_cast<std::uint32_t>(p.lpMinSamples));
	// Asymmetry alone does not tell low-power traffic from a real transfer
	// (a backup or AirDrop upload is "bursty up, quiet down" too, just at
	// 1000x the scale): gate on the recent mean uplink rate.
	const std::uint64_t meanUp = (t.upRecent16 <= 0) ? 0U : (static_cast<std::uint64_t>(t.upRecent16) / 16U);
	const bool small = (p.lpMaxMeanBps <= 0) || (meanUp <= static_cast<std::uint64_t>(p.lpMaxMeanBps));

	if (!enough || !small || !t.lastActive || ((su == 0U) && (sd == 0U))) {
		r = LP_NO_EVIDENCE;
	} else if (sd == 0U) {
		r = LP_S_MAX;
	} else {
		const std::uint64_t s100 = (static_cast<std::uint64_t>(lpAlpha(p, band)) * su) / sd;
		r = (s100 > static_cast<std::uint64_t>(LP_S_MAX)) ? LP_S_MAX : static_cast<int>(s100);
	}
	return r;
}

int updateLpScore(const PolicyConfig &p, int theta, int s100) noexcept
{
	int r = theta;
	if (s100 != LP_NO_EVIDENCE) {
		r = (s100 > 100) ? (theta + 1) : (theta - 1);
	}
	const int hi = (p.lpScoreMax > 0) ? p.lpScoreMax : 0;
	return (r < 0) ? 0 : ((r > hi) ? hi : r);
}

bool isLowPower(const PolicyConfig &p, int theta, bool wasLowPower) noexcept
{
	return wasLowPower ? (theta >= (p.lpThreshold - p.lpHysteresis)) : (theta > p.lpThreshold);
}

} // namespace policy
} // namespace donghoa
