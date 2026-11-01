// SPDX-License-Identifier: MIT
#include "policy.hpp"

#include <array>

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

bool isRssiTriggered(const PolicyConfig &p, int rssi, int lowCount) noexcept
{
	return p.rssiSteering && (rssi != 0) && (rssi < p.rssiLow) && (lowCount >= p.rssiLowCount);
}

bool isBandTriggered(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept
{
	return p.bandSteering && (band == arcp::BAND_2G) && (rssi != 0) && (rssi >= p.bandSteerRssi);
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

} // namespace policy
} // namespace donghoa
