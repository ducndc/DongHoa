// SPDX-License-Identifier: MIT
#include "policy.hpp"

#include <array>

namespace donghoa {
namespace policy {

namespace {

// 1000 / (1 + exp(-0.3 * d)) for d = -30..30 dB around the midpoint
constexpr std::array<std::uint16_t, 61U> kQuality{
	0U,    0U,    0U,    0U,    0U,    1U,    1U,    1U,    1U,    2U,
	2U,    3U,    4U,    6U,    8U,    11U,   15U,   20U,   27U,   36U,
	47U,   63U,   83U,   109U,  142U,  182U,  231U,  289U,  354U,  426U,
	500U,  574U,  646U,  711U,  769U,  818U,  858U,  891U,  917U,  937U,
	953U,  964U,  973U,  980U,  985U,  989U,  992U,  994U,  996U,  997U,
	998U,  998U,  999U,  999U,  999U,  999U,  1000U, 1000U, 1000U, 1000U,
	1000U,
};

// Top MCS, short GI, one stream, per width kBw20..kBw320
constexpr std::array<int, 5U> kHt{72, 150, 150, 150, 150};
constexpr std::array<int, 5U> kVht{87, 200, 433, 867, 867};
constexpr std::array<int, 5U> kHe{143, 287, 601, 1201, 2402};

int band_bonus(const PolicyConfig &p, std::uint8_t band) noexcept
{
	int b = 0;
	if (band == arcp::kBand5g) {
		b = p.band_bonus_5g;
	} else if (band == arcp::kBand6g) {
		b = p.band_bonus_6g;
	} else {
		// 2.4 GHz: no bonus
	}
	return b;
}

// Throughput model: compare expected throughput at the target with what
// the STA gets now. The caller has applied the hard gates.
int score_tput(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept
{
	const std::int64_t tgt = expected_kbps(p, c.est_rssi, c.peak_mbps, c.util_pct);
	const std::int64_t cur = expected_kbps(p, ctx.cur_rssi, ctx.cur_peak_mbps, ctx.cur_util_pct);
	bool eligible = true;

	switch (ctx.reason) {
	case arcp::SteerReason::rssi:
		eligible = (tgt * 100) >= (cur * p.tput_gain_pct);
		break;
	case arcp::SteerReason::load:
		eligible = !((c.util_pct >= 0) && (c.util_pct > (p.util_high - p.lb_margin))) &&
			   (tgt >= cur); // the STA must not lose throughput
		break;
	case arcp::SteerReason::band:
		eligible = (c.band > ctx.cur_band) && ((tgt * 100) >= (cur * p.tput_gain_pct));
		break;
	default: // manual: any eligible candidate
		break;
	}
	return eligible ? static_cast<int>(tgt) : kIneligible;
}

} // namespace

int link_quality(const PolicyConfig &p, int rssi) noexcept
{
	int q = 0;
	if ((rssi != 0) && (rssi != kRssiUnknown)) {
		const int d = rssi - p.tput_rssi_mid;
		if (d > 30) {
			q = 1000;
		} else if (d >= -30) {
			q = static_cast<int>(kQuality[static_cast<std::size_t>(d + 30)]);
		} else {
			// far below the midpoint: no link
		}
	}
	return q;
}

int peak_mbps(std::uint16_t caps, std::uint8_t bw, int nss) noexcept
{
	const std::size_t w = (bw > arcp::kBw320) ? static_cast<std::size_t>(arcp::kBw320)
						 : static_cast<std::size_t>(bw);
	const int n = (nss < 1) ? 1 : nss;
	int r = 54;

	if ((caps & (arcp::kCapHe | arcp::kCapEht)) != 0U) {
		r = kHe[w] * n;
	} else if ((caps & arcp::kCapVht) != 0U) {
		r = kVht[w] * n;
	} else if ((caps & arcp::kCapHt) != 0U) {
		r = kHt[w] * n;
	} else {
		// legacy OFDM
	}
	return r;
}

int expected_kbps(const PolicyConfig &p, int rssi, int peak, int util_pct) noexcept
{
	// Unknown utilisation: assume the airtime is free, like the linear
	// model, which then applies no load penalty.
	const int util = (util_pct > 100) ? 100 : util_pct;
	const std::int64_t free_pct = (util_pct < 0) ? 100 : (100 - util);
	return static_cast<int>((static_cast<std::int64_t>(link_quality(p, rssi)) * peak * free_pct) /
				100);
}

int score(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept
{
	int r = kIneligible;
	const bool gated = (!c.accepting) || (c.est_rssi == kRssiUnknown) ||
			   ((c.max_sta != 0) && (c.sta_count >= c.max_sta)) ||
			   ((c.util_pct >= 0) && (c.util_pct >= p.util_admit_max)) ||
			   (c.est_rssi < p.rssi_min_target);

	if (gated) {
		r = kIneligible;
	} else if (p.score_model == ScoreModel::tput) {
		r = score_tput(p, ctx, c);
	} else {
		int floor = p.rssi_min_target;
		bool eligible = true;

		switch (ctx.reason) {
		case arcp::SteerReason::rssi:
			floor = ctx.cur_rssi + p.rssi_hysteresis;
			break;
		case arcp::SteerReason::load:
			eligible = !((c.util_pct >= 0) && (c.util_pct > (p.util_high - p.lb_margin)));
			floor = ctx.cur_rssi - p.lb_rssi_tolerance;
			break;
		case arcp::SteerReason::band:
			eligible = c.band > ctx.cur_band;
			break;
		default: // manual: any eligible candidate
			break;
		}
		if (eligible && (c.est_rssi >= floor)) {
			r = c.est_rssi + band_bonus(p, c.band);
			if (c.util_pct >= 0) {
				r -= (p.util_weight * c.util_pct) / 10;
			}
		}
	}
	return r;
}

bool rssi_trigger(const PolicyConfig &p, int rssi, int low_count) noexcept
{
	return p.rssi_steering && (rssi != 0) && (rssi < p.rssi_low) && (low_count >= p.rssi_low_count);
}

bool band_trigger(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept
{
	return p.band_steering && (band == arcp::kBand2g) && (rssi != 0) && (rssi >= p.band_steer_rssi);
}

bool bss_overloaded(const PolicyConfig &p, int util_pct, int sta_count, int max_sta) noexcept
{
	return p.load_balancing && (((util_pct >= 0) && (util_pct >= p.util_high)) ||
				    ((max_sta != 0) && (sta_count >= max_sta)));
}

bool lb_sta_eligible(const PolicyConfig &p, std::uint32_t tput_kbps) noexcept
{
	return (!p.lb_only_idle) || (tput_kbps < static_cast<std::uint32_t>(p.idle_kbps));
}

arcp::SteerStatus admit(const PolicyConfig &p, int util_pct, int sta_count, int reserved,
			int max_sta) noexcept
{
	arcp::SteerStatus s = arcp::SteerStatus::accept;
	if ((max_sta != 0) && ((sta_count + reserved) >= max_sta)) {
		s = arcp::SteerStatus::capacity;
	} else if ((util_pct >= 0) && (util_pct >= p.util_admit_max)) {
		s = arcp::SteerStatus::load;
	} else {
		// admitted
	}
	return s;
}

int backoff_ms(const PolicyConfig &p, int failures) noexcept
{
	std::int64_t ms = p.steer_cooldown_ms;
	for (int i = 0; (i < failures) && (ms < p.steer_backoff_max_ms); i++) {
		ms *= 2;
	}
	if (ms > p.steer_backoff_max_ms) {
		ms = p.steer_backoff_max_ms;
	}
	return static_cast<int>(ms);
}

} // namespace policy
} // namespace donghoa
