// SPDX-License-Identifier: MIT
// Steering and load-balancing decisions. Pure functions, no I/O.
#ifndef DONGHOA_POLICY_HPP
#define DONGHOA_POLICY_HPP

#include <cstdint>
#include <limits>

#include "config.hpp"
#include "proto.hpp"

namespace donghoa {
namespace policy {

constexpr int kIneligible = std::numeric_limits<int>::min();
constexpr int kRssiUnknown = -128;

struct CandInput {
	std::uint8_t band{0U};
	int est_rssi{kRssiUnknown}; // STA-measured level of the target
	int util_pct{-1};           // -1 unknown
	int sta_count{0};
	int max_sta{0};             // 0 = unlimited
	bool accepting{true};
	int peak_mbps{0};           // peak_mbps() of the target (tput model)
};

struct SteerCtx {
	arcp::SteerReason reason{arcp::SteerReason::manual};
	int cur_rssi{0};
	std::uint8_t cur_band{0U};
	int cur_util_pct{-1};       // tput model
	int cur_peak_mbps{0};       // tput model
};

// 0..254 utilisation as a percentage; -1 for 255 (unknown).
constexpr int util_to_pct(int util255) noexcept
{
	return ((util255 < 0) || (util255 > 254)) ? -1 : (((util255 * 100) + 127) / 255);
}

// Link quality 0..1000: logistic curve, slope 0.3/dB, 500 at tput_rssi_mid.
// 0 for RSSI 0 (unknown) and kRssiUnknown.
int link_quality(const PolicyConfig &p, int rssi) noexcept;
// Top PHY rate of a BSS (Mbps) from its caps and width, for nss streams.
int peak_mbps(std::uint16_t caps, std::uint8_t bw, int nss) noexcept;
// Expected throughput (kbps) = quality x peak x free airtime.
int expected_kbps(const PolicyConfig &p, int rssi, int peak, int util_pct) noexcept;

// Candidate score (higher is better) or kIneligible. With the tput model
// the score is the candidate's expected throughput in kbps.
int score(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept;

bool rssi_trigger(const PolicyConfig &p, int rssi, int low_count) noexcept;
bool band_trigger(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept;
bool bss_overloaded(const PolicyConfig &p, int util_pct, int sta_count, int max_sta) noexcept;
bool lb_sta_eligible(const PolicyConfig &p, std::uint32_t tput_kbps) noexcept;
// Target-side admission control for STEER_REQ.
arcp::SteerStatus admit(const PolicyConfig &p, int util_pct, int sta_count, int reserved,
			int max_sta) noexcept;
// Exponential backoff after failed steering attempts.
int backoff_ms(const PolicyConfig &p, int failures) noexcept;

} // namespace policy
} // namespace donghoa

#endif
