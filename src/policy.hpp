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

constexpr int INELIGIBLE = std::numeric_limits<int>::min();
constexpr int RSSI_UNKNOWN = -128;

struct CandInput {
	std::uint8_t band{0U};
	int estRssi{RSSI_UNKNOWN}; // STA-measured level of the target
	int utilPct{-1};           // -1 unknown
	int staCount{0};
	int maxSta{0};             // 0 = unlimited
	bool accepting{true};
	int peakMbps{0};           // computePeakMbps() of the target (tput model)
};

struct SteerCtx {
	arcp::SteerReason reason{arcp::SteerReason::MANUAL};
	int curRssi{0};
	std::uint8_t curBand{0U};
	int curUtilPct{-1};       // tput model
	int curPeakMbps{0};       // tput model
};

// 0..254 utilisation as a percentage; -1 for 255 (unknown).
constexpr int utilToPct(int util255) noexcept
{
	return ((util255 < 0) || (util255 > 254)) ? -1 : (((util255 * 100) + 127) / 255);
}

// Link quality 0..1000: logistic curve, slope 0.3/dB, 500 at tput_rssi_mid.
// 0 for RSSI 0 (unknown) and RSSI_UNKNOWN.
int computeLinkQuality(const PolicyConfig &p, int rssi) noexcept;
// Top PHY rate of a BSS (Mbps) from its caps and width, for nss streams.
int computePeakMbps(std::uint16_t caps, std::uint8_t bw, int nss) noexcept;
// Expected throughput (kbps) = quality x peak x free airtime.
int computeExpectedKbps(const PolicyConfig &p, int rssi, int peak, int utilPct) noexcept;

// Candidate score (higher is better) or INELIGIBLE. With the tput model
// the score is the candidate's expected throughput in kbps.
int score(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept;

bool isRssiTriggered(const PolicyConfig &p, int rssi, int lowCount) noexcept;
bool isBandTriggered(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept;
bool isBssOverloaded(const PolicyConfig &p, int utilPct, int staCount, int maxSta) noexcept;
bool isLbStaEligible(const PolicyConfig &p, std::uint32_t tputKbps) noexcept;
// Target-side admission control for STEER_REQ.
arcp::SteerStatus admit(const PolicyConfig &p, int utilPct, int staCount, int reserved,
			int maxSta) noexcept;
// Exponential backoff after failed steering attempts.
int backoffMs(const PolicyConfig &p, int failures) noexcept;

} // namespace policy
} // namespace donghoa

#endif
