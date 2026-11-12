// SPDX-License-Identifier: MIT
// Configuration consistency across the APs of a mesh (feature 18). Pure:
// compares what the peers advertise (BSS_INFO, the POLICY TLV of HELLO)
// with this AP's own values and names what differs.
//
// Two kinds of finding:
//  - BSS pairs of one ESS whose 802.11r / security settings make roaming
//    between them slow or impossible (a different mobility domain, FT on
//    one side only, open and secured under one SSID);
//  - steering settings that differ between APs (thresholds, enabled
//    features), which makes STAs ping-pong or be steered unevenly.
#ifndef DONGHOA_CONSISTENCY_HPP
#define DONGHOA_CONSISTENCY_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "config.hpp"
#include "proto.hpp"
#include "text.hpp"

namespace donghoa {
namespace consistency {

// ---- BSS pairs of one ESS (bit mask) ----
constexpr std::uint32_t MDID_DIFFERS = 0x01U;     // both FT, different mobility domains
constexpr std::uint32_t FT_ONE_SIDED = 0x02U;     // FT on one BSS only
constexpr std::uint32_t FT_DS_DIFFERS = 0x04U;    // FT over DS on one only (same domain)
constexpr std::uint32_t SECURITY_DIFFERS = 0x08U; // open and secured under one SSID
constexpr std::size_t PAIR_BITS = 4U;

// Bit k of the pair issues.
constexpr std::uint32_t pairBit(std::size_t k) noexcept
{
	return 1U << k;
}

// Issues between a and b; 0 when they are not of one ESS, or are links of
// one AP MLD (one device, hostapd keeps them consistent).
std::uint32_t checkPair(const arcp::BssInfo &a, const arcp::BssInfo &b) noexcept;

// Short name ("mdid_differs") and what it breaks, for one bit.
std::string_view pairIssueName(std::uint32_t bit) noexcept;
std::string_view pairIssueHint(std::uint32_t bit) noexcept;

// ---- steering settings (bit mask, one bit per field) ----
constexpr std::uint32_t POL_FEATURES = 0x0001U; // POL_* flags
constexpr std::uint32_t POL_RSSI_LOW = 0x0002U;
constexpr std::uint32_t POL_RSSI_HYSTERESIS = 0x0004U;
constexpr std::uint32_t POL_RSSI_MIN_TARGET = 0x0008U;
constexpr std::uint32_t POL_BAND_STEER_RSSI = 0x0010U;
constexpr std::uint32_t POL_BAND_STEER_6G_RSSI = 0x0020U;
constexpr std::uint32_t POL_UTIL_HIGH = 0x0040U;
constexpr std::uint32_t POL_UTIL_ADMIT_MAX = 0x0080U;
constexpr std::uint32_t POL_LB_MARGIN = 0x0100U;
constexpr std::uint32_t POL_SCORE_MODEL = 0x0200U;
constexpr std::uint32_t POL_STEER_COOLDOWN = 0x0400U;

// This AP's settings as carried in HELLO.
arcp::PolicySum summarize(const PolicyConfig &p) noexcept;
// Fields that differ.
std::uint32_t diffPolicy(const arcp::PolicySum &a, const arcp::PolicySum &b) noexcept;
// "rssi_low -75/-70 util_high 70/80": own value first, then the peer's.
using DiffText = FixedString<512U>;
void describePolicyDiff(DiffText &out, const arcp::PolicySum &own, const arcp::PolicySum &peer,
			std::uint32_t diff) noexcept;

} // namespace consistency
} // namespace donghoa

#endif
