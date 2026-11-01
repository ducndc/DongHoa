// SPDX-License-Identifier: MIT
// Parsers for hostapd control-interface output (pure; no I/O). The formats
// relied on are listed in docs/ARCHITECTURE.md ("Assumptions to verify").
#ifndef DONGHOA_HAPD_PARSE_HPP
#define DONGHOA_HAPD_PARSE_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

#include "types.hpp"

namespace donghoa {
namespace hapd {

struct Status {
	int freq{0};
	std::uint8_t channel{0U};
	std::uint8_t band{0U};
	std::uint8_t bw{0U};
	std::uint16_t caps{0U};
	Mac bssid{};
	std::array<std::uint8_t, 32U> ssid{};
	std::uint8_t ssidLen{0U};
	int numSta{0};
	int maxTxpower{0};
	int chanUtil{-1}; // 0..255, -1 if not reported
};

// "STATUS" output, choosing the per-BSS entry of ifname.
std::optional<Status> parseStatus(std::string_view buf, std::string_view ifname) noexcept;

struct Sta {
	Mac addr{};
	bool authorized{false};
	int signal{0}; // dBm, 0 if unknown
	std::uint64_t rxBytes{0U};
	std::uint64_t txBytes{0U};
	std::uint32_t inactiveMs{0U};
	std::uint32_t connectedS{0U};
	std::uint16_t rxRateMbps{0U};
	std::uint16_t txRateMbps{0U};
	bool btmKnown{false};
	bool btm{false};
	bool ftKnown{false};
	bool ft{false};
};

// "STA <addr>" / "STA-FIRST" / "STA-NEXT" output.
std::optional<Sta> parseSta(std::string_view buf) noexcept;

// "BSS-TM-RESP <addr> dialog_token=.. status_code=.. ... target_bssid=.."
struct BtmResp {
	Mac addr{};
	int status{0};
	Mac target{};
	bool hasTarget{false};
};

std::optional<BtmResp> parseBtmResp(std::string_view ev) noexcept;

} // namespace hapd
} // namespace donghoa

#endif
