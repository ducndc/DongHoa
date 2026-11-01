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
	std::uint8_t ssid_len{0U};
	int num_sta{0};
	int max_txpower{0};
	int chan_util{-1}; // 0..255, -1 if not reported
};

// "STATUS" output, choosing the per-BSS entry of ifname.
std::optional<Status> parse_status(std::string_view buf, std::string_view ifname) noexcept;

struct Sta {
	Mac addr{};
	bool authorized{false};
	int signal{0}; // dBm, 0 if unknown
	std::uint64_t rx_bytes{0U};
	std::uint64_t tx_bytes{0U};
	std::uint32_t inactive_ms{0U};
	std::uint32_t connected_s{0U};
	std::uint16_t rx_rate_mbps{0U};
	std::uint16_t tx_rate_mbps{0U};
	bool btm_known{false};
	bool btm{false};
	bool ft_known{false};
	bool ft{false};
};

// "STA <addr>" / "STA-FIRST" / "STA-NEXT" output.
std::optional<Sta> parse_sta(std::string_view buf) noexcept;

// "BSS-TM-RESP <addr> dialog_token=.. status_code=.. ... target_bssid=.."
struct BtmResp {
	Mac addr{};
	int status{0};
	Mac target{};
	bool has_target{false};
};

std::optional<BtmResp> parse_btm_resp(std::string_view ev) noexcept;

} // namespace hapd
} // namespace donghoa

#endif
