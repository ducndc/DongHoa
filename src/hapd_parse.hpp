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
	Mac mldAddr{};    // AP MLD address (mld_addr[i]), zero if not an MLD link
	int linkId{-1};   // mld_link_id[i], -1 if not an MLD link
};

// hostapd names the control socket of an AP MLD link "<netdev>_link<id>".
// The netdev part of a control socket name (the whole name otherwise).
std::string_view netdevName(std::string_view ctrlName) noexcept;
// The link ID of such a name, empty for a plain netdev name.
std::optional<int> ctrlLinkId(std::string_view ctrlName) noexcept;

// "STATUS" output, choosing the per-BSS entry of ifname: bss[i] equal to
// ifname, or for "<netdev>_link<id>" bss[i] equal to <netdev> with
// mld_link_id[i] equal to <id>.
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
	std::uint8_t bands{0U}; // rrm::BANDS_* from supp_op_classes, 0 if absent
	bool akmNo6g{false};    // its AKM is not allowed on 6 GHz (WPA2-PSK)
	// From flags=[...]: arcp::CAP_VHT/CAP_HE/CAP_EHT bits it negotiated.
	// HT is common even on cheap IoT silicon; VHT/HE/EHT need meaningfully
	// more RF complexity and power, so devclass.cpp treats any of them as
	// ruling out a low-power classification outright.
	std::uint8_t phyCaps{0U};
	// Wi-Fi 7 MLO: an MLD STA (addr is its MLD address) lists its links
	// as peer_addr[<link id>]=<link address>.
	bool mld{false};
	std::uint16_t linkMask{0U}; // bit = link ID with a peer_addr
	int maxSimulLinks{-1};      // max_simul_links, -1 if absent
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
