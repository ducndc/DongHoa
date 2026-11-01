// SPDX-License-Identifier: MIT
// 802.11k/v byte layouts, channel and operating-class maps, radiotap. Pure:
// no I/O. 802.11 fields are little-endian (unlike ARCP).
#ifndef DONGHOA_RRM_HPP
#define DONGHOA_RRM_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "proto.hpp"
#include "types.hpp"

namespace donghoa {
namespace rrm {

// Neighbor Report BSSID Information bits (IEEE 802.11-2020, 9.4.2.36)
constexpr std::uint32_t kBiReachable = 0x00000003U;
constexpr std::uint32_t kBiSecurity = 0x00000004U;
constexpr std::uint32_t kBiKeyScope = 0x00000008U;
constexpr std::uint32_t kBiQos = 0x00000020U;
constexpr std::uint32_t kBiRrm = 0x00000080U;
constexpr std::uint32_t kBiImmBa = 0x00000200U;
constexpr std::uint32_t kBiMobilityDomain = 0x00000400U;
constexpr std::uint32_t kBiHt = 0x00000800U;
constexpr std::uint32_t kBiVht = 0x00001000U;
constexpr std::uint32_t kBiHe = 0x00004000U;

// Condensed PHY type (dot11PHYType)
constexpr std::uint8_t kPhyOfdm = 4U;
constexpr std::uint8_t kPhyErp = 6U;
constexpr std::uint8_t kPhyHt = 7U;
constexpr std::uint8_t kPhyVht = 9U;
constexpr std::uint8_t kPhyHe = 14U;

// Beacon Request measurement modes
enum class BeaconMode : std::uint8_t { passive = 0U, active = 1U, table = 2U };
// A passive measurement must last a beacon interval (typically 100 TU).
constexpr std::uint16_t kPassiveMinTu = 120U;
constexpr std::size_t kMaxBeaconChannels = 8U;

std::string_view beacon_mode_name(BeaconMode m) noexcept;

struct ChanBand {
	std::uint8_t channel{0U};
	std::uint8_t band{0U};
};

std::optional<ChanBand> freq_to_chan(int freq) noexcept;
// Global operating class of the 20 MHz primary channel, 0 if unknown.
std::uint8_t op_class_20mhz(std::uint8_t band, std::uint8_t chan) noexcept;
std::uint8_t phy_type_from_caps(std::uint16_t caps, std::uint8_t band) noexcept;
std::uint32_t bssid_info_build(std::uint16_t caps, bool secured) noexcept;

// RCPI <-> dBm (RCPI = 2 * (dBm + 110); 255 = not available)
int rcpi_to_dbm(std::uint8_t rcpi) noexcept;
std::uint8_t dbm_to_rcpi(int dbm) noexcept;

// Neighbor Report element body (no ID/length) as hex for hostapd
// SET_NEIGHBOR nr=. local_mdid decides the Mobility Domain bit.
bool nr_build_hex(const arcp::BssInfo &b, std::uint16_t local_mdid, FixedString<64U> &out) noexcept;

struct OpChan {
	std::uint8_t op_class{0U};
	std::uint8_t channel{0U};
};
using OpChanList = std::array<OpChan, kMaxBeaconChannels>;

// Beacon Request fields (from Operating Class on) as hex for REQ_BEACON.
// One channel: a plain request. Several: Channel 255 plus AP Channel Report
// subelements, so the STA measures all of them in one request (STAs handle
// one beacon measurement at a time). bssid may be null (wildcard).
bool bcn_req_build_hex(const OpChanList &chans, std::size_t n, BeaconMode mode,
		       std::uint16_t duration, const Mac *bssid, ByteView ssid,
		       FixedString<256U> &out) noexcept;

struct BeaconReport {
	std::uint8_t op_class{0U};
	std::uint8_t channel{0U};
	std::uint16_t duration{0U};
	std::uint8_t frame_info{0U};
	std::uint8_t rcpi{0U};
	std::uint8_t rsni{0U};
	Mac bssid{};
};

// Beacon Report body (from Operating Class on), given as hex.
std::optional<BeaconReport> bcn_rep_parse_hex(std::string_view hex) noexcept;

// A frame heard by an air monitor (radiotap monitor interface).
struct AirFrame {
	Mac ta{};      // transmitter: the STA
	int freq{0};   // MHz, 0 if radiotap carries no channel
	int signal{0}; // dBm
	bool probe{false};
};

// Radiotap + 802.11 header: a frame a STA sent towards an AP (data with
// ToDS and not FromDS, or a probe request) with a dBm signal and no bad FCS.
std::optional<AirFrame> radiotap_parse(ByteView buf) noexcept;

// Extended Capabilities bit 19 = BSS Transition.
bool ext_capab_has_btm(ByteView ext) noexcept;
// AKM suite selector as printed by hostapd ("00-0f-ac-4").
bool akm_is_ft(std::string_view akm) noexcept;

} // namespace rrm
} // namespace donghoa

#endif
