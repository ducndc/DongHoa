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
constexpr std::uint32_t BI_REACHABLE = 0x00000003U;
constexpr std::uint32_t BI_SECURITY = 0x00000004U;
constexpr std::uint32_t BI_KEY_SCOPE = 0x00000008U;
constexpr std::uint32_t BI_QOS = 0x00000020U;
constexpr std::uint32_t BI_RRM = 0x00000080U;
constexpr std::uint32_t BI_IMM_BA = 0x00000200U;
constexpr std::uint32_t BI_MOBILITY_DOMAIN = 0x00000400U;
constexpr std::uint32_t BI_HT = 0x00000800U;
constexpr std::uint32_t BI_VHT = 0x00001000U;
constexpr std::uint32_t BI_HE = 0x00004000U;

// Condensed PHY type (dot11PHYType)
constexpr std::uint8_t PHY_OFDM = 4U;
constexpr std::uint8_t PHY_ERP = 6U;
constexpr std::uint8_t PHY_HT = 7U;
constexpr std::uint8_t PHY_VHT = 9U;
constexpr std::uint8_t PHY_HE = 14U;

// Beacon Request measurement modes
enum class BeaconMode : std::uint8_t { PASSIVE = 0U, ACTIVE = 1U, TABLE = 2U };
// A passive measurement must last a beacon interval (typically 100 TU).
constexpr std::uint16_t PASSIVE_MIN_TU = 120U;
constexpr std::size_t MAX_BEACON_CHANNELS = 8U;

std::string_view beaconModeName(BeaconMode m) noexcept;

struct ChanBand {
	std::uint8_t channel{0U};
	std::uint8_t band{0U};
};

std::optional<ChanBand> freqToChan(int freq) noexcept;
// Global operating class of the 20 MHz primary channel, 0 if unknown.
std::uint8_t opClass20mhz(std::uint8_t band, std::uint8_t chan) noexcept;
std::uint8_t phyTypeFromCaps(std::uint16_t caps, std::uint8_t band) noexcept;
std::uint32_t buildBssidInfo(std::uint16_t caps, bool secured) noexcept;

// RCPI <-> dBm (RCPI = 2 * (dBm + 110); 255 = not available)
int rcpiToDbm(std::uint8_t rcpi) noexcept;
std::uint8_t dbmToRcpi(int dbm) noexcept;

// Neighbor Report element body (no ID/length) as hex for hostapd
// SET_NEIGHBOR nr=. localMdid decides the Mobility Domain bit.
bool buildNrHex(const arcp::BssInfo &b, std::uint16_t localMdid, FixedString<64U> &out) noexcept;

struct OpChan {
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
};
using OpChanList = std::array<OpChan, MAX_BEACON_CHANNELS>;

// Beacon Request fields (from Operating Class on) as hex for REQ_BEACON.
// One channel: a plain request. Several: Channel 255 plus AP Channel Report
// subelements, so the STA measures all of them in one request (STAs handle
// one beacon measurement at a time). bssid may be null (wildcard).
bool buildBcnReqHex(const OpChanList &chans, std::size_t n, BeaconMode mode,
		       std::uint16_t duration, const Mac *bssid, ByteView ssid,
		       FixedString<256U> &out) noexcept;

struct BeaconReport {
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
	std::uint16_t duration{0U};
	std::uint8_t frameInfo{0U};
	std::uint8_t rcpi{0U};
	std::uint8_t rsni{0U};
	Mac bssid{};
};

// Beacon Report body (from Operating Class on), given as hex.
std::optional<BeaconReport> parseBcnRepHex(std::string_view hex) noexcept;

// ---- decoders for the 802.11k/v log (rrm_log.cpp) ----

// Beacon Request fields as REQ_BEACON carries them (the inverse of
// buildBcnReqHex). Unknown subelements are skipped.
struct BeaconRequest {
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U}; // 255: channels in AP Channel Reports
	std::uint16_t randInt{0U}; // TU
	std::uint16_t duration{0U}; // TU
	std::uint8_t mode{0U};      // BeaconMode
	Mac bssid{};
	std::array<std::uint8_t, 32U> ssid{};
	std::size_t ssidLen{0U};
	bool hasSsid{false};
	int detail{-1}; // Reporting Detail, -1 if absent
	OpChanList chans{}; // from AP Channel Report subelements
	std::size_t nChans{0U};
};

std::optional<BeaconRequest> parseBcnReqHex(std::string_view hex) noexcept;

// Neighbor Report element body (the inverse of buildNrHex).
struct NeighborReport {
	Mac bssid{};
	std::uint32_t bssidInfo{0U};
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
	std::uint8_t phyType{0U};
};

std::optional<NeighborReport> parseNrHex(std::string_view hex) noexcept;

// BSSID Information bits as text, e.g. "reach=3 sec key_scope md ht vht".
void describeBssidInfo(std::uint32_t bi, FixedString<96U> &out) noexcept;
// Measurement Report Mode octet: "ok", "late", "incapable" or "refused".
std::string_view reportModeName(std::uint8_t mode) noexcept;
// BTM Response status code (IEEE 802.11-2020 Table 9-428).
std::string_view btmStatusName(int status) noexcept;

// A frame heard by an air monitor (radiotap monitor interface).
struct AirFrame {
	Mac ta{};      // transmitter: the STA
	int freq{0};   // MHz, 0 if radiotap carries no channel
	int signal{0}; // dBm
	bool probe{false};
};

// Radiotap + 802.11 header: a frame a STA sent towards an AP (data with
// ToDS and not FromDS, or a probe request) with a dBm signal and no bad FCS.
std::optional<AirFrame> parseRadiotap(ByteView buf) noexcept;

// Extended Capabilities bit 19 = BSS Transition.
bool hasBtmCapab(ByteView ext) noexcept;
// AKM suite selector as printed by hostapd ("00-0f-ac-4").
bool isFtAkm(std::string_view akm) noexcept;
// AKM a STA cannot use on 6 GHz (WPA2-Personal: PSK, FT-PSK, PSK-SHA256).
// 6 GHz allows only SAE, OWE and 802.1X with PMF. A STA that chose such an
// AKM on a transition-mode BSS is taken not to support WPA3.
bool isAkmForbidden6g(std::string_view akm) noexcept;

// Bands a STA can use, as a bit mask: advertised in its Supported Operating
// Classes element, or seen in use. 0 = nothing known.
constexpr std::uint8_t BANDS_2G = 0x01U;
constexpr std::uint8_t BANDS_5G = 0x02U;
constexpr std::uint8_t BANDS_6G = 0x04U;

// arcp::BAND_* as a BANDS_* bit; 0 for an unknown band.
std::uint8_t bandBit(std::uint8_t band) noexcept;
// BANDS_* bit of a global operating class (Annex E, Table E-4); 0 if the
// class is not a 2.4/5/6 GHz one.
std::uint8_t opClassBandBit(std::uint8_t opClass) noexcept;
// Bands in a Supported Operating Classes element body (no ID/length, as
// hostapd prints it in supp_op_classes=): the Current Operating Class,
// then the supported classes up to the OneHundredAndThirty (130) or Zero
// delimiter. 130 is a delimiter there, not the 5 GHz 80+80 class.
std::uint8_t bandsFromOpClasses(ByteView body) noexcept;

} // namespace rrm
} // namespace donghoa

#endif
