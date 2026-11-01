// SPDX-License-Identifier: MIT
// ARCP - AP Roaming Coordination Protocol: a custom Layer-2 protocol in
// Ethernet frames (no IP). docs/PROTOCOL.md describes the semantics; this
// header is the single source of truth for the numbers.
#ifndef DONGHOA_PROTO_HPP
#define DONGHOA_PROTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "types.hpp"

namespace donghoa {
namespace arcp {

// IEEE Std 802 "Local Experimental EtherType 1": replace for a product.
constexpr std::uint16_t kEthertype = 0x88B5U;
// Locally administered group address 03:41:52:43:50:00 ("ARCP").
constexpr Mac kGroupAddr{{0x03U, 0x41U, 0x52U, 0x43U, 0x50U, 0x00U}};
constexpr std::uint16_t kMagic = 0x4152U; // "AR"
constexpr std::uint8_t kVersion = 1U;
constexpr std::size_t kHdrLen = 24U;
// Header + TLVs; leaves room for VLAN/backhaul encapsulation in 1500 bytes.
constexpr std::size_t kMaxPayload = 1400U;
constexpr std::size_t kAuthLen = 16U;
constexpr std::size_t kTlvHdrLen = 3U;
constexpr std::size_t kStaEntryLen = 30U;

// Header flags
constexpr std::uint8_t kFlagAckReq = 0x01U;
constexpr std::uint8_t kFlagAuth = 0x02U;

enum class MsgType : std::uint8_t {
	hello = 0x01U,
	bss_status = 0x02U,
	sta_status = 0x03U,
	rf_status = 0x04U,
	sta_event = 0x05U,
	steer_req = 0x10U,
	steer_resp = 0x11U,
	steer_result = 0x12U,
	sta_monitor_req = 0x13U,
	sta_monitor_report = 0x14U,
	ack = 0x20U,
	bye = 0x21U,
};

enum class Tlv : std::uint8_t {
	ap_info = 0x01U,
	bss_info = 0x02U,
	bss_load = 0x03U,
	sta_entry = 0x04U,
	rf_info = 0x05U,
	sta_event = 0x06U,
	steer_req = 0x10U,
	steer_resp = 0x11U,
	steer_result = 0x12U,
	ack = 0x13U,
	sta_monitor_req = 0x14U,
	sta_monitor_result = 0x15U,
	auth = 0xFFU,
};

constexpr std::uint8_t raw(MsgType t) noexcept
{
	return static_cast<std::uint8_t>(t);
}

constexpr std::uint8_t raw(Tlv t) noexcept
{
	return static_cast<std::uint8_t>(t);
}

// AP flags (ApInfo::flags)
constexpr std::uint16_t kApFlagAirMonitor = 0x0001U;

// Band (BssInfo::band)
constexpr std::uint8_t kBand2g = 2U;
constexpr std::uint8_t kBand5g = 5U;
constexpr std::uint8_t kBand6g = 6U;

// Channel width code (BssInfo::bw)
constexpr std::uint8_t kBw20 = 0U;
constexpr std::uint8_t kBw40 = 1U;
constexpr std::uint8_t kBw80 = 2U;
constexpr std::uint8_t kBw160 = 3U;
constexpr std::uint8_t kBw320 = 4U;

// BSS capability bits (BssInfo::caps)
constexpr std::uint16_t kCapFt = 0x0001U;
constexpr std::uint16_t kCapBtm = 0x0002U;
constexpr std::uint16_t kCapRrmNr = 0x0004U;
constexpr std::uint16_t kCapRrmBcn = 0x0008U;
constexpr std::uint16_t kCapHt = 0x0010U;
constexpr std::uint16_t kCapVht = 0x0020U;
constexpr std::uint16_t kCapHe = 0x0040U;
constexpr std::uint16_t kCapEht = 0x0080U;
constexpr std::uint16_t kCapFtOverDs = 0x0100U;

// STA flag bits (StaEntry::flags, SteerReq::sta_flags)
constexpr std::uint8_t kStaF11k = 0x01U;
constexpr std::uint8_t kStaF11v = 0x02U;
constexpr std::uint8_t kStaF11r = 0x04U;
constexpr std::uint8_t kStaFIdle = 0x08U;
constexpr std::uint8_t kStaFSteering = 0x10U;

// BssLoad::flags
constexpr std::uint8_t kLoadAccepting = 0x01U;

enum class StaEventType : std::uint8_t { assoc = 1U, disassoc = 2U };

enum class SteerReason : std::uint8_t { rssi = 1U, load = 2U, band = 3U, manual = 4U };

enum class SteerStatus : std::uint8_t {
	accept = 0U,
	unknown_bss = 1U,
	capacity = 2U,
	load = 3U,
	busy = 4U,
	policy = 5U,
};

enum class SteerOutcome : std::uint8_t {
	success = 0U,
	btm_reject = 1U,
	btm_timeout = 2U,
	roam_timeout = 3U,
	wrong_target = 4U,
	aborted = 5U,
};

// ---- message contents (fields that are enums on the wire stay raw bytes,
// so values from newer peers pass through) ----

struct ApInfo {
	std::uint16_t flags{0U};
	std::uint16_t hello_ms{0U};
	std::uint8_t num_bss{0U};
	FixedString<32U> name{};
};

struct BssInfo {
	Mac bssid{};
	std::uint16_t freq{0U};
	std::uint8_t op_class{0U};
	std::uint8_t channel{0U};
	std::uint8_t band{0U};
	std::uint8_t bw{0U};
	std::uint8_t phy_type{0U};
	std::uint16_t caps{0U};
	std::uint16_t mdid{0U};
	std::uint32_t bssid_info{0U}; // 802.11 Neighbor Report BSSID Information
	std::uint8_t ssid_len{0U};
	std::array<std::uint8_t, 32U> ssid{};

	ByteView ssid_view() const noexcept { return ByteView(ssid.data(), ssid_len); }
};

// Field-wise equality; SSIDs compare up to ssid_len.
bool operator==(const BssInfo &a, const BssInfo &b) noexcept;
inline bool operator!=(const BssInfo &a, const BssInfo &b) noexcept
{
	return !(a == b);
}
// Same ESS: same SSID.
bool same_ess(const BssInfo &a, const BssInfo &b) noexcept;

struct BssLoad {
	Mac bssid{};
	std::uint16_t sta_count{0U};
	std::uint16_t max_sta{0U};
	std::uint8_t util{255U}; // 0..254 like the BSS Load element; 255 = unknown
	std::int8_t noise{0};
	std::int8_t tx_power{0};
	std::uint8_t flags{0U};
};

struct StaEntry {
	Mac sta{};
	Mac bssid{};
	std::int8_t rssi{0};
	std::uint8_t flags{0U};
	std::uint32_t connected_s{0U};
	std::uint32_t inactive_ms{0U};
	std::uint16_t tx_rate_mbps{0U};
	std::uint16_t rx_rate_mbps{0U};
	std::uint32_t tput_kbps{0U};
};

struct RfInfo {
	std::uint8_t radio_id{0U};
	std::uint16_t freq{0U};
	std::uint8_t op_class{0U};
	std::uint8_t channel{0U};
	std::uint8_t bw{0U};
	std::uint8_t util{0U};
	std::int8_t noise{0};
	std::int8_t tx_power{0};
};

struct StaEvent {
	Mac sta{};
	Mac bssid{};
	std::uint8_t event{0U}; // StaEventType
	std::uint16_t reason{0U};
};

struct SteerReq {
	std::uint32_t txn{0U};
	Mac sta{};
	Mac src_bssid{};
	Mac tgt_bssid{};
	std::uint8_t reason{0U}; // SteerReason
	std::uint8_t rcpi{255U}; // STA-measured RCPI of the target, 255 = n/a
	std::uint8_t sta_flags{0U};
	std::int8_t cur_rssi{0};
};

struct SteerResp {
	std::uint32_t txn{0U};
	std::uint8_t status{0U}; // SteerStatus
	std::uint16_t hold_ms{0U};
};

struct SteerResult {
	std::uint32_t txn{0U};
	Mac sta{};
	std::uint8_t outcome{0U}; // SteerOutcome
	std::uint8_t btm_status{0U};
};

// Ask a peer to measure a STA with its air monitors.
struct StaMonitorReq {
	std::uint32_t txn{0U};
	Mac sta{};
	std::uint16_t duration_ms{0U};
	std::uint8_t op_class{0U}; // channel the STA is on now (hint)
	std::uint8_t channel{0U};
};

// RSSI of a STA's frames as heard by one BSS's radio (uplink).
struct StaMonitorResult {
	std::uint32_t txn{0U};
	Mac sta{};
	Mac bssid{};
	std::int8_t rssi{0};
	std::uint16_t samples{0U};
	std::uint16_t age_ms{0U}; // since the last sample
};

// ---- encoding ----

class Message {
public:
	void begin(MsgType type, std::uint8_t flags, const Mac &origin, std::uint32_t boot_id,
		   std::uint32_t msg_id) noexcept;
	// Bytes still available for TLVs, keeping room for the AUTH TLV.
	std::size_t room() const noexcept;

	// Each returns false (and marks the message overflowed) when it does
	// not fit.
	bool add(const ApInfo &v) noexcept;
	bool add(const BssInfo &v) noexcept;
	bool add(const BssLoad &v) noexcept;
	bool add(const StaEntry &v) noexcept;
	bool add(const RfInfo &v) noexcept;
	bool add(const StaEvent &v) noexcept;
	bool add(const SteerReq &v) noexcept;
	bool add(const SteerResp &v) noexcept;
	bool add(const SteerResult &v) noexcept;
	bool add(const StaMonitorReq &v) noexcept;
	bool add(const StaMonitorResult &v) noexcept;
	bool add_ack(std::uint32_t msg_id) noexcept;

	// Sets the length and, with a non-empty key, appends the HMAC.
	// False if any TLV did not fit.
	bool finish(ByteView key) noexcept;

	ByteView bytes() const noexcept { return ByteView(buf_.data(), len_); }
	std::uint8_t type() const noexcept { return buf_[3U]; }
	std::uint8_t flags() const noexcept { return buf_[4U]; }
	std::uint32_t msg_id() const noexcept { return get_be32(view_of(buf_), 6U); }

private:
	bool put_tlv(Tlv t, ByteView value) noexcept;

	std::array<std::uint8_t, kMaxPayload> buf_{};
	std::size_t len_{0U};
	bool overflow_{false};
};

// ---- decoding ----

struct Header {
	std::uint8_t version{0U};
	std::uint8_t type{0U};
	std::uint8_t flags{0U};
	std::uint32_t msg_id{0U};
	std::uint32_t boot_id{0U};
	Mac origin{}; // AP identifier, independent of the egress interface
	std::uint16_t body_len{0U};
};

std::optional<Header> parse_header(ByteView frame) noexcept;
// True if authentication succeeds, or if no key is configured and the
// message carries no AUTH.
bool verify(ByteView frame, const Header &h, ByteView key) noexcept;

class TlvReader {
public:
	TlvReader(ByteView frame, const Header &h) noexcept;
	// True while a well-formed TLV is available.
	bool next(std::uint8_t &type, ByteView &value) noexcept;

private:
	ByteView body_;
	std::size_t pos_{0U};
};

// Decoders accept values longer than they understand (forward compatible).
bool decode(ByteView v, ApInfo &o) noexcept;
bool decode(ByteView v, BssInfo &o) noexcept;
bool decode(ByteView v, BssLoad &o) noexcept;
bool decode(ByteView v, StaEntry &o) noexcept;
bool decode(ByteView v, RfInfo &o) noexcept;
bool decode(ByteView v, StaEvent &o) noexcept;
bool decode(ByteView v, SteerReq &o) noexcept;
bool decode(ByteView v, SteerResp &o) noexcept;
bool decode(ByteView v, SteerResult &o) noexcept;
bool decode(ByteView v, StaMonitorReq &o) noexcept;
bool decode(ByteView v, StaMonitorResult &o) noexcept;
bool decode_ack(ByteView v, std::uint32_t &msg_id) noexcept;

std::string_view msg_name(std::uint8_t type) noexcept;
std::string_view tlv_name(std::uint8_t type) noexcept;

} // namespace arcp
} // namespace donghoa

#endif
