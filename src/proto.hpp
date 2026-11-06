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
constexpr std::uint16_t ETHERTYPE = 0x88B5U;
// Locally administered group address 03:41:52:43:50:00 ("ARCP").
constexpr Mac GROUP_ADDR{{0x03U, 0x41U, 0x52U, 0x43U, 0x50U, 0x00U}};
constexpr std::uint16_t MAGIC = 0x4152U; // "AR"
constexpr std::uint8_t VERSION = 1U;
constexpr std::size_t HDR_LEN = 24U;
// Header + TLVs; leaves room for VLAN/backhaul encapsulation in 1500 bytes.
constexpr std::size_t MAX_PAYLOAD = 1400U;
constexpr std::size_t AUTH_LEN = 16U;
constexpr std::size_t TLV_HDR_LEN = 3U;
constexpr std::size_t STA_ENTRY_LEN = 30U;

// Header flags
constexpr std::uint8_t FLAG_ACK_REQ = 0x01U;
constexpr std::uint8_t FLAG_AUTH = 0x02U;

enum class MsgType : std::uint8_t {
	HELLO = 0x01U,
	BSS_STATUS = 0x02U,
	STA_STATUS = 0x03U,
	RF_STATUS = 0x04U,
	STA_EVENT = 0x05U,
	STA_CLASS = 0x06U,
	STEER_REQ = 0x10U,
	STEER_RESP = 0x11U,
	STEER_RESULT = 0x12U,
	STA_MONITOR_REQ = 0x13U,
	STA_MONITOR_REPORT = 0x14U,
	ACK = 0x20U,
	BYE = 0x21U,
};

enum class Tlv : std::uint8_t {
	AP_INFO = 0x01U,
	BSS_INFO = 0x02U,
	BSS_LOAD = 0x03U,
	STA_ENTRY = 0x04U,
	RF_INFO = 0x05U,
	STA_EVENT = 0x06U,
	STA_CLASS = 0x07U,
	STEER_REQ = 0x10U,
	STEER_RESP = 0x11U,
	STEER_RESULT = 0x12U,
	ACK = 0x13U,
	STA_MONITOR_REQ = 0x14U,
	STA_MONITOR_RESULT = 0x15U,
	STA_MONITOR_STATUS = 0x16U,
	AUTH = 0xFFU,
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
constexpr std::uint16_t AP_FLAG_AIR_MONITOR = 0x0001U;

// Band (BssInfo::band)
constexpr std::uint8_t BAND_2G = 2U;
constexpr std::uint8_t BAND_5G = 5U;
constexpr std::uint8_t BAND_6G = 6U;

// Channel width code (BssInfo::bw)
constexpr std::uint8_t BW20 = 0U;
constexpr std::uint8_t BW40 = 1U;
constexpr std::uint8_t BW80 = 2U;
constexpr std::uint8_t BW160 = 3U;
constexpr std::uint8_t BW320 = 4U;

// BSS capability bits (BssInfo::caps)
constexpr std::uint16_t CAP_FT = 0x0001U;
constexpr std::uint16_t CAP_BTM = 0x0002U;
constexpr std::uint16_t CAP_RRM_NR = 0x0004U;
constexpr std::uint16_t CAP_RRM_BCN = 0x0008U;
constexpr std::uint16_t CAP_HT = 0x0010U;
constexpr std::uint16_t CAP_VHT = 0x0020U;
constexpr std::uint16_t CAP_HE = 0x0040U;
constexpr std::uint16_t CAP_EHT = 0x0080U;
constexpr std::uint16_t CAP_FT_OVER_DS = 0x0100U;

// STA flag bits (StaEntry::flags, SteerReq::staFlags)
constexpr std::uint8_t STA_F11K = 0x01U;
constexpr std::uint8_t STA_F11V = 0x02U;
constexpr std::uint8_t STA_F11R = 0x04U;
constexpr std::uint8_t STA_F_IDLE = 0x08U;
constexpr std::uint8_t STA_F_STEERING = 0x10U;
constexpr std::uint8_t STA_F_LOW_POWER = 0x20U; // classified low-power (IoT) device

// BssLoad::flags
constexpr std::uint8_t LOAD_ACCEPTING = 0x01U;

enum class StaEventType : std::uint8_t { ASSOC = 1U, DISASSOC = 2U };

enum class SteerReason : std::uint8_t { RSSI = 1U, LOAD = 2U, BAND = 3U, MANUAL = 4U };

enum class SteerStatus : std::uint8_t {
	ACCEPT = 0U,
	UNKNOWN_BSS = 1U,
	CAPACITY = 2U,
	LOAD = 3U,
	BUSY = 4U,
	POLICY = 5U,
};

enum class SteerOutcome : std::uint8_t {
	SUCCESS = 0U,
	BTM_REJECT = 1U,
	BTM_TIMEOUT = 2U,
	ROAM_TIMEOUT = 3U,
	WRONG_TARGET = 4U,
	ABORTED = 5U,
};

// ---- message contents (fields that are enums on the wire stay raw bytes,
// so values from newer peers pass through) ----

struct ApInfo {
	std::uint16_t flags{0U};
	std::uint16_t helloMs{0U};
	std::uint8_t numBss{0U};
	FixedString<32U> name{};
};

// BssInfo::linkId of a BSS that is not affiliated with an AP MLD.
constexpr std::uint8_t LINK_NONE = 255U;

struct BssInfo {
	Mac bssid{};
	std::uint16_t freq{0U};
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
	std::uint8_t band{0U};
	std::uint8_t bw{0U};
	std::uint8_t phyType{0U};
	std::uint16_t caps{0U};
	std::uint16_t mdid{0U};
	std::uint32_t bssidInfo{0U}; // 802.11 Neighbor Report BSSID Information
	std::uint8_t ssidLen{0U};
	std::array<std::uint8_t, 32U> ssid{};
	// Wi-Fi 7 MLO: the AP MLD this BSS is a link of (zero: none) and its
	// link ID. Optional trailing fields of BSS_INFO.
	Mac mldAddr{};
	std::uint8_t linkId{LINK_NONE};

	ByteView ssidView() const noexcept { return ByteView(ssid.data(), ssidLen); }
	bool isMldLink() const noexcept { return !mldAddr.isZero(); }
};

// Field-wise equality; SSIDs compare up to ssidLen.
bool operator==(const BssInfo &a, const BssInfo &b) noexcept;
inline bool operator!=(const BssInfo &a, const BssInfo &b) noexcept
{
	return !(a == b);
}
// Same ESS: same SSID.
bool isSameEss(const BssInfo &a, const BssInfo &b) noexcept;
// Links of one AP MLD: both affiliated, same MLD address.
bool isSameMld(const BssInfo &a, const BssInfo &b) noexcept;

struct BssLoad {
	Mac bssid{};
	std::uint16_t staCount{0U};
	std::uint16_t maxSta{0U};
	std::uint8_t util{255U}; // 0..254 like the BSS Load element; 255 = unknown
	std::int8_t noise{0};
	std::int8_t txPower{0};
	std::uint8_t flags{0U};
};

struct StaEntry {
	Mac sta{};
	Mac bssid{};
	std::int8_t rssi{0};
	std::uint8_t flags{0U};
	std::uint32_t connectedS{0U};
	std::uint32_t inactiveMs{0U};
	std::uint16_t txRateMbps{0U};
	std::uint16_t rxRateMbps{0U};
	std::uint32_t tputKbps{0U};
};

struct RfInfo {
	std::uint8_t radioId{0U};
	std::uint16_t freq{0U};
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
	std::uint8_t bw{0U};
	std::uint8_t util{0U};
	std::int8_t noise{0};
	std::int8_t txPower{0};
};

struct StaEvent {
	Mac sta{};
	Mac bssid{};
	std::uint8_t event{0U}; // StaEventType
	std::uint16_t reason{0U};
};

// Device class of a STA (behaviour-based low-power classification).
enum class DevClass : std::uint8_t { NORMAL = 0U, LOW_POWER = 1U };

struct StaClass {
	Mac sta{};
	std::uint8_t devClass{0U}; // DevClass
	std::int32_t score{0};      // classification score (theta)
	std::uint32_t samples{0U};  // traffic samples behind the score
};

struct SteerReq {
	std::uint32_t txn{0U};
	Mac sta{};
	Mac srcBssid{};
	Mac tgtBssid{};
	std::uint8_t reason{0U}; // SteerReason
	std::uint8_t rcpi{255U}; // STA-measured RCPI of the target, 255 = n/a
	std::uint8_t staFlags{0U};
	std::int8_t curRssi{0};
};

struct SteerResp {
	std::uint32_t txn{0U};
	std::uint8_t status{0U}; // SteerStatus
	std::uint16_t holdMs{0U};
};

struct SteerResult {
	std::uint32_t txn{0U};
	Mac sta{};
	std::uint8_t outcome{0U}; // SteerOutcome
	std::uint8_t btmStatus{0U};
};

// Ask a peer to measure a STA with its air monitors.
struct StaMonitorReq {
	std::uint32_t txn{0U};
	Mac sta{};
	std::uint16_t durationMs{0U};
	std::uint8_t opClass{0U}; // channel the STA is on now (hint)
	std::uint8_t channel{0U};
};

// RSSI of a STA's frames as heard by one BSS's radio (uplink).
struct StaMonitorResult {
	std::uint32_t txn{0U};
	Mac sta{};
	Mac bssid{};
	std::int8_t rssi{0};
	std::uint16_t samples{0U};
	std::uint16_t ageMs{0U}; // since the last sample
};

// Outcome of one STA_MONITOR_REQ at one AP. Every AP that receives the
// request answers with exactly one, so the source knows who has answered.
enum class MonitorStatus : std::uint8_t {
	MEASURED = 0U,    // STA_MONITOR_RESULTs follow in the same report
	NOT_HEARD = 1U,   // measured for duration_ms, no frame of the STA
	UNSUPPORTED = 2U, // no monitor interface and no driver RSSI API
	BUSY = 3U,        // watch table full
	FAILED = 4U,      // the driver API returned an error
};

struct StaMonitorStatus {
	std::uint32_t txn{0U};
	Mac sta{};
	std::uint8_t status{0U}; // MonitorStatus
};

// ---- encoding ----

class Message {
public:
	void begin(MsgType type, std::uint8_t flags, const Mac &origin, std::uint32_t bootId,
		   std::uint32_t msgId) noexcept;
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
	bool add(const StaClass &v) noexcept;
	bool add(const SteerReq &v) noexcept;
	bool add(const SteerResp &v) noexcept;
	bool add(const SteerResult &v) noexcept;
	bool add(const StaMonitorReq &v) noexcept;
	bool add(const StaMonitorResult &v) noexcept;
	bool add(const StaMonitorStatus &v) noexcept;
	bool addAck(std::uint32_t msgId) noexcept;

	// Sets the length and, with a non-empty key, appends the HMAC.
	// False if any TLV did not fit.
	bool finish(ByteView key) noexcept;

	ByteView bytes() const noexcept { return ByteView(mBuf.data(), mLen); }
	std::uint8_t type() const noexcept { return mBuf[3U]; }
	std::uint8_t flags() const noexcept { return mBuf[4U]; }
	std::uint32_t msgId() const noexcept { return getBe32(viewOf(mBuf), 6U); }

private:
	bool putTlv(Tlv t, ByteView value) noexcept;

	std::array<std::uint8_t, MAX_PAYLOAD> mBuf{};
	std::size_t mLen{0U};
	bool mOverflow{false};
};

// ---- decoding ----

struct Header {
	std::uint8_t version{0U};
	std::uint8_t type{0U};
	std::uint8_t flags{0U};
	std::uint32_t msgId{0U};
	std::uint32_t bootId{0U};
	Mac origin{}; // AP identifier, independent of the egress interface
	std::uint16_t bodyLen{0U};
};

std::optional<Header> parseHeader(ByteView frame) noexcept;
// True if authentication succeeds, or if no key is configured and the
// message carries no AUTH.
bool verify(ByteView frame, const Header &h, ByteView key) noexcept;

class TlvReader {
public:
	TlvReader(ByteView frame, const Header &h) noexcept;
	// True while a well-formed TLV is available.
	bool next(std::uint8_t &type, ByteView &value) noexcept;

private:
	ByteView mBody;
	std::size_t mPos{0U};
};

// Decoders accept values longer than they understand (forward compatible).
bool decode(ByteView v, ApInfo &o) noexcept;
bool decode(ByteView v, BssInfo &o) noexcept;
bool decode(ByteView v, BssLoad &o) noexcept;
bool decode(ByteView v, StaEntry &o) noexcept;
bool decode(ByteView v, RfInfo &o) noexcept;
bool decode(ByteView v, StaEvent &o) noexcept;
bool decode(ByteView v, StaClass &o) noexcept;
bool decode(ByteView v, SteerReq &o) noexcept;
bool decode(ByteView v, SteerResp &o) noexcept;
bool decode(ByteView v, SteerResult &o) noexcept;
bool decode(ByteView v, StaMonitorReq &o) noexcept;
bool decode(ByteView v, StaMonitorResult &o) noexcept;
bool decode(ByteView v, StaMonitorStatus &o) noexcept;
std::string_view monitorStatusName(std::uint8_t status) noexcept;
bool decodeAck(ByteView v, std::uint32_t &msgId) noexcept;

std::string_view msgName(std::uint8_t type) noexcept;
std::string_view tlvName(std::uint8_t type) noexcept;

} // namespace arcp
} // namespace donghoa

#endif
