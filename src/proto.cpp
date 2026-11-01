// SPDX-License-Identifier: MIT
#include "proto.hpp"

#include "sha256.hpp"

namespace donghoa {
namespace arcp {

// Header layout (24 bytes, network byte order):
//   0 magic(2) 2 version(1) 3 type(1) 4 flags(1) 5 reserved(1)
//   6 msg_id(4) 10 boot_id(4) 14 origin(6) 20 body_len(2) 22 reserved(2)

namespace {

constexpr std::size_t kAuthTlvTotal = kTlvHdrLen + kAuthLen;

void put_mac(const ByteSpan &s, std::size_t off, const Mac &m) noexcept
{
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		s[off + i] = m.b[i];
	}
}

Mac get_mac(ByteView v, std::size_t off) noexcept
{
	Mac m;
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		m.b[i] = v[off + i];
	}
	return m;
}

std::uint8_t as_u8(std::int8_t v) noexcept
{
	return static_cast<std::uint8_t>(v);
}

std::int8_t as_s8(std::uint8_t v) noexcept
{
	return static_cast<std::int8_t>(v);
}

// Constant-time comparison of two equally long byte ranges.
bool ct_equal(ByteView a, ByteView b) noexcept
{
	std::uint32_t d = (a.size() == b.size()) ? 0U : 1U;
	for (std::size_t i = 0U; (i < a.size()) && (i < b.size()); i++) {
		d |= static_cast<std::uint32_t>(a[i] ^ b[i]);
	}
	return d == 0U;
}

} // namespace

bool operator==(const BssInfo &a, const BssInfo &b) noexcept
{
	return (a.bssid == b.bssid) && (a.freq == b.freq) && (a.op_class == b.op_class) &&
	       (a.channel == b.channel) && (a.band == b.band) && (a.bw == b.bw) &&
	       (a.phy_type == b.phy_type) && (a.caps == b.caps) && (a.mdid == b.mdid) &&
	       (a.bssid_info == b.bssid_info) && same_ess(a, b);
}

bool same_ess(const BssInfo &a, const BssInfo &b) noexcept
{
	return (a.ssid_len == b.ssid_len) && (a.ssid_len <= a.ssid.size()) &&
	       equal(a.ssid_view(), b.ssid_view());
}

// ---- encoding ----

void Message::begin(MsgType type, std::uint8_t flags, const Mac &origin, std::uint32_t boot_id,
		    std::uint32_t msg_id) noexcept
{
	const ByteSpan b = span_of(buf_);

	for (std::size_t i = 0U; i < kHdrLen; i++) {
		b[i] = 0U;
	}
	put_be16(b, 0U, kMagic);
	b[2U] = kVersion;
	b[3U] = raw(type);
	b[4U] = flags;
	put_be32(b, 6U, msg_id);
	put_be32(b, 10U, boot_id);
	put_mac(b, 14U, origin);
	len_ = kHdrLen;
	overflow_ = false;
}

std::size_t Message::room() const noexcept
{
	const std::size_t used = len_ + kAuthTlvTotal;
	return (used >= kMaxPayload) ? 0U : (kMaxPayload - used);
}

bool Message::put_tlv(Tlv t, ByteView value) noexcept
{
	bool ok = (value.size() + kTlvHdrLen) <= room();
	if (ok) {
		const ByteSpan b = span_of(buf_);
		b[len_] = raw(t);
		put_be16(b, len_ + 1U, static_cast<std::uint16_t>(value.size()));
		for (std::size_t i = 0U; i < value.size(); i++) {
			b[len_ + kTlvHdrLen + i] = value[i];
		}
		len_ += kTlvHdrLen + value.size();
	} else {
		overflow_ = true;
	}
	return ok;
}

bool Message::add(const ApInfo &v) noexcept
{
	std::array<std::uint8_t, 6U + 32U> b{};
	const std::size_t nl = (v.name.size() > 32U) ? 32U : v.name.size();
	const std::string_view name = v.name.view();

	put_be16(span_of(b), 0U, v.flags);
	put_be16(span_of(b), 2U, v.hello_ms);
	b[4U] = v.num_bss;
	b[5U] = static_cast<std::uint8_t>(nl);
	for (std::size_t i = 0U; i < nl; i++) {
		b[6U + i] = static_cast<std::uint8_t>(name[i]);
	}
	return put_tlv(Tlv::ap_info, view_of(b).first(6U + nl));
}

bool Message::add(const BssInfo &v) noexcept
{
	std::array<std::uint8_t, 22U + 32U> b{};
	const std::size_t sl = (v.ssid_len > 32U) ? 32U : v.ssid_len;
	const ByteSpan s = span_of(b);

	put_mac(s, 0U, v.bssid);
	put_be16(s, 6U, v.freq);
	b[8U] = v.op_class;
	b[9U] = v.channel;
	b[10U] = v.band;
	b[11U] = v.bw;
	b[12U] = v.phy_type;
	put_be16(s, 13U, v.caps);
	put_be16(s, 15U, v.mdid);
	put_be32(s, 17U, v.bssid_info);
	b[21U] = static_cast<std::uint8_t>(sl);
	for (std::size_t i = 0U; i < sl; i++) {
		b[22U + i] = v.ssid[i];
	}
	return put_tlv(Tlv::bss_info, view_of(b).first(22U + sl));
}

bool Message::add(const BssLoad &v) noexcept
{
	std::array<std::uint8_t, 14U> b{};
	const ByteSpan s = span_of(b);

	put_mac(s, 0U, v.bssid);
	put_be16(s, 6U, v.sta_count);
	put_be16(s, 8U, v.max_sta);
	b[10U] = v.util;
	b[11U] = as_u8(v.noise);
	b[12U] = as_u8(v.tx_power);
	b[13U] = v.flags;
	return put_tlv(Tlv::bss_load, view_of(b));
}

bool Message::add(const StaEntry &v) noexcept
{
	std::array<std::uint8_t, kStaEntryLen> b{};
	const ByteSpan s = span_of(b);

	put_mac(s, 0U, v.sta);
	put_mac(s, 6U, v.bssid);
	b[12U] = as_u8(v.rssi);
	b[13U] = v.flags;
	put_be32(s, 14U, v.connected_s);
	put_be32(s, 18U, v.inactive_ms);
	put_be16(s, 22U, v.tx_rate_mbps);
	put_be16(s, 24U, v.rx_rate_mbps);
	put_be32(s, 26U, v.tput_kbps);
	return put_tlv(Tlv::sta_entry, view_of(b));
}

bool Message::add(const RfInfo &v) noexcept
{
	std::array<std::uint8_t, 9U> b{};

	b[0U] = v.radio_id;
	put_be16(span_of(b), 1U, v.freq);
	b[3U] = v.op_class;
	b[4U] = v.channel;
	b[5U] = v.bw;
	b[6U] = v.util;
	b[7U] = as_u8(v.noise);
	b[8U] = as_u8(v.tx_power);
	return put_tlv(Tlv::rf_info, view_of(b));
}

bool Message::add(const StaEvent &v) noexcept
{
	std::array<std::uint8_t, 15U> b{};
	const ByteSpan s = span_of(b);

	put_mac(s, 0U, v.sta);
	put_mac(s, 6U, v.bssid);
	b[12U] = v.event;
	put_be16(s, 13U, v.reason);
	return put_tlv(Tlv::sta_event, view_of(b));
}

bool Message::add(const SteerReq &v) noexcept
{
	std::array<std::uint8_t, 26U> b{};
	const ByteSpan s = span_of(b);

	put_be32(s, 0U, v.txn);
	put_mac(s, 4U, v.sta);
	put_mac(s, 10U, v.src_bssid);
	put_mac(s, 16U, v.tgt_bssid);
	b[22U] = v.reason;
	b[23U] = v.rcpi;
	b[24U] = v.sta_flags;
	b[25U] = as_u8(v.cur_rssi);
	return put_tlv(Tlv::steer_req, view_of(b));
}

bool Message::add(const SteerResp &v) noexcept
{
	std::array<std::uint8_t, 7U> b{};

	put_be32(span_of(b), 0U, v.txn);
	b[4U] = v.status;
	put_be16(span_of(b), 5U, v.hold_ms);
	return put_tlv(Tlv::steer_resp, view_of(b));
}

bool Message::add(const SteerResult &v) noexcept
{
	std::array<std::uint8_t, 12U> b{};

	put_be32(span_of(b), 0U, v.txn);
	put_mac(span_of(b), 4U, v.sta);
	b[10U] = v.outcome;
	b[11U] = v.btm_status;
	return put_tlv(Tlv::steer_result, view_of(b));
}

bool Message::add(const StaMonitorReq &v) noexcept
{
	std::array<std::uint8_t, 14U> b{};
	const ByteSpan s = span_of(b);

	put_be32(s, 0U, v.txn);
	put_mac(s, 4U, v.sta);
	put_be16(s, 10U, v.duration_ms);
	b[12U] = v.op_class;
	b[13U] = v.channel;
	return put_tlv(Tlv::sta_monitor_req, view_of(b));
}

bool Message::add(const StaMonitorResult &v) noexcept
{
	std::array<std::uint8_t, 21U> b{};
	const ByteSpan s = span_of(b);

	put_be32(s, 0U, v.txn);
	put_mac(s, 4U, v.sta);
	put_mac(s, 10U, v.bssid);
	b[16U] = as_u8(v.rssi);
	put_be16(s, 17U, v.samples);
	put_be16(s, 19U, v.age_ms);
	return put_tlv(Tlv::sta_monitor_result, view_of(b));
}

bool Message::add_ack(std::uint32_t msg_id) noexcept
{
	std::array<std::uint8_t, 4U> b{};

	put_be32(span_of(b), 0U, msg_id);
	return put_tlv(Tlv::ack, view_of(b));
}

bool Message::finish(ByteView key) noexcept
{
	const ByteSpan b = span_of(buf_);
	bool ok = !overflow_;

	if (ok && !key.empty()) {
		b[4U] = static_cast<std::uint8_t>(b[4U] | kFlagAuth);
		put_be16(b, 20U, static_cast<std::uint16_t>((len_ - kHdrLen) + kAuthTlvTotal));
		const Digest mac = hmac_sha256(key, bytes());
		b[len_] = raw(Tlv::auth);
		put_be16(b, len_ + 1U, static_cast<std::uint16_t>(kAuthLen));
		for (std::size_t i = 0U; i < kAuthLen; i++) {
			b[len_ + kTlvHdrLen + i] = mac[i];
		}
		len_ += kAuthTlvTotal;
	} else if (ok) {
		put_be16(b, 20U, static_cast<std::uint16_t>(len_ - kHdrLen));
	} else {
		// overflowed: never sent
	}
	return ok;
}

// ---- decoding ----

std::optional<Header> parse_header(ByteView frame) noexcept
{
	std::optional<Header> r;

	if ((frame.size() >= kHdrLen) && (get_be16(frame, 0U) == kMagic) && (frame[2U] == kVersion)) {
		Header h;
		h.version = frame[2U];
		h.type = frame[3U];
		h.flags = frame[4U];
		h.msg_id = get_be32(frame, 6U);
		h.boot_id = get_be32(frame, 10U);
		h.origin = get_mac(frame, 14U);
		h.body_len = get_be16(frame, 20U);
		// Ethernet may pad short frames: only require the body to fit.
		if ((static_cast<std::size_t>(h.body_len) + kHdrLen) <= frame.size()) {
			r = h;
		}
	}
	return r;
}

bool verify(ByteView frame, const Header &h, ByteView key) noexcept
{
	const bool has_auth = (h.flags & kFlagAuth) != 0U;
	const std::size_t total = kHdrLen + h.body_len;
	bool ok = false;

	if (key.empty()) {
		// No key: a message claiming AUTH shows a misconfiguration.
		ok = !has_auth;
	} else if (has_auth && (h.body_len >= kAuthTlvTotal) && (total <= frame.size())) {
		const std::size_t t = total - kAuthTlvTotal;
		if ((frame[t] == raw(Tlv::auth)) && (get_be16(frame, t + 1U) == kAuthLen)) {
			const Digest mac = hmac_sha256(key, frame.first(t));
			ok = ct_equal(view_of(mac).first(kAuthLen), frame.sub(t + kTlvHdrLen, kAuthLen));
		}
	} else {
		// key configured but no valid AUTH TLV
	}
	return ok;
}

TlvReader::TlvReader(ByteView frame, const Header &h) noexcept
	: body_(frame.sub(kHdrLen, h.body_len))
{
}

bool TlvReader::next(std::uint8_t &type, ByteView &value) noexcept
{
	bool ok = false;

	if ((body_.size() - pos_) >= kTlvHdrLen) {
		const std::size_t l = get_be16(body_, pos_ + 1U);
		if ((body_.size() - pos_ - kTlvHdrLen) >= l) {
			type = body_[pos_];
			value = body_.sub(pos_ + kTlvHdrLen, l);
			pos_ += kTlvHdrLen + l;
			ok = true;
		}
	}
	return ok;
}

bool decode(ByteView v, ApInfo &o) noexcept
{
	bool ok = (v.size() >= 6U) && (v[5U] <= 32U) && (v.size() >= (6U + v[5U]));
	if (ok) {
		o.flags = get_be16(v, 0U);
		o.hello_ms = get_be16(v, 2U);
		o.num_bss = v[4U];
		o.name.clear();
		for (std::size_t i = 0U; i < v[5U]; i++) {
			(void)o.name.push_back(static_cast<char>(v[6U + i]));
		}
	}
	return ok;
}

bool decode(ByteView v, BssInfo &o) noexcept
{
	bool ok = (v.size() >= 22U) && (v[21U] <= 32U) && (v.size() >= (22U + v[21U]));
	if (ok) {
		o = BssInfo{};
		o.bssid = get_mac(v, 0U);
		o.freq = get_be16(v, 6U);
		o.op_class = v[8U];
		o.channel = v[9U];
		o.band = v[10U];
		o.bw = v[11U];
		o.phy_type = v[12U];
		o.caps = get_be16(v, 13U);
		o.mdid = get_be16(v, 15U);
		o.bssid_info = get_be32(v, 17U);
		o.ssid_len = v[21U];
		for (std::size_t i = 0U; i < o.ssid_len; i++) {
			o.ssid[i] = v[22U + i];
		}
	}
	return ok;
}

bool decode(ByteView v, BssLoad &o) noexcept
{
	bool ok = v.size() >= 14U;
	if (ok) {
		o.bssid = get_mac(v, 0U);
		o.sta_count = get_be16(v, 6U);
		o.max_sta = get_be16(v, 8U);
		o.util = v[10U];
		o.noise = as_s8(v[11U]);
		o.tx_power = as_s8(v[12U]);
		o.flags = v[13U];
	}
	return ok;
}

bool decode(ByteView v, StaEntry &o) noexcept
{
	bool ok = v.size() >= kStaEntryLen;
	if (ok) {
		o.sta = get_mac(v, 0U);
		o.bssid = get_mac(v, 6U);
		o.rssi = as_s8(v[12U]);
		o.flags = v[13U];
		o.connected_s = get_be32(v, 14U);
		o.inactive_ms = get_be32(v, 18U);
		o.tx_rate_mbps = get_be16(v, 22U);
		o.rx_rate_mbps = get_be16(v, 24U);
		o.tput_kbps = get_be32(v, 26U);
	}
	return ok;
}

bool decode(ByteView v, RfInfo &o) noexcept
{
	bool ok = v.size() >= 9U;
	if (ok) {
		o.radio_id = v[0U];
		o.freq = get_be16(v, 1U);
		o.op_class = v[3U];
		o.channel = v[4U];
		o.bw = v[5U];
		o.util = v[6U];
		o.noise = as_s8(v[7U]);
		o.tx_power = as_s8(v[8U]);
	}
	return ok;
}

bool decode(ByteView v, StaEvent &o) noexcept
{
	bool ok = v.size() >= 15U;
	if (ok) {
		o.sta = get_mac(v, 0U);
		o.bssid = get_mac(v, 6U);
		o.event = v[12U];
		o.reason = get_be16(v, 13U);
	}
	return ok;
}

bool decode(ByteView v, SteerReq &o) noexcept
{
	bool ok = v.size() >= 26U;
	if (ok) {
		o.txn = get_be32(v, 0U);
		o.sta = get_mac(v, 4U);
		o.src_bssid = get_mac(v, 10U);
		o.tgt_bssid = get_mac(v, 16U);
		o.reason = v[22U];
		o.rcpi = v[23U];
		o.sta_flags = v[24U];
		o.cur_rssi = as_s8(v[25U]);
	}
	return ok;
}

bool decode(ByteView v, SteerResp &o) noexcept
{
	bool ok = v.size() >= 7U;
	if (ok) {
		o.txn = get_be32(v, 0U);
		o.status = v[4U];
		o.hold_ms = get_be16(v, 5U);
	}
	return ok;
}

bool decode(ByteView v, SteerResult &o) noexcept
{
	bool ok = v.size() >= 12U;
	if (ok) {
		o.txn = get_be32(v, 0U);
		o.sta = get_mac(v, 4U);
		o.outcome = v[10U];
		o.btm_status = v[11U];
	}
	return ok;
}

bool decode(ByteView v, StaMonitorReq &o) noexcept
{
	bool ok = v.size() >= 14U;
	if (ok) {
		o.txn = get_be32(v, 0U);
		o.sta = get_mac(v, 4U);
		o.duration_ms = get_be16(v, 10U);
		o.op_class = v[12U];
		o.channel = v[13U];
	}
	return ok;
}

bool decode(ByteView v, StaMonitorResult &o) noexcept
{
	bool ok = v.size() >= 21U;
	if (ok) {
		o.txn = get_be32(v, 0U);
		o.sta = get_mac(v, 4U);
		o.bssid = get_mac(v, 10U);
		o.rssi = as_s8(v[16U]);
		o.samples = get_be16(v, 17U);
		o.age_ms = get_be16(v, 19U);
	}
	return ok;
}

bool decode_ack(ByteView v, std::uint32_t &msg_id) noexcept
{
	bool ok = v.size() >= 4U;
	if (ok) {
		msg_id = get_be32(v, 0U);
	}
	return ok;
}

std::string_view msg_name(std::uint8_t type) noexcept
{
	std::string_view n = "?";
	switch (type) {
	case raw(MsgType::hello): n = "HELLO"; break;
	case raw(MsgType::bss_status): n = "BSS_STATUS"; break;
	case raw(MsgType::sta_status): n = "STA_STATUS"; break;
	case raw(MsgType::rf_status): n = "RF_STATUS"; break;
	case raw(MsgType::sta_event): n = "STA_EVENT"; break;
	case raw(MsgType::steer_req): n = "STEER_REQ"; break;
	case raw(MsgType::steer_resp): n = "STEER_RESP"; break;
	case raw(MsgType::steer_result): n = "STEER_RESULT"; break;
	case raw(MsgType::sta_monitor_req): n = "STA_MONITOR_REQ"; break;
	case raw(MsgType::sta_monitor_report): n = "STA_MONITOR_REPORT"; break;
	case raw(MsgType::ack): n = "ACK"; break;
	case raw(MsgType::bye): n = "BYE"; break;
	default: break;
	}
	return n;
}

std::string_view tlv_name(std::uint8_t type) noexcept
{
	std::string_view n = "?";
	switch (type) {
	case raw(Tlv::ap_info): n = "AP_INFO"; break;
	case raw(Tlv::bss_info): n = "BSS_INFO"; break;
	case raw(Tlv::bss_load): n = "BSS_LOAD"; break;
	case raw(Tlv::sta_entry): n = "STA_ENTRY"; break;
	case raw(Tlv::rf_info): n = "RF_INFO"; break;
	case raw(Tlv::sta_event): n = "STA_EVENT"; break;
	case raw(Tlv::steer_req): n = "STEER_REQ"; break;
	case raw(Tlv::steer_resp): n = "STEER_RESP"; break;
	case raw(Tlv::steer_result): n = "STEER_RESULT"; break;
	case raw(Tlv::ack): n = "ACK"; break;
	case raw(Tlv::sta_monitor_req): n = "STA_MONITOR_REQ"; break;
	case raw(Tlv::sta_monitor_result): n = "STA_MONITOR_RESULT"; break;
	case raw(Tlv::auth): n = "AUTH"; break;
	default: break;
	}
	return n;
}

} // namespace arcp
} // namespace donghoa
