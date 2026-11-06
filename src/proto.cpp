// SPDX-License-Identifier: MIT
#include "proto.hpp"

#include "sha256.hpp"

namespace donghoa {
namespace arcp {

// Header layout (24 bytes, network byte order):
//   0 magic(2) 2 version(1) 3 type(1) 4 flags(1) 5 reserved(1)
//   6 msgId(4) 10 bootId(4) 14 origin(6) 20 bodyLen(2) 22 reserved(2)

namespace {

constexpr std::size_t AUTH_TLV_TOTAL = TLV_HDR_LEN + AUTH_LEN;

void putMac(const ByteSpan &s, std::size_t off, const Mac &m) noexcept
{
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		s[off + i] = m.b[i];
	}
}

Mac getMac(ByteView v, std::size_t off) noexcept
{
	Mac m;
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		m.b[i] = v[off + i];
	}
	return m;
}

std::uint8_t asU8(std::int8_t v) noexcept
{
	return static_cast<std::uint8_t>(v);
}

std::int8_t asS8(std::uint8_t v) noexcept
{
	return static_cast<std::int8_t>(v);
}

// Constant-time comparison of two equally long byte ranges.
bool ctEqual(ByteView a, ByteView b) noexcept
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
	return (a.bssid == b.bssid) && (a.freq == b.freq) && (a.opClass == b.opClass) &&
	       (a.channel == b.channel) && (a.band == b.band) && (a.bw == b.bw) &&
	       (a.phyType == b.phyType) && (a.caps == b.caps) && (a.mdid == b.mdid) &&
	       (a.bssidInfo == b.bssidInfo) && isSameEss(a, b) && (a.mldAddr == b.mldAddr) &&
	       (a.linkId == b.linkId);
}

bool isSameMld(const BssInfo &a, const BssInfo &b) noexcept
{
	return a.isMldLink() && b.isMldLink() && (a.mldAddr == b.mldAddr);
}

bool isSameEss(const BssInfo &a, const BssInfo &b) noexcept
{
	return (a.ssidLen == b.ssidLen) && (a.ssidLen <= a.ssid.size()) &&
	       equal(a.ssidView(), b.ssidView());
}

// ---- encoding ----

void Message::begin(MsgType type, std::uint8_t flags, const Mac &origin, std::uint32_t bootId,
		    std::uint32_t msgId) noexcept
{
	const ByteSpan b = spanOf(mBuf);

	for (std::size_t i = 0U; i < HDR_LEN; i++) {
		b[i] = 0U;
	}
	putBe16(b, 0U, MAGIC);
	b[2U] = VERSION;
	b[3U] = raw(type);
	b[4U] = flags;
	putBe32(b, 6U, msgId);
	putBe32(b, 10U, bootId);
	putMac(b, 14U, origin);
	mLen = HDR_LEN;
	mOverflow = false;
}

std::size_t Message::room() const noexcept
{
	const std::size_t used = mLen + AUTH_TLV_TOTAL;
	return (used >= MAX_PAYLOAD) ? 0U : (MAX_PAYLOAD - used);
}

bool Message::putTlv(Tlv t, ByteView value) noexcept
{
	bool ok = (value.size() + TLV_HDR_LEN) <= room();
	if (ok) {
		const ByteSpan b = spanOf(mBuf);
		b[mLen] = raw(t);
		putBe16(b, mLen + 1U, static_cast<std::uint16_t>(value.size()));
		for (std::size_t i = 0U; i < value.size(); i++) {
			b[mLen + TLV_HDR_LEN + i] = value[i];
		}
		mLen += TLV_HDR_LEN + value.size();
	} else {
		mOverflow = true;
	}
	return ok;
}

bool Message::add(const ApInfo &v) noexcept
{
	std::array<std::uint8_t, 6U + 32U> b{};
	const std::size_t nl = (v.name.size() > 32U) ? 32U : v.name.size();
	const std::string_view name = v.name.view();

	putBe16(spanOf(b), 0U, v.flags);
	putBe16(spanOf(b), 2U, v.helloMs);
	b[4U] = v.numBss;
	b[5U] = static_cast<std::uint8_t>(nl);
	for (std::size_t i = 0U; i < nl; i++) {
		b[6U + i] = static_cast<std::uint8_t>(name[i]);
	}
	return putTlv(Tlv::AP_INFO, viewOf(b).first(6U + nl));
}

bool Message::add(const BssInfo &v) noexcept
{
	std::array<std::uint8_t, 22U + 32U + 7U> b{};
	const std::size_t sl = (v.ssidLen > 32U) ? 32U : v.ssidLen;
	const ByteSpan s = spanOf(b);
	std::size_t n = 22U + sl;

	putMac(s, 0U, v.bssid);
	putBe16(s, 6U, v.freq);
	b[8U] = v.opClass;
	b[9U] = v.channel;
	b[10U] = v.band;
	b[11U] = v.bw;
	b[12U] = v.phyType;
	putBe16(s, 13U, v.caps);
	putBe16(s, 15U, v.mdid);
	putBe32(s, 17U, v.bssidInfo);
	b[21U] = static_cast<std::uint8_t>(sl);
	for (std::size_t i = 0U; i < sl; i++) {
		b[22U + i] = v.ssid[i];
	}
	// Optional MLO trailer, only for an AP MLD link: older peers ignore it.
	if (v.isMldLink()) {
		putMac(s, n, v.mldAddr);
		b[n + 6U] = v.linkId;
		n += 7U;
	}
	return putTlv(Tlv::BSS_INFO, viewOf(b).first(n));
}

bool Message::add(const BssLoad &v) noexcept
{
	std::array<std::uint8_t, 14U> b{};
	const ByteSpan s = spanOf(b);

	putMac(s, 0U, v.bssid);
	putBe16(s, 6U, v.staCount);
	putBe16(s, 8U, v.maxSta);
	b[10U] = v.util;
	b[11U] = asU8(v.noise);
	b[12U] = asU8(v.txPower);
	b[13U] = v.flags;
	return putTlv(Tlv::BSS_LOAD, viewOf(b));
}

bool Message::add(const StaEntry &v) noexcept
{
	std::array<std::uint8_t, STA_ENTRY_LEN> b{};
	const ByteSpan s = spanOf(b);

	putMac(s, 0U, v.sta);
	putMac(s, 6U, v.bssid);
	b[12U] = asU8(v.rssi);
	b[13U] = v.flags;
	putBe32(s, 14U, v.connectedS);
	putBe32(s, 18U, v.inactiveMs);
	putBe16(s, 22U, v.txRateMbps);
	putBe16(s, 24U, v.rxRateMbps);
	putBe32(s, 26U, v.tputKbps);
	return putTlv(Tlv::STA_ENTRY, viewOf(b));
}

bool Message::add(const RfInfo &v) noexcept
{
	std::array<std::uint8_t, 9U> b{};

	b[0U] = v.radioId;
	putBe16(spanOf(b), 1U, v.freq);
	b[3U] = v.opClass;
	b[4U] = v.channel;
	b[5U] = v.bw;
	b[6U] = v.util;
	b[7U] = asU8(v.noise);
	b[8U] = asU8(v.txPower);
	return putTlv(Tlv::RF_INFO, viewOf(b));
}

bool Message::add(const StaEvent &v) noexcept
{
	std::array<std::uint8_t, 15U> b{};
	const ByteSpan s = spanOf(b);

	putMac(s, 0U, v.sta);
	putMac(s, 6U, v.bssid);
	b[12U] = v.event;
	putBe16(s, 13U, v.reason);
	return putTlv(Tlv::STA_EVENT, viewOf(b));
}

bool Message::add(const SteerReq &v) noexcept
{
	std::array<std::uint8_t, 26U> b{};
	const ByteSpan s = spanOf(b);

	putBe32(s, 0U, v.txn);
	putMac(s, 4U, v.sta);
	putMac(s, 10U, v.srcBssid);
	putMac(s, 16U, v.tgtBssid);
	b[22U] = v.reason;
	b[23U] = v.rcpi;
	b[24U] = v.staFlags;
	b[25U] = asU8(v.curRssi);
	return putTlv(Tlv::STEER_REQ, viewOf(b));
}

bool Message::add(const SteerResp &v) noexcept
{
	std::array<std::uint8_t, 7U> b{};

	putBe32(spanOf(b), 0U, v.txn);
	b[4U] = v.status;
	putBe16(spanOf(b), 5U, v.holdMs);
	return putTlv(Tlv::STEER_RESP, viewOf(b));
}

bool Message::add(const SteerResult &v) noexcept
{
	std::array<std::uint8_t, 12U> b{};

	putBe32(spanOf(b), 0U, v.txn);
	putMac(spanOf(b), 4U, v.sta);
	b[10U] = v.outcome;
	b[11U] = v.btmStatus;
	return putTlv(Tlv::STEER_RESULT, viewOf(b));
}

bool Message::add(const StaMonitorReq &v) noexcept
{
	std::array<std::uint8_t, 14U> b{};
	const ByteSpan s = spanOf(b);

	putBe32(s, 0U, v.txn);
	putMac(s, 4U, v.sta);
	putBe16(s, 10U, v.durationMs);
	b[12U] = v.opClass;
	b[13U] = v.channel;
	return putTlv(Tlv::STA_MONITOR_REQ, viewOf(b));
}

bool Message::add(const StaMonitorResult &v) noexcept
{
	std::array<std::uint8_t, 21U> b{};
	const ByteSpan s = spanOf(b);

	putBe32(s, 0U, v.txn);
	putMac(s, 4U, v.sta);
	putMac(s, 10U, v.bssid);
	b[16U] = asU8(v.rssi);
	putBe16(s, 17U, v.samples);
	putBe16(s, 19U, v.ageMs);
	return putTlv(Tlv::STA_MONITOR_RESULT, viewOf(b));
}

bool Message::add(const StaMonitorStatus &v) noexcept
{
	std::array<std::uint8_t, 11U> b{};
	const ByteSpan s = spanOf(b);

	putBe32(s, 0U, v.txn);
	putMac(s, 4U, v.sta);
	b[10U] = v.status;
	return putTlv(Tlv::STA_MONITOR_STATUS, viewOf(b));
}

bool Message::add(const StaClass &v) noexcept
{
	std::array<std::uint8_t, 15U> b{};
	const ByteSpan s = spanOf(b);

	putMac(s, 0U, v.sta);
	b[6U] = v.devClass;
	putBe32(s, 7U, static_cast<std::uint32_t>(v.score));
	putBe32(s, 11U, v.samples);
	return putTlv(Tlv::STA_CLASS, viewOf(b));
}

bool Message::addAck(std::uint32_t msgId) noexcept
{
	std::array<std::uint8_t, 4U> b{};

	putBe32(spanOf(b), 0U, msgId);
	return putTlv(Tlv::ACK, viewOf(b));
}

bool Message::finish(ByteView key) noexcept
{
	const ByteSpan b = spanOf(mBuf);
	bool ok = !mOverflow;

	if (ok && !key.empty()) {
		b[4U] = static_cast<std::uint8_t>(b[4U] | FLAG_AUTH);
		putBe16(b, 20U, static_cast<std::uint16_t>((mLen - HDR_LEN) + AUTH_TLV_TOTAL));
		const Digest mac = computeHmacSha256(key, bytes());
		b[mLen] = raw(Tlv::AUTH);
		putBe16(b, mLen + 1U, static_cast<std::uint16_t>(AUTH_LEN));
		for (std::size_t i = 0U; i < AUTH_LEN; i++) {
			b[mLen + TLV_HDR_LEN + i] = mac[i];
		}
		mLen += AUTH_TLV_TOTAL;
	} else if (ok) {
		putBe16(b, 20U, static_cast<std::uint16_t>(mLen - HDR_LEN));
	} else {
		// overflowed: never sent
	}
	return ok;
}

// ---- decoding ----

std::optional<Header> parseHeader(ByteView frame) noexcept
{
	std::optional<Header> r;

	if ((frame.size() >= HDR_LEN) && (getBe16(frame, 0U) == MAGIC) && (frame[2U] == VERSION)) {
		Header h;
		h.version = frame[2U];
		h.type = frame[3U];
		h.flags = frame[4U];
		h.msgId = getBe32(frame, 6U);
		h.bootId = getBe32(frame, 10U);
		h.origin = getMac(frame, 14U);
		h.bodyLen = getBe16(frame, 20U);
		// Ethernet may pad short frames: only require the body to fit.
		if ((static_cast<std::size_t>(h.bodyLen) + HDR_LEN) <= frame.size()) {
			r = h;
		}
	}
	return r;
}

bool verify(ByteView frame, const Header &h, ByteView key) noexcept
{
	const bool hasAuth = (h.flags & FLAG_AUTH) != 0U;
	const std::size_t total = HDR_LEN + h.bodyLen;
	bool ok = false;

	if (key.empty()) {
		// No key: a message claiming AUTH shows a misconfiguration.
		ok = !hasAuth;
	} else if (hasAuth && (h.bodyLen >= AUTH_TLV_TOTAL) && (total <= frame.size())) {
		const std::size_t t = total - AUTH_TLV_TOTAL;
		if ((frame[t] == raw(Tlv::AUTH)) && (getBe16(frame, t + 1U) == AUTH_LEN)) {
			const Digest mac = computeHmacSha256(key, frame.first(t));
			ok = ctEqual(viewOf(mac).first(AUTH_LEN), frame.sub(t + TLV_HDR_LEN, AUTH_LEN));
		}
	} else {
		// key configured but no valid AUTH TLV
	}
	return ok;
}

TlvReader::TlvReader(ByteView frame, const Header &h) noexcept
	: mBody(frame.sub(HDR_LEN, h.bodyLen))
{
}

bool TlvReader::next(std::uint8_t &type, ByteView &value) noexcept
{
	bool ok = false;

	if ((mBody.size() - mPos) >= TLV_HDR_LEN) {
		const std::size_t l = getBe16(mBody, mPos + 1U);
		if ((mBody.size() - mPos - TLV_HDR_LEN) >= l) {
			type = mBody[mPos];
			value = mBody.sub(mPos + TLV_HDR_LEN, l);
			mPos += TLV_HDR_LEN + l;
			ok = true;
		}
	}
	return ok;
}

bool decode(ByteView v, ApInfo &o) noexcept
{
	bool ok = (v.size() >= 6U) && (v[5U] <= 32U) && (v.size() >= (6U + v[5U]));
	if (ok) {
		o.flags = getBe16(v, 0U);
		o.helloMs = getBe16(v, 2U);
		o.numBss = v[4U];
		o.name.clear();
		for (std::size_t i = 0U; i < v[5U]; i++) {
			(void)o.name.pushBack(static_cast<char>(v[6U + i]));
		}
	}
	return ok;
}

bool decode(ByteView v, BssInfo &o) noexcept
{
	bool ok = (v.size() >= 22U) && (v[21U] <= 32U) && (v.size() >= (22U + v[21U]));
	if (ok) {
		o = BssInfo{};
		o.bssid = getMac(v, 0U);
		o.freq = getBe16(v, 6U);
		o.opClass = v[8U];
		o.channel = v[9U];
		o.band = v[10U];
		o.bw = v[11U];
		o.phyType = v[12U];
		o.caps = getBe16(v, 13U);
		o.mdid = getBe16(v, 15U);
		o.bssidInfo = getBe32(v, 17U);
		o.ssidLen = v[21U];
		for (std::size_t i = 0U; i < o.ssidLen; i++) {
			o.ssid[i] = v[22U + i];
		}
		const std::size_t mld = 22U + o.ssidLen;
		if (v.size() >= (mld + 7U)) {
			o.mldAddr = getMac(v, mld);
			o.linkId = v[mld + 6U];
		}
	}
	return ok;
}

bool decode(ByteView v, BssLoad &o) noexcept
{
	bool ok = v.size() >= 14U;
	if (ok) {
		o.bssid = getMac(v, 0U);
		o.staCount = getBe16(v, 6U);
		o.maxSta = getBe16(v, 8U);
		o.util = v[10U];
		o.noise = asS8(v[11U]);
		o.txPower = asS8(v[12U]);
		o.flags = v[13U];
	}
	return ok;
}

bool decode(ByteView v, StaEntry &o) noexcept
{
	bool ok = v.size() >= STA_ENTRY_LEN;
	if (ok) {
		o.sta = getMac(v, 0U);
		o.bssid = getMac(v, 6U);
		o.rssi = asS8(v[12U]);
		o.flags = v[13U];
		o.connectedS = getBe32(v, 14U);
		o.inactiveMs = getBe32(v, 18U);
		o.txRateMbps = getBe16(v, 22U);
		o.rxRateMbps = getBe16(v, 24U);
		o.tputKbps = getBe32(v, 26U);
	}
	return ok;
}

bool decode(ByteView v, RfInfo &o) noexcept
{
	bool ok = v.size() >= 9U;
	if (ok) {
		o.radioId = v[0U];
		o.freq = getBe16(v, 1U);
		o.opClass = v[3U];
		o.channel = v[4U];
		o.bw = v[5U];
		o.util = v[6U];
		o.noise = asS8(v[7U]);
		o.txPower = asS8(v[8U]);
	}
	return ok;
}

bool decode(ByteView v, StaEvent &o) noexcept
{
	bool ok = v.size() >= 15U;
	if (ok) {
		o.sta = getMac(v, 0U);
		o.bssid = getMac(v, 6U);
		o.event = v[12U];
		o.reason = getBe16(v, 13U);
	}
	return ok;
}

bool decode(ByteView v, SteerReq &o) noexcept
{
	bool ok = v.size() >= 26U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.sta = getMac(v, 4U);
		o.srcBssid = getMac(v, 10U);
		o.tgtBssid = getMac(v, 16U);
		o.reason = v[22U];
		o.rcpi = v[23U];
		o.staFlags = v[24U];
		o.curRssi = asS8(v[25U]);
	}
	return ok;
}

bool decode(ByteView v, SteerResp &o) noexcept
{
	bool ok = v.size() >= 7U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.status = v[4U];
		o.holdMs = getBe16(v, 5U);
	}
	return ok;
}

bool decode(ByteView v, SteerResult &o) noexcept
{
	bool ok = v.size() >= 12U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.sta = getMac(v, 4U);
		o.outcome = v[10U];
		o.btmStatus = v[11U];
	}
	return ok;
}

bool decode(ByteView v, StaMonitorReq &o) noexcept
{
	bool ok = v.size() >= 14U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.sta = getMac(v, 4U);
		o.durationMs = getBe16(v, 10U);
		o.opClass = v[12U];
		o.channel = v[13U];
	}
	return ok;
}

bool decode(ByteView v, StaMonitorResult &o) noexcept
{
	bool ok = v.size() >= 21U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.sta = getMac(v, 4U);
		o.bssid = getMac(v, 10U);
		o.rssi = asS8(v[16U]);
		o.samples = getBe16(v, 17U);
		o.ageMs = getBe16(v, 19U);
	}
	return ok;
}

bool decode(ByteView v, StaMonitorStatus &o) noexcept
{
	bool ok = v.size() >= 11U;
	if (ok) {
		o.txn = getBe32(v, 0U);
		o.sta = getMac(v, 4U);
		o.status = v[10U];
	}
	return ok;
}

std::string_view monitorStatusName(std::uint8_t status) noexcept
{
	std::string_view n = "?";
	switch (status) {
	case static_cast<std::uint8_t>(MonitorStatus::MEASURED): n = "measured"; break;
	case static_cast<std::uint8_t>(MonitorStatus::NOT_HEARD): n = "not heard"; break;
	case static_cast<std::uint8_t>(MonitorStatus::UNSUPPORTED): n = "unsupported"; break;
	case static_cast<std::uint8_t>(MonitorStatus::BUSY): n = "busy"; break;
	case static_cast<std::uint8_t>(MonitorStatus::FAILED): n = "failed"; break;
	default: break;
	}
	return n;
}

bool decode(ByteView v, StaClass &o) noexcept
{
	bool ok = v.size() >= 15U;
	if (ok) {
		o.sta = getMac(v, 0U);
		o.devClass = v[6U];
		o.score = static_cast<std::int32_t>(getBe32(v, 7U));
		o.samples = getBe32(v, 11U);
	}
	return ok;
}

bool decodeAck(ByteView v, std::uint32_t &msgId) noexcept
{
	bool ok = v.size() >= 4U;
	if (ok) {
		msgId = getBe32(v, 0U);
	}
	return ok;
}

std::string_view msgName(std::uint8_t type) noexcept
{
	std::string_view n = "?";
	switch (type) {
	case raw(MsgType::HELLO): n = "HELLO"; break;
	case raw(MsgType::BSS_STATUS): n = "BSS_STATUS"; break;
	case raw(MsgType::STA_STATUS): n = "STA_STATUS"; break;
	case raw(MsgType::RF_STATUS): n = "RF_STATUS"; break;
	case raw(MsgType::STA_EVENT): n = "STA_EVENT"; break;
	case raw(MsgType::STA_CLASS): n = "STA_CLASS"; break;
	case raw(MsgType::STEER_REQ): n = "STEER_REQ"; break;
	case raw(MsgType::STEER_RESP): n = "STEER_RESP"; break;
	case raw(MsgType::STEER_RESULT): n = "STEER_RESULT"; break;
	case raw(MsgType::STA_MONITOR_REQ): n = "STA_MONITOR_REQ"; break;
	case raw(MsgType::STA_MONITOR_REPORT): n = "STA_MONITOR_REPORT"; break;
	case raw(MsgType::ACK): n = "ACK"; break;
	case raw(MsgType::BYE): n = "BYE"; break;
	default: break;
	}
	return n;
}

std::string_view tlvName(std::uint8_t type) noexcept
{
	std::string_view n = "?";
	switch (type) {
	case raw(Tlv::AP_INFO): n = "AP_INFO"; break;
	case raw(Tlv::BSS_INFO): n = "BSS_INFO"; break;
	case raw(Tlv::BSS_LOAD): n = "BSS_LOAD"; break;
	case raw(Tlv::STA_ENTRY): n = "STA_ENTRY"; break;
	case raw(Tlv::RF_INFO): n = "RF_INFO"; break;
	case raw(Tlv::STA_EVENT): n = "STA_EVENT"; break;
	case raw(Tlv::STA_CLASS): n = "STA_CLASS"; break;
	case raw(Tlv::STEER_REQ): n = "STEER_REQ"; break;
	case raw(Tlv::STEER_RESP): n = "STEER_RESP"; break;
	case raw(Tlv::STEER_RESULT): n = "STEER_RESULT"; break;
	case raw(Tlv::ACK): n = "ACK"; break;
	case raw(Tlv::STA_MONITOR_REQ): n = "STA_MONITOR_REQ"; break;
	case raw(Tlv::STA_MONITOR_RESULT): n = "STA_MONITOR_RESULT"; break;
	case raw(Tlv::STA_MONITOR_STATUS): n = "STA_MONITOR_STATUS"; break;
	case raw(Tlv::AUTH): n = "AUTH"; break;
	default: break;
	}
	return n;
}

} // namespace arcp
} // namespace donghoa
