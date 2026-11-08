// SPDX-License-Identifier: MIT
#include "nlparse.hpp"

#include <linux/netlink.h>
#include <linux/nl80211.h>

#include "os.hpp"

namespace donghoa {
namespace nl {

namespace {

constexpr std::uint16_t u16(int v) noexcept
{
	return static_cast<std::uint16_t>(v);
}

int toDbm(ByteView v) noexcept
{
	return (v.size() >= 1U) ? static_cast<int>(static_cast<std::int8_t>(v[0U])) : 0;
}

// NL80211_ATTR_STA_INFO's nested rate info -> Mbit/s (BITRATE32 or BITRATE
// in 100 kbit/s units).
std::uint16_t rateMbps(ByteView rate) noexcept
{
	std::uint32_t r100k = 0U;
	const ByteView b32 = findAttr(rate, u16(NL80211_RATE_INFO_BITRATE32));
	const ByteView b16 = findAttr(rate, u16(NL80211_RATE_INFO_BITRATE));
	if (b32.size() >= 4U) {
		r100k = os::loadNe32(b32, 0U);
	} else if (b16.size() >= 2U) {
		r100k = os::loadNe16(b16, 0U);
	} else {
		// no rate
	}
	const std::uint32_t mbps = r100k / 10U;
	return static_cast<std::uint16_t>((mbps > 0xffffU) ? 0xffffU : mbps);
}

std::uint64_t bytes(ByteView info, int attr64, int attr32) noexcept
{
	std::uint64_t r = 0U;
	const ByteView b64 = findAttr(info, u16(attr64));
	const ByteView b32 = findAttr(info, u16(attr32));
	if (b64.size() >= 8U) {
		r = os::loadNe64(b64, 0U);
	} else if (b32.size() >= 4U) {
		r = os::loadNe32(b32, 0U);
	} else {
		// absent
	}
	return r;
}

} // namespace

ByteView findAttr(ByteView attrs, std::uint16_t type) noexcept
{
	ByteView found;
	std::size_t off = 0U;
	bool more = true;

	while (more && ((attrs.size() - off) >= ATTR_HDR)) {
		const std::size_t len = os::loadNe16(attrs, off);
		const std::uint16_t t = static_cast<std::uint16_t>(os::loadNe16(attrs, off + 2U) &
								   static_cast<std::uint16_t>(NLA_TYPE_MASK));
		if ((len < ATTR_HDR) || (len > (attrs.size() - off))) {
			more = false;
		} else if (t == type) {
			found = attrs.sub(off + ATTR_HDR, len - ATTR_HDR);
			if (found.empty()) {
				found = attrs.sub(off, ATTR_HDR);
			}
			more = false;
		} else {
			off += align4(len);
			more = off < attrs.size();
		}
	}
	return found;
}

bool hasAttr(ByteView attrs, std::uint16_t type) noexcept
{
	return !findAttr(attrs, type).empty();
}

ByteView genlAttrs(ByteView msg) noexcept
{
	ByteView r;
	if (msg.size() >= (NL_HDR + GENL_HDR)) {
		const std::size_t len = os::loadNe32(msg, 0U);
		const std::size_t end = ((len <= msg.size()) &&
					 (len >= (NL_HDR + GENL_HDR))) ? len : msg.size();
		r = msg.sub(NL_HDR + GENL_HDR, end - (NL_HDR + GENL_HDR));
	}
	return r;
}

std::optional<Station> parseStation(ByteView msg) noexcept
{
	std::optional<Station> r;
	const ByteView attrs = genlAttrs(msg);
	const ByteView mac = findAttr(attrs, u16(NL80211_ATTR_MAC));
	const ByteView info = findAttr(attrs, u16(NL80211_ATTR_STA_INFO));

	if ((mac.size() >= 6U) && (info.size() > ATTR_HDR)) {
		Station s;
		for (std::size_t i = 0U; i < 6U; i++) {
			s.addr.b[i] = mac[i];
		}
		const ByteView fl = findAttr(info, u16(NL80211_STA_INFO_STA_FLAGS));
		if (fl.size() >= 8U) {
			// struct nl80211_sta_flag_update { u32 mask; u32 set; }
			const std::uint32_t bit = 1U << static_cast<unsigned>(NL80211_STA_FLAG_AUTHORIZED);
			const bool inMask = (os::loadNe32(fl, 0U) & bit) != 0U;
			const bool isSet = (os::loadNe32(fl, 4U) & bit) != 0U;
			s.authorized = inMask && isSet;
		}
		s.signal = toDbm(findAttr(info, u16(NL80211_STA_INFO_SIGNAL)));
		s.signalAvg = toDbm(findAttr(info, u16(NL80211_STA_INFO_SIGNAL_AVG)));
		const ByteView in = findAttr(info, u16(NL80211_STA_INFO_INACTIVE_TIME));
		s.inactiveMs = (in.size() >= 4U) ? os::loadNe32(in, 0U) : 0U;
		const ByteView ct = findAttr(info, u16(NL80211_STA_INFO_CONNECTED_TIME));
		s.connectedS = (ct.size() >= 4U) ? os::loadNe32(ct, 0U) : 0U;
		s.rxBytes = bytes(info, NL80211_STA_INFO_RX_BYTES64, NL80211_STA_INFO_RX_BYTES);
		s.txBytes = bytes(info, NL80211_STA_INFO_TX_BYTES64, NL80211_STA_INFO_TX_BYTES);
		s.rxRateMbps = rateMbps(findAttr(info, u16(NL80211_STA_INFO_RX_BITRATE)));
		s.txRateMbps = rateMbps(findAttr(info, u16(NL80211_STA_INFO_TX_BITRATE)));
		r = s;
	}
	return r;
}

} // namespace nl
} // namespace donghoa
