// SPDX-License-Identifier: MIT
// Unit tests: nl80211 message parsing (src/core/nlparse).
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <linux/nl80211.h>

#include "unit.hpp"

#include "core/nlparse.hpp"

using namespace donghoa;

// nl80211 station dump entry (synthetic kernel message, host byte order)
namespace {

void putAttr(std::vector<std::uint8_t> &out, std::uint16_t type, const std::vector<std::uint8_t> &data)
{
	const std::size_t len = 4U + data.size();
	out.push_back(static_cast<std::uint8_t>(len & 0xffU));
	out.push_back(static_cast<std::uint8_t>(len >> 8U));
	out.push_back(static_cast<std::uint8_t>(type & 0xffU));
	out.push_back(static_cast<std::uint8_t>(type >> 8U));
	out.insert(out.end(), data.begin(), data.end());
	while ((out.size() % 4U) != 0U) {
		out.push_back(0U);
	}
}

std::vector<std::uint8_t> le(std::uint64_t v, std::size_t n)
{
	std::vector<std::uint8_t> r;
	for (std::size_t i = 0U; i < n; i++) {
		r.push_back(static_cast<std::uint8_t>((v >> (8U * i)) & 0xffU));
	}
	return r;
}

std::vector<std::uint8_t> nlMessage(const std::vector<std::uint8_t> &attrs)
{
	std::vector<std::uint8_t> m(20U, 0U); // nlmsghdr + genlmsghdr
	m.insert(m.end(), attrs.begin(), attrs.end());
	const std::vector<std::uint8_t> len = le(m.size(), 4U);
	for (std::size_t i = 0U; i < 4U; i++) {
		m[i] = len[i];
	}
	return m;
}

} // namespace

void testNlParse()
{
	std::vector<std::uint8_t> rate;
	putAttr(rate, NL80211_RATE_INFO_BITRATE32, le(8667U, 4U)); // 866.7 Mbit/s
	std::vector<std::uint8_t> rate16;
	putAttr(rate16, NL80211_RATE_INFO_BITRATE, le(540U, 2U)); // 54 Mbit/s, legacy u16
	const std::uint32_t auth = 1U << static_cast<unsigned>(NL80211_STA_FLAG_AUTHORIZED);
	std::vector<std::uint8_t> flags = le(auth, 4U);
	const std::vector<std::uint8_t> set = le(auth, 4U);
	flags.insert(flags.end(), set.begin(), set.end());
	std::vector<std::uint8_t> info;
	putAttr(info, NL80211_STA_INFO_INACTIVE_TIME, le(1170U, 4U));
	putAttr(info, NL80211_STA_INFO_RX_BYTES64, le(5000000000ULL, 8U)); // > 32 bits
	putAttr(info, NL80211_STA_INFO_TX_BYTES, le(1234U, 4U));            // only the u32 form
	putAttr(info, NL80211_STA_INFO_SIGNAL, le(static_cast<std::uint8_t>(-61), 1U));
	putAttr(info, NL80211_STA_INFO_SIGNAL_AVG, le(static_cast<std::uint8_t>(-58), 1U));
	putAttr(info, NL80211_STA_INFO_TX_BITRATE, rate);
	putAttr(info, NL80211_STA_INFO_RX_BITRATE, rate16);
	putAttr(info, NL80211_STA_INFO_CONNECTED_TIME, le(42U, 4U));
	putAttr(info, NL80211_STA_INFO_STA_FLAGS, flags);
	putAttr(info, 0x7ff0U, le(1U, 4U)); // unknown attribute from a newer kernel: skipped
	std::vector<std::uint8_t> attrs;
	putAttr(attrs, NL80211_ATTR_IFINDEX, le(7U, 4U));
	putAttr(attrs, NL80211_ATTR_MAC, {0x02U, 0x00U, 0x00U, 0x00U, 0x02U, 0x00U});
	putAttr(attrs, NL80211_ATTR_STA_INFO, info);
	const std::vector<std::uint8_t> msg = nlMessage(attrs);

	const std::optional<nl::Station> st = nl::parseStation(ByteView(msg.data(), msg.size()));
	CHECK(st.has_value());
	if (st.has_value()) {
		CHECK(st->addr == mac("02:00:00:00:02:00"));
		CHECK(st->authorized);
		CHECK((st->signal == -61) && (st->signalAvg == -58));
		CHECK(st->inactiveMs == 1170U);
		CHECK(st->rxBytes == 5000000000ULL);
		CHECK(st->txBytes == 1234U);
		CHECK((st->txRateMbps == 866U) && (st->rxRateMbps == 54U));
		CHECK(st->connectedS == 42U);
	}
	// not authorized: the flag is in the mask but not set
	std::vector<std::uint8_t> info2;
	std::vector<std::uint8_t> half = le(auth, 4U);
	const std::vector<std::uint8_t> zero = le(0U, 4U);
	half.insert(half.end(), zero.begin(), zero.end());
	putAttr(info2, NL80211_STA_INFO_STA_FLAGS, half);
	putAttr(info2, NL80211_STA_INFO_SIGNAL, le(static_cast<std::uint8_t>(-70), 1U));
	std::vector<std::uint8_t> attrs2;
	putAttr(attrs2, NL80211_ATTR_MAC, {0x02U, 0x00U, 0x00U, 0x00U, 0x02U, 0x01U});
	putAttr(attrs2, NL80211_ATTR_STA_INFO, info2);
	const std::vector<std::uint8_t> msg2 = nlMessage(attrs2);
	const std::optional<nl::Station> st2 = nl::parseStation(ByteView(msg2.data(), msg2.size()));
	CHECK(st2.has_value() && !st2->authorized && (st2->signalAvg == 0) && (st2->rxBytes == 0U));
	// no MAC or no STA_INFO: not a station entry; truncated: no crash
	std::vector<std::uint8_t> attrs3;
	putAttr(attrs3, NL80211_ATTR_STA_INFO, info);
	const std::vector<std::uint8_t> msg3 = nlMessage(attrs3);
	CHECK(!nl::parseStation(ByteView(msg3.data(), msg3.size())).has_value());
	for (std::size_t cut = 0U; cut < msg.size(); cut += 7U) {
		(void)nl::parseStation(ByteView(msg.data(), cut)); // must not read past the end
	}
	CHECK(!nl::parseStation(ByteView(msg.data(), 10U)).has_value());
}
