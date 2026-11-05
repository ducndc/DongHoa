// SPDX-License-Identifier: MIT
#include "survey.hpp"

#include <array>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>

#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::SURVEY};
constexpr std::size_t NL_HDR = 16U;   // struct nlmsghdr
constexpr std::size_t GENL_HDR = 4U;  // struct genlmsghdr
constexpr std::size_t ATTR_HDR = 4U;  // struct nlattr
constexpr int RECV_TIMEOUT_MS = 500;

constexpr std::size_t align4(std::size_t n) noexcept
{
	return (n + 3U) & ~static_cast<std::size_t>(3U);
}

// Netlink request built in host byte order (no struct casts).
class Request {
public:
	Request(std::uint16_t type, std::uint16_t flags, std::uint32_t seq, std::uint8_t cmd,
		std::uint8_t version) noexcept
	{
		const ByteSpan s = spanOf(mBuf);
		os::storeNe16(s, 4U, type);
		os::storeNe16(s, 6U, flags);
		os::storeNe32(s, 8U, seq);
		mBuf[NL_HDR] = cmd;
		mBuf[NL_HDR + 1U] = version;
		mLen = NL_HDR + GENL_HDR;
	}

	void attr(std::uint16_t type, ByteView data) noexcept
	{
		const std::size_t total = ATTR_HDR + data.size();
		if ((align4(mLen) + align4(total)) <= mBuf.size()) {
			const ByteSpan s = spanOf(mBuf);
			const std::size_t at = align4(mLen);
			os::storeNe16(s, at, static_cast<std::uint16_t>(total));
			os::storeNe16(s, at + 2U, type);
			for (std::size_t i = 0U; i < data.size(); i++) {
				mBuf[at + ATTR_HDR + i] = data[i];
			}
			mLen = at + align4(total);
		}
	}

	ByteView finish() noexcept
	{
		os::storeNe32(spanOf(mBuf), 0U, static_cast<std::uint32_t>(mLen));
		return viewOf(mBuf).first(mLen);
	}

private:
	std::array<std::uint8_t, 64U> mBuf{};
	std::size_t mLen{0U};
};

// Attribute of the given type inside attrs, or an empty view.
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
			// An attribute may legitimately be empty (a flag): mark found.
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

// Accepts this message only if it is the in-use survey entry for wantFreq.
// A single-link wiphy has at most one in-use entry, but a multi-link (MLO)
// wiphy marks every concurrently active link's channel in use in the same
// dump: without the frequency check, whichever entry a vif's ifindex is not
// actually on would win, giving every BSS on that wiphy the same reading.
void parseSurvey(ByteView msg, int wantFreq, SurveySample &out) noexcept
{
	const ByteView attrs = msg.sub(NL_HDR + GENL_HDR, msg.size() - (NL_HDR + GENL_HDR));
	const ByteView si = findAttr(attrs, static_cast<std::uint16_t>(NL80211_ATTR_SURVEY_INFO));

	if (si.empty() || !hasAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_IN_USE))) {
		return;
	}
	const ByteView f = findAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_FREQUENCY));
	if ((f.size() < 4U) || (static_cast<int>(os::loadNe32(f, 0U)) != wantFreq)) {
		return;
	}
	out = SurveySample{};
	out.valid = true;
	out.freq = wantFreq;
	const ByteView n = findAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_NOISE));
	if (n.size() >= 1U) {
		out.noise = static_cast<std::int8_t>(n[0U]);
	}
	const ByteView t = findAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_TIME));
	if (t.size() >= 8U) {
		out.activeMs = os::loadNe64(t, 0U);
	}
	const ByteView b = findAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_TIME_BUSY));
	if (b.size() >= 8U) {
		out.busyMs = os::loadNe64(b, 0U);
	}
}

} // namespace

bool Survey::open() noexcept
{
	std::array<std::uint8_t, 16384U> buf{};
	const std::array<std::uint8_t, 8U> name{{'n', 'l', '8', '0', '2', '1', '1', '\0'}};

	mFamily = 0U;
	mFd = os::openNetlink();
	mSeq++;
	Request r(static_cast<std::uint16_t>(GENL_ID_CTRL), static_cast<std::uint16_t>(NLM_F_REQUEST), mSeq,
		  static_cast<std::uint8_t>(CTRL_CMD_GETFAMILY), 1U);
	r.attr(static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_NAME), viewOf(name));
	bool ok = mFd.valid() && os::sendNetlink(mFd, r.finish());
	std::optional<std::size_t> n;
	if (ok) {
		n = os::recvNetlink(mFd, spanOf(buf), RECV_TIMEOUT_MS);
		ok = n.has_value() && (*n >= (NL_HDR + GENL_HDR));
	}
	if (ok) {
		const ByteView msg = viewOf(buf).first(*n);
		ok = os::loadNe16(msg, 4U) != static_cast<std::uint16_t>(NLMSG_ERROR);
		if (ok) {
			const std::size_t len = os::loadNe32(msg, 0U);
			const ByteView attrs = msg.sub(NL_HDR + GENL_HDR, ((len <= *n) ? len : *n) - (NL_HDR + GENL_HDR));
			const ByteView id = findAttr(attrs, static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_ID));
			ok = id.size() >= 2U;
			mFamily = ok ? os::loadNe16(id, 0U) : 0U;
		}
	}
	if (!ok) {
		logging::warn(LOG_MODULE, "nl80211 unavailable, channel utilisation from hostapd only");
		mFd.reset();
	}
	return ok;
}

bool Survey::get(int ifindex, int wantFreq, SurveySample &out) noexcept
{
	std::array<std::uint8_t, 16384U> buf{};
	std::array<std::uint8_t, 4U> idx{};
	bool ok = mFd.valid() && (mFamily != 0U);
	bool done = !ok;

	out.valid = false;
	if (ok) {
		mSeq++;
		os::storeNe32(spanOf(idx), 0U, static_cast<std::uint32_t>(ifindex));
		Request r(mFamily, static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_DUMP), mSeq,
			  static_cast<std::uint8_t>(NL80211_CMD_GET_SURVEY), 0U);
		r.attr(static_cast<std::uint16_t>(NL80211_ATTR_IFINDEX), viewOf(idx));
		ok = os::sendNetlink(mFd, r.finish());
		done = !ok;
	}
	while (!done) {
		const std::optional<std::size_t> n = os::recvNetlink(mFd, spanOf(buf), RECV_TIMEOUT_MS);
		if (!n.has_value()) {
			ok = false;
			done = true;
		}
		const ByteView all = viewOf(buf).first(n.has_value() ? *n : 0U);
		std::size_t off = 0U;
		while (!done && ((all.size() - off) >= NL_HDR)) {
			const std::size_t len = os::loadNe32(all, off);
			if ((len < NL_HDR) || (len > (all.size() - off))) {
				break;
			}
			const ByteView msg = all.sub(off, len);
			const std::uint16_t type = os::loadNe16(msg, 4U);
			if (os::loadNe32(msg, 8U) == mSeq) {
				if (type == static_cast<std::uint16_t>(NLMSG_DONE)) {
					ok = out.valid;
					done = true;
				} else if (type == static_cast<std::uint16_t>(NLMSG_ERROR)) {
					ok = false;
					done = true;
				} else {
					parseSurvey(msg, wantFreq, out);
				}
			}
			off += align4(len);
		}
	}
	return ok;
}

int Survey::util(const SurveySample &prev, const SurveySample &cur) noexcept
{
	int u = -1;
	if (prev.valid && cur.valid && (prev.freq == cur.freq) && (cur.activeMs > prev.activeMs) &&
	    (cur.busyMs >= prev.busyMs)) {
		const std::uint64_t da = cur.activeMs - prev.activeMs;
		std::uint64_t db = cur.busyMs - prev.busyMs;
		if (db > da) {
			db = da;
		}
		u = static_cast<int>((db * 255U) / da);
	}
	return u;
}

} // namespace donghoa
