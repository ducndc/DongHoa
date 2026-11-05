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

// The in-use survey entry carried by msg, if it is one. A single-link
// wiphy has at most one in-use entry; a multi-link (MLO) wiphy marks every
// concurrently active link's channel in use in the same dump, so all of
// them are kept and find() picks one by frequency.
std::optional<SurveySample> parseInUse(ByteView msg) noexcept
{
	std::optional<SurveySample> r;
	const ByteView attrs = msg.sub(NL_HDR + GENL_HDR, msg.size() - (NL_HDR + GENL_HDR));
	const ByteView si = findAttr(attrs, static_cast<std::uint16_t>(NL80211_ATTR_SURVEY_INFO));
	const ByteView f = findAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_FREQUENCY));

	if (!si.empty() && hasAttr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_IN_USE)) && (f.size() >= 4U)) {
		SurveySample out;
		out.valid = true;
		out.freq = static_cast<int>(os::loadNe32(f, 0U));
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
		r = out;
	}
	return r;
}

// ID of the nl80211 generic-netlink family, asked on fd.
std::uint16_t askFamily(const os::Fd &fd, std::uint32_t seq) noexcept
{
	std::array<std::uint8_t, 4096U> buf{};
	const std::array<std::uint8_t, 8U> name{{'n', 'l', '8', '0', '2', '1', '1', '\0'}};
	std::uint16_t family = 0U;

	Request r(static_cast<std::uint16_t>(GENL_ID_CTRL), static_cast<std::uint16_t>(NLM_F_REQUEST), seq,
		  static_cast<std::uint8_t>(CTRL_CMD_GETFAMILY), 1U);
	r.attr(static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_NAME), viewOf(name));
	const std::optional<std::size_t> n =
		(fd.valid() && os::sendNetlink(fd, r.finish())) ? os::recvNetlink(fd, spanOf(buf), RECV_TIMEOUT_MS)
								 : std::optional<std::size_t>();
	if (n.has_value() && (*n >= (NL_HDR + GENL_HDR))) {
		const ByteView msg = viewOf(buf).first(*n);
		if (os::loadNe16(msg, 4U) != static_cast<std::uint16_t>(NLMSG_ERROR)) {
			const std::size_t len = os::loadNe32(msg, 0U);
			const ByteView attrs =
				msg.sub(NL_HDR + GENL_HDR, ((len <= *n) ? len : *n) - (NL_HDR + GENL_HDR));
			const ByteView id = findAttr(attrs, static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_ID));
			family = (id.size() >= 2U) ? os::loadNe16(id, 0U) : static_cast<std::uint16_t>(0U);
		}
	}
	return family;
}

} // namespace

bool Survey::resolveFamily() noexcept
{
	mFd = os::openNetlink();
	mSeq++;
	mFamily = askFamily(mFd, mSeq);
	if (mFamily == 0U) {
		mFd.reset();
	}
	return mFamily != 0U;
}

bool Survey::open() noexcept
{
	const bool ok = resolveFamily();
	if (!ok) {
		logging::warn(LOG_MODULE, "nl80211 unavailable, channel utilisation from hostapd only");
	}
	return ok;
}

std::optional<std::uint32_t> Survey::findWiphy(int ifindex) noexcept
{
	std::array<std::uint8_t, 8192U> buf{};
	std::array<std::uint8_t, 4U> idx{};
	std::optional<std::uint32_t> wiphy;
	const os::Fd fd = (isOpen() && (ifindex > 0)) ? os::openNetlink() : os::Fd{};

	if (fd.valid()) {
		// Own socket, own sequence: mSeq belongs to the dump in flight,
		// whose replies would otherwise look stale and be dropped.
		constexpr std::uint32_t seq = 1U;
		os::storeNe32(spanOf(idx), 0U, static_cast<std::uint32_t>(ifindex));
		Request r(mFamily, static_cast<std::uint16_t>(NLM_F_REQUEST), seq,
			  static_cast<std::uint8_t>(NL80211_CMD_GET_INTERFACE), 0U);
		r.attr(static_cast<std::uint16_t>(NL80211_ATTR_IFINDEX), viewOf(idx));
		const std::optional<std::size_t> n = os::sendNetlink(fd, r.finish())
							     ? os::recvNetlink(fd, spanOf(buf), RECV_TIMEOUT_MS)
							     : std::optional<std::size_t>();
		const ByteView msg = viewOf(buf).first(n.has_value() ? *n : 0U);
		if ((msg.size() >= (NL_HDR + GENL_HDR)) && (os::loadNe32(msg, 8U) == seq) &&
		    (os::loadNe16(msg, 4U) == mFamily)) {
			const std::size_t len = os::loadNe32(msg, 0U);
			const ByteView attrs = msg.sub(NL_HDR + GENL_HDR,
						       ((len <= msg.size()) ? len : msg.size()) - (NL_HDR + GENL_HDR));
			const ByteView w = findAttr(attrs, static_cast<std::uint16_t>(NL80211_ATTR_WIPHY));
			if (w.size() >= 4U) {
				wiphy = os::loadNe32(w, 0U);
			}
		}
	}
	return wiphy;
}

void Survey::request(std::uint32_t wiphy, int ifindex) noexcept
{
	Radio *r = nullptr;
	Radio *spare = nullptr;

	if (!isOpen() || (ifindex <= 0)) {
		return;
	}
	for (Radio &x : mRadio) {
		if (x.used && (x.wiphy == wiphy)) {
			r = &x;
		} else if ((spare == nullptr) && !x.used) {
			spare = &x;
		} else {
			// another wiphy, or a later free slot
		}
	}
	if ((r == nullptr) && (spare != nullptr)) {
		r = spare;
		*r = Radio{};
		r->used = true;
		r->wiphy = wiphy;
		mStats.radios++;
	}
	if (r == nullptr) {
		return; // more wiphys than slots
	}
	r->ifindex = ifindex;
	const bool inFlight = mInFlight.has_value() && (&mRadio[*mInFlight] == r);
	if (!inFlight) {
		r->queued = true;
	}
	if (!mInFlight.has_value()) {
		sendNext();
	}
}

void Survey::sendNext() noexcept
{
	for (std::size_t i = 0U; (i < mRadio.size()) && !mInFlight.has_value(); i++) {
		Radio &r = mRadio[i];
		if (!(r.used && r.queued)) {
			continue;
		}
		r.queued = false;
		r.nNext = 0U;
		std::array<std::uint8_t, 4U> idx{};
		mSeq++;
		os::storeNe32(spanOf(idx), 0U, static_cast<std::uint32_t>(r.ifindex));
		Request q(mFamily, static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_DUMP), mSeq,
			  static_cast<std::uint8_t>(NL80211_CMD_GET_SURVEY), 0U);
		q.attr(static_cast<std::uint16_t>(NL80211_ATTR_IFINDEX), viewOf(idx));
		// The kernel fills the first part of the dump (driver calls
		// included) inside this sendto().
		const std::uint64_t t0 = os::nowUs();
		const bool sent = os::sendNetlink(mFd, q.finish());
		mBlockedUs = os::nowUs() - t0;
		if (sent) {
			mInFlight = i;
			mDeadline = os::nowMs() + DUMP_TIMEOUT_MS;
		} else {
			mStats.errors++;
			logging::dbg(LOG_MODULE, "wiphy {}: survey request not sent: {}", r.wiphy, os::lastError());
		}
	}
}

void Survey::finish(bool ok) noexcept
{
	if (!mInFlight.has_value()) {
		return;
	}
	Radio &r = mRadio[*mInFlight];
	const std::uint64_t us = mBlockedUs;
	const std::uint32_t us32 = (us > 0xffffffffU) ? 0xffffffffU : static_cast<std::uint32_t>(us);

	mInFlight.reset();
	if (ok) {
		const Millis now = os::nowMs();
		mStats.dumps++;
		mStats.lastUs = us32;
		if (us32 > mStats.maxUs) {
			mStats.maxUs = us32;
		}
		for (std::size_t i = 0U; i < r.nNext; i++) {
			r.next[i].ts = now;
			r.cur[i] = r.next[i];
		}
		r.nCur = r.nNext;
		logging::dbg(LOG_MODULE, "wiphy {}: survey dump blocked {} us, {} in-use channel(s)", r.wiphy, us32,
			     r.nCur);
		if ((us32 > SLOW_US) && !mWarnedSlow) {
			mWarnedSlow = true;
			logging::warn(LOG_MODULE,
				      "wiphy {}: one survey dump held the daemon {} ms in the driver (slow firmware or "
				      "bus); it runs once per radio every sta_poll_interval_ms",
				      r.wiphy, us32 / 1000U);
		}
	} else {
		mStats.errors++;
		logging::dbg(LOG_MODULE, "wiphy {}: survey dump refused by the kernel", r.wiphy);
	}
	sendNext();
}

void Survey::onReadable() noexcept
{
	std::array<std::uint8_t, 16384U> buf{};
	std::size_t n = 0U;
	os::Rx rx = os::Rx::DATA;

	while (mInFlight.has_value() && (rx == os::Rx::DATA)) {
		// Reading lets the kernel fill the next part of the dump (more
		// driver calls) inside this recv().
		const std::uint64_t t0 = os::nowUs();
		rx = os::recvNowait(mFd, spanOf(buf), n);
		mBlockedUs += os::nowUs() - t0;
		if (rx != os::Rx::DATA) {
			break;
		}
		const ByteView all = viewOf(buf).first(n);
		std::size_t off = 0U;
		while (mInFlight.has_value() && ((all.size() - off) >= NL_HDR)) {
			const std::size_t len = os::loadNe32(all, off);
			if ((len < NL_HDR) || (len > (all.size() - off))) {
				break;
			}
			const ByteView msg = all.sub(off, len);
			const std::uint16_t type = os::loadNe16(msg, 4U);
			if (os::loadNe32(msg, 8U) != mSeq) {
				// left over from an abandoned dump
			} else if (type == static_cast<std::uint16_t>(NLMSG_DONE)) {
				finish(true);
			} else if (type == static_cast<std::uint16_t>(NLMSG_ERROR)) {
				finish(os::loadNe32(msg, NL_HDR) == 0U); // error 0 = ACK
			} else {
				Radio &r = mRadio[*mInFlight];
				const std::optional<SurveySample> s = parseInUse(msg);
				if (s.has_value() && (r.nNext < r.next.size())) {
					r.next[r.nNext] = *s;
					r.nNext++;
				}
			}
			off += align4(len);
		}
	}
	if (rx == os::Rx::ERROR) {
		// e.g. ENOBUFS: the dump is lost; tick() reopens the socket
		logging::dbg(LOG_MODULE, "survey socket: {}", os::lastError());
	}
}

void Survey::tick(Millis now) noexcept
{
	if (!mInFlight.has_value() || (now < mDeadline)) {
		return;
	}
	const Radio &r = mRadio[*mInFlight];
	mStats.timeouts++;
	logging::warn(LOG_MODULE, "wiphy {}: no survey reply in {} ms, abandoned", r.wiphy, DUMP_TIMEOUT_MS);
	mInFlight.reset();
	// A new socket ends the kernel's half-done dump (a second dump on the
	// same socket would get EBUSY) and discards its late messages.
	if (!resolveFamily()) {
		logging::warn(LOG_MODULE, "nl80211 lost, channel utilisation from hostapd only");
		return;
	}
	sendNext();
}

const SurveySample *Survey::find(std::uint32_t wiphy, int freq) const noexcept
{
	const SurveySample *s = nullptr;
	for (const Radio &r : mRadio) {
		if (!(r.used && (r.wiphy == wiphy))) {
			continue;
		}
		for (std::size_t i = 0U; (i < r.nCur) && (s == nullptr); i++) {
			if (r.cur[i].valid && (r.cur[i].freq == freq)) {
				s = &r.cur[i];
			}
		}
	}
	return s;
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
