// SPDX-License-Identifier: MIT
#include "survey.hpp"

#include <array>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>

#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::survey};
constexpr std::size_t kNlHdr = 16U;   // struct nlmsghdr
constexpr std::size_t kGenlHdr = 4U;  // struct genlmsghdr
constexpr std::size_t kAttrHdr = 4U;  // struct nlattr
constexpr int kRecvTimeoutMs = 500;

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
		const ByteSpan s = span_of(buf_);
		os::store_ne16(s, 4U, type);
		os::store_ne16(s, 6U, flags);
		os::store_ne32(s, 8U, seq);
		buf_[kNlHdr] = cmd;
		buf_[kNlHdr + 1U] = version;
		len_ = kNlHdr + kGenlHdr;
	}

	void attr(std::uint16_t type, ByteView data) noexcept
	{
		const std::size_t total = kAttrHdr + data.size();
		if ((align4(len_) + align4(total)) <= buf_.size()) {
			const ByteSpan s = span_of(buf_);
			const std::size_t at = align4(len_);
			os::store_ne16(s, at, static_cast<std::uint16_t>(total));
			os::store_ne16(s, at + 2U, type);
			for (std::size_t i = 0U; i < data.size(); i++) {
				buf_[at + kAttrHdr + i] = data[i];
			}
			len_ = at + align4(total);
		}
	}

	ByteView finish() noexcept
	{
		os::store_ne32(span_of(buf_), 0U, static_cast<std::uint32_t>(len_));
		return view_of(buf_).first(len_);
	}

private:
	std::array<std::uint8_t, 64U> buf_{};
	std::size_t len_{0U};
};

// Attribute of the given type inside attrs, or an empty view.
ByteView find_attr(ByteView attrs, std::uint16_t type) noexcept
{
	ByteView found;
	std::size_t off = 0U;
	bool more = true;

	while (more && ((attrs.size() - off) >= kAttrHdr)) {
		const std::size_t len = os::load_ne16(attrs, off);
		const std::uint16_t t = static_cast<std::uint16_t>(os::load_ne16(attrs, off + 2U) &
								   static_cast<std::uint16_t>(NLA_TYPE_MASK));
		if ((len < kAttrHdr) || (len > (attrs.size() - off))) {
			more = false;
		} else if (t == type) {
			found = attrs.sub(off + kAttrHdr, len - kAttrHdr);
			// An attribute may legitimately be empty (a flag): mark found.
			if (found.empty()) {
				found = attrs.sub(off, kAttrHdr);
			}
			more = false;
		} else {
			off += align4(len);
			more = off < attrs.size();
		}
	}
	return found;
}

bool has_attr(ByteView attrs, std::uint16_t type) noexcept
{
	return !find_attr(attrs, type).empty();
}

void parse_survey(ByteView msg, SurveySample &out) noexcept
{
	const ByteView attrs = msg.sub(kNlHdr + kGenlHdr, msg.size() - (kNlHdr + kGenlHdr));
	const ByteView si = find_attr(attrs, static_cast<std::uint16_t>(NL80211_ATTR_SURVEY_INFO));

	if (!si.empty() && has_attr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_IN_USE))) {
		out = SurveySample{};
		out.valid = true;
		const ByteView f = find_attr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_FREQUENCY));
		if (f.size() >= 4U) {
			out.freq = static_cast<int>(os::load_ne32(f, 0U));
		}
		const ByteView n = find_attr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_NOISE));
		if (n.size() >= 1U) {
			out.noise = static_cast<std::int8_t>(n[0U]);
		}
		const ByteView t = find_attr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_TIME));
		if (t.size() >= 8U) {
			out.active_ms = os::load_ne64(t, 0U);
		}
		const ByteView b = find_attr(si, static_cast<std::uint16_t>(NL80211_SURVEY_INFO_TIME_BUSY));
		if (b.size() >= 8U) {
			out.busy_ms = os::load_ne64(b, 0U);
		}
	}
}

} // namespace

bool Survey::open() noexcept
{
	std::array<std::uint8_t, 16384U> buf{};
	const std::array<std::uint8_t, 8U> name{{'n', 'l', '8', '0', '2', '1', '1', '\0'}};

	family_ = 0U;
	fd_ = os::netlink_open();
	seq_++;
	Request r(static_cast<std::uint16_t>(GENL_ID_CTRL), static_cast<std::uint16_t>(NLM_F_REQUEST), seq_,
		  static_cast<std::uint8_t>(CTRL_CMD_GETFAMILY), 1U);
	r.attr(static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_NAME), view_of(name));
	bool ok = fd_.valid() && os::netlink_send(fd_, r.finish());
	std::optional<std::size_t> n;
	if (ok) {
		n = os::netlink_recv(fd_, span_of(buf), kRecvTimeoutMs);
		ok = n.has_value() && (*n >= (kNlHdr + kGenlHdr));
	}
	if (ok) {
		const ByteView msg = view_of(buf).first(*n);
		ok = os::load_ne16(msg, 4U) != static_cast<std::uint16_t>(NLMSG_ERROR);
		if (ok) {
			const std::size_t len = os::load_ne32(msg, 0U);
			const ByteView attrs = msg.sub(kNlHdr + kGenlHdr, ((len <= *n) ? len : *n) - (kNlHdr + kGenlHdr));
			const ByteView id = find_attr(attrs, static_cast<std::uint16_t>(CTRL_ATTR_FAMILY_ID));
			ok = id.size() >= 2U;
			family_ = ok ? os::load_ne16(id, 0U) : 0U;
		}
	}
	if (!ok) {
		logging::warn(kMod, "nl80211 unavailable, channel utilisation from hostapd only");
		fd_.reset();
	}
	return ok;
}

bool Survey::get(int ifindex, SurveySample &out) noexcept
{
	std::array<std::uint8_t, 16384U> buf{};
	std::array<std::uint8_t, 4U> idx{};
	bool ok = fd_.valid() && (family_ != 0U);
	bool done = !ok;

	out.valid = false;
	if (ok) {
		seq_++;
		os::store_ne32(span_of(idx), 0U, static_cast<std::uint32_t>(ifindex));
		Request r(family_, static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_DUMP), seq_,
			  static_cast<std::uint8_t>(NL80211_CMD_GET_SURVEY), 0U);
		r.attr(static_cast<std::uint16_t>(NL80211_ATTR_IFINDEX), view_of(idx));
		ok = os::netlink_send(fd_, r.finish());
		done = !ok;
	}
	while (!done) {
		const std::optional<std::size_t> n = os::netlink_recv(fd_, span_of(buf), kRecvTimeoutMs);
		if (!n.has_value()) {
			ok = false;
			done = true;
		}
		const ByteView all = view_of(buf).first(n.has_value() ? *n : 0U);
		std::size_t off = 0U;
		while (!done && ((all.size() - off) >= kNlHdr)) {
			const std::size_t len = os::load_ne32(all, off);
			if ((len < kNlHdr) || (len > (all.size() - off))) {
				break;
			}
			const ByteView msg = all.sub(off, len);
			const std::uint16_t type = os::load_ne16(msg, 4U);
			if (os::load_ne32(msg, 8U) == seq_) {
				if (type == static_cast<std::uint16_t>(NLMSG_DONE)) {
					ok = out.valid;
					done = true;
				} else if (type == static_cast<std::uint16_t>(NLMSG_ERROR)) {
					ok = false;
					done = true;
				} else {
					parse_survey(msg, out);
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
	if (prev.valid && cur.valid && (prev.freq == cur.freq) && (cur.active_ms > prev.active_ms) &&
	    (cur.busy_ms >= prev.busy_ms)) {
		const std::uint64_t da = cur.active_ms - prev.active_ms;
		std::uint64_t db = cur.busy_ms - prev.busy_ms;
		if (db > da) {
			db = da;
		}
		u = static_cast<int>((db * 255U) / da);
	}
	return u;
}

} // namespace donghoa
