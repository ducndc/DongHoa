// SPDX-License-Identifier: MIT
#include "hapd.hpp"

#include "log.hpp"

namespace donghoa {
namespace hapd {

namespace {

constexpr LogModule kMod{LogModule::hapd};
constexpr int kCmdTimeoutMs = 1000;

std::uint32_t g_counter = 0U;

void to_text(ByteView bytes, Reply &out) noexcept
{
	out.clear();
	for (std::size_t i = 0U; i < bytes.size(); i++) {
		(void)out.push_back(static_cast<char>(bytes[i]));
	}
}

// Local client socket bound at /tmp/donghoa-<pid>-<ifname>-<tag><n>,
// connected to hostapd's socket at remote.
os::Fd open_one(const Path &remote, Path &local, const IfName &ifname, char tag) noexcept
{
	local.clear();
	format_to(local, "/tmp/donghoa-{}-{}-", os::process_id(), ifname);
	(void)local.push_back(tag);
	format_to(local, "{}", g_counter);
	g_counter++;
	os::Fd fd = os::unix_bind(local.c_str(), false);
	if (fd.valid()) {
		// hostapd replies by sending to our socket, which needs write
		// permission: OpenWrt runs hostapd as user "network".
		os::share_owner(local.c_str(), remote.c_str());
		if (!os::unix_connect(fd, remote.c_str())) {
			fd.reset();
		}
	}
	if (!fd.valid()) {
		os::remove_file(local.c_str());
		local.clear();
	}
	return fd;
}

// Waits for a reply on fd, skipping unsolicited "<N>..." messages.
bool recv_reply(const os::Fd &fd, Reply &reply, int timeout_ms) noexcept
{
	const Millis deadline = os::now_ms() + static_cast<Millis>(timeout_ms);
	std::array<std::uint8_t, kReplyMax> buf{};
	bool done = false;
	bool ok = false;

	while (!done) {
		const Millis now = os::now_ms();
		const int left = (now < deadline) ? static_cast<int>(deadline - now) : 0;
		if (!os::wait_readable(fd.get(), left)) {
			done = true;
		} else {
			const std::optional<std::size_t> n = os::recv_bytes(fd, span_of(buf));
			if (!n.has_value()) {
				done = true;
			} else {
				to_text(view_of(buf).first(*n), reply);
				if ((*n == 0U) || (buf[0U] != static_cast<std::uint8_t>('<'))) {
					ok = true;
					done = true;
				}
			}
		}
	}
	return ok;
}

} // namespace

bool Conn::open(const Path &dir, const IfName &ifname) noexcept
{
	Reply r;

	close();
	ifname_ = ifname;
	path_.clear();
	format_to(path_, "{}/{}", dir, ifname);
	cmd_ = open_one(path_, local_cmd_, ifname, 'c');
	if (cmd_.valid()) {
		ev_ = open_one(path_, local_ev_, ifname, 'e');
	}
	bool ok = cmd_.valid() && ev_.valid() && os::send_text(ev_, "ATTACH", false) &&
		  recv_reply(ev_, r, kCmdTimeoutMs) && starts_with(r.view(), "OK");
	if (ok) {
		logging::info(kMod, "connected to {}", path_);
	} else {
		close();
	}
	return ok;
}

void Conn::close() noexcept
{
	if (ev_.valid()) {
		(void)os::send_text(ev_, "DETACH", true);
	}
	ev_.reset();
	cmd_.reset();
	if (!local_cmd_.empty()) {
		os::remove_file(local_cmd_.c_str());
	}
	if (!local_ev_.empty()) {
		os::remove_file(local_ev_.c_str());
	}
	local_cmd_.clear();
	local_ev_.clear();
}

bool Conn::cmd(std::string_view command, Reply &reply) noexcept
{
	bool ok = cmd_.valid();

	reply.clear();
	if (ok) {
		logging::dbg(kMod, "hapd[{}] > {}", ifname_, command);
		ok = os::send_text(cmd_, command, false);
		if (!ok) {
			logging::warn(kMod, "hapd[{}]: send: {}", ifname_, os::last_error());
			close();
		}
	}
	if (ok) {
		ok = recv_reply(cmd_, reply, kCmdTimeoutMs);
		if (!ok) {
			logging::warn(kMod, "hapd[{}]: no reply to '{}'", ifname_, sub_view(command, 0U, 32U));
			close();
		}
	}
	return ok;
}

os::Rx Conn::recv_event(Reply &ev) noexcept
{
	std::array<std::uint8_t, kReplyMax> buf{};
	std::size_t n = 0U;
	const os::Rx r = os::recv_nowait(ev_, span_of(buf), n);

	ev.clear();
	if (r == os::Rx::data) {
		ByteView v = view_of(buf).first(n);
		if ((n > 0U) && (v[0U] == static_cast<std::uint8_t>('<'))) {
			std::size_t i = 0U;
			while ((i < n) && (v[i] != static_cast<std::uint8_t>('>'))) {
				i++;
			}
			v = (i < n) ? v.sub(i + 1U, n - i - 1U) : v;
		}
		to_text(v, ev);
	}
	return r;
}

} // namespace hapd
} // namespace donghoa
