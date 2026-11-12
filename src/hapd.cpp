// SPDX-License-Identifier: MIT
#include "hapd.hpp"

#include "log.hpp"
#include "rrm_log.hpp"

namespace donghoa {
namespace hapd {

namespace {

constexpr LogModule LOG_MODULE{LogModule::HAPD};
constexpr int CMD_TIMEOUT_MS = 1000;

std::uint32_t sCounter = 0U;

void toText(ByteView bytes, Reply &out) noexcept
{
	out.clear();
	for (std::size_t i = 0U; i < bytes.size(); i++) {
		(void)out.pushBack(static_cast<char>(bytes[i]));
	}
}

// Local client socket bound at /tmp/donghoa-<pid>-<ifname>-<tag><n>,
// connected to hostapd's socket at remote.
os::Fd openOne(const Path &remote, Path &local, const IfName &ifname, char tag) noexcept
{
	local.clear();
	formatTo(local, "/tmp/donghoa-{}-{}-", os::processId(), ifname);
	(void)local.pushBack(tag);
	formatTo(local, "{}", sCounter);
	sCounter++;
	os::Fd fd = os::bindUnix(local.cStr(), false);
	if (fd.valid()) {
		// hostapd replies by sending to our socket, which needs write
		// permission: OpenWrt runs hostapd as user "network".
		os::shareOwner(local.cStr(), remote.cStr());
		if (!os::connectUnix(fd, remote.cStr())) {
			fd.reset();
		}
	}
	if (!fd.valid()) {
		os::removeFile(local.cStr());
		local.clear();
	}
	return fd;
}

// Waits for a reply on fd, skipping unsolicited "<N>..." messages.
bool recvReply(const os::Fd &fd, Reply &reply, int timeoutMs) noexcept
{
	const Millis deadline = os::nowMs() + static_cast<Millis>(timeoutMs);
	std::array<std::uint8_t, REPLY_MAX> buf{};
	bool done = false;
	bool ok = false;

	while (!done) {
		const Millis now = os::nowMs();
		const int left = (now < deadline) ? static_cast<int>(deadline - now) : 0;
		if (!os::waitReadable(fd.get(), left)) {
			done = true;
		} else {
			const std::optional<std::size_t> n = os::recvBytes(fd, spanOf(buf));
			if (!n.has_value()) {
				done = true;
			} else {
				toText(viewOf(buf).first(*n), reply);
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
	mIfname = ifname;
	mPath.clear();
	formatTo(mPath, "{}/{}", dir, ifname);
	mCmd = openOne(mPath, mLocalCmd, ifname, 'c');
	if (mCmd.valid()) {
		mEv = openOne(mPath, mLocalEv, ifname, 'e');
	}
	bool ok = mCmd.valid() && mEv.valid() && os::sendText(mEv, "ATTACH", false) &&
		  recvReply(mEv, r, CMD_TIMEOUT_MS) && startsWith(r.view(), "OK");
	if (ok) {
		logging::notice(LOG_MODULE, "connected to {}", mPath);
	} else {
		close();
	}
	return ok;
}

void Conn::close() noexcept
{
	if (mEv.valid()) {
		(void)os::sendText(mEv, "DETACH", true);
	}
	mEv.reset();
	mCmd.reset();
	if (!mLocalCmd.empty()) {
		os::removeFile(mLocalCmd.cStr());
	}
	if (!mLocalEv.empty()) {
		os::removeFile(mLocalEv.cStr());
	}
	mLocalCmd.clear();
	mLocalEv.clear();
}

bool Conn::runCommand(std::string_view command, Reply &reply) noexcept
{
	bool ok = mCmd.valid();

	reply.clear();
	if (ok) {
		logging::dbg(LOG_MODULE, "hapd[{}] > {}", mIfname, command);
		ok = os::sendText(mCmd, command, false);
		if (!ok) {
			logging::warn(LOG_MODULE, "hapd[{}]: send: {}", mIfname, os::lastError());
			close();
		}
	}
	if (ok) {
		ok = recvReply(mCmd, reply, CMD_TIMEOUT_MS);
		if (!ok) {
			logging::warn(LOG_MODULE, "hapd[{}]: no reply to '{}'", mIfname,
					      subView(command, 0U, 32U));
			close();
		} else {
			rrmlog::logCommand(mIfname.view(), command, reply.view());
		}
	}
	return ok;
}

os::Rx Conn::recvEvent(Reply &ev) noexcept
{
	std::array<std::uint8_t, REPLY_MAX> buf{};
	std::size_t n = 0U;
	const os::Rx r = os::recvNowait(mEv, spanOf(buf), n);

	ev.clear();
	if (r == os::Rx::DATA) {
		ByteView v = viewOf(buf).first(n);
		if ((n > 0U) && (v[0U] == static_cast<std::uint8_t>('<'))) {
			std::size_t i = 0U;
			while ((i < n) && (v[i] != static_cast<std::uint8_t>('>'))) {
				i++;
			}
			v = (i < n) ? v.sub(i + 1U, n - i - 1U) : v;
		}
		toText(v, ev);
		rrmlog::logEvent(mIfname.view(), ev.view());
	}
	return r;
}

} // namespace hapd
} // namespace donghoa
