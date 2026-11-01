// SPDX-License-Identifier: MIT
// hostapd control-interface client: one command socket and one event
// socket (ATTACHed) per BSS.
#ifndef DONGHOA_HAPD_HPP
#define DONGHOA_HAPD_HPP

#include <array>
#include <cstddef>
#include <string_view>

#include "config.hpp"
#include "os.hpp"
#include "types.hpp"

namespace donghoa {
namespace hapd {

constexpr std::size_t REPLY_MAX = 4096U;
using Reply = FixedString<REPLY_MAX>;

class Conn {
public:
	Conn() noexcept = default;
	~Conn() noexcept { close(); }
	Conn(const Conn &) = delete;
	Conn &operator=(const Conn &) = delete;
	Conn(Conn &&) = delete;
	Conn &operator=(Conn &&) = delete;

	bool open(const Path &dir, const IfName &ifname) noexcept;
	void close() noexcept;
	bool isOpen() const noexcept { return mCmd.valid(); }
	// Sends cmd and waits up to 1 s for the reply (unsolicited "<N>"
	// messages skipped). On failure the connection is closed.
	bool runCommand(std::string_view command, Reply &reply) noexcept;
	// Next pending event without its "<N>" prefix. Rx::EMPTY when none.
	os::Rx recvEvent(Reply &ev) noexcept;
	int eventFd() const noexcept { return mEv.get(); }

private:
	os::Fd mCmd{};
	os::Fd mEv{};
	Path mPath{};
	Path mLocalCmd{};
	Path mLocalEv{};
	IfName mIfname{};
};

} // namespace hapd
} // namespace donghoa

#endif
