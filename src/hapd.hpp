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

constexpr std::size_t kReplyMax = 4096U;
using Reply = FixedString<kReplyMax>;

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
	bool is_open() const noexcept { return cmd_.valid(); }
	// Sends cmd and waits up to 1 s for the reply (unsolicited "<N>"
	// messages skipped). On failure the connection is closed.
	bool cmd(std::string_view command, Reply &reply) noexcept;
	// Next pending event without its "<N>" prefix. Rx::empty when none.
	os::Rx recv_event(Reply &ev) noexcept;
	int event_fd() const noexcept { return ev_.get(); }

private:
	os::Fd cmd_{};
	os::Fd ev_{};
	Path path_{};
	Path local_cmd_{};
	Path local_ev_{};
	IfName ifname_{};
};

} // namespace hapd
} // namespace donghoa

#endif
