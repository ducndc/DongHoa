// SPDX-License-Identifier: MIT
// Layer-2 attachment points. A real port is an AF_PACKET socket on a netdev
// (bridge, Ethernet, 4-address/WDS or mesh Wi-Fi). A sim port carries the
// identical Ethernet frame in UDP on loopback, so the whole stack runs
// without CAP_NET_RAW.
#ifndef DONGHOA_L2_HPP
#define DONGHOA_L2_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "config.hpp"
#include "os.hpp"
#include "types.hpp"

namespace donghoa {

constexpr std::size_t kEthHdrLen = 14U;

class L2 {
public:
	struct Port {
		os::Fd fd{};
		bool sim{false};
		int ifindex{0};
		IfName name{};
		Mac mac{};
		std::array<std::uint16_t, kMaxSimPeers> sim_peers{};
		std::size_t n_sim_peers{0U};
	};

	bool add_iface(const IfName &ifname) noexcept;
	bool add_sim(std::uint16_t port, const std::array<std::uint16_t, kMaxSimPeers> &peers,
		     std::size_t n, const Mac &mac) noexcept;
	// Sends ARCP payload (header + body) to dst on one port.
	bool send(std::size_t port, const Mac &dst, ByteView payload) noexcept;
	// Receives one ARCP frame into payload. Rx::empty for frames to ignore.
	os::Rx recv(std::size_t port, Mac &src, const ByteSpan &payload, std::size_t &n) noexcept;

	std::size_t size() const noexcept { return n_; }
	const Port &port(std::size_t i) const noexcept { return ports_[i]; }

private:
	std::array<Port, kMaxL2Ports> ports_{};
	std::size_t n_{0U};
};

} // namespace donghoa

#endif
