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

constexpr std::size_t ETH_HDR_LEN = 14U;

class L2 {
public:
	struct Port {
		os::Fd fd{};
		bool sim{false};
		int ifindex{0};
		IfName name{};
		Mac mac{};
		std::array<std::uint16_t, MAX_SIM_PEERS> simPeers{};
		std::size_t nSimPeers{0U};
	};

	bool addIface(const IfName &ifname) noexcept;
	bool addSim(std::uint16_t port, const std::array<std::uint16_t, MAX_SIM_PEERS> &peers,
		     std::size_t n, const Mac &mac) noexcept;
	// Sends ARCP payload (header + body) to dst on one port.
	bool send(std::size_t port, const Mac &dst, ByteView payload) noexcept;
	// Receives one ARCP frame into payload. Rx::EMPTY for frames to ignore.
	os::Rx recv(std::size_t port, Mac &src, const ByteSpan &payload, std::size_t &n) noexcept;

	std::size_t size() const noexcept { return mN; }
	const Port &port(std::size_t i) const noexcept { return mPorts[i]; }

private:
	std::array<Port, MAX_L2_PORTS> mPorts{};
	std::size_t mN{0U};
};

} // namespace donghoa

#endif
