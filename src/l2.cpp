// SPDX-License-Identifier: MIT
#include "l2.hpp"

#include "log.hpp"
#include "proto.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::L2};

Mac macAt(ByteView v, std::size_t off) noexcept
{
	Mac m;
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		m.b[i] = v[off + i];
	}
	return m;
}

} // namespace

bool L2::addIface(const IfName &ifname) noexcept
{
	bool ok = mN < mPorts.size();
	if (ok) {
		Port &p = mPorts[mN];
		os::LinkInfo info;
		p.fd = os::openPacket(ifname.cStr(), arcp::ETHERTYPE, arcp::GROUP_ADDR, info);
		ok = p.fd.valid();
		if (ok) {
			p.sim = false;
			p.ifindex = info.ifindex;
			p.mac = info.mac;
			p.name = ifname;
			logging::info(LOG_MODULE, "port {} ifindex {} mac {}", ifname, p.ifindex, p.mac);
			mN++;
		} else {
			logging::err(LOG_MODULE, "{}: cannot open raw socket: {} (needs CAP_NET_RAW)", ifname,
				     os::lastError());
		}
	}
	return ok;
}

bool L2::addSim(std::uint16_t port, const std::array<std::uint16_t, MAX_SIM_PEERS> &peers,
		 std::size_t n, const Mac &mac) noexcept
{
	bool ok = (mN < mPorts.size()) && (n <= MAX_SIM_PEERS);
	if (ok) {
		Port &p = mPorts[mN];
		p.fd = os::bindUdpLoopback(port);
		ok = p.fd.valid();
		if (ok) {
			p.sim = true;
			p.simPeers = peers;
			p.nSimPeers = n;
			p.mac = mac;
			p.name.clear();
			formatTo(p.name, "sim{}", port);
			logging::info(LOG_MODULE, "sim port {} ({} peers) mac {}", port, n, mac);
			mN++;
		} else {
			logging::err(LOG_MODULE, "sim bind {}: {}", port, os::lastError());
		}
	}
	return ok;
}

bool L2::send(std::size_t port, const Mac &dst, ByteView payload) noexcept
{
	std::array<std::uint8_t, ETH_HDR_LEN + arcp::MAX_PAYLOAD> frame{};
	bool ok = (port < mN) && (payload.size() <= arcp::MAX_PAYLOAD);

	if (ok) {
		const Port &p = mPorts[port];
		const ByteSpan f = spanOf(frame);
		for (std::size_t i = 0U; i < 6U; i++) {
			frame[i] = dst.b[i];
			frame[6U + i] = p.mac.b[i];
		}
		putBe16(f, 12U, arcp::ETHERTYPE);
		for (std::size_t i = 0U; i < payload.size(); i++) {
			frame[ETH_HDR_LEN + i] = payload[i];
		}
		const ByteView out = viewOf(frame).first(ETH_HDR_LEN + payload.size());
		if (p.sim) {
			for (std::size_t i = 0U; i < p.nSimPeers; i++) {
				os::sendUdpLoopback(p.fd, p.simPeers[i], out);
			}
		} else {
			ok = os::sendPacket(p.fd, p.ifindex, dst, out);
			if (!ok) {
				logging::warn(LOG_MODULE, "{}: sendto: {}", p.name, os::lastError());
			}
		}
	}
	return ok;
}

os::Rx L2::recv(std::size_t port, Mac &src, const ByteSpan &payload, std::size_t &n) noexcept
{
	std::array<std::uint8_t, 2048U> frame{};
	std::size_t len = 0U;
	os::Rx r = os::Rx::ERROR;

	n = 0U;
	if (port < mN) {
		const Port &p = mPorts[port];
		r = p.sim ? os::recvNowait(p.fd, spanOf(frame), len)
			  : os::recvPacket(p.fd, spanOf(frame), len);
		if (r == os::Rx::DATA) {
			const ByteView f = viewOf(frame).first(len);
			// Our EtherType, addressed to us or the group, not sent by us.
			const bool mine = (len >= ETH_HDR_LEN) && (getBe16(f, 12U) == arcp::ETHERTYPE) &&
					  ((macAt(f, 0U) == p.mac) || (macAt(f, 0U) == arcp::GROUP_ADDR)) &&
					  (macAt(f, 6U) != p.mac);
			if (mine) {
				src = macAt(f, 6U);
				n = copyBytes(payload, f.sub(ETH_HDR_LEN, len - ETH_HDR_LEN));
			} else {
				r = os::Rx::EMPTY;
			}
		}
	}
	return r;
}

} // namespace donghoa
