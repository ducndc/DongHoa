// SPDX-License-Identifier: MIT
#include "l2.hpp"

#include "log.hpp"
#include "proto.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::l2};

Mac mac_at(ByteView v, std::size_t off) noexcept
{
	Mac m;
	for (std::size_t i = 0U; i < m.b.size(); i++) {
		m.b[i] = v[off + i];
	}
	return m;
}

} // namespace

bool L2::add_iface(const IfName &ifname) noexcept
{
	bool ok = n_ < ports_.size();
	if (ok) {
		Port &p = ports_[n_];
		os::LinkInfo info;
		p.fd = os::packet_open(ifname.c_str(), arcp::kEthertype, arcp::kGroupAddr, info);
		ok = p.fd.valid();
		if (ok) {
			p.sim = false;
			p.ifindex = info.ifindex;
			p.mac = info.mac;
			p.name = ifname;
			logging::info(kMod, "port {} ifindex {} mac {}", ifname, p.ifindex, p.mac);
			n_++;
		} else {
			logging::err(kMod, "{}: cannot open raw socket: {} (needs CAP_NET_RAW)", ifname,
				     os::last_error());
		}
	}
	return ok;
}

bool L2::add_sim(std::uint16_t port, const std::array<std::uint16_t, kMaxSimPeers> &peers,
		 std::size_t n, const Mac &mac) noexcept
{
	bool ok = (n_ < ports_.size()) && (n <= kMaxSimPeers);
	if (ok) {
		Port &p = ports_[n_];
		p.fd = os::udp_bind_loopback(port);
		ok = p.fd.valid();
		if (ok) {
			p.sim = true;
			p.sim_peers = peers;
			p.n_sim_peers = n;
			p.mac = mac;
			p.name.clear();
			format_to(p.name, "sim{}", port);
			logging::info(kMod, "sim port {} ({} peers) mac {}", port, n, mac);
			n_++;
		} else {
			logging::err(kMod, "sim bind {}: {}", port, os::last_error());
		}
	}
	return ok;
}

bool L2::send(std::size_t port, const Mac &dst, ByteView payload) noexcept
{
	std::array<std::uint8_t, kEthHdrLen + arcp::kMaxPayload> frame{};
	bool ok = (port < n_) && (payload.size() <= arcp::kMaxPayload);

	if (ok) {
		const Port &p = ports_[port];
		const ByteSpan f = span_of(frame);
		for (std::size_t i = 0U; i < 6U; i++) {
			frame[i] = dst.b[i];
			frame[6U + i] = p.mac.b[i];
		}
		put_be16(f, 12U, arcp::kEthertype);
		for (std::size_t i = 0U; i < payload.size(); i++) {
			frame[kEthHdrLen + i] = payload[i];
		}
		const ByteView out = view_of(frame).first(kEthHdrLen + payload.size());
		if (p.sim) {
			for (std::size_t i = 0U; i < p.n_sim_peers; i++) {
				os::udp_send_loopback(p.fd, p.sim_peers[i], out);
			}
		} else {
			ok = os::packet_send(p.fd, p.ifindex, dst, out);
			if (!ok) {
				logging::warn(kMod, "{}: sendto: {}", p.name, os::last_error());
			}
		}
	}
	return ok;
}

os::Rx L2::recv(std::size_t port, Mac &src, const ByteSpan &payload, std::size_t &n) noexcept
{
	std::array<std::uint8_t, 2048U> frame{};
	std::size_t len = 0U;
	os::Rx r = os::Rx::error;

	n = 0U;
	if (port < n_) {
		const Port &p = ports_[port];
		r = p.sim ? os::recv_nowait(p.fd, span_of(frame), len)
			  : os::packet_recv(p.fd, span_of(frame), len);
		if (r == os::Rx::data) {
			const ByteView f = view_of(frame).first(len);
			// Our EtherType, addressed to us or the group, not sent by us.
			const bool mine = (len >= kEthHdrLen) && (get_be16(f, 12U) == arcp::kEthertype) &&
					  ((mac_at(f, 0U) == p.mac) || (mac_at(f, 0U) == arcp::kGroupAddr)) &&
					  (mac_at(f, 6U) != p.mac);
			if (mine) {
				src = mac_at(f, 6U);
				n = copy_bytes(payload, f.sub(kEthHdrLen, len - kEthHdrLen));
			} else {
				r = os::Rx::empty;
			}
		}
	}
	return r;
}

} // namespace donghoa
