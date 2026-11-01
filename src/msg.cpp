// SPDX-License-Identifier: MIT
// ARCP messaging: periodic messages, reliable unicast, receive path.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::msg};
constexpr Millis kRetxIntervalMs = 300U;
constexpr int kRetxMaxTries = 4;

} // namespace

void Daemon::msg_begin(arcp::Message &m, arcp::MsgType type, std::uint8_t flags) noexcept
{
	next_msg_id_++;
	m.begin(type, flags, ap_id_, boot_id_, next_msg_id_);
}

bool Daemon::finish(arcp::Message &m) noexcept
{
	const bool ok = m.finish(cfg_.key_view());
	if (!ok) {
		logging::err(kMod, "tx: message type {} overflow", m.type());
	}
	return ok;
}

// Debug trace of one ARCP frame: "<dir> <TYPE> #<id> <peer> via <port>
// [flags]: <TLV list>". Built only when module msg logs at debug.
void Daemon::trace(std::string_view dir, ByteView frame, const Mac *peer, std::string_view port,
		   int tries) const noexcept
{
	if (!logging::enabled(kMod, LogLevel::debug)) {
		return;
	}
	const std::optional<arcp::Header> h = arcp::parse_header(frame);
	if (!h.has_value()) {
		return;
	}
	std::array<std::uint8_t, 16U> order{};
	std::array<std::uint16_t, 256U> count{};
	std::size_t n_order = 0U;
	arcp::TlvReader rd(frame, *h);
	std::uint8_t t = 0U;
	ByteView v;

	while (rd.next(t, v)) {
		if ((count[t] == 0U) && (n_order < order.size())) {
			order[n_order] = t;
			n_order++;
		}
		count[t]++;
	}
	FixedString<256U> tlvs;
	for (std::size_t i = 0U; i < n_order; i++) {
		if (count[order[i]] > 1U) {
			format_to(tlvs, " {}*{}", arcp::tlv_name(order[i]), count[order[i]]);
		} else {
			format_to(tlvs, " {}", arcp::tlv_name(order[i]));
		}
	}
	FixedString<24U> who{"group"};
	if (peer != nullptr) {
		who.clear();
		format_to(who, "{}", *peer);
	}
	logging::dbg(kMod, "{} {} #{} {} via {}{}{}{}:{}", dir, arcp::msg_name(h->type), h->msg_id, who,
		     port, ((h->flags & arcp::kFlagAckReq) != 0U) ? " [ack-req]" : "",
		     ((h->flags & arcp::kFlagAuth) != 0U) ? " [auth]" : "", (tries > 1) ? " [retry]" : "",
		     tlvs);
}

void Daemon::multicast(arcp::Message &m) noexcept
{
	if (finish(m)) {
		const std::string_view port = (l2_.size() > 1U) ? std::string_view("all ports")
					      : ((l2_.size() == 1U) ? l2_.port(0U).name.view()
								    : std::string_view("-"));
		trace("tx", m.bytes(), nullptr, port, 1);
		for (std::size_t i = 0U; i < l2_.size(); i++) {
			(void)l2_.send(i, arcp::kGroupAddr, m.bytes());
		}
	}
}

bool Daemon::unicast(const Mac &peer_id, arcp::Message &m) noexcept
{
	const Peer *const p = peer_find(peer_id);
	bool ok = (p != nullptr) && p->port.has_value();

	if (!ok) {
		logging::warn(kMod, "tx: peer {} unreachable", peer_id);
	} else {
		ok = finish(m);
	}
	if (ok) {
		trace("tx", m.bytes(), &peer_id, l2_.port(*p->port).name.view(), 1);
		(void)l2_.send(*p->port, p->l2addr, m.bytes());
		if ((m.flags() & arcp::kFlagAckReq) != 0U) {
			bool queued = false;
			for (PendingTx &t : pending_) {
				if (!queued && !t.used) {
					t.used = true;
					t.msg_id = m.msg_id();
					t.peer = peer_id;
					t.tries = 1;
					t.next_try = os::now_ms() + kRetxIntervalMs;
					t.msg = m;
					queued = true;
				}
			}
			if (!queued) {
				logging::warn(kMod, "tx: pending queue full, no retransmission");
			}
		}
	}
	return ok;
}

void Daemon::retransmit(Millis now) noexcept
{
	for (PendingTx &t : pending_) {
		if (t.used && (now >= t.next_try)) {
			const Peer *const p = peer_find(t.peer);
			if ((p == nullptr) || !p->port.has_value() || (t.tries >= kRetxMaxTries)) {
				logging::warn(kMod, "tx: {} msg {} to {} not acknowledged",
					      arcp::msg_name(t.msg.type()), t.msg_id, t.peer);
				t.used = false;
			} else {
				t.tries++;
				trace("tx", t.msg.bytes(), &t.peer, l2_.port(*p->port).name.view(), t.tries);
				(void)l2_.send(*p->port, p->l2addr, t.msg.bytes());
				t.next_try = now + kRetxIntervalMs;
			}
		}
	}
}

void Daemon::ack_received(const Mac &peer, std::uint32_t id) noexcept
{
	for (PendingTx &t : pending_) {
		if (t.used && (t.msg_id == id) && (t.peer == peer)) {
			t.used = false;
		}
	}
}

void Daemon::send_ack(const Mac &peer, std::uint32_t id) noexcept
{
	arcp::Message m;
	msg_begin(m, arcp::MsgType::ack, 0U);
	(void)m.add_ack(id);
	(void)unicast(peer, m);
}

// ---- periodic messages ----

void Daemon::send_hello() noexcept
{
	arcp::Message m;
	arcp::ApInfo ai;

	ai.hello_ms = static_cast<std::uint16_t>(cfg_.hello_ms);
	(void)ai.name.assign(cfg_.name.view());
	if (n_amon_ > 0U) {
		ai.flags = static_cast<std::uint16_t>(ai.flags | arcp::kApFlagAirMonitor);
	}
	for (std::size_t i = 0U; i < n_bss_; i++) {
		if (bss_[i].up) {
			ai.num_bss++;
		}
	}
	msg_begin(m, arcp::MsgType::hello, 0U);
	(void)m.add(ai);
	for (std::size_t i = 0U; i < n_bss_; i++) {
		if (bss_[i].up) {
			(void)m.add(bss_[i].info);
		}
	}
	multicast(m);
}

void Daemon::send_bss_status() noexcept
{
	arcp::Message m;
	msg_begin(m, arcp::MsgType::bss_status, 0U);
	for (std::size_t i = 0U; i < n_bss_; i++) {
		if (bss_[i].up) {
			(void)m.add(bss_[i].info);
			(void)m.add(bss_[i].load);
		}
	}
	multicast(m);
}

void Daemon::send_sta_status() noexcept
{
	arcp::Message m;
	bool open = false;

	for (const Sta &s : sta_) {
		if (s.used && !s.away && bss_[s.bss].up) {
			if (open && (m.room() < (arcp::kTlvHdrLen + arcp::kStaEntryLen))) {
				multicast(m);
				open = false;
			}
			if (!open) {
				msg_begin(m, arcp::MsgType::sta_status, 0U);
				open = true;
			}
			(void)m.add(fill_entry(s));
		}
	}
	if (open) {
		multicast(m);
	}
}

void Daemon::send_rf_status() noexcept
{
	arcp::Message m;
	std::size_t n = 0U;

	msg_begin(m, arcp::MsgType::rf_status, 0U);
	// One RF_INFO per distinct operating channel (radio).
	for (std::size_t i = 0U; i < n_bss_; i++) {
		const LocalBss &b = bss_[i];
		bool dup = false;
		for (std::size_t j = 0U; j < i; j++) {
			dup = dup || (bss_[j].up && (bss_[j].info.freq == b.info.freq));
		}
		if (b.up && !dup) {
			arcp::RfInfo rf;
			rf.radio_id = static_cast<std::uint8_t>(i);
			rf.freq = b.info.freq;
			rf.op_class = b.info.op_class;
			rf.channel = b.info.channel;
			rf.bw = b.info.bw;
			rf.util = b.load.util;
			rf.noise = b.load.noise;
			rf.tx_power = b.load.tx_power;
			(void)m.add(rf);
			n++;
		}
	}
	if (n > 0U) {
		multicast(m);
	}
}

void Daemon::send_sta_event(const Mac &sta, std::size_t bss, arcp::StaEventType ev,
			    std::uint16_t reason) noexcept
{
	arcp::Message m;
	arcp::StaEvent e;

	e.sta = sta;
	e.bssid = bss_[bss].info.bssid;
	e.event = static_cast<std::uint8_t>(ev);
	e.reason = reason;
	msg_begin(m, arcp::MsgType::sta_event, 0U);
	(void)m.add(e);
	multicast(m);
}

void Daemon::send_bye() noexcept
{
	arcp::Message m;
	msg_begin(m, arcp::MsgType::bye, 0U);
	multicast(m);
}

// ---- receive ----

void Daemon::rx_tlvs(Peer &p, ByteView frame, const arcp::Header &h) noexcept
{
	arcp::TlvReader rd(frame, h);
	std::uint8_t t = 0U;
	ByteView v;
	bool bss_changed = false;
	std::size_t n_rf = 0U;

	while (rd.next(t, v)) {
		switch (static_cast<arcp::Tlv>(t)) {
		case arcp::Tlv::ap_info: {
			arcp::ApInfo ai;
			if (arcp::decode(v, ai)) {
				p.name = ai.name;
				p.flags = ai.flags;
			}
			break;
		}
		case arcp::Tlv::bss_info: {
			arcp::BssInfo bi;
			if (arcp::decode(v, bi)) {
				const RemoteBss *const rb = peer_bss_update(p, bi);
				bss_changed = bss_changed || ((rb != nullptr) && !rb->nr_installed);
			}
			break;
		}
		case arcp::Tlv::bss_load: {
			arcp::BssLoad bl;
			if (arcp::decode(v, bl)) {
				RemoteBss *const rb = peer_bss_find(p, bl.bssid);
				if (rb != nullptr) {
					rb->load = bl;
					rb->has_load = true;
				}
			}
			break;
		}
		case arcp::Tlv::sta_entry: {
			arcp::StaEntry e;
			if (arcp::decode(v, e)) {
				remote_sta_update(p.id, e);
			}
			break;
		}
		case arcp::Tlv::rf_info:
			if ((n_rf < kMaxRadio) && arcp::decode(v, p.rf[n_rf])) {
				n_rf++;
				p.n_rf = n_rf;
			}
			break;
		case arcp::Tlv::sta_event: {
			arcp::StaEvent e;
			if (arcp::decode(v, e)) {
				if (e.event == static_cast<std::uint8_t>(arcp::StaEventType::assoc)) {
					arcp::StaEntry se;
					se.sta = e.sta;
					se.bssid = e.bssid;
					remote_sta_update(p.id, se);
				} else {
					remote_sta_forget(e.sta);
				}
				steer_on_sta_event(p.id, e);
			}
			break;
		}
		case arcp::Tlv::steer_req: {
			arcp::SteerReq r;
			if (arcp::decode(v, r)) {
				steer_on_req(p, r);
			}
			break;
		}
		case arcp::Tlv::steer_resp: {
			arcp::SteerResp r;
			if (arcp::decode(v, r)) {
				steer_on_resp(p, r);
			}
			break;
		}
		case arcp::Tlv::steer_result: {
			arcp::SteerResult r;
			if (arcp::decode(v, r)) {
				steer_on_result(p, r);
			}
			break;
		}
		case arcp::Tlv::sta_monitor_req: {
			arcp::StaMonitorReq r;
			if (arcp::decode(v, r)) {
				amon_on_req(p, r);
			}
			break;
		}
		case arcp::Tlv::sta_monitor_result: {
			arcp::StaMonitorResult r;
			if (arcp::decode(v, r)) {
				amon_on_result(p.id, r);
			}
			break;
		}
		case arcp::Tlv::ack: {
			std::uint32_t id = 0U;
			if (arcp::decode_ack(v, id)) {
				ack_received(p.id, id);
			}
			break;
		}
		default:
			break; // unknown TLVs are ignored (forward compatibility)
		}
	}
	if (bss_changed) {
		nr_sync();
	}
}

void Daemon::msg_rx(std::size_t port) noexcept
{
	std::array<std::uint8_t, arcp::kMaxPayload + 64U> buf{};
	bool more = true;

	while (more) {
		Mac src;
		std::size_t n = 0U;
		more = l2_.recv(port, src, span_of(buf), n) == os::Rx::data;
		if (!more) {
			break;
		}
		const ByteView frame = view_of(buf).first(n);
		const std::optional<arcp::Header> h = arcp::parse_header(frame);
		if (!h.has_value() || (h->origin == ap_id_)) {
			continue;
		}
		if (!arcp::verify(frame, *h, cfg_.key_view())) {
			logging::dbg(kMod, "rx: {} from {} failed authentication", arcp::msg_name(h->type),
				     h->origin);
			continue;
		}
		const bool is_new_peer = peer_find(h->origin) == nullptr;
		if (h->type == arcp::raw(arcp::MsgType::bye)) {
			Peer *const p = peer_find(h->origin);
			if ((p != nullptr) && peer_accept_seq(*p, h->boot_id, h->msg_id)) {
				peer_remove(*p);
			}
			continue;
		}
		Peer *const p = peer_get(h->origin);
		if (p == nullptr) {
			continue;
		}
		if (!peer_accept_seq(*p, h->boot_id, h->msg_id)) {
			// Duplicate (other path or retransmission): ACK again.
			if ((h->flags & arcp::kFlagAckReq) != 0U) {
				send_ack(p->id, h->msg_id);
			}
			continue;
		}
		// The path delivering the first copy of a new message wins, so
		// unicast follows backhaul changes (wired <-> wireless).
		p->port = port;
		p->l2addr = src;
		p->last_seen = os::now_ms();
		trace("rx", frame, &h->origin, l2_.port(port).name.view(), 1);
		if ((h->flags & arcp::kFlagAckReq) != 0U) {
			send_ack(p->id, h->msg_id);
		}
		rx_tlvs(*p, frame, *h);
		if (is_new_peer) {
			next_hello_ = 0U; // introduce ourselves
			next_bss_status_ = 0U;
		}
	}
}

} // namespace donghoa
