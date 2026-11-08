// SPDX-License-Identifier: MIT
// ARCP messaging: periodic messages, reliable unicast, receive path.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::MSG};
constexpr Millis RETX_INTERVAL_MS = 300U;
constexpr int RETX_MAX_TRIES = 4;

} // namespace

void Daemon::beginMsg(arcp::Message &m, arcp::MsgType type, std::uint8_t flags) noexcept
{
	mNextMsgId++;
	m.begin(type, flags, mApId, mBootId, mNextMsgId);
}

bool Daemon::finish(arcp::Message &m) noexcept
{
	const bool ok = m.finish(mCfg.keyView());
	if (!ok) {
		logging::err(LOG_MODULE, "tx: message type {} overflow", m.type());
	}
	return ok;
}

// Debug trace of one ARCP frame: "<dir> <TYPE> #<id> <peer> via <port>
// [flags]: <TLV list>". Built only when module msg logs at debug.
void Daemon::trace(std::string_view dir, ByteView frame, const Mac *peer, std::string_view port,
		   int tries) const noexcept
{
	if (!logging::enabled(LOG_MODULE, LogLevel::DEBUG)) {
		return;
	}
	const std::optional<arcp::Header> h = arcp::parseHeader(frame);
	if (!h.has_value()) {
		return;
	}
	std::array<std::uint8_t, 16U> order{};
	std::array<std::uint16_t, 256U> count{};
	std::size_t nOrder = 0U;
	arcp::TlvReader rd(frame, *h);
	std::uint8_t t = 0U;
	ByteView v;

	while (rd.next(t, v)) {
		if ((count[t] == 0U) && (nOrder < order.size())) {
			order[nOrder] = t;
			nOrder++;
		}
		count[t]++;
	}
	FixedString<256U> tlvs;
	for (std::size_t i = 0U; i < nOrder; i++) {
		if (count[order[i]] > 1U) {
			formatTo(tlvs, " {}*{}", arcp::tlvName(order[i]), count[order[i]]);
		} else {
			formatTo(tlvs, " {}", arcp::tlvName(order[i]));
		}
	}
	FixedString<24U> who{"group"};
	if (peer != nullptr) {
		who.clear();
		formatTo(who, "{}", *peer);
	}
	logging::dbg(LOG_MODULE, "{} {} #{} {} via {}{}{}{}:{}", dir, arcp::msgName(h->type), h->msgId, who,
		     port, ((h->flags & arcp::FLAG_ACK_REQ) != 0U) ? " [ack-req]" : "",
		     ((h->flags & arcp::FLAG_AUTH) != 0U) ? " [auth]" : "", (tries > 1) ? " [retry]" : "",
		     tlvs);
}

void Daemon::multicast(arcp::Message &m) noexcept
{
	if (finish(m)) {
		const std::string_view port = (mL2.size() > 1U) ? std::string_view("all ports")
					      : ((mL2.size() == 1U) ? mL2.port(0U).name.view()
								    : std::string_view("-"));
		trace("tx", m.bytes(), nullptr, port, 1);
		for (std::size_t i = 0U; i < mL2.size(); i++) {
			(void)mL2.send(i, arcp::GROUP_ADDR, m.bytes());
		}
	}
}

bool Daemon::unicast(const Mac &peerId, arcp::Message &m) noexcept
{
	const Peer *const p = findPeer(peerId);
	bool ok = (p != nullptr) && p->port.has_value();

	if (!ok) {
		logging::warn(LOG_MODULE, "tx: peer {} unreachable", peerId);
	} else {
		ok = finish(m);
	}
	if (ok) {
		trace("tx", m.bytes(), &peerId, mL2.port(*p->port).name.view(), 1);
		(void)mL2.send(*p->port, p->l2addr, m.bytes());
		if ((m.flags() & arcp::FLAG_ACK_REQ) != 0U) {
			bool queued = false;
			for (PendingTx &t : mPending) {
				if (!queued && !t.used) {
					t.used = true;
					t.msgId = m.msgId();
					t.peer = peerId;
					t.tries = 1;
					t.nextTry = os::nowMs() + RETX_INTERVAL_MS;
					t.msg = m;
					queued = true;
				}
			}
			if (!queued) {
				logging::warn(LOG_MODULE, "tx: pending queue full, no retransmission");
			}
		}
	}
	return ok;
}

void Daemon::retransmit(Millis now) noexcept
{
	for (PendingTx &t : mPending) {
		if (t.used && (now >= t.nextTry)) {
			const Peer *const p = findPeer(t.peer);
			if ((p == nullptr) || !p->port.has_value() || (t.tries >= RETX_MAX_TRIES)) {
				logging::warn(LOG_MODULE, "tx: {} msg {} to {} not acknowledged",
					      arcp::msgName(t.msg.type()), t.msgId, t.peer);
				t.used = false;
			} else {
				t.tries++;
				trace("tx", t.msg.bytes(), &t.peer, mL2.port(*p->port).name.view(), t.tries);
				(void)mL2.send(*p->port, p->l2addr, t.msg.bytes());
				t.nextTry = now + RETX_INTERVAL_MS;
			}
		}
	}
}

void Daemon::onAckReceived(const Mac &peer, std::uint32_t id) noexcept
{
	for (PendingTx &t : mPending) {
		if (t.used && (t.msgId == id) && (t.peer == peer)) {
			t.used = false;
		}
	}
}

void Daemon::sendAck(const Mac &peer, std::uint32_t id) noexcept
{
	arcp::Message m;
	beginMsg(m, arcp::MsgType::ACK, 0U);
	(void)m.addAck(id);
	(void)unicast(peer, m);
}

// ---- periodic messages ----

// HELLO and BSS_STATUS carry every local BSS in one message, and a message
// that overflows is not sent at all: raising MAX_BSS must keep them inside
// MAX_PAYLOAD (header, worst-case TLVs, AUTH).
static_assert((arcp::HDR_LEN + (arcp::TLV_HDR_LEN + arcp::AP_INFO_MAX_LEN) +
	       (MAX_BSS * (arcp::TLV_HDR_LEN + arcp::BSS_INFO_MAX_LEN)) + arcp::TLV_HDR_LEN +
	       arcp::AUTH_LEN) <=
		      arcp::MAX_PAYLOAD,
	      "HELLO with MAX_BSS BSSes does not fit one ARCP message");
static_assert((arcp::HDR_LEN +
	       (MAX_BSS * ((arcp::TLV_HDR_LEN + arcp::BSS_INFO_MAX_LEN) + (arcp::TLV_HDR_LEN +
									   arcp::BSS_LOAD_LEN))) +
	       arcp::TLV_HDR_LEN + arcp::AUTH_LEN) <= arcp::MAX_PAYLOAD,
	      "BSS_STATUS with MAX_BSS BSSes does not fit one ARCP message");

void Daemon::sendHello() noexcept
{
	arcp::Message m;
	arcp::ApInfo ai;

	ai.helloMs = static_cast<std::uint16_t>(mCfg.helloMs);
	(void)ai.name.assign(mCfg.name.view());
	if (canMeasureStas()) {
		ai.flags = static_cast<std::uint16_t>(ai.flags | arcp::AP_FLAG_AIR_MONITOR);
	}
	for (std::size_t i = 0U; i < mNBss; i++) {
		if (mBss[i].up) {
			ai.numBss++;
		}
	}
	beginMsg(m, arcp::MsgType::HELLO, 0U);
	(void)m.add(ai);
	for (std::size_t i = 0U; i < mNBss; i++) {
		if (mBss[i].up) {
			(void)m.add(mBss[i].info);
		}
	}
	multicast(m);
}

void Daemon::sendBssStatus() noexcept
{
	arcp::Message m;
	beginMsg(m, arcp::MsgType::BSS_STATUS, 0U);
	for (std::size_t i = 0U; i < mNBss; i++) {
		if (mBss[i].up) {
			(void)m.add(mBss[i].info);
			(void)m.add(mBss[i].load);
		}
	}
	multicast(m);
}

void Daemon::sendStaStatus() noexcept
{
	arcp::Message m;
	bool open = false;

	for (const Sta &s : mSta) {
		if (s.used && !s.away && mBss[s.bss].up) {
			if (open && (m.room() < (arcp::TLV_HDR_LEN + arcp::STA_ENTRY_LEN))) {
				multicast(m);
				open = false;
			}
			if (!open) {
				beginMsg(m, arcp::MsgType::STA_STATUS, 0U);
				open = true;
			}
			(void)m.add(fillEntry(s));
		}
	}
	if (open) {
		multicast(m);
	}
}

void Daemon::sendRfStatus() noexcept
{
	arcp::Message m;
	std::size_t n = 0U;

	beginMsg(m, arcp::MsgType::RF_STATUS, 0U);
	// One RF_INFO per distinct operating channel (radio).
	for (std::size_t i = 0U; i < mNBss; i++) {
		const LocalBss &b = mBss[i];
		bool dup = false;
		for (std::size_t j = 0U; j < i; j++) {
			dup = dup || (mBss[j].up && (mBss[j].info.freq == b.info.freq));
		}
		if (b.up && !dup) {
			arcp::RfInfo rf;
			rf.radioId = static_cast<std::uint8_t>(i);
			rf.freq = b.info.freq;
			rf.opClass = b.info.opClass;
			rf.channel = b.info.channel;
			rf.bw = b.info.bw;
			rf.util = b.load.util;
			rf.noise = b.load.noise;
			rf.txPower = b.load.txPower;
			(void)m.add(rf);
			n++;
		}
	}
	if (n > 0U) {
		multicast(m);
	}
}

void Daemon::sendStaEvent(const Mac &sta, std::size_t bss, arcp::StaEventType ev,
			    std::uint16_t reason) noexcept
{
	arcp::Message m;
	arcp::StaEvent e;

	e.sta = sta;
	e.bssid = mBss[bss].info.bssid;
	e.event = static_cast<std::uint8_t>(ev);
	e.reason = reason;
	beginMsg(m, arcp::MsgType::STA_EVENT, 0U);
	(void)m.add(e);
	multicast(m);
}

void Daemon::sendBye() noexcept
{
	arcp::Message m;
	beginMsg(m, arcp::MsgType::BYE, 0U);
	multicast(m);
}

// ---- receive ----

void Daemon::handleTlvs(Peer &p, ByteView frame, const arcp::Header &h) noexcept
{
	arcp::TlvReader rd(frame, h);
	std::uint8_t t = 0U;
	ByteView v;
	bool bssChanged = false;
	std::size_t nRf = 0U;

	while (rd.next(t, v)) {
		switch (static_cast<arcp::Tlv>(t)) {
		case arcp::Tlv::AP_INFO: {
			arcp::ApInfo ai;
			if (arcp::decode(v, ai)) {
				p.name = ai.name;
				p.flags = ai.flags;
			}
			break;
		}
		case arcp::Tlv::BSS_INFO: {
			arcp::BssInfo bi;
			if (arcp::decode(v, bi)) {
				const RemoteBss *const rb = updatePeerBss(p, bi);
				bssChanged = bssChanged || ((rb != nullptr) && !rb->nrInstalled);
			}
			break;
		}
		case arcp::Tlv::BSS_LOAD: {
			arcp::BssLoad bl;
			if (arcp::decode(v, bl)) {
				RemoteBss *const rb = findPeerBss(p, bl.bssid);
				if (rb != nullptr) {
					rb->load = bl;
					rb->hasLoad = true;
				}
			}
			break;
		}
		case arcp::Tlv::STA_ENTRY: {
			arcp::StaEntry e;
			if (arcp::decode(v, e)) {
				updateRemoteSta(p.id, e);
			}
			break;
		}
		case arcp::Tlv::RF_INFO:
			if ((nRf < MAX_RADIO) && arcp::decode(v, p.rf[nRf])) {
				nRf++;
				p.nRf = nRf;
			}
			break;
		case arcp::Tlv::STA_EVENT: {
			arcp::StaEvent e;
			if (arcp::decode(v, e)) {
				if (e.event == static_cast<std::uint8_t>(arcp::StaEventType::ASSOC)) {
					arcp::StaEntry se;
					se.sta = e.sta;
					se.bssid = e.bssid;
					updateRemoteSta(p.id, se);
					onPeerStaAssoc(p.id, e.sta);
				} else {
					forgetRemoteSta(e.sta);
				}
				onStaEvent(p.id, e);
			}
			break;
		}
		case arcp::Tlv::STA_CLASS: {
			arcp::StaClass c;
			if (arcp::decode(v, c)) {
				onStaClass(p, c);
			}
			break;
		}
		case arcp::Tlv::STA_ROAM: {
			arcp::StaRoam r;
			if (arcp::decode(v, r)) {
				onStaRoam(p, r);
			}
			break;
		}
		case arcp::Tlv::STEER_REQ: {
			arcp::SteerReq r;
			if (arcp::decode(v, r)) {
				onSteerReq(p, r);
			}
			break;
		}
		case arcp::Tlv::STEER_RESP: {
			arcp::SteerResp r;
			if (arcp::decode(v, r)) {
				onSteerResp(p, r);
			}
			break;
		}
		case arcp::Tlv::STEER_RESULT: {
			arcp::SteerResult r;
			if (arcp::decode(v, r)) {
				onSteerResult(p, r);
			}
			break;
		}
		case arcp::Tlv::STA_MONITOR_REQ: {
			arcp::StaMonitorReq r;
			if (arcp::decode(v, r)) {
				onAmonReq(p, r);
			}
			break;
		}
		case arcp::Tlv::STA_MONITOR_RESULT: {
			arcp::StaMonitorResult r;
			if (arcp::decode(v, r)) {
				onAmonResult(p.id, r);
			}
			break;
		}
		case arcp::Tlv::STA_MONITOR_STATUS: {
			arcp::StaMonitorStatus r;
			if (arcp::decode(v, r)) {
				onAmonStatus(p.id, r);
			}
			break;
		}
		case arcp::Tlv::ACK: {
			std::uint32_t id = 0U;
			if (arcp::decodeAck(v, id)) {
				onAckReceived(p.id, id);
			}
			break;
		}
		default:
			break; // unknown TLVs are ignored (forward compatibility)
		}
	}
	if (bssChanged) {
		syncNeighbors();
	}
}

void Daemon::receiveMsg(std::size_t port) noexcept
{
	std::array<std::uint8_t, arcp::MAX_PAYLOAD + 64U> buf{};
	bool more = true;

	while (more) {
		Mac src;
		std::size_t n = 0U;
		more = mL2.recv(port, src, spanOf(buf), n) == os::Rx::DATA;
		if (!more) {
			break;
		}
		const ByteView frame = viewOf(buf).first(n);
		const std::optional<arcp::Header> h = arcp::parseHeader(frame);
		if (!h.has_value() || (h->origin == mApId)) {
			continue;
		}
		if (!arcp::verify(frame, *h, mCfg.keyView())) {
			logging::dbg(LOG_MODULE, "rx: {} from {} failed authentication",
				     arcp::msgName(h->type), h->origin);
			continue;
		}
		if ((mDropCount > 0U) && (h->type == mDropType)) {
			mDropCount--;
			logging::info(LOG_MODULE, "rx: {} #{} from {} dropped (fault injection, {} left)",
				      arcp::msgName(h->type), h->msgId, h->origin, mDropCount);
			continue;
		}
		const bool isNewPeer = findPeer(h->origin) == nullptr;
		if (h->type == arcp::raw(arcp::MsgType::BYE)) {
			Peer *const p = findPeer(h->origin);
			if ((p != nullptr) && acceptPeerSeq(*p, h->bootId, h->msgId)) {
				removePeer(*p);
			}
			continue;
		}
		Peer *const p = getPeer(h->origin);
		if (p == nullptr) {
			continue;
		}
		const bool restarted = (p->bootId != 0U) && (p->bootId != h->bootId);
		if (!acceptPeerSeq(*p, h->bootId, h->msgId)) {
			// Duplicate (other path or retransmission): ACK again.
			if ((h->flags & arcp::FLAG_ACK_REQ) != 0U) {
				sendAck(p->id, h->msgId);
			}
			continue;
		}
		// The path delivering the first copy of a new message wins, so
		// unicast follows backhaul changes (wired <-> wireless).
		p->port = port;
		p->l2addr = src;
		p->lastSeen = os::nowMs();
		trace("rx", frame, &h->origin, mL2.port(port).name.view(), 1);
		if ((h->flags & arcp::FLAG_ACK_REQ) != 0U) {
			sendAck(p->id, h->msgId);
		}
		handleTlvs(*p, frame, *h);
		if (isNewPeer) {
			mNextHello = 0U; // introduce ourselves
			mNextBssStatus = 0U;
		}
		if (isNewPeer || restarted) {
			syncDevClass(p->id); // it may have lost the device classes
		}
	}
}

} // namespace donghoa
