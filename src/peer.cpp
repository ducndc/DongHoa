// SPDX-License-Identifier: MIT
// Peer table, replay window, remote BSSes and STAs, expiry.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::PEER};

} // namespace

bool acceptPeerSeq(Peer &p, std::uint32_t bootId, std::uint32_t msgId) noexcept
{
	arcp::ReplayWindow w{p.bootId, p.seqHi, p.seqWin};
	const bool accept = arcp::acceptSeq(w, bootId, msgId);
	p.bootId = w.bootId;
	p.seqHi = w.seqHi;
	p.seqWin = w.seqWin;
	return accept;
}

Peer *Daemon::findPeer(const Mac &id) noexcept
{
	Peer *r = nullptr;
	for (Peer &p : mPeers) {
		if ((r == nullptr) && p.used && (p.id == id)) {
			r = &p;
		}
	}
	return r;
}

const RemoteSta *Daemon::findRemoteSta(const Mac &sta) const noexcept
{
	const RemoteSta *r = nullptr;
	for (const RemoteSta &x : mRsta) {
		if ((r == nullptr) && x.used && (x.sta == sta)) {
			r = &x;
		}
	}
	return r;
}

Peer *Daemon::getPeer(const Mac &id) noexcept
{
	Peer *r = findPeer(id);
	for (Peer &p : mPeers) {
		if ((r == nullptr) && !p.used) {
			p = Peer{};
			p.used = true;
			p.id = id;
			logging::notice(LOG_MODULE, "peer {} discovered", id);
			r = &p;
		}
	}
	if (r == nullptr) {
		logging::warn(LOG_MODULE, "peer table full, ignoring {}", id);
	}
	return r;
}

RemoteBss *Daemon::findPeerBss(Peer &p, const Mac &bssid) noexcept
{
	RemoteBss *r = nullptr;
	for (RemoteBss &b : p.bss) {
		if ((r == nullptr) && b.used && (b.info.bssid == bssid)) {
			r = &b;
		}
	}
	return r;
}

RemoteBss *Daemon::updatePeerBss(Peer &p, const arcp::BssInfo &bi) noexcept
{
	RemoteBss *rb = findPeerBss(p, bi.bssid);

	if (rb == nullptr) {
		for (RemoteBss &b : p.bss) {
			if ((rb == nullptr) && !b.used) {
				rb = &b;
			}
		}
		if (rb != nullptr) {
			*rb = RemoteBss{};
			rb->used = true;
			logging::info(LOG_MODULE, "peer {}: BSS {} ch {}", p.id, bi.bssid, bi.channel);
		}
	} else if (rb->info != bi) {
		// Neighbor report content changed: re-install.
		rb->nrInstalled = false;
	} else {
		// unchanged
	}
	if (rb != nullptr) {
		rb->info = bi;
		rb->ts = os::nowMs();
	}
	return rb;
}

RemoteBss *Daemon::lookupRemoteBss(const Mac &bssid, Peer **owner) noexcept
{
	RemoteBss *r = nullptr;
	for (Peer &p : mPeers) {
		if ((r == nullptr) && p.used) {
			r = findPeerBss(p, bssid);
			if ((r != nullptr) && (owner != nullptr)) {
				*owner = &p;
			}
		}
	}
	return r;
}

void Daemon::removePeer(Peer &p) noexcept
{
	logging::notice(LOG_MODULE, "peer {} ({}) lost", p.id, p.name);
	onPeerLost(p);
	for (const RemoteBss &b : p.bss) {
		if (b.used) {
			removeNeighbor(b.info);
		}
	}
	for (RemoteSta &r : mRsta) {
		if (r.used && (r.ap == p.id)) {
			r.used = false;
		}
	}
	p.used = false;
}

void Daemon::expirePeers(Millis now) noexcept
{
	const Millis bssAge = (3U * static_cast<Millis>(mCfg.bssStatusMs)) +
			      static_cast<Millis>(mCfg.helloMs);

	for (Peer &p : mPeers) {
		if (!p.used) {
			continue;
		}
		if ((now - p.lastSeen) > static_cast<Millis>(mCfg.peerTimeoutMs)) {
			removePeer(p);
			continue;
		}
		// Drop BSSes the peer stopped advertising.
		for (RemoteBss &b : p.bss) {
			if (b.used && ((now - b.ts) > bssAge)) {
				removeNeighbor(b.info);
				b.used = false;
			}
		}
	}
	for (RemoteSta &r : mRsta) {
		if (r.used && ((now - r.ts) > (3U * static_cast<Millis>(mCfg.staStatusMs)))) {
			r.used = false;
		}
	}
}

void Daemon::updateRemoteSta(const Mac &ap, const arcp::StaEntry &e) noexcept
{
	RemoteSta *r = nullptr;
	RemoteSta *freeSlot = nullptr;

	for (RemoteSta &x : mRsta) {
		if ((r == nullptr) && x.used && (x.sta == e.sta)) {
			r = &x;
		}
		if ((freeSlot == nullptr) && !x.used) {
			freeSlot = &x;
		}
	}
	if ((r == nullptr) && (freeSlot != nullptr)) {
		r = freeSlot;
		r->used = true;
		r->sta = e.sta;
	}
	if (r != nullptr) {
		r->ap = ap;
		r->bssid = e.bssid;
		r->rssi = e.rssi;
		r->flags = e.flags;
		r->ts = os::nowMs();
	}
}

void Daemon::forgetRemoteSta(const Mac &sta) noexcept
{
	for (RemoteSta &r : mRsta) {
		if (r.used && (r.sta == sta)) {
			r.used = false;
		}
	}
}

} // namespace donghoa
