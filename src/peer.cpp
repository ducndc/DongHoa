// SPDX-License-Identifier: MIT
// Peer table, replay window, remote BSSes and STAs, expiry.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::peer};

} // namespace

bool peer_accept_seq(Peer &p, std::uint32_t boot_id, std::uint32_t msg_id) noexcept
{
	bool accept = false;

	if (boot_id != p.boot_id) {
		if (p.boot_id != 0U) {
			logging::info(kMod, "peer {} restarted", p.id);
		}
		p.boot_id = boot_id;
		p.seq_hi = msg_id;
		p.seq_win = 1U;
		accept = true;
	} else if (msg_id > p.seq_hi) {
		const std::uint32_t diff = msg_id - p.seq_hi;
		p.seq_win = (diff >= 64U) ? 0U : (p.seq_win << diff);
		p.seq_win |= 1U;
		p.seq_hi = msg_id;
		accept = true;
	} else {
		const std::uint32_t diff = p.seq_hi - msg_id;
		const std::uint64_t bit = (diff < 64U) ? (static_cast<std::uint64_t>(1U) << diff) : 0U;
		if ((bit != 0U) && ((p.seq_win & bit) == 0U)) {
			p.seq_win |= bit;
			accept = true;
		}
	}
	return accept;
}

Peer *Daemon::peer_find(const Mac &id) noexcept
{
	Peer *r = nullptr;
	for (Peer &p : peers_) {
		if ((r == nullptr) && p.used && (p.id == id)) {
			r = &p;
		}
	}
	return r;
}

Peer *Daemon::peer_get(const Mac &id) noexcept
{
	Peer *r = peer_find(id);
	for (Peer &p : peers_) {
		if ((r == nullptr) && !p.used) {
			p = Peer{};
			p.used = true;
			p.id = id;
			logging::info(kMod, "peer {} discovered", id);
			r = &p;
		}
	}
	if (r == nullptr) {
		logging::warn(kMod, "peer table full, ignoring {}", id);
	}
	return r;
}

RemoteBss *Daemon::peer_bss_find(Peer &p, const Mac &bssid) noexcept
{
	RemoteBss *r = nullptr;
	for (RemoteBss &b : p.bss) {
		if ((r == nullptr) && b.used && (b.info.bssid == bssid)) {
			r = &b;
		}
	}
	return r;
}

RemoteBss *Daemon::peer_bss_update(Peer &p, const arcp::BssInfo &bi) noexcept
{
	RemoteBss *rb = peer_bss_find(p, bi.bssid);

	if (rb == nullptr) {
		for (RemoteBss &b : p.bss) {
			if ((rb == nullptr) && !b.used) {
				rb = &b;
			}
		}
		if (rb != nullptr) {
			*rb = RemoteBss{};
			rb->used = true;
			logging::info(kMod, "peer {}: BSS {} ch {}", p.id, bi.bssid, bi.channel);
		}
	} else if (rb->info != bi) {
		// Neighbor report content changed: re-install.
		rb->nr_installed = false;
	} else {
		// unchanged
	}
	if (rb != nullptr) {
		rb->info = bi;
		rb->ts = os::now_ms();
	}
	return rb;
}

RemoteBss *Daemon::remote_bss_lookup(const Mac &bssid, Peer **owner) noexcept
{
	RemoteBss *r = nullptr;
	for (Peer &p : peers_) {
		if ((r == nullptr) && p.used) {
			r = peer_bss_find(p, bssid);
			if ((r != nullptr) && (owner != nullptr)) {
				*owner = &p;
			}
		}
	}
	return r;
}

void Daemon::peer_remove(Peer &p) noexcept
{
	logging::info(kMod, "peer {} ({}) lost", p.id, p.name);
	steer_on_peer_lost(p);
	for (const RemoteBss &b : p.bss) {
		if (b.used) {
			nr_remove(b.info);
		}
	}
	for (RemoteSta &r : rsta_) {
		if (r.used && (r.ap == p.id)) {
			r.used = false;
		}
	}
	p.used = false;
}

void Daemon::peer_expire(Millis now) noexcept
{
	const Millis bss_age = (3U * static_cast<Millis>(cfg_.bss_status_ms)) + static_cast<Millis>(cfg_.hello_ms);

	for (Peer &p : peers_) {
		if (!p.used) {
			continue;
		}
		if ((now - p.last_seen) > static_cast<Millis>(cfg_.peer_timeout_ms)) {
			peer_remove(p);
			continue;
		}
		// Drop BSSes the peer stopped advertising.
		for (RemoteBss &b : p.bss) {
			if (b.used && ((now - b.ts) > bss_age)) {
				nr_remove(b.info);
				b.used = false;
			}
		}
	}
	for (RemoteSta &r : rsta_) {
		if (r.used && ((now - r.ts) > (3U * static_cast<Millis>(cfg_.sta_status_ms)))) {
			r.used = false;
		}
	}
}

void Daemon::remote_sta_update(const Mac &ap, const arcp::StaEntry &e) noexcept
{
	RemoteSta *r = nullptr;
	RemoteSta *free_slot = nullptr;

	for (RemoteSta &x : rsta_) {
		if ((r == nullptr) && x.used && (x.sta == e.sta)) {
			r = &x;
		}
		if ((free_slot == nullptr) && !x.used) {
			free_slot = &x;
		}
	}
	if ((r == nullptr) && (free_slot != nullptr)) {
		r = free_slot;
		r->used = true;
		r->sta = e.sta;
	}
	if (r != nullptr) {
		r->ap = ap;
		r->bssid = e.bssid;
		r->rssi = e.rssi;
		r->flags = e.flags;
		r->ts = os::now_ms();
	}
}

void Daemon::remote_sta_forget(const Mac &sta) noexcept
{
	for (RemoteSta &r : rsta_) {
		if (r.used && (r.sta == sta)) {
			r.used = false;
		}
	}
}

} // namespace donghoa
