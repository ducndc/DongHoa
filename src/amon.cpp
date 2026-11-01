// SPDX-License-Identifier: MIT
// Air monitor: measure the RSSI of STAs from the frames they send, on
// radiotap monitor interfaces. Used when a STA gives no 802.11k beacon
// report (no 11k support, or too busy to answer).
//
// A source AP asks with STA_MONITOR_REQ; this AP watches the STA for the
// requested time and answers with one STA_MONITOR_RESULT per local BSS on
// whose frequency the STA was heard. A stock radio hears only its own
// channel: uplink data of STAs on that channel, probe requests of scanning
// STAs.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::amon};
constexpr int kMaxDurationMs = 5000;

} // namespace

void Daemon::amon_init() noexcept
{
	n_amon_ = 0U;
	for (std::size_t i = 0U; i < cfg_.n_monitors; i++) {
		AmonPort &p = amon_[n_amon_];
		p.fd = os::monitor_open(cfg_.monitors[i].c_str());
		if (p.fd.valid()) {
			p.sim = false;
			p.name = cfg_.monitors[i];
			logging::info(kMod, "listening on {}", p.name);
			n_amon_++;
		} else {
			// A missing monitor is not fatal: this AP just cannot measure.
			logging::err(kMod, "{}: {} (a monitor interface: iw phy <phy> interface add {} type monitor)",
				     cfg_.monitors[i], os::last_error(), cfg_.monitors[i]);
		}
	}
	if (cfg_.monitor_sim_port != 0U) {
		// Test input: radiotap frames in UDP datagrams on loopback.
		AmonPort &p = amon_[n_amon_];
		p.fd = os::udp_bind_loopback(cfg_.monitor_sim_port);
		if (p.fd.valid()) {
			p.sim = true;
			p.name.clear();
			format_to(p.name, "amonsim{}", cfg_.monitor_sim_port);
			logging::info(kMod, "sim input on udp {}", cfg_.monitor_sim_port);
			n_amon_++;
		} else {
			logging::err(kMod, "sim port {}: {}", cfg_.monitor_sim_port, os::last_error());
		}
	}
}

void Daemon::amon_sample(const rrm::AirFrame &f) noexcept
{
	const Millis now = os::now_ms();

	for (AmonWatch &w : watch_) {
		if (!w.used || (w.sta != f.ta) || (now >= w.until)) {
			continue;
		}
		AmonAcc *a = nullptr;
		for (AmonAcc &x : w.acc) {
			if ((a == nullptr) && (x.n != 0) && (x.freq == f.freq)) {
				a = &x;
			}
		}
		for (AmonAcc &x : w.acc) {
			if ((a == nullptr) && (x.n == 0)) {
				a = &x;
			}
		}
		if (a != nullptr) {
			a->freq = f.freq;
			a->sum += f.signal;
			a->n++;
			a->last = now;
		}
	}
}

void Daemon::amon_rx(std::size_t port) noexcept
{
	std::array<std::uint8_t, 512U> buf{};
	bool more = port < n_amon_;

	while (more) {
		std::size_t n = 0U;
		more = os::recv_nowait(amon_[port].fd, span_of(buf), n) == os::Rx::data;
		if (more) {
			const std::optional<rrm::AirFrame> f = rrm::radiotap_parse(view_of(buf).first(n));
			if (f.has_value()) {
				amon_sample(*f);
			}
		}
	}
}

bool Daemon::amon_watch_start(const Mac &sta, const Mac &requester, std::uint32_t txn,
			      int duration_ms) noexcept
{
	AmonWatch *w = nullptr;
	const int dur = ((duration_ms <= 0) || (duration_ms > kMaxDurationMs)) ? cfg_.pol.amon_duration_ms
									       : duration_ms;

	if (n_amon_ == 0U) {
		return false;
	}
	for (AmonWatch &x : watch_) {
		if ((w == nullptr) && !x.used) {
			w = &x;
		}
	}
	if (w == nullptr) {
		logging::warn(kMod, "watch table full, {} not measured", sta);
		return false;
	}
	*w = AmonWatch{};
	w->used = true;
	w->sta = sta;
	w->requester = requester;
	w->txn = txn;
	w->until = os::now_ms() + static_cast<Millis>(dur);
	logging::dbg(kMod, "watching {} for {} ms (txn {})", sta, dur, txn);
	return true;
}

void Daemon::amon_on_req(const Peer &from, const arcp::StaMonitorReq &r) noexcept
{
	if (amon_watch_start(r.sta, from.id, r.txn, static_cast<int>(r.duration_ms))) {
		logging::info(kMod, "{} asks to measure {} (ch {})", from.id, r.sta, r.channel);
	}
}

// Watch over: one result per local BSS on a frequency the STA was heard on.
void Daemon::amon_finish(AmonWatch &w, Millis now) noexcept
{
	const bool local = w.requester == ap_id_;
	arcp::Message m;
	std::size_t n = 0U;

	if (!local) {
		msg_begin(m, arcp::MsgType::sta_monitor_report, arcp::kFlagAckReq);
	}
	for (const AmonAcc &a : w.acc) {
		if (a.n == 0) {
			continue;
		}
		for (std::size_t b = 0U; b < n_bss_; b++) {
			if (!bss_[b].up || (static_cast<int>(bss_[b].info.freq) != a.freq)) {
				continue;
			}
			const Millis age = now - a.last;
			arcp::StaMonitorResult r;
			r.txn = w.txn;
			r.sta = w.sta;
			r.bssid = bss_[b].info.bssid;
			r.rssi = static_cast<std::int8_t>(a.sum / a.n);
			r.samples = static_cast<std::uint16_t>((a.n > 65535) ? 65535 : a.n);
			r.age_ms = static_cast<std::uint16_t>((age > 65535U) ? 65535U : age);
			if (local) {
				amon_on_result(ap_id_, r);
			} else {
				(void)m.add(r);
			}
			n++;
		}
	}
	if (n == 0U) {
		logging::dbg(kMod, "{} not heard", w.sta);
	} else if (!local) {
		(void)unicast(w.requester, m);
	} else {
		// local results already stored
	}
	w.used = false;
}

void Daemon::amon_tick(Millis now) noexcept
{
	for (AmonWatch &w : watch_) {
		if (w.used && (now >= w.until)) {
			amon_finish(w, now);
		}
	}
}

void Daemon::amon_on_result(const Mac &from, const arcp::StaMonitorResult &r) noexcept
{
	Sta *const s = sta_find(r.sta);
	const RemoteBss *const rb = remote_bss_lookup(r.bssid, nullptr);
	const std::optional<std::size_t> b = local_bss_by_bssid(r.bssid);
	const arcp::BssInfo *const bi = (rb != nullptr) ? &rb->info : (b.has_value() ? &bss_[*b].info : nullptr);

	logging::info(kMod, "{} heard by {} (AP {}): {} dBm, {} samples", r.sta, r.bssid, from, r.rssi, r.samples);
	if ((s != nullptr) && (bi != nullptr)) {
		meas_store(*s, r.bssid, MeasSrc::air_monitor,
			   rrm::dbm_to_rcpi(static_cast<int>(r.rssi) + cfg_.pol.amon_rssi_offset), bi->op_class,
			   bi->channel, os::now_ms() - r.age_ms);
		steer_on_monitor_result(*s);
	}
}

} // namespace donghoa
