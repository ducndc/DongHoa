// SPDX-License-Identifier: MIT
// Local BSSes and STAs: hostapd polling and events, 802.11k neighbor DB.
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "text.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::local};
constexpr Millis kReconnectMs = 5000U;

} // namespace

void Daemon::local_init() noexcept
{
	n_bss_ = cfg_.n_bss;
	for (std::size_t i = 0U; i < n_bss_; i++) {
		LocalBss &b = bss_[i];
		b.cfg = &cfg_.bss[i];
		b.ifindex = os::ifname_to_index(b.cfg->ifname.c_str());
		b.hapd_util = -1;
	}
	(void)survey_.open();
}

std::optional<std::size_t> Daemon::local_bss_by_bssid(const Mac &bssid) const noexcept
{
	std::optional<std::size_t> r;
	for (std::size_t i = 0U; (i < n_bss_) && !r.has_value(); i++) {
		if (bss_[i].up && (bss_[i].info.bssid == bssid)) {
			r = i;
		}
	}
	return r;
}

// ---- STA table ----

Sta *Daemon::sta_find(const Mac &addr) noexcept
{
	Sta *r = nullptr;
	for (Sta &s : sta_) {
		if ((r == nullptr) && s.used && (s.addr == addr)) {
			r = &s;
		}
	}
	return r;
}

Sta *Daemon::sta_get(const Mac &addr, std::size_t bss) noexcept
{
	Sta *r = sta_find(addr);

	if (r != nullptr) {
		if (r->bss != bss) {
			// Moved between local BSSes (e.g. band steering).
			r->bss = bss;
			r->rssi = 0;
			r->low_count = 0;
			r->n_meas = 0U;
		}
	} else {
		for (Sta &s : sta_) {
			if ((r == nullptr) && !s.used) {
				s = Sta{};
				s.used = true;
				s.addr = addr;
				s.bss = bss;
				// Do not steer a STA right after it joined.
				s.next_steer_ms = os::now_ms() + static_cast<Millis>(cfg_.pol.steer_cooldown_ms);
				r = &s;
			}
		}
		if (r == nullptr) {
			logging::warn(kMod, "STA table full");
		}
	}
	return r;
}

arcp::StaEntry Daemon::fill_entry(const Sta &s) const noexcept
{
	arcp::StaEntry e;

	e.sta = s.addr;
	e.bssid = bss_[s.bss].info.bssid;
	e.rssi = static_cast<std::int8_t>(s.rssi);
	e.flags = s.flags;
	if (s.tput_kbps < static_cast<std::uint32_t>(cfg_.pol.idle_kbps)) {
		e.flags = static_cast<std::uint8_t>(e.flags | arcp::kStaFIdle);
	}
	for (const SteerTxn &t : txn_) {
		if (t.used && (t.sta == s.addr)) {
			e.flags = static_cast<std::uint8_t>(e.flags | arcp::kStaFSteering);
		}
	}
	e.connected_s = s.connected_s;
	e.inactive_ms = s.inactive_ms;
	e.tx_rate_mbps = s.tx_rate;
	e.rx_rate_mbps = s.rx_rate;
	e.tput_kbps = s.tput_kbps;
	return e;
}

void Daemon::sta_apply_sample(Sta &s, const hapd::Sta &h) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	const Millis now = os::now_ms();
	const bool assume = p.assume_kvr;

	if (h.signal != 0) {
		s.rssi = (s.rssi != 0) ? (((3 * s.rssi) + h.signal) - 2) / 4 : h.signal;
		s.low_count = (h.signal < p.rssi_low) ? (s.low_count + 1) : 0;
	}
	const std::uint64_t total = h.rx_bytes + h.tx_bytes;
	const std::uint64_t prev = s.rx_bytes + s.tx_bytes;
	if ((s.bytes_ts != 0U) && (now > s.bytes_ts) && (total >= prev)) {
		s.tput_kbps = static_cast<std::uint32_t>(((total - prev) * 8U) / (now - s.bytes_ts));
	}
	s.rx_bytes = h.rx_bytes;
	s.tx_bytes = h.tx_bytes;
	s.bytes_ts = now;
	s.inactive_ms = h.inactive_ms;
	s.connected_s = h.connected_s;
	s.tx_rate = h.tx_rate_mbps;
	s.rx_rate = h.rx_rate_mbps;

	s.flags = 0U;
	if (h.btm_known ? h.btm : assume) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::kStaF11v);
	}
	if (h.ft_known ? h.ft : (assume && (bss_[s.bss].cfg->mdid != 0U))) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::kStaF11r);
	}
	// No STA 11k indicator in ctrl output; hostapd refusing REQ_BEACON in
	// every mode marks the STA as lacking beacon reports.
	if (assume && !s.bcn_unsupported) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::kStaF11k);
	}
	s.last_poll_ms = now;
}

// ---- BSS polling ----

void Daemon::bss_mark_down(std::size_t i) noexcept
{
	LocalBss &b = bss_[i];

	if (b.up) {
		logging::warn(kMod, "bss {} down", b.cfg->ifname);
	}
	b.up = false;
	b.next_reconnect_ms = os::now_ms() + kReconnectMs;
	for (Sta &s : sta_) {
		if (s.used && (s.bss == i)) {
			s.used = false;
		}
	}
}

void Daemon::bss_refresh(std::size_t i) noexcept
{
	LocalBss &b = bss_[i];
	hapd::Reply reply;
	const arcp::BssInfo old = b.info;
	const bool was_up = b.up;
	std::optional<hapd::Status> st;

	if (b.hapd.cmd("STATUS", reply)) {
		st = hapd::parse_status(reply.view(), b.cfg->ifname.view());
	}
	if (!st.has_value()) {
		bss_mark_down(i);
		return;
	}
	if (!was_up && b.hapd.cmd("GET_CONFIG", reply)) {
		const std::optional<long> wpa = kv_get_int(reply.view(), "wpa");
		b.secured = wpa.has_value() && (*wpa != 0);
		if ((b.cfg->mdid != 0U) && (reply.view().find("FT-") == std::string_view::npos)) {
			logging::warn(kMod, "bss {}: mdid configured but hostapd key_mgmt has no FT AKM",
				      b.cfg->ifname);
		}
	}

	b.info = arcp::BssInfo{};
	b.info.bssid = st->bssid;
	b.info.freq = static_cast<std::uint16_t>(st->freq);
	b.info.channel = st->channel;
	b.info.band = st->band;
	b.info.bw = st->bw;
	b.info.op_class = rrm::op_class_20mhz(st->band, st->channel);
	// 11k/11v must be enabled in hostapd (see README).
	b.info.caps = static_cast<std::uint16_t>(st->caps | arcp::kCapBtm | arcp::kCapRrmNr | arcp::kCapRrmBcn);
	if (b.cfg->mdid != 0U) {
		b.info.caps = static_cast<std::uint16_t>(b.info.caps | arcp::kCapFt);
	}
	if (b.cfg->ft_over_ds) {
		b.info.caps = static_cast<std::uint16_t>(b.info.caps | arcp::kCapFtOverDs);
	}
	b.info.mdid = b.cfg->mdid;
	b.info.phy_type = rrm::phy_type_from_caps(b.info.caps, st->band);
	b.info.bssid_info = rrm::bssid_info_build(b.info.caps, b.secured);
	b.info.ssid_len = st->ssid_len;
	b.info.ssid = st->ssid;

	b.hapd_util = st->chan_util;
	int util = -1;
	SurveySample cur;
	if ((b.ifindex != 0) && survey_.get(b.ifindex, cur)) {
		util = Survey::util(b.survey_prev, cur);
		b.survey_prev = cur;
		b.load.noise = cur.noise;
	}
	if (util < 0) {
		util = b.hapd_util;
	}
	if (util > 254) {
		util = 254; // 255 means "unknown" on the wire
	}
	if (util >= 0) {
		b.load.util = (!was_up || (b.load.util == 255U))
				      ? static_cast<std::uint8_t>(util)
				      : static_cast<std::uint8_t>(((3 * static_cast<int>(b.load.util)) + util + 2) / 4);
	} else if (!was_up) {
		b.load.util = 255U;
	} else {
		// keep the last value
	}
	b.load.bssid = st->bssid;
	b.load.sta_count = static_cast<std::uint16_t>(st->num_sta);
	b.load.max_sta = static_cast<std::uint16_t>(b.cfg->max_sta);
	b.load.tx_power = static_cast<std::int8_t>(st->max_txpower);
	b.load.flags = (policy::admit(cfg_.pol, policy::util_to_pct(b.load.util), st->num_sta,
				      resv_count(i, os::now_ms()), b.cfg->max_sta) == arcp::SteerStatus::accept)
			       ? arcp::kLoadAccepting
			       : 0U;
	b.up = true;
	if (!was_up) {
		logging::info(kMod, "bss {} up: {} ch {} band {} ssid '{}'{}", b.cfg->ifname, b.info.bssid,
			      b.info.channel, b.info.band, SsidText{b.info.ssid_view()},
			      (b.info.mdid != 0U) ? " FT" : "");
	}
	if (!was_up || (old != b.info)) {
		// Sibling neighbor entries depend on this BSS: reinstall all.
		for (Peer &p : peers_) {
			for (RemoteBss &rb : p.bss) {
				rb.nr_installed = false;
			}
		}
		nr_sync();
	}
}

void Daemon::poll_bss() noexcept
{
	const Millis now = os::now_ms();

	for (std::size_t i = 0U; i < n_bss_; i++) {
		LocalBss &b = bss_[i];
		bool ready = b.hapd.is_open();

		if (!ready && (now >= b.next_reconnect_ms)) {
			ready = b.hapd.open(cfg_.hostapd_dir, b.cfg->ifname);
			if (!ready) {
				bss_mark_down(i);
			}
		}
		if (ready) {
			bss_refresh(i);
		}
	}
}

void Daemon::poll_stas() noexcept
{
	const Millis start = os::now_ms();
	hapd::Reply reply;

	for (std::size_t i = 0U; i < n_bss_; i++) {
		LocalBss &b = bss_[i];
		if (!b.up) {
			continue;
		}
		FixedString<64U> cmd{"STA-FIRST"};
		for (std::size_t guard = 0U; guard < kMaxSta; guard++) {
			std::optional<hapd::Sta> h;
			if (b.hapd.cmd(cmd.view(), reply) && !reply.empty()) {
				h = hapd::parse_sta(reply.view());
			}
			if (!h.has_value()) {
				break;
			}
			cmd.clear();
			format_to(cmd, "STA-NEXT {}", h->addr);
			if (h->authorized) {
				Sta *const s = sta_get(h->addr, i);
				if (s != nullptr) {
					sta_apply_sample(*s, *h);
				}
			}
		}
		if (!b.hapd.is_open()) {
			bss_mark_down(i);
			continue;
		}
		// Drop STAs hostapd no longer reports (missed events).
		for (Sta &s : sta_) {
			if (s.used && (s.bss == i) && (s.last_poll_ms < start) && (s.last_poll_ms != 0U)) {
				steer_on_local_disassoc(s.addr);
				s.used = false;
			}
		}
	}
	for (Sta &s : sta_) {
		if (s.used && (s.last_poll_ms >= start)) {
			steer_on_sta_poll(s);
		}
	}
}

// ---- hostapd events ----

void Daemon::ev_connected(std::size_t bss, const Mac &addr) noexcept
{
	Sta *const s = sta_get(addr, bss);

	logging::info(kMod, "sta {} associated to {}", addr, bss_[bss].cfg->ifname);
	if (s != nullptr) {
		arcp::StaEvent e;
		s->away = false;
		remote_sta_forget(addr);
		send_sta_event(addr, bss, arcp::StaEventType::assoc, 0U);
		e.sta = addr;
		e.bssid = bss_[bss].info.bssid;
		e.event = static_cast<std::uint8_t>(arcp::StaEventType::assoc);
		steer_on_sta_event(ap_id_, e);
	}
}

void Daemon::ev_disconnected(std::size_t bss, const Mac &addr) noexcept
{
	Sta *const s = sta_find(addr);

	logging::info(kMod, "sta {} disassociated from {}", addr, bss_[bss].cfg->ifname);
	// A STA moving between local BSSes may report CONNECTED first.
	if ((s == nullptr) || (s->bss == bss)) {
		send_sta_event(addr, bss, arcp::StaEventType::disassoc, 0U);
		steer_on_local_disassoc(addr);
		if (s != nullptr) {
			s->used = false;
		}
	}
}

// "<addr> <token> <rep_mode> <report hex>"
void Daemon::ev_beacon_resp(std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view addr;
	std::string_view tok;
	std::string_view mode;
	std::string_view hex;

	if (!(t.next(addr) && t.next(tok) && t.next(mode))) {
		return;
	}
	const bool have_hex = t.next(hex);
	const std::optional<Mac> a = parse_mac(addr);
	Sta *const s = a.has_value() ? sta_find(*a) : nullptr;
	if (s == nullptr) {
		return;
	}
	// Non-zero report mode = late/incapable/refused (no report body).
	const std::optional<long> rep_mode = parse_long(mode, 16, 0, 255);
	const std::optional<rrm::BeaconReport> r = (rep_mode.has_value() && (*rep_mode == 0) && have_hex)
						      ? rrm::bcn_rep_parse_hex(hex)
						      : std::optional<rrm::BeaconReport>();
	if (!r.has_value()) {
		logging::dbg(kMod, "sta {} beacon report mode {}", *a, mode);
	} else {
		logging::dbg(kMod, "sta {} sees {} ch {} rcpi {} ({} dBm)", *a, r->bssid, r->channel, r->rcpi,
			     rrm::rcpi_to_dbm(r->rcpi));
	}
	steer_on_beacon_report(*s, r);
}

void Daemon::handle_event(std::size_t bss, std::string_view ev) noexcept
{
	constexpr std::string_view kConn = "AP-STA-CONNECTED ";
	constexpr std::string_view kDisc = "AP-STA-DISCONNECTED ";
	constexpr std::string_view kBcn = "BEACON-RESP-RX ";
	constexpr std::string_view kBtm = "BSS-TM-RESP ";

	logging::dbg(kMod, "hapd[{}] < {}", bss_[bss].cfg->ifname, ev);
	if (starts_with(ev, kConn)) {
		const std::optional<Mac> a = parse_mac_prefix(sub_view(ev, kConn.size()));
		if (a.has_value() && bss_[bss].up) {
			ev_connected(bss, *a);
		}
	} else if (starts_with(ev, kDisc)) {
		const std::optional<Mac> a = parse_mac_prefix(sub_view(ev, kDisc.size()));
		if (a.has_value()) {
			ev_disconnected(bss, *a);
		}
	} else if (starts_with(ev, kBcn)) {
		ev_beacon_resp(sub_view(ev, kBcn.size()));
	} else if (starts_with(ev, kBtm)) {
		const std::optional<hapd::BtmResp> r = hapd::parse_btm_resp(ev);
		if (r.has_value()) {
			steer_on_btm_resp(*r);
		}
	} else {
		// other hostapd events are not used
	}
}

// ---- 802.11k neighbor database (hostapd SET_NEIGHBOR) ----

void Daemon::nr_set(LocalBss &lb, const arcp::BssInfo &bi) noexcept
{
	FixedString<64U> nr;
	FixedString<256U> cmd;
	hapd::Reply reply;

	if (rrm::nr_build_hex(bi, lb.info.mdid, nr)) {
		format_to(cmd, "SET_NEIGHBOR {} ssid={} nr={}", bi.bssid, HexBytes{bi.ssid_view()}, nr);
		if (!lb.hapd.cmd(cmd.view(), reply) || !starts_with(reply.view(), "OK")) {
			logging::warn(kMod, "bss {}: SET_NEIGHBOR {} failed (rrm_neighbor_report=1?)",
				      lb.cfg->ifname, bi.bssid);
		}
	}
}

void Daemon::nr_remove(const arcp::BssInfo &bi) noexcept
{
	FixedString<160U> cmd;
	hapd::Reply reply;

	format_to(cmd, "REMOVE_NEIGHBOR {} ssid={}", bi.bssid, HexBytes{bi.ssid_view()});
	for (std::size_t i = 0U; i < n_bss_; i++) {
		if (bss_[i].up && arcp::same_ess(bss_[i].info, bi)) {
			(void)bss_[i].hapd.cmd(cmd.view(), reply);
		}
	}
}

void Daemon::nr_sync() noexcept
{
	// Local siblings (other radios of this AP). Idempotent in hostapd.
	for (std::size_t i = 0U; i < n_bss_; i++) {
		for (std::size_t j = 0U; j < n_bss_; j++) {
			if ((i != j) && bss_[i].up && bss_[j].up && arcp::same_ess(bss_[i].info, bss_[j].info)) {
				nr_set(bss_[i], bss_[j].info);
			}
		}
	}
	for (Peer &p : peers_) {
		if (!p.used) {
			continue;
		}
		for (RemoteBss &rb : p.bss) {
			if (rb.used && !rb.nr_installed) {
				for (std::size_t i = 0U; i < n_bss_; i++) {
					if (bss_[i].up && arcp::same_ess(bss_[i].info, rb.info)) {
						nr_set(bss_[i], rb.info);
					}
				}
				rb.nr_installed = true;
			}
		}
	}
}

} // namespace donghoa
