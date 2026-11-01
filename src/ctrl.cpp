// SPDX-License-Identifier: MIT
// Local control socket (UNIX datagram), used by donghoa_cli and tests.
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::ctrl};
using Out = FixedString<8192U>;

void put_bss(Out &o, const arcp::BssInfo &bi, const arcp::BssLoad *bl) noexcept
{
	format_to(o, "  bss {} ssid={} ch={} band={} op_class={} mdid={} caps={}", bi.bssid,
		  SsidText{bi.ssid_view()}, bi.channel, bi.band, bi.op_class, hex(bi.mdid, 4U), hex(bi.caps, 4U));
	if (bl != nullptr) {
		format_to(o, " sta={} util={}% noise={} accepting={}", bl->sta_count, policy::util_to_pct(bl->util),
			  bl->noise, ((bl->flags & arcp::kLoadAccepting) != 0U) ? 1 : 0);
	}
	format_to(o, "\n");
}

// LOG                       show the level of every module
// LOG <level>               set every module
// LOG <level> <module>...   set the named modules
void cmd_log(Out &o, std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view a;

	if (t.next(a)) {
		const std::optional<LogLevel> lvl = logging::parse_level(a);
		if (!lvl.has_value()) {
			format_to(o, "FAIL usage: LOG [err|warn|info|debug [<module>...]]\n");
			return;
		}
		std::string_view m;
		bool any = false;
		while (t.next(m)) {
			const std::optional<LogModule> mod = logging::parse_module(m);
			if (!mod.has_value()) {
				format_to(o, "FAIL unknown module {}\n", m);
				return;
			}
			logging::set_level(*mod, *lvl);
			any = true;
		}
		if (!any) {
			logging::set_all(*lvl);
		}
	}
	for (std::size_t i = 0U; i < logging::kModules; i++) {
		const LogModule mod = logging::module_at(i);
		format_to(o, "{}={}\n", logging::module_name(mod), logging::level_name(logging::level(mod)));
	}
}

} // namespace

bool Daemon::ctrl_open() noexcept
{
	bool ok = true;
	if (!cfg_.ctrl_socket.empty()) {
		ctrl_fd_ = os::unix_bind(cfg_.ctrl_socket.c_str(), true);
		ok = ctrl_fd_.valid();
		if (!ok) {
			logging::err(kMod, "bind {}: {}", cfg_.ctrl_socket, os::last_error());
		}
	}
	return ok;
}

void Daemon::ctrl_close() noexcept
{
	if (ctrl_fd_.valid()) {
		ctrl_fd_.reset();
		os::remove_file(cfg_.ctrl_socket.c_str());
	}
}

void Daemon::ctrl_command(std::string_view req, Out &o) noexcept
{
	const Millis now = os::now_ms();

	if (req == "PING") {
		format_to(o, "PONG\n");
	} else if (req == "STATUS") {
		format_to(o, "ap_id={}\nname={}\nboot_id={}\n", ap_id_, cfg_.name, hex(boot_id_, 8U));
		for (std::size_t i = 0U; i < l2_.size(); i++) {
			format_to(o, "port={}\n", l2_.port(i).name);
		}
		for (std::size_t i = 0U; i < n_amon_; i++) {
			format_to(o, "air_monitor={}\n", amon_[i].name);
		}
		for (std::size_t i = 0U; i < n_bss_; i++) {
			format_to(o, "{} {}\n", bss_[i].cfg->ifname, bss_[i].up ? "up" : "down");
			if (bss_[i].up) {
				put_bss(o, bss_[i].info, &bss_[i].load);
			}
		}
	} else if (req == "PEERS") {
		for (const Peer &p : peers_) {
			if (!p.used) {
				continue;
			}
			format_to(o, "peer {} name={} port={} age={}ms\n", p.id, p.name,
				  p.port.has_value() ? l2_.port(*p.port).name.view() : std::string_view("-"),
				  now - p.last_seen);
			for (const RemoteBss &b : p.bss) {
				if (b.used) {
					put_bss(o, b.info, b.has_load ? &b.load : nullptr);
				}
			}
			for (std::size_t k = 0U; k < p.n_rf; k++) {
				const arcp::RfInfo &rf = p.rf[k];
				format_to(o, "  radio {} freq={} ch={} util={}% noise={} txpower={}\n", rf.radio_id, rf.freq,
					  rf.channel, policy::util_to_pct(rf.util), rf.noise, rf.tx_power);
			}
		}
	} else if (req == "STAS") {
		for (const Sta &s : sta_) {
			if (!s.used) {
				continue;
			}
			const std::string_view bcn = s.bcn_unsupported ? std::string_view("none")
						     : (s.bcn_mode.has_value() ? rrm::beacon_mode_name(*s.bcn_mode)
									      : std::string_view("unknown"));
			const std::int64_t backoff = static_cast<std::int64_t>(s.next_steer_ms) - static_cast<std::int64_t>(now);
			format_to(o, "sta {} bss={}{} rssi={} tput={}kbps flags={}{}{} bcn={} backoff={}ms\n", s.addr,
				  bss_[s.bss].cfg->ifname, s.away ? "(away)" : "", s.rssi, s.tput_kbps,
				  ((s.flags & arcp::kStaF11k) != 0U) ? "k" : "", ((s.flags & arcp::kStaF11v) != 0U) ? "v" : "",
				  ((s.flags & arcp::kStaF11r) != 0U) ? "r" : "", bcn, backoff);
		}
		for (const RemoteSta &r : rsta_) {
			if (r.used) {
				format_to(o, "remote {} ap={} bss={} rssi={}\n", r.sta, r.ap, r.bssid, r.rssi);
			}
		}
	} else if (req == "STEERS") {
		for (const SteerTxn &t : txn_) {
			if (t.used) {
				const long cur = (t.cur >= kMaxCand) ? -1L : static_cast<long>(t.cur);
				format_to(o, "txn {} sta {} state={} cand={}/{}\n", t.id, t.sta, steer_state_name(t.state), cur,
					  t.n_cand);
			}
		}
		for (const Reservation &r : resv_) {
			if (r.used) {
				format_to(o, "reservation sta {} bss={} txn={}\n", r.sta, bss_[r.bss].cfg->ifname, r.txn);
			}
		}
	} else if (starts_with(req, "STEER ")) {
		Tokens t(sub_view(req, 6U), " ");
		std::string_view a;
		std::string_view b;
		const bool has_a = t.next(a);
		const bool has_b = t.next(b);
		const std::optional<Mac> sta = has_a ? parse_mac(a) : std::optional<Mac>();
		const std::optional<Mac> tgt = has_b ? parse_mac(b) : std::optional<Mac>();
		if (!sta.has_value() || (has_b && !tgt.has_value())) {
			format_to(o, "FAIL usage: STEER <sta> [<bssid>]\n");
		} else {
			Sta *const s = sta_find(*sta);
			if (s == nullptr) {
				format_to(o, "FAIL unknown sta\n");
			} else {
				s->next_steer_ms = 0U;
				const bool ok = steer_start(*s, arcp::SteerReason::manual, tgt.has_value() ? &*tgt : nullptr);
				format_to(o, ok ? "OK\n" : "FAIL\n");
			}
		}
	} else if (starts_with(req, "MONITOR ")) {
		// Measure a STA with this AP's air monitors; the result goes to the
		// log (and to the STA's measurements when it is associated here).
		Tokens t(sub_view(req, 8U), " ");
		std::string_view a;
		std::string_view b;
		const bool has_a = t.next(a);
		const bool has_b = t.next(b);
		const std::optional<Mac> sta = has_a ? parse_mac(a) : std::optional<Mac>();
		const std::optional<long> ms = has_b ? parse_long(b, 10, 1, 5000)
						     : std::optional<long>(static_cast<long>(cfg_.pol.amon_duration_ms));
		if (!sta.has_value() || !ms.has_value()) {
			format_to(o, "FAIL usage: MONITOR <sta> [<ms 1..5000>]\n");
		} else if (n_amon_ == 0U) {
			format_to(o, "FAIL no air_monitor configured\n");
		} else {
			format_to(o, amon_watch_start(*sta, ap_id_, 0U, static_cast<int>(*ms))
					     ? "OK result in the log after the watch (logread -e donghoa)\n"
					     : "FAIL\n");
		}
	} else if (req == "LOG") {
		cmd_log(o, std::string_view());
	} else if (starts_with(req, "LOG ")) {
		cmd_log(o, sub_view(req, 4U));
	} else {
		format_to(o, "UNKNOWN COMMAND\n");
	}
}

void Daemon::ctrl_handle() noexcept
{
	std::array<std::uint8_t, 255U> buf{};
	bool more = ctrl_fd_.valid();

	while (more) {
		std::size_t n = 0U;
		os::UnixAddr from;
		more = os::recv_from(ctrl_fd_, span_of(buf), n, from) == os::Rx::data;
		if (more) {
			FixedString<255U> req;
			for (std::size_t i = 0U; i < n; i++) {
				(void)req.push_back(static_cast<char>(buf[i]));
			}
			Out out;
			ctrl_command(trim(req.view()), out);
			if (out.empty()) {
				format_to(out, "\n");
			}
			std::array<std::uint8_t, 8192U> reply{};
			const std::string_view text = out.view();
			for (std::size_t i = 0U; i < text.size(); i++) {
				reply[i] = static_cast<std::uint8_t>(text[i]);
			}
			os::send_to(ctrl_fd_, view_of(reply).first(text.size()), from);
		}
	}
}

} // namespace donghoa
