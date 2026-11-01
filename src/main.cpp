// SPDX-License-Identifier: MIT
// DongHoa entry point: start-up, the poll() event loop, timers, shutdown.
#include <string_view>

#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::main};
constexpr int kLoopTickMs = 100;

// Owner of each polled descriptor.
enum class Src : std::uint8_t { l2, hapd, ctrl, amon };

} // namespace

bool Daemon::setup_transport() noexcept
{
	bool ok = true;

	for (std::size_t i = 0U; ok && (i < cfg_.n_ifaces); i++) {
		ok = l2_.add_iface(cfg_.ifaces[i]);
	}
	if (ok) {
		if (cfg_.ap_id_set) {
			ap_id_ = cfg_.ap_id;
		} else if (l2_.size() > 0U) {
			ap_id_ = l2_.port(0U).mac;
		} else {
			logging::err(kMod, "ap_id must be configured when only sim ports are used");
			ok = false;
		}
	}
	if (ok && (cfg_.sim_port != 0U)) {
		ok = l2_.add_sim(cfg_.sim_port, cfg_.sim_peers, cfg_.n_sim_peers, ap_id_);
	}
	return ok;
}

bool Daemon::init(const char *cfg_path, bool debug_all) noexcept
{
	bool ok = config_load(cfg_, cfg_path);

	if (ok) {
		logging::set_all(cfg_.log_level);
		for (std::size_t i = 0U; i < logging::kModules; i++) {
			if ((cfg_.log_debug_mask & (1U << static_cast<std::uint32_t>(i))) != 0U) {
				logging::set_level(logging::module_at(i), LogLevel::debug);
			}
		}
		if (debug_all) {
			logging::set_all(LogLevel::debug);
		}
		ok = setup_transport();
	}
	if (ok) {
		std::optional<std::uint32_t> r = os::random_u32();
		while (!r.has_value() || (*r == 0U)) {
			const std::uint64_t seed = os::now_ms() ^
				(static_cast<std::uint64_t>(static_cast<std::uint32_t>(os::process_id())) << 16U);
			r = static_cast<std::uint32_t>((seed & 0xffffffffU) | 1U);
		}
		boot_id_ = *r;
		local_init();
		ok = ctrl_open();
	}
	if (ok) {
		amon_init();
		os::install_signal_handlers();
		logging::info(kMod, "DongHoa '{}' ap_id {} boot {}{}", cfg_.name, ap_id_, hex(boot_id_, 8U),
			      cfg_.key_view().empty() ? " (NO authentication)" : " (authenticated)");
	}
	return ok;
}

void Daemon::run_timers() noexcept
{
	const Millis now = os::now_ms();

	if (now >= next_sta_poll_) {
		poll_bss();
		poll_stas();
		next_sta_poll_ = now + static_cast<Millis>(cfg_.sta_poll_ms);
	}
	if (now >= next_hello_) {
		send_hello();
		next_hello_ = now + static_cast<Millis>(cfg_.hello_ms);
	}
	if (now >= next_bss_status_) {
		send_bss_status();
		next_bss_status_ = now + static_cast<Millis>(cfg_.bss_status_ms);
	}
	if (now >= next_sta_status_) {
		send_sta_status();
		next_sta_status_ = now + static_cast<Millis>(cfg_.sta_status_ms);
	}
	if (now >= next_rf_status_) {
		send_rf_status();
		next_rf_status_ = now + static_cast<Millis>(cfg_.rf_status_ms);
	}
	if (now >= next_lb_) {
		steer_lb_round();
		next_lb_ = now + static_cast<Millis>(cfg_.pol.lb_interval_ms);
	}
	steer_tick(now);
	amon_tick(now);
	retransmit(now);
	peer_expire(now);
}

void Daemon::run() noexcept
{
	while (!os::stop_requested()) {
		std::array<int, os::kMaxPoll> fds{};
		std::array<Src, os::kMaxPoll> src{};
		std::array<std::size_t, os::kMaxPoll> idx{};
		std::array<bool, os::kMaxPoll> ready{};
		std::size_t n = 0U;
		const auto add = [&](int fd, Src s, std::size_t i) {
			if ((fd >= 0) && (n < os::kMaxPoll)) {
				fds[n] = fd;
				src[n] = s;
				idx[n] = i;
				n++;
			}
		};

		for (std::size_t i = 0U; i < l2_.size(); i++) {
			add(l2_.port(i).fd.get(), Src::l2, i);
		}
		for (std::size_t i = 0U; i < n_bss_; i++) {
			add(bss_[i].hapd.event_fd(), Src::hapd, i);
		}
		add(ctrl_fd_.get(), Src::ctrl, 0U);
		for (std::size_t i = 0U; i < n_amon_; i++) {
			add(amon_[i].fd.get(), Src::amon, i);
		}
		if (!os::poll_readable(fds, n, kLoopTickMs, ready)) {
			logging::err(kMod, "poll: {}", os::last_error());
			break;
		}
		for (std::size_t k = 0U; k < n; k++) {
			if (!ready[k]) {
				continue;
			}
			switch (src[k]) {
			case Src::l2:
				msg_rx(idx[k]);
				break;
			case Src::hapd: {
				LocalBss &b = bss_[idx[k]];
				hapd::Reply ev;
				os::Rx r = os::Rx::data;
				while (b.hapd.is_open() && (r == os::Rx::data)) {
					r = b.hapd.recv_event(ev);
					if (r == os::Rx::data) {
						handle_event(idx[k], ev.view());
					} else if (r == os::Rx::error) {
						b.hapd.close();
					} else {
						// drained
					}
				}
				break;
			}
			case Src::ctrl:
				ctrl_handle();
				break;
			case Src::amon:
				amon_rx(idx[k]);
				break;
			default:
				break;
			}
		}
		run_timers();
	}
}

void Daemon::shutdown() noexcept
{
	send_bye();
	for (std::size_t i = 0U; i < n_bss_; i++) {
		bss_[i].hapd.close();
	}
	ctrl_close();
	logging::info(kMod, "DongHoa stopped");
}

} // namespace donghoa

namespace {

donghoa::Daemon g_daemon;

void usage(std::string_view prog) noexcept
{
	donghoa::Line u;
	donghoa::format_to(u,
			   "usage: {} -c <config> [-d] [-s]\n"
			   "  -c  configuration file\n"
			   "  -d  debug logging for every module (overrides log_level/log_debug)\n"
			   "  -s  log to syslog (daemon facility) instead of stderr\n"
			   "Log levels can also be changed at run time: donghoa_cli <socket> LOG\n",
			   prog);
	donghoa::os::write_stderr(u.view());
}

} // namespace

int main(int argc, char **argv)
{
	const char *cfg_path = nullptr;
	bool debug_all = false;
	bool syslog = false;
	int rc = 0;
	const std::string_view prog = (argc > 0) ? std::string_view(argv[0]) : std::string_view("donghoa");

	for (int i = 1; (i < argc) && (rc == 0); i++) {
		const std::string_view a(argv[i]);
		if ((a == "-c") && ((i + 1) < argc)) {
			i++;
			cfg_path = argv[i];
		} else if (a == "-d") {
			debug_all = true;
		} else if (a == "-s") {
			syslog = true;
		} else if (a == "-h") {
			usage(prog);
			return 0;
		} else {
			rc = 1;
		}
	}
	if ((rc != 0) || (cfg_path == nullptr)) {
		usage(prog);
		return 1;
	}
	donghoa::logging::use_syslog(syslog);
	if (!g_daemon.init(cfg_path, debug_all)) {
		return 1;
	}
	g_daemon.run();
	g_daemon.shutdown();
	return 0;
}
