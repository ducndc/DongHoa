// SPDX-License-Identifier: MIT
#include "config.hpp"

#include <limits>

#include "os.hpp"
#include "sha256.hpp"
#include "text.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::config};

// Integer and boolean keys, as typed pointers to members (no offsetof).
struct PolInt {
	std::string_view key;
	int PolicyConfig::*field;
};

struct PolBool {
	std::string_view key;
	bool PolicyConfig::*field;
};

struct CfgInt {
	std::string_view key;
	int Config::*field;
};

constexpr std::array<CfgInt, 6U> kCfgInts{{
	{"hello_interval_ms", &Config::hello_ms},
	{"bss_status_interval_ms", &Config::bss_status_ms},
	{"sta_status_interval_ms", &Config::sta_status_ms},
	{"rf_status_interval_ms", &Config::rf_status_ms},
	{"sta_poll_interval_ms", &Config::sta_poll_ms},
	{"peer_timeout_ms", &Config::peer_timeout_ms},
}};

constexpr std::array<PolBool, 7U> kPolBools{{
	{"rssi_steering", &PolicyConfig::rssi_steering},
	{"load_balancing", &PolicyConfig::load_balancing},
	{"band_steering", &PolicyConfig::band_steering},
	{"lb_only_idle", &PolicyConfig::lb_only_idle},
	{"disassoc_imminent", &PolicyConfig::disassoc_imminent},
	{"assume_kvr", &PolicyConfig::assume_kvr},
	{"amon_request", &PolicyConfig::amon_request},
}};

constexpr std::array<PolInt, 29U> kPolInts{{
	{"rssi_low", &PolicyConfig::rssi_low},
	{"rssi_low_count", &PolicyConfig::rssi_low_count},
	{"rssi_hysteresis", &PolicyConfig::rssi_hysteresis},
	{"rssi_min_target", &PolicyConfig::rssi_min_target},
	{"band_steer_rssi", &PolicyConfig::band_steer_rssi},
	{"util_high", &PolicyConfig::util_high},
	{"util_admit_max", &PolicyConfig::util_admit_max},
	{"lb_margin", &PolicyConfig::lb_margin},
	{"lb_rssi_tolerance", &PolicyConfig::lb_rssi_tolerance},
	{"idle_kbps", &PolicyConfig::idle_kbps},
	{"lb_interval_ms", &PolicyConfig::lb_interval_ms},
	{"util_weight", &PolicyConfig::util_weight},
	{"band_bonus_5g", &PolicyConfig::band_bonus_5g},
	{"band_bonus_6g", &PolicyConfig::band_bonus_6g},
	{"steer_cooldown_ms", &PolicyConfig::steer_cooldown_ms},
	{"steer_backoff_max_ms", &PolicyConfig::steer_backoff_max_ms},
	{"beacon_req_timeout_ms", &PolicyConfig::beacon_req_timeout_ms},
	{"steer_resp_timeout_ms", &PolicyConfig::steer_resp_timeout_ms},
	{"btm_timeout_ms", &PolicyConfig::btm_timeout_ms},
	{"roam_timeout_ms", &PolicyConfig::roam_timeout_ms},
	{"reserve_hold_ms", &PolicyConfig::reserve_hold_ms},
	{"btm_valid_int", &PolicyConfig::btm_valid_int},
	{"disassoc_timer", &PolicyConfig::disassoc_timer},
	{"beacon_duration", &PolicyConfig::beacon_duration},
	{"tput_rssi_mid", &PolicyConfig::tput_rssi_mid},
	{"tput_gain_pct", &PolicyConfig::tput_gain_pct},
	{"sta_nss", &PolicyConfig::sta_nss},
	{"amon_duration_ms", &PolicyConfig::amon_duration_ms},
	{"amon_rssi_offset", &PolicyConfig::amon_rssi_offset},
}};

std::optional<int> parse_int(std::string_view v) noexcept
{
	std::optional<int> r;
	const std::optional<long> n =
		parse_long(v, 10, std::numeric_limits<int>::min(), std::numeric_limits<int>::max());
	if (n.has_value()) {
		r = static_cast<int>(*n);
	}
	return r;
}

// UDP port 1..65535
bool parse_port(std::string_view v, std::uint16_t &port) noexcept
{
	const std::optional<long> n = parse_long(v, 10, 1, 65535);
	if (n.has_value()) {
		port = static_cast<std::uint16_t>(*n);
	}
	return n.has_value();
}

// "bss <ifname> [mdid=<hex>] [max_sta=<n>] [ft_over_ds=1]"
bool parse_bss(Config &c, std::string_view args) noexcept
{
	Tokens t(args, " \t");
	std::string_view tok;
	bool ok = (c.n_bss < kMaxBss) && t.next(tok);

	if (ok) {
		BssCfg b;
		(void)b.ifname.assign(tok);
		while (ok && t.next(tok)) {
			if (starts_with(tok, "mdid=")) {
				const std::optional<long> v = parse_long(sub_view(tok, 5U), 16, 0, 0xffff);
				ok = v.has_value();
				b.mdid = ok ? static_cast<std::uint16_t>(*v) : 0U;
			} else if (starts_with(tok, "max_sta=")) {
				const std::optional<long> v = parse_long(sub_view(tok, 8U), 10, 0, 65535);
				ok = v.has_value();
				b.max_sta = ok ? static_cast<int>(*v) : 0;
			} else if (tok == "ft_over_ds=1") {
				b.ft_over_ds = true;
			} else {
				ok = false;
			}
		}
		if (ok) {
			c.bss[c.n_bss] = b;
			c.n_bss++;
		}
	}
	return ok;
}

// "hex:<32..128 hex digits>", or a passphrase (>= 8 characters) hashed to
// 32 bytes: SHA256("arcp-key:" || passphrase).
bool parse_key(Config &c, std::string_view v) noexcept
{
	bool ok = false;
	if (starts_with(v, "hex:")) {
		const std::optional<std::size_t> n = hex_decode(sub_view(v, 4U), span_of(c.key));
		ok = n.has_value() && (*n >= 16U);
		c.key_len = ok ? *n : 0U;
	} else if (v.size() >= 8U) {
		Sha256 h;
		FixedString<200U> material{"arcp-key:"};
		ok = material.append(v);
		if (ok) {
			std::array<std::uint8_t, 200U> bytes{};
			const std::string_view m = material.view();
			for (std::size_t i = 0U; i < m.size(); i++) {
				bytes[i] = static_cast<std::uint8_t>(m[i]);
			}
			h.update(view_of(bytes).first(m.size()));
			const Digest d = h.finish();
			c.key_len = copy_bytes(span_of(c.key), view_of(d));
		}
	} else {
		// too short
	}
	return ok;
}

// "log_debug steer,amon msg": modules logged at debug level
bool parse_log_debug(Config &c, std::string_view v) noexcept
{
	Tokens t(v, " \t,");
	std::string_view tok;
	bool ok = false;

	while (t.next(tok)) {
		const std::optional<LogModule> m = logging::parse_module(tok);
		if (!m.has_value()) {
			return false;
		}
		c.log_debug_mask |= 1U << static_cast<std::uint32_t>(*m);
		ok = true;
	}
	return ok;
}

bool parse_numeric(Config &c, std::string_view k, std::string_view v, bool &known) noexcept
{
	bool ok = false;
	known = false;

	for (const CfgInt &o : kCfgInts) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parse_int(v);
			ok = n.has_value();
			if (ok) {
				c.*(o.field) = *n;
			}
		}
	}
	for (const PolInt &o : kPolInts) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parse_int(v);
			ok = n.has_value();
			if (ok) {
				c.pol.*(o.field) = *n;
			}
		}
	}
	for (const PolBool &o : kPolBools) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parse_int(v);
			ok = n.has_value();
			if (ok) {
				c.pol.*(o.field) = (*n != 0);
			}
		}
	}
	return ok;
}

} // namespace

bool config_line(Config &c, std::string_view line) noexcept
{
	std::string_view s = line;
	const std::size_t hash = s.find('#');

	if (hash != std::string_view::npos) {
		s = sub_view(s, 0U, hash);
	}
	s = trim(s);
	if (s.empty()) {
		return true;
	}
	std::size_t sp = 0U;
	while ((sp < s.size()) && !is_space(s[sp])) {
		sp++;
	}
	const std::string_view k = sub_view(s, 0U, sp);
	const std::string_view v = trim(sub_view(s, sp));
	bool ok = true;

	if (k == "name") {
		(void)c.name.assign(v);
	} else if (k == "ap_id") {
		const std::optional<Mac> m = parse_mac(v);
		ok = m.has_value();
		if (ok) {
			c.ap_id = *m;
			c.ap_id_set = true;
		}
	} else if (k == "iface") {
		ok = (c.n_ifaces < kMaxL2Ports) && !v.empty();
		if (ok) {
			(void)c.ifaces[c.n_ifaces].assign(v);
			c.n_ifaces++;
		}
	} else if (k == "sim_port") {
		ok = parse_port(v, c.sim_port);
	} else if (k == "sim_peer") {
		ok = (c.n_sim_peers < kMaxSimPeers) && parse_port(v, c.sim_peers[c.n_sim_peers]);
		if (ok) {
			c.n_sim_peers++;
		}
	} else if (k == "hostapd_ctrl_dir") {
		ok = c.hostapd_dir.assign(v);
	} else if (k == "ctrl_socket") {
		ok = c.ctrl_socket.assign(v);
	} else if (k == "log_level") {
		const std::optional<LogLevel> l = logging::parse_level(v);
		ok = l.has_value();
		if (ok) {
			c.log_level = *l;
		}
	} else if (k == "log_debug") {
		ok = parse_log_debug(c, v);
	} else if (k == "air_monitor") {
		ok = (c.n_monitors < kMaxMonitors) && !v.empty();
		if (ok) {
			(void)c.monitors[c.n_monitors].assign(v);
			c.n_monitors++;
		}
	} else if (k == "air_monitor_sim") {
		ok = parse_port(v, c.monitor_sim_port);
	} else if (k == "bss") {
		ok = parse_bss(c, v);
	} else if (k == "key") {
		ok = parse_key(c, v);
	} else if (k == "score_model") {
		const std::optional<long> n = parse_long(v, 10, 0, 1);
		ok = n.has_value();
		if (ok) {
			c.pol.score_model = (*n == 1) ? ScoreModel::tput : ScoreModel::linear;
		}
	} else if (k == "beacon_mode") {
		const std::optional<long> n = parse_long(v, 10, 0, 2);
		ok = n.has_value();
		if (ok) {
			c.pol.beacon_mode = (*n == 0) ? rrm::BeaconMode::passive
					    : ((*n == 1) ? rrm::BeaconMode::active : rrm::BeaconMode::table);
		}
	} else {
		bool known = false;
		ok = parse_numeric(c, k, v, known) && known;
	}
	return ok;
}

bool config_load(Config &c, const char *path) noexcept
{
	FixedString<16384U> text;
	bool ok = os::read_text_file(path, text);

	if (!ok) {
		logging::err(kMod, "cannot open {}", path);
	}
	std::string_view rest = text.view();
	std::size_t lineno = 0U;
	while (ok && !rest.empty()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view line = (eol == std::string_view::npos) ? rest : sub_view(rest, 0U, eol);

		lineno++;
		if (!config_line(c, line)) {
			logging::err(kMod, "{}:{}: invalid line", path, lineno);
			ok = false;
		}
		rest = (eol == std::string_view::npos) ? std::string_view() : sub_view(rest, eol + 1U);
	}
	if (ok && (c.n_bss == 0U)) {
		logging::err(kMod, "no 'bss' configured");
		ok = false;
	}
	if (ok && (c.n_ifaces == 0U) && (c.sim_port == 0U)) {
		logging::err(kMod, "no 'iface' (or sim_port) configured");
		ok = false;
	}
	return ok;
}

} // namespace donghoa
