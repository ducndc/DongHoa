// SPDX-License-Identifier: MIT
#include "config.hpp"

#include <limits>

#include "os.hpp"
#include "sha256.hpp"
#include "text.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::CONFIG};

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

constexpr std::array<CfgInt, 6U> CFG_INTS{{
	{"hello_interval_ms", &Config::helloMs},
	{"bss_status_interval_ms", &Config::bssStatusMs},
	{"sta_status_interval_ms", &Config::staStatusMs},
	{"rf_status_interval_ms", &Config::rfStatusMs},
	{"sta_poll_interval_ms", &Config::staPollMs},
	{"peer_timeout_ms", &Config::peerTimeoutMs},
}};

constexpr std::array<PolBool, 7U> POL_BOOLS{{
	{"rssi_steering", &PolicyConfig::rssiSteering},
	{"load_balancing", &PolicyConfig::loadBalancing},
	{"band_steering", &PolicyConfig::bandSteering},
	{"lb_only_idle", &PolicyConfig::lbOnlyIdle},
	{"disassoc_imminent", &PolicyConfig::disassocImminent},
	{"assume_kvr", &PolicyConfig::assumeKvr},
	{"amon_request", &PolicyConfig::amonRequest},
}};

constexpr std::array<PolInt, 29U> POL_INTS{{
	{"rssi_low", &PolicyConfig::rssiLow},
	{"rssi_low_count", &PolicyConfig::rssiLowCount},
	{"rssi_hysteresis", &PolicyConfig::rssiHysteresis},
	{"rssi_min_target", &PolicyConfig::rssiMinTarget},
	{"band_steer_rssi", &PolicyConfig::bandSteerRssi},
	{"util_high", &PolicyConfig::utilHigh},
	{"util_admit_max", &PolicyConfig::utilAdmitMax},
	{"lb_margin", &PolicyConfig::lbMargin},
	{"lb_rssi_tolerance", &PolicyConfig::lbRssiTolerance},
	{"idle_kbps", &PolicyConfig::idleKbps},
	{"lb_interval_ms", &PolicyConfig::lbIntervalMs},
	{"util_weight", &PolicyConfig::utilWeight},
	{"band_bonus_5g", &PolicyConfig::bandBonus5g},
	{"band_bonus_6g", &PolicyConfig::bandBonus6g},
	{"steer_cooldown_ms", &PolicyConfig::steerCooldownMs},
	{"steer_backoff_max_ms", &PolicyConfig::steerBackoffMaxMs},
	{"beacon_req_timeout_ms", &PolicyConfig::beaconReqTimeoutMs},
	{"steer_resp_timeout_ms", &PolicyConfig::steerRespTimeoutMs},
	{"btm_timeout_ms", &PolicyConfig::btmTimeoutMs},
	{"roam_timeout_ms", &PolicyConfig::roamTimeoutMs},
	{"reserve_hold_ms", &PolicyConfig::reserveHoldMs},
	{"btm_valid_int", &PolicyConfig::btmValidInt},
	{"disassoc_timer", &PolicyConfig::disassocTimer},
	{"beacon_duration", &PolicyConfig::beaconDuration},
	{"tput_rssi_mid", &PolicyConfig::tputRssiMid},
	{"tput_gain_pct", &PolicyConfig::tputGainPct},
	{"sta_nss", &PolicyConfig::staNss},
	{"amon_duration_ms", &PolicyConfig::amonDurationMs},
	{"amon_rssi_offset", &PolicyConfig::amonRssiOffset},
}};

std::optional<int> parseInt(std::string_view v) noexcept
{
	std::optional<int> r;
	const std::optional<long> n =
		parseLong(v, 10, std::numeric_limits<int>::min(), std::numeric_limits<int>::max());
	if (n.has_value()) {
		r = static_cast<int>(*n);
	}
	return r;
}

// UDP port 1..65535
bool parsePort(std::string_view v, std::uint16_t &port) noexcept
{
	const std::optional<long> n = parseLong(v, 10, 1, 65535);
	if (n.has_value()) {
		port = static_cast<std::uint16_t>(*n);
	}
	return n.has_value();
}

// "bss <ifname> [mdid=<hex>] [max_sta=<n>] [ft_over_ds=1]"
bool parseBss(Config &c, std::string_view args) noexcept
{
	Tokens t(args, " \t");
	std::string_view tok;
	bool ok = (c.nBss < MAX_BSS) && t.next(tok);

	if (ok) {
		BssCfg b;
		(void)b.ifname.assign(tok);
		while (ok && t.next(tok)) {
			if (startsWith(tok, "mdid=")) {
				const std::optional<long> v = parseLong(subView(tok, 5U), 16, 0, 0xffff);
				ok = v.has_value();
				b.mdid = ok ? static_cast<std::uint16_t>(*v) : 0U;
			} else if (startsWith(tok, "max_sta=")) {
				const std::optional<long> v = parseLong(subView(tok, 8U), 10, 0, 65535);
				ok = v.has_value();
				b.maxSta = ok ? static_cast<int>(*v) : 0;
			} else if (tok == "ft_over_ds=1") {
				b.ftOverDs = true;
			} else {
				ok = false;
			}
		}
		if (ok) {
			c.bss[c.nBss] = b;
			c.nBss++;
		}
	}
	return ok;
}

// "hex:<32..128 hex digits>", or a passphrase (>= 8 characters) hashed to
// 32 bytes: SHA256("arcp-key:" || passphrase).
bool parseKey(Config &c, std::string_view v) noexcept
{
	bool ok = false;
	if (startsWith(v, "hex:")) {
		const std::optional<std::size_t> n = hexDecode(subView(v, 4U), spanOf(c.key));
		ok = n.has_value() && (*n >= 16U);
		c.keyLen = ok ? *n : 0U;
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
			h.update(viewOf(bytes).first(m.size()));
			const Digest d = h.finish();
			c.keyLen = copyBytes(spanOf(c.key), viewOf(d));
		}
	} else {
		// too short
	}
	return ok;
}

// "log_debug steer,amon msg": modules logged at debug level
bool parseLogDebug(Config &c, std::string_view v) noexcept
{
	Tokens t(v, " \t,");
	std::string_view tok;
	bool ok = false;

	while (t.next(tok)) {
		const std::optional<LogModule> m = logging::parseModule(tok);
		if (!m.has_value()) {
			return false;
		}
		c.logDebugMask |= 1U << static_cast<std::uint32_t>(*m);
		ok = true;
	}
	return ok;
}

bool parseNumeric(Config &c, std::string_view k, std::string_view v, bool &known) noexcept
{
	bool ok = false;
	known = false;

	for (const CfgInt &o : CFG_INTS) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parseInt(v);
			ok = n.has_value();
			if (ok) {
				c.*(o.field) = *n;
			}
		}
	}
	for (const PolInt &o : POL_INTS) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parseInt(v);
			ok = n.has_value();
			if (ok) {
				c.pol.*(o.field) = *n;
			}
		}
	}
	for (const PolBool &o : POL_BOOLS) {
		if (!known && (k == o.key)) {
			known = true;
			const std::optional<int> n = parseInt(v);
			ok = n.has_value();
			if (ok) {
				c.pol.*(o.field) = (*n != 0);
			}
		}
	}
	return ok;
}

} // namespace

bool parseConfigLine(Config &c, std::string_view line) noexcept
{
	std::string_view s = line;
	const std::size_t hash = s.find('#');

	if (hash != std::string_view::npos) {
		s = subView(s, 0U, hash);
	}
	s = trim(s);
	if (s.empty()) {
		return true;
	}
	std::size_t sp = 0U;
	while ((sp < s.size()) && !isSpace(s[sp])) {
		sp++;
	}
	const std::string_view k = subView(s, 0U, sp);
	const std::string_view v = trim(subView(s, sp));
	bool ok = true;

	if (k == "name") {
		(void)c.name.assign(v);
	} else if (k == "ap_id") {
		const std::optional<Mac> m = parseMac(v);
		ok = m.has_value();
		if (ok) {
			c.apId = *m;
			c.apIdSet = true;
		}
	} else if (k == "iface") {
		ok = (c.nIfaces < MAX_L2_PORTS) && !v.empty();
		if (ok) {
			(void)c.ifaces[c.nIfaces].assign(v);
			c.nIfaces++;
		}
	} else if (k == "sim_port") {
		ok = parsePort(v, c.simPort);
	} else if (k == "sim_peer") {
		ok = (c.nSimPeers < MAX_SIM_PEERS) && parsePort(v, c.simPeers[c.nSimPeers]);
		if (ok) {
			c.nSimPeers++;
		}
	} else if (k == "hostapd_ctrl_dir") {
		ok = c.hostapdDir.assign(v);
	} else if (k == "ctrl_socket") {
		ok = c.ctrlSocket.assign(v);
	} else if (k == "log_level") {
		const std::optional<LogLevel> l = logging::parseLevel(v);
		ok = l.has_value();
		if (ok) {
			c.logLevel = *l;
		}
	} else if (k == "log_debug") {
		ok = parseLogDebug(c, v);
	} else if (k == "air_monitor") {
		ok = (c.nMonitors < MAX_MONITORS) && !v.empty();
		if (ok) {
			(void)c.monitors[c.nMonitors].assign(v);
			c.nMonitors++;
		}
	} else if (k == "air_monitor_sim") {
		ok = parsePort(v, c.monitorSimPort);
	} else if (k == "bss") {
		ok = parseBss(c, v);
	} else if (k == "key") {
		ok = parseKey(c, v);
	} else if (k == "score_model") {
		const std::optional<long> n = parseLong(v, 10, 0, 1);
		ok = n.has_value();
		if (ok) {
			c.pol.scoreModel = (*n == 1) ? ScoreModel::TPUT : ScoreModel::LINEAR;
		}
	} else if (k == "beacon_mode") {
		const std::optional<long> n = parseLong(v, 10, 0, 2);
		ok = n.has_value();
		if (ok) {
			c.pol.beaconMode = (*n == 0) ? rrm::BeaconMode::PASSIVE
					    : ((*n == 1) ? rrm::BeaconMode::ACTIVE : rrm::BeaconMode::TABLE);
		}
	} else {
		bool known = false;
		ok = parseNumeric(c, k, v, known) && known;
	}
	return ok;
}

bool loadConfig(Config &c, const char *path) noexcept
{
	FixedString<16384U> text;
	bool ok = os::readTextFile(path, text);

	if (!ok) {
		logging::err(LOG_MODULE, "cannot open {}", path);
	}
	std::string_view rest = text.view();
	std::size_t lineno = 0U;
	while (ok && !rest.empty()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view line = (eol == std::string_view::npos) ? rest : subView(rest, 0U, eol);

		lineno++;
		if (!parseConfigLine(c, line)) {
			logging::err(LOG_MODULE, "{}:{}: invalid line", path, lineno);
			ok = false;
		}
		rest = (eol == std::string_view::npos) ? std::string_view() : subView(rest, eol + 1U);
	}
	if (ok && (c.nBss == 0U)) {
		logging::err(LOG_MODULE, "no 'bss' configured");
		ok = false;
	}
	if (ok && (c.nIfaces == 0U) && (c.simPort == 0U)) {
		logging::err(LOG_MODULE, "no 'iface' (or sim_port) configured");
		ok = false;
	}
	return ok;
}

} // namespace donghoa
