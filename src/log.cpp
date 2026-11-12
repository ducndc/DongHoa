// SPDX-License-Identifier: MIT
#include "log.hpp"

#include <array>

#include "os.hpp"

namespace donghoa {
namespace logging {

namespace {

// Every module starts at INFO (filled, so a new module cannot be missed).
constexpr std::array<LogLevel, MODULES> makeDefaultLevels() noexcept
{
	std::array<LogLevel, MODULES> a{};
	for (LogLevel &l : a) {
		l = LogLevel::INFO;
	}
	return a;
}

std::array<LogLevel, MODULES> sLevels = makeDefaultLevels();

constexpr std::array<std::string_view, MODULES> MODULE_NAMES{
	"main", "l2", "msg", "peer", "hapd", "local", "steer", "policy", "amon", "survey", "ctrl",
	"config", "rrm", "class", "enroll", "check",
};

// The RFC 5424 severity codes in use: ERR (3) .. DEBUG (7).
constexpr std::size_t FIRST = static_cast<std::size_t>(LogLevel::ERR);
constexpr std::size_t LEVELS = 5U;
constexpr long MAX_CODE = 7;

struct LevelName {
	std::string_view name;
	LogLevel level;
};

// Every name a level can be set by. The first LEVELS entries are the RFC
// 5424 keywords in severity order: a level is shown as entry (code - FIRST).
// emerg, alert and crit set ERR, the most severe level in use.
constexpr std::array<LevelName, 10U> LEVEL_NAMES{{
	{"err", LogLevel::ERR},
	{"warning", LogLevel::WARN},
	{"notice", LogLevel::NOTICE},
	{"info", LogLevel::INFO},
	{"debug", LogLevel::DEBUG},
	{"error", LogLevel::ERR},
	{"warn", LogLevel::WARN},
	{"emerg", LogLevel::ERR},
	{"alert", LogLevel::ERR},
	{"crit", LogLevel::ERR},
}};
constexpr std::array<std::string_view, LEVELS> TAGS{"ERR", "WRN", "NTC", "INF", "DBG"};

constexpr bool isNameOrderOk() noexcept
{
	bool ok = true;
	for (std::size_t i = 0U; i < LEVELS; i++) {
		ok = ok && (static_cast<std::size_t>(LEVEL_NAMES[i].level) == (FIRST + i));
	}
	return ok;
}
static_assert(isNameOrderOk(), "LEVEL_NAMES starts with the keywords in severity order");

bool isValid(LogLevel l) noexcept
{
	const std::size_t i = static_cast<std::size_t>(l);
	return (i >= FIRST) && (i < (FIRST + LEVELS));
}

bool sSyslog = false;

std::size_t idx(LogModule m) noexcept
{
	return static_cast<std::size_t>(m);
}

std::size_t idx(LogLevel l) noexcept
{
	return static_cast<std::size_t>(l);
}

} // namespace

bool enabled(LogModule m, LogLevel l) noexcept
{
	return (idx(m) < MODULES) && (idx(l) <= idx(sLevels[idx(m)]));
}

LogLevel level(LogModule m) noexcept
{
	return (idx(m) < MODULES) ? sLevels[idx(m)] : LogLevel::INFO;
}

void setLevel(LogModule m, LogLevel l) noexcept
{
	if ((idx(m) < MODULES) && isValid(l)) {
		sLevels[idx(m)] = l;
	}
}

void setAll(LogLevel l) noexcept
{
	if (isValid(l)) {
		for (LogLevel &x : sLevels) {
			x = l;
		}
	}
}

std::optional<LogLevel> parseLevel(std::string_view s) noexcept
{
	std::optional<LogLevel> r;
	for (const LevelName &n : LEVEL_NAMES) {
		if (s == n.name) {
			r = n.level;
		}
	}
	// A severity code is one digit: "-0", "00" and "007" are not levels.
	if (!r.has_value() && (s.size() == 1U)) {
		const std::optional<long> n = parseLong(s, 10, 0, MAX_CODE);
		if (n.has_value()) {
			const std::size_t code = static_cast<std::size_t>(*n);
			r = static_cast<LogLevel>((code < FIRST) ? FIRST : code); // 0..2 set ERR
		}
	}
	return r;
}

std::optional<LogModule> parseModule(std::string_view s) noexcept
{
	std::optional<LogModule> r;
	for (std::size_t i = 0U; i < MODULES; i++) {
		if (s == MODULE_NAMES[i]) {
			r = moduleAt(i);
		}
	}
	return r;
}

std::string_view levelName(LogLevel l) noexcept
{
	return isValid(l) ? LEVEL_NAMES[idx(l) - FIRST].name : std::string_view("?");
}

std::string_view moduleName(LogModule m) noexcept
{
	return (idx(m) < MODULES) ? MODULE_NAMES[idx(m)] : std::string_view("?");
}

LogModule moduleAt(std::size_t i) noexcept
{
	return (i < MODULES) ? static_cast<LogModule>(i) : LogModule::MAIN;
}

void useSyslog(bool on) noexcept
{
	if (on && !sSyslog) {
		os::openSyslog();
	} else if (!on && sSyslog) {
		os::closeSyslog();
	} else {
		// unchanged
	}
	sSyslog = on;
}

void emit(LogModule m, LogLevel l, std::string_view text) noexcept
{
	const Millis t = os::nowMs();
	const bool valid = isValid(l);
	Line line;

	// "<s>.<ms> [TAG] module: text". The monotonic time lines up exactly
	// with this AP's own timers; milliseconds are padded to three digits.
	formatTo(line, "{}.", t / 1000U);
	const std::uint64_t ms = t % 1000U;
	if (ms < 100U) {
		(void)line.pushBack('0');
	}
	if (ms < 10U) {
		(void)line.pushBack('0');
	}
	const std::string_view tag = valid ? TAGS[idx(l) - FIRST] : std::string_view("?");
	formatTo(line, "{} [{}] {}: {}", ms, tag, moduleName(m), text);
	if (sSyslog) {
		// A value outside ERR..DEBUG must not reach syslog as emerg, alert or
		// crit, which many syslog daemons write to every console.
		const LogLevel prio = valid ? l : LogLevel::INFO;
		os::writeSyslog(static_cast<std::uint8_t>(idx(prio)), line.view());
	} else {
		(void)line.pushBack('\n');
		os::writeStderr(line.view());
	}
}

} // namespace logging
} // namespace donghoa
