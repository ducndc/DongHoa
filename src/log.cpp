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

// Indexed by severity code 0..7 (RFC 5424); 0..2 are never set.
constexpr std::size_t LEVELS = 8U;
constexpr std::array<std::string_view, LEVELS> LEVEL_NAMES{"emerg",  "alert", "crit", "err",
							  "warning", "notice", "info", "debug"};
constexpr std::array<std::string_view, LEVELS> TAGS{"EMR", "ALR", "CRT", "ERR", "WRN", "NTC", "INF", "DBG"};

struct LevelAlias {
	std::string_view name;
	LogLevel level;
};
constexpr std::array<LevelAlias, 5U> LEVEL_ALIASES{{
	{"emerg", LogLevel::ERR},
	{"alert", LogLevel::ERR},
	{"crit", LogLevel::ERR},
	{"error", LogLevel::ERR},
	{"warn", LogLevel::WARN},
}};

bool isValid(LogLevel l) noexcept
{
	const std::size_t i = static_cast<std::size_t>(l);
	return (i >= static_cast<std::size_t>(LogLevel::ERR)) && (i < LEVELS);
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
	const std::optional<long> n = parseLong(s, 10, 0, static_cast<long>(LEVELS) - 1L);
	const std::size_t lowest = static_cast<std::size_t>(LogLevel::ERR);
	for (std::size_t i = lowest; i < LEVELS; i++) {
		if ((s == LEVEL_NAMES[i]) || (n.has_value() && (static_cast<std::size_t>(*n) == i))) {
			r = static_cast<LogLevel>(i);
		}
	}
	for (const LevelAlias &a : LEVEL_ALIASES) {
		if (s == a.name) {
			r = a.level;
		}
	}
	if (!r.has_value() && n.has_value()) {
		r = LogLevel::ERR; // 0..2: emerg, alert, crit
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
	return isValid(l) ? LEVEL_NAMES[idx(l)] : std::string_view("?");
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
	formatTo(line, "{} [{}] {}: {}", ms, isValid(l) ? TAGS[idx(l)] : std::string_view("?"), moduleName(m),
		 text);
	if (sSyslog) {
		os::writeSyslog(static_cast<std::uint8_t>(idx(l)), line.view());
	} else {
		(void)line.pushBack('\n');
		os::writeStderr(line.view());
	}
}

} // namespace logging
} // namespace donghoa
