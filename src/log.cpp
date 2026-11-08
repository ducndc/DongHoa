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
	"config", "rrm", "class", "enroll",
};

constexpr std::array<std::string_view, 4U> LEVEL_NAMES{"err", "warn", "info", "debug"};
constexpr std::array<std::string_view, 4U> TAGS{"ERR", "WRN", "INF", "DBG"};

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
	if ((idx(m) < MODULES) && (idx(l) < LEVEL_NAMES.size())) {
		sLevels[idx(m)] = l;
	}
}

void setAll(LogLevel l) noexcept
{
	for (LogLevel &x : sLevels) {
		x = l;
	}
}

std::optional<LogLevel> parseLevel(std::string_view s) noexcept
{
	std::optional<LogLevel> r;
	for (std::size_t i = 0U; i < LEVEL_NAMES.size(); i++) {
		if (s == LEVEL_NAMES[i]) {
			r = static_cast<LogLevel>(i);
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
	return (idx(l) < LEVEL_NAMES.size()) ? LEVEL_NAMES[idx(l)] : std::string_view("?");
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
	formatTo(line, "{} [{}] {}: {}", ms, TAGS[idx(l)], moduleName(m), text);
	if (sSyslog) {
		os::writeSyslog(static_cast<std::uint8_t>(idx(l)), line.view());
	} else {
		(void)line.pushBack('\n');
		os::writeStderr(line.view());
	}
}

} // namespace logging
} // namespace donghoa
