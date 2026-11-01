// SPDX-License-Identifier: MIT
#include "log.hpp"

#include <array>

#include "os.hpp"

namespace donghoa {
namespace logging {

namespace {

std::array<LogLevel, kModules> g_levels{
	LogLevel::info, LogLevel::info, LogLevel::info, LogLevel::info,
	LogLevel::info, LogLevel::info, LogLevel::info, LogLevel::info,
	LogLevel::info, LogLevel::info, LogLevel::info, LogLevel::info,
};

constexpr std::array<std::string_view, kModules> kModuleNames{
	"main", "l2", "msg", "peer", "hapd", "local", "steer", "policy", "amon", "survey", "ctrl",
	"config",
};

constexpr std::array<std::string_view, 4U> kLevelNames{"err", "warn", "info", "debug"};
constexpr std::array<std::string_view, 4U> kTags{"ERR", "WRN", "INF", "DBG"};

bool g_syslog = false;

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
	return (idx(m) < kModules) && (idx(l) <= idx(g_levels[idx(m)]));
}

LogLevel level(LogModule m) noexcept
{
	return (idx(m) < kModules) ? g_levels[idx(m)] : LogLevel::info;
}

void set_level(LogModule m, LogLevel l) noexcept
{
	if ((idx(m) < kModules) && (idx(l) < kLevelNames.size())) {
		g_levels[idx(m)] = l;
	}
}

void set_all(LogLevel l) noexcept
{
	for (LogLevel &x : g_levels) {
		x = l;
	}
}

std::optional<LogLevel> parse_level(std::string_view s) noexcept
{
	std::optional<LogLevel> r;
	for (std::size_t i = 0U; i < kLevelNames.size(); i++) {
		if (s == kLevelNames[i]) {
			r = static_cast<LogLevel>(i);
		}
	}
	return r;
}

std::optional<LogModule> parse_module(std::string_view s) noexcept
{
	std::optional<LogModule> r;
	for (std::size_t i = 0U; i < kModules; i++) {
		if (s == kModuleNames[i]) {
			r = module_at(i);
		}
	}
	return r;
}

std::string_view level_name(LogLevel l) noexcept
{
	return (idx(l) < kLevelNames.size()) ? kLevelNames[idx(l)] : std::string_view("?");
}

std::string_view module_name(LogModule m) noexcept
{
	return (idx(m) < kModules) ? kModuleNames[idx(m)] : std::string_view("?");
}

LogModule module_at(std::size_t i) noexcept
{
	return (i < kModules) ? static_cast<LogModule>(i) : LogModule::main;
}

void use_syslog(bool on) noexcept
{
	if (on && !g_syslog) {
		os::syslog_open();
	} else if (!on && g_syslog) {
		os::syslog_close();
	} else {
		// unchanged
	}
	g_syslog = on;
}

void emit(LogModule m, LogLevel l, std::string_view text) noexcept
{
	const Millis t = os::now_ms();
	Line line;

	// "<s>.<ms> [TAG] module: text". The monotonic time lines up exactly
	// with this AP's own timers; milliseconds are padded to three digits.
	format_to(line, "{}.", t / 1000U);
	const std::uint64_t ms = t % 1000U;
	if (ms < 100U) {
		(void)line.push_back('0');
	}
	if (ms < 10U) {
		(void)line.push_back('0');
	}
	format_to(line, "{} [{}] {}: {}", ms, kTags[idx(l)], module_name(m), text);
	if (g_syslog) {
		os::syslog_write(static_cast<std::uint8_t>(idx(l)), line.view());
	} else {
		(void)line.push_back('\n');
		os::write_stderr(line.view());
	}
}

} // namespace logging
} // namespace donghoa
