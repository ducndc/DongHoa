// SPDX-License-Identifier: MIT
// Logging with a level per module and type-safe "{}" formatting:
//
//   namespace { constexpr LogModule kMod{LogModule::steer}; }
//   logging::info(kMod, "steer #{} start", id);
#ifndef DONGHOA_LOG_HPP
#define DONGHOA_LOG_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "text.hpp"

namespace donghoa {

enum class LogLevel : std::uint8_t { err = 0U, warn = 1U, info = 2U, debug = 3U };

enum class LogModule : std::uint8_t {
	main = 0U,
	l2,
	msg,
	peer,
	hapd,
	local,
	steer,
	policy,
	amon,
	survey,
	ctrl,
	config,
	count
};

namespace logging {

constexpr std::size_t kModules = static_cast<std::size_t>(LogModule::count);

bool enabled(LogModule m, LogLevel l) noexcept;
LogLevel level(LogModule m) noexcept;
void set_level(LogModule m, LogLevel l) noexcept;
void set_all(LogLevel l) noexcept;
std::optional<LogLevel> parse_level(std::string_view s) noexcept;
std::optional<LogModule> parse_module(std::string_view s) noexcept;
std::string_view level_name(LogLevel l) noexcept;
std::string_view module_name(LogModule m) noexcept;
// Module from its index 0..kModules-1.
LogModule module_at(std::size_t i) noexcept;
// Log to syslog (daemon facility, ident "donghoa") instead of stderr.
void use_syslog(bool on) noexcept;
void emit(LogModule m, LogLevel l, std::string_view text) noexcept;

template <typename... A>
void write(LogModule m, LogLevel l, std::string_view fmt, const A &...args) noexcept
{
	if (enabled(m, l)) {
		Line line;
		format_to(line, fmt, args...);
		emit(m, l, line.view());
	}
}

template <typename... A>
void err(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::err, fmt, args...);
}

template <typename... A>
void warn(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::warn, fmt, args...);
}

template <typename... A>
void info(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::info, fmt, args...);
}

template <typename... A>
void dbg(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::debug, fmt, args...);
}

} // namespace logging
} // namespace donghoa

#endif
