// SPDX-License-Identifier: MIT
// Logging with a level per module and type-safe "{}" formatting:
//
//   namespace { constexpr LogModule LOG_MODULE{LogModule::STEER}; }
//   logging::info(LOG_MODULE, "steer #{} start", id);
#ifndef DONGHOA_LOG_HPP
#define DONGHOA_LOG_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "text.hpp"

namespace donghoa {

enum class LogLevel : std::uint8_t { ERR = 0U, WARN = 1U, INFO = 2U, DEBUG = 3U };

enum class LogModule : std::uint8_t {
	MAIN = 0U,
	L2,
	MSG,
	PEER,
	HAPD,
	LOCAL,
	STEER,
	POLICY,
	AMON,
	SURVEY,
	CTRL,
	CONFIG,
	RRM,
	CLASS,
	COUNT
};

namespace logging {

constexpr std::size_t MODULES = static_cast<std::size_t>(LogModule::COUNT);

bool enabled(LogModule m, LogLevel l) noexcept;
LogLevel level(LogModule m) noexcept;
void setLevel(LogModule m, LogLevel l) noexcept;
void setAll(LogLevel l) noexcept;
std::optional<LogLevel> parseLevel(std::string_view s) noexcept;
std::optional<LogModule> parseModule(std::string_view s) noexcept;
std::string_view levelName(LogLevel l) noexcept;
std::string_view moduleName(LogModule m) noexcept;
// Module from its index 0..MODULES-1.
LogModule moduleAt(std::size_t i) noexcept;
// Log to syslog (daemon facility, ident "donghoa") instead of stderr.
void useSyslog(bool on) noexcept;
void emit(LogModule m, LogLevel l, std::string_view text) noexcept;

template <typename... A>
void write(LogModule m, LogLevel l, std::string_view fmt, const A &...args) noexcept
{
	if (enabled(m, l)) {
		Line line;
		formatTo(line, fmt, args...);
		emit(m, l, line.view());
	}
}

template <typename... A>
void err(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::ERR, fmt, args...);
}

template <typename... A>
void warn(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::WARN, fmt, args...);
}

template <typename... A>
void info(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::INFO, fmt, args...);
}

template <typename... A>
void dbg(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::DEBUG, fmt, args...);
}

} // namespace logging
} // namespace donghoa

#endif
