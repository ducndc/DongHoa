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

// RFC 5424 (syslog) severities, with their numeric codes. emerg (0), alert
// (1) and crit (2) are accepted as names and set ERR: nothing in a steering
// daemon is system-wide or needs immediate action.
//   ERR     the daemon cannot do something it should (socket, config, hostapd)
//   WARN    something is wrong but handled (rejected peer, lost message, a
//           mismatched setting)
//   NOTICE  normal but significant: peers joining and leaving, steering
//           outcomes, enrollment decisions, configuration findings clearing
//   INFO    routine operation: each step of a steer, measurements, offloads
//   DEBUG   traces (frames, commands, per-poll values)
enum class LogLevel : std::uint8_t { ERR = 3U, WARN = 4U, NOTICE = 5U, INFO = 6U, DEBUG = 7U };

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
	ENROLL,
	CHECK,
	COUNT
};

namespace logging {

constexpr std::size_t MODULES = static_cast<std::size_t>(LogModule::COUNT);

bool enabled(LogModule m, LogLevel l) noexcept;
LogLevel level(LogModule m) noexcept;
void setLevel(LogModule m, LogLevel l) noexcept;
void setAll(LogLevel l) noexcept;
// RFC 5424 keyword ("err", "warning", "notice", ...), its common alias
// ("error", "warn"), or its number 0..7; 0..2 / emerg, alert, crit give ERR.
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
void notice(LogModule m, std::string_view fmt, const A &...args) noexcept
{
	write(m, LogLevel::NOTICE, fmt, args...);
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
