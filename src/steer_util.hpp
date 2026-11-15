// SPDX-License-Identifier: MIT
// Internals shared by the steering files (steer.cpp, steer_measure.cpp,
// steer_trigger.cpp, steer_target.cpp, steer_learn.cpp). Not for other
// modules.
#ifndef DONGHOA_STEER_UTIL_HPP
#define DONGHOA_STEER_UTIL_HPP

#include <cstdint>
#include <string_view>

#include "daemon.hpp"

namespace donghoa {
namespace steer {

// Measurement age that still orders the candidate pool.
constexpr Millis POOL_HINT_MS = 120000U;

// Names for log lines (steer.cpp). The raw forms take the wire value.
std::string_view reasonName(arcp::SteerReason r) noexcept;
std::string_view reasonNameRaw(std::uint8_t r) noexcept;
std::string_view outcomeName(std::uint8_t o) noexcept;

constexpr std::uint8_t raw(arcp::SteerOutcome o) noexcept
{
	return static_cast<std::uint8_t>(o);
}

// Fresh levels of bssid as seen for the STA (steer_measure.cpp); nullptr
// when there is none.
// STA-measured (11k beacon report) level.
const Measurement *bcnLookup(const Sta &s, const Mac &bssid) noexcept;
// Best available level: the STA's own report, else an air monitor's.
const Measurement *levelLookup(const Sta &s, const Mac &bssid) noexcept;

} // namespace steer
} // namespace donghoa

#endif
