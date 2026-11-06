// SPDX-License-Identifier: MIT
// Per-STA RSSI from the Wi-Fi driver: the chipset vendor's API that takes a
// STA's MAC address and measures the RSSI of its frames on a radio, whether
// or not the STA is associated to this AP. The air monitor (amon.cpp) uses
// it next to, or instead of, a radiotap monitor interface.
//
// The vendor implementation is a placeholder (see vendor_rssi.cpp) until
// the chipset documentation is reviewed. A simulated driver backed by a
// text file stands in for it in tests (sta_rssi_sim).
#ifndef DONGHOA_VENDOR_RSSI_HPP
#define DONGHOA_VENDOR_RSSI_HPP

#include <cstdint>
#include <string_view>

#include "types.hpp"

namespace donghoa {
namespace vendor {

enum class RssiStatus : std::uint8_t {
	OK,          // measuring (start) / a sample is available (read)
	NOT_HEARD,   // no frame of the STA since start
	UNSUPPORTED, // no such API for this radio
	FAILED,      // the API returned an error
};

struct RssiSample {
	std::int8_t rssi{0};       // dBm, average over the measurement
	std::uint16_t samples{0U}; // frames behind it
	std::uint16_t ageMs{0U};   // since the last frame
};

// Selects the simulated driver (tests), file format in vendor_rssi.cpp.
// An empty path selects the vendor implementation.
void useSimFile(std::string_view path) noexcept;

// True if the radio of BSS interface ifname can measure a given STA.
bool isStaRssiSupported(std::string_view ifname) noexcept;
// Starts measuring sta on the radio of ifname (its own channel; opClass /
// channel are the STA's current channel, a hint for drivers that can go
// off-channel) for durationMs.
RssiStatus startStaRssi(std::string_view ifname, const Mac &sta, std::uint8_t opClass, std::uint8_t channel,
			std::uint16_t durationMs) noexcept;
// Result of the measurement started on ifname.
RssiStatus readStaRssi(std::string_view ifname, const Mac &sta, RssiSample &out) noexcept;
// Ends the measurement (also after a failed start).
void stopStaRssi(std::string_view ifname, const Mac &sta) noexcept;

} // namespace vendor
} // namespace donghoa

#endif
