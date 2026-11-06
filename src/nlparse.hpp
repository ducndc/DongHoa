// SPDX-License-Identifier: MIT
// Pure parsing of nl80211 generic-netlink messages (no I/O): attribute
// lookup and the station-dump entry (NL80211_CMD_GET_STATION). survey.cpp
// owns the socket; this layer only reads bytes, so it is unit-tested.
#ifndef DONGHOA_NLPARSE_HPP
#define DONGHOA_NLPARSE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>

#include "types.hpp"

namespace donghoa {
namespace nl {

constexpr std::size_t NL_HDR = 16U;  // struct nlmsghdr
constexpr std::size_t GENL_HDR = 4U; // struct genlmsghdr
constexpr std::size_t ATTR_HDR = 4U; // struct nlattr

constexpr std::size_t align4(std::size_t n) noexcept
{
	return (n + 3U) & ~static_cast<std::size_t>(3U);
}

// Payload of the attribute of the given type inside attrs; empty view if
// absent. A present but empty attribute (a flag) returns its header, so
// "found" is !empty().
ByteView findAttr(ByteView attrs, std::uint16_t type) noexcept;
bool hasAttr(ByteView attrs, std::uint16_t type) noexcept;
// Attributes of a generic-netlink message (after both headers), bounded
// by the message's own length.
ByteView genlAttrs(ByteView msg) noexcept;

// One station of an interface, as the kernel reports it. Rates in Mbit/s.
struct Station {
	Mac addr{};
	bool authorized{false};
	int signal{0};    // dBm of the last frame, 0 if absent
	int signalAvg{0}; // dBm, the kernel's per-frame average, 0 if absent
	std::uint32_t inactiveMs{0U};
	std::uint32_t connectedS{0U};
	std::uint64_t rxBytes{0U}; // from the STA (uplink)
	std::uint64_t txBytes{0U}; // to the STA (downlink)
	std::uint16_t rxRateMbps{0U};
	std::uint16_t txRateMbps{0U};
};

// The station carried by one NL80211_CMD_NEW_STATION dump message.
std::optional<Station> parseStation(ByteView msg) noexcept;

} // namespace nl
} // namespace donghoa

#endif
