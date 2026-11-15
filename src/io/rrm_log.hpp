// SPDX-License-Identifier: MIT
// Dump of the 802.11k/v traffic between DongHoa and hostapd: commands
// (REQ_BEACON, BSS_TM_REQ, SET_NEIGHBOR, REMOVE_NEIGHBOR) with their
// replies, and events (BEACON-RESP-RX, BEACON-REQ-TX-STATUS, BSS-TM-RESP,
// BSS-TM-QUERY). Each is logged raw and decoded, at debug level of log
// module "rrm" (donghoa_cli <sock> LOG debug rrm, or "log_debug rrm").
#ifndef DONGHOA_RRM_LOG_HPP
#define DONGHOA_RRM_LOG_HPP

#include <string_view>

namespace donghoa {
namespace rrmlog {

// command was sent to hostapd of ifname and answered with reply. Other
// commands are ignored.
void logCommand(std::string_view ifname, std::string_view command, std::string_view reply) noexcept;
// ev arrived from hostapd of ifname (without the "<N>" prefix). Other
// events are ignored.
void logEvent(std::string_view ifname, std::string_view ev) noexcept;

} // namespace rrmlog
} // namespace donghoa

#endif
