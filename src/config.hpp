// SPDX-License-Identifier: MIT
// Configuration: "key value" lines, '#' comments. Defaults are the member
// initializers; docs/SRS.md Appendix A lists every key.
#ifndef DONGHOA_CONFIG_HPP
#define DONGHOA_CONFIG_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "log.hpp"
#include "rrm.hpp"
#include "types.hpp"

namespace donghoa {

constexpr std::size_t kMaxBss = 8U;
constexpr std::size_t kMaxMonitors = 4U;
constexpr std::size_t kMaxL2Ports = 8U;
constexpr std::size_t kMaxSimPeers = 16U;
constexpr std::size_t kIfNameMax = 15U;

using IfName = FixedString<kIfNameMax>;
using Path = FixedString<107U>;

enum class ScoreModel : std::uint8_t { linear = 0U, tput = 1U };

struct BssCfg {
	IfName ifname{};          // hostapd BSS interface (ctrl socket name)
	std::uint16_t mdid{0U};   // 802.11r Mobility Domain ID, 0 = FT disabled
	int max_sta{0};
	bool ft_over_ds{false};
};

struct PolicyConfig {
	bool rssi_steering{true};
	bool load_balancing{true};
	bool band_steering{true};

	int rssi_low{-75};        // dBm: STA below this is a roam candidate
	int rssi_low_count{3};    // consecutive polls below rssi_low
	int rssi_hysteresis{8};   // dB the target must beat the current RSSI by
	int rssi_min_target{-70}; // dBm: minimum STA-measured target level
	int band_steer_rssi{-55}; // dBm: 2.4 GHz STA above this -> 5/6 GHz

	int util_high{70};        // %: local BSS overloaded
	int util_admit_max{80};   // %: target refuses steer-in above this
	int lb_margin{15};        // %: target must be this far below util_high
	int lb_rssi_tolerance{5}; // dB accepted RSSI loss for load balancing
	bool lb_only_idle{true};
	int idle_kbps{50};
	int lb_interval_ms{10000};

	int util_weight{2};       // score penalty per 10 % target utilisation
	int band_bonus_5g{5};
	int band_bonus_6g{8};

	int steer_cooldown_ms{30000};
	int steer_backoff_max_ms{600000};
	int beacon_req_timeout_ms{1500};
	int steer_resp_timeout_ms{1000};
	int btm_timeout_ms{2000};
	int roam_timeout_ms{5000};
	int reserve_hold_ms{8000};

	int btm_valid_int{100};   // TBTTs
	bool disassoc_imminent{false};
	int disassoc_timer{0};    // TBTTs, with disassoc_imminent
	rrm::BeaconMode beacon_mode{rrm::BeaconMode::active};
	int beacon_duration{50};  // TUs
	bool assume_kvr{true};    // STAs are 11k/v/r capable unless shown otherwise

	ScoreModel score_model{ScoreModel::linear};
	int tput_rssi_mid{-72};   // dBm: link quality 50 % (sigmoid midpoint)
	int tput_gain_pct{150};   // %: target tput needed vs current (RSSI/band)
	int sta_nss{2};           // spatial streams assumed for the peak rate

	bool amon_request{true};  // ask peers' air monitors during MEASURE
	int amon_duration_ms{1000};
	int amon_rssi_offset{0};  // dB added to monitor (uplink) RSSI
};

struct Config {
	FixedString<32U> name{"arcp-ap"};
	Mac ap_id{};
	bool ap_id_set{false};

	std::array<IfName, kMaxL2Ports> ifaces{};
	std::size_t n_ifaces{0U};

	std::uint16_t sim_port{0U};
	std::array<std::uint16_t, kMaxSimPeers> sim_peers{};
	std::size_t n_sim_peers{0U};

	LogLevel log_level{LogLevel::info};
	std::uint32_t log_debug_mask{0U}; // bit = LogModule at debug level

	Path hostapd_dir{"/var/run/hostapd"};
	Path ctrl_socket{};

	std::array<BssCfg, kMaxBss> bss{};
	std::size_t n_bss{0U};

	std::array<IfName, kMaxMonitors> monitors{}; // radiotap monitor interfaces
	std::size_t n_monitors{0U};
	std::uint16_t monitor_sim_port{0U};          // test input: radiotap over UDP

	std::array<std::uint8_t, 64U> key{};
	std::size_t key_len{0U};

	int hello_ms{2000};
	int bss_status_ms{5000};
	int sta_status_ms{10000};
	int rf_status_ms{10000};
	int sta_poll_ms{1000};
	int peer_timeout_ms{7000};

	PolicyConfig pol{};

	ByteView key_view() const noexcept { return ByteView(key.data(), key_len); }
};

// One "key value" line; false if the key or value is invalid.
bool config_line(Config &c, std::string_view line) noexcept;
// Loads a file; logs "<path>:<line>: invalid line" and returns false on error.
bool config_load(Config &c, const char *path) noexcept;

} // namespace donghoa

#endif
