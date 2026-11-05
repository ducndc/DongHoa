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

constexpr std::size_t MAX_BSS = 8U;
constexpr std::size_t MAX_MONITORS = 4U;
constexpr std::size_t MAX_L2_PORTS = 8U;
constexpr std::size_t MAX_SIM_PEERS = 16U;
// hostapd control socket name: a netdev name (15) or, for an AP MLD link,
// "<netdev>_link<id>" (up to 22).
constexpr std::size_t IF_NAME_MAX = 22U;

using IfName = FixedString<IF_NAME_MAX>;
using Path = FixedString<107U>;

enum class ScoreModel : std::uint8_t { LINEAR = 0U, TPUT = 1U };

struct BssCfg {
	IfName ifname{};          // hostapd BSS interface (ctrl socket name)
	std::uint16_t mdid{0U};   // 802.11r Mobility Domain ID, 0 = FT disabled
	int maxSta{0};
	bool ftOverDs{false};
};

struct PolicyConfig {
	bool rssiSteering{true};
	bool loadBalancing{true};
	bool bandSteering{true};

	int rssiLow{-75};        // dBm: STA below this is a roam candidate
	int rssiLowCount{3};    // consecutive polls below rssi_low
	int rssiHysteresis{8};   // dB the target must beat the current RSSI by
	int rssiMinTarget{-70}; // dBm: minimum STA-measured target level
	int bandSteerRssi{-55}; // dBm: 2.4 GHz STA above this -> 5/6 GHz
	bool bandSteer6g{true};    // also steer 5 GHz STAs that support 6 GHz up
	int bandSteer6gRssi{-55}; // dBm: 5 GHz STA above this -> 6 GHz

	int utilHigh{70};        // %: local BSS overloaded
	int utilAdmitMax{80};   // %: target refuses steer-in above this
	int lbMargin{15};        // %: target must be this far below util_high
	int lbRssiTolerance{5}; // dB accepted RSSI loss for load balancing
	bool lbOnlyIdle{true};
	int idleKbps{50};
	int lbIntervalMs{10000};

	int utilWeight{2};       // score penalty per 10 % target utilisation
	int bandBonus5g{5};
	int bandBonus6g{8};

	int steerCooldownMs{30000};
	int steerBackoffMaxMs{600000};
	int beaconReqTimeoutMs{1500};
	int steerRespTimeoutMs{1000};
	int btmTimeoutMs{2000};
	int roamTimeoutMs{5000};
	int reserveHoldMs{8000};

	int btmValidInt{100};   // TBTTs
	bool disassocImminent{false};
	int disassocTimer{0};    // TBTTs, with disassoc_imminent
	rrm::BeaconMode beaconMode{rrm::BeaconMode::ACTIVE};
	int beaconDuration{50};  // TUs
	bool assumeKvr{true};    // STAs are 11k/v/r capable unless shown otherwise

	ScoreModel scoreModel{ScoreModel::LINEAR};
	int tputRssiMid{-72};   // dBm: link quality 50 % (sigmoid midpoint)
	int tputGainPct{150};   // %: target tput needed vs current (RSSI/band)
	int staNss{2};           // spatial streams assumed for the peak rate

	bool amonRequest{true};  // ask peers' air monitors during MEASURE
	int amonDurationMs{1000};
	int amonRssiOffset{0};  // dB added to monitor (uplink) RSSI
};

struct Config {
	FixedString<32U> name{"arcp-ap"};
	Mac apId{};
	bool apIdSet{false};

	std::array<IfName, MAX_L2_PORTS> ifaces{};
	std::size_t nIfaces{0U};

	std::uint16_t simPort{0U};
	std::array<std::uint16_t, MAX_SIM_PEERS> simPeers{};
	std::size_t nSimPeers{0U};

	LogLevel logLevel{LogLevel::INFO};
	std::uint32_t logDebugMask{0U}; // bit = LogModule at debug level

	Path hostapdDir{"/var/run/hostapd"};
	Path ctrlSocket{};

	std::array<BssCfg, MAX_BSS> bss{};
	std::size_t nBss{0U};

	std::array<IfName, MAX_MONITORS> monitors{}; // radiotap monitor interfaces
	std::size_t nMonitors{0U};
	std::uint16_t monitorSimPort{0U};          // test input: radiotap over UDP

	std::array<std::uint8_t, 64U> key{};
	std::size_t keyLen{0U};

	int helloMs{2000};
	int bssStatusMs{5000};
	int staStatusMs{10000};
	int rfStatusMs{10000};
	int staPollMs{1000};
	int peerTimeoutMs{7000};

	PolicyConfig pol{};

	ByteView keyView() const noexcept { return ByteView(key.data(), keyLen); }
};

// One "key value" line; false if the key or value is invalid.
bool parseConfigLine(Config &c, std::string_view line) noexcept;
// Loads a file; logs "<path>:<line>: invalid line" and returns false on error.
bool loadConfig(Config &c, const char *path) noexcept;

} // namespace donghoa

#endif
