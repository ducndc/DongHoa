// SPDX-License-Identifier: MIT
// Configuration: "key value" lines, '#' comments. Defaults are the member
// initializers; docs/SRS.md Appendix A lists every key.
#ifndef DONGHOA_CONFIG_HPP
#define DONGHOA_CONFIG_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ed25519.hpp"
#include "log.hpp"
#include "rrm.hpp"
#include "types.hpp"

namespace donghoa {

constexpr std::size_t MAX_BSS = 16U; // local BSSes managed (and tracked per peer)
constexpr std::size_t MAX_MONITORS = 4U;
constexpr std::size_t MAX_L2_PORTS = 8U;
constexpr std::size_t MAX_SIM_PEERS = 16U;
constexpr std::size_t MAX_TRUSTED = 64U; // peer_key lines (this AP's own may be listed)

// "peer_key <ap_id> hex:<public key>": an AP allowed to talk ARCP
struct TrustedKey {
	Mac apId{};
	ed25519::PublicKey pub{};
};
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
	// Per-STA roaming threshold, learned from each STA's RSSI-steer outcomes
	// and its own roams, kept in roam_thr_min..roam_thr_max; rssi_low is
	// the starting point and what an unlearned STA uses.
	bool roamThrLearn{true};
	// Q-learning of when to roam (policy::rl*): 0 off (default), 1 shadow
	// (learn from the RSSI trigger's decisions, behaviour unchanged), 2
	// active (the learned table decides, exploring rl_epsilon_pct % in safe
	// states). Enabled by this key or at run time with "RL mode <n>".
	int rlRoam{0};
	int rlEpsilonPct{1};
	// Contextual bandit for the choice of target (policy::bandit*): 0 off
	// (default), 1 shadow (learn from the outcomes of the score's choice),
	// 2 active (order eligible candidates by learned value; swap the top
	// two in bandit_epsilon_pct % of steers). Also "BANDIT mode <n>".
	int banditTarget{0};
	int banditEpsilonPct{5};
	int roamThrMin{-82};
	int roamThrMax{-65};
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
	// Feedback: after a utilisation-triggered offload, utilisation must
	// drop by lb_min_drop_pct points; after lb_max_futile moves that did
	// not, offloading from that BSS pauses for lb_hold_ms (busy time of
	// other networks or interference does not go away by moving STAs).
	int lbMinDropPct{3};
	int lbMaxFutile{2};
	int lbHoldMs{300000};

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
	int amonRssiOffset{0};  // dB added to monitor (uplink) RSSI until learned
	// Learn the uplink -> downlink offset per BSS from STAs measured both
	// ways (11k report and AP-side level of the same BSS), and use it
	// instead of amon_rssi_offset once a BSS has this many samples.
	bool amonOffsetLearn{true};
	int amonOffsetMinSamples{3};

	// Low-power (IoT) device classification from traffic behaviour:
	// S = alpha(band) x sigma_up / sigma_down over the connection; theta
	// +1 when S > 1, -1 otherwise; low-power while theta > lp_threshold.
	bool lpClassify{true};
	bool lpNoSteer{true};    // no automatic steering of low-power STAs
	// A STA that negotiated one of these PHYs is never low-power. VHT/EHT
	// radios are rare on battery devices; HE is not (Wi-Fi 6 IoT chips use
	// it for TWT power saving), so it is off by default.
	bool lpExcludeVht{true};
	bool lpExcludeHe{false};
	bool lpExcludeEht{true};
	int lpThreshold{60};     // delta: theta above it -> low-power
	int lpHysteresis{10};    // low-power ends when theta < delta - this
	int lpScoreMax{120};     // theta is kept in 0..this
	int lpMinSamples{10};    // traffic samples before S counts
	// A low-power device's traffic is small in absolute terms, not just
	// asymmetric: a phone doing a large upload (backup, AirDrop) looks
	// exactly as "bursty up, quiet down" as a sensor while moving 1000x
	// the data. Above this mean uplink rate, S is not evidence either way.
	int lpMaxMeanBps{20000}; // bytes/s; 0 disables the gate
	int lpAlpha2g{100};      // alpha x 100 on 2.4 GHz
	int lpAlpha5g{100};      // alpha x 100 on 5 GHz
	int lpAlpha6g{100};      // alpha x 100 on 6 GHz
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
	// Valid bss lines beyond MAX_BSS: ignored (with a warning at start-up)
	// rather than refusing to start, since on OpenWrt the lines come from
	// /etc/config/wireless and the operator did not write them.
	std::size_t nBssSkipped{0U};
	IfName bssSkippedFirst{};

	std::array<IfName, MAX_MONITORS> monitors{}; // radiotap monitor interfaces
	std::size_t nMonitors{0U};
	std::uint16_t monitorSimPort{0U};          // test input: radiotap over UDP
	bool staRssiApi{false}; // measure STAs with the driver's per-STA RSSI API
	Path staRssiSim{};      // test: simulated driver (implies staRssiApi)

	std::array<std::uint8_t, 64U> key{};
	std::size_t keyLen{0U};
	bool keyPlaceholder{false}; // 'key' was the shipped example value (refused)

	// Per-AP signatures: this AP signs with signKey; messages are accepted
	// only from origins in trusted[], signed with their key. Both or neither.
	bool signing{false};
	ed25519::KeyPair signKey{};
	std::array<TrustedKey, MAX_TRUSTED> trusted{};
	std::size_t nTrusted{0U};

	// Liveness check (CHALLENGE / RESPONSE) before adopting a peer's boot:
	// stops replays across boots. Off by default; answering a peer's
	// CHALLENGE is always on.
	bool livenessCheck{false};

	// Automatic enrollment (implies signing): own key from seedFile
	// (created on first start), trust table kept in trustFile; peer_key
	// lines become fixed anchors.
	bool enroll{false};
	Path seedFile{"/etc/donghoa.seed"};
	Path trustFile{"/etc/donghoa.trust"};

	// Public key listed for origin, or nullptr.
	const ed25519::PublicKey *findTrusted(const Mac &origin) const noexcept
	{
		const ed25519::PublicKey *r = nullptr;
		for (std::size_t i = 0U; i < nTrusted; i++) {
			if ((r == nullptr) && (trusted[i].apId == origin)) {
				r = &trusted[i].pub;
			}
		}
		return r;
	}

	int helloMs{2000};
	int bssStatusMs{5000};
	int staStatusMs{10000};
	int rfStatusMs{10000};
	int staPollMs{1000};
	int peerTimeoutMs{7000};

	PolicyConfig pol{};

	ByteView keyView() const noexcept { return ByteView(key.data(), keyLen); }
};

// The example key of donghoa.conf.example and the OpenWrt package. It is
// public, so it is refused instead of authenticating anything.
constexpr std::string_view KEY_PLACEHOLDER{"change-me-to-a-long-random-secret"};
// Passphrase keys: PBKDF2-HMAC-SHA256(passphrase, KEY_KDF_SALT, iterations).
// The salt is fixed (every AP must derive the same key); the iteration count
// costs about 0.1 s on x86-64 and well under 2 s on an ARMv7 AP, once at start.
constexpr std::string_view KEY_KDF_SALT{"donghoa-arcp-key"};
constexpr std::uint32_t KEY_KDF_ITERATIONS = 100000U;
constexpr std::size_t KEY_PASSPHRASE_MAX = 128U;

// One "key value" line; false if the key or value is invalid.
bool parseConfigLine(Config &c, std::string_view line) noexcept;
// Loads a file; logs "<path>:<line>: invalid line" and returns false on error.
bool loadConfig(Config &c, const char *path) noexcept;

} // namespace donghoa

#endif
