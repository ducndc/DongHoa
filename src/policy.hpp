// SPDX-License-Identifier: MIT
// Steering and load-balancing decisions. Pure functions, no I/O.
#ifndef DONGHOA_POLICY_HPP
#define DONGHOA_POLICY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <limits>

#include "config.hpp"
#include "proto.hpp"

namespace donghoa {
namespace policy {

constexpr int INELIGIBLE = std::numeric_limits<int>::min();
constexpr int RSSI_UNKNOWN = -128;

struct CandInput {
	std::uint8_t band{0U};
	int estRssi{RSSI_UNKNOWN}; // STA-measured level of the target
	int utilPct{-1};           // -1 unknown
	int staCount{0};
	int maxSta{0};             // 0 = unlimited
	bool accepting{true};
	int peakMbps{0};           // computePeakMbps() of the target (tput model)
};

struct SteerCtx {
	arcp::SteerReason reason{arcp::SteerReason::MANUAL};
	int curRssi{0};
	std::uint8_t curBand{0U};
	int curUtilPct{-1};       // tput model
	int curPeakMbps{0};       // tput model
};

// 0..254 utilisation as a percentage; -1 for 255 (unknown).
constexpr int utilToPct(int util255) noexcept
{
	return ((util255 < 0) || (util255 > 254)) ? -1 : (((util255 * 100) + 127) / 255);
}

// Link quality 0..1000: logistic curve, slope 0.3/dB, 500 at tput_rssi_mid.
// 0 for RSSI 0 (unknown) and RSSI_UNKNOWN.
int computeLinkQuality(const PolicyConfig &p, int rssi) noexcept;
// Top PHY rate of a BSS (Mbps) from its caps and width, for nss streams.
int computePeakMbps(std::uint16_t caps, std::uint8_t bw, int nss) noexcept;
// Expected throughput (kbps) = quality x peak x free airtime.
int computeExpectedKbps(const PolicyConfig &p, int rssi, int peak, int utilPct) noexcept;

// Candidate score (higher is better) or INELIGIBLE. With the tput model
// the score is the candidate's expected throughput in kbps.
int score(const PolicyConfig &p, const SteerCtx &ctx, const CandInput &c) noexcept;

// thresholdDbm: the STA's roaming threshold (roamThreshold()).
bool isRssiTriggered(const PolicyConfig &p, int rssi, int lowCount, int thresholdDbm) noexcept;

// ---- per-STA roaming threshold ----
// A STA's threshold in dBm: its learned value (0 = none yet) when learning
// is on, else rssi_low; always within roam_thr_min..roam_thr_max.
int roamThreshold(const PolicyConfig &p, int learnedDbm) noexcept;
enum class RoamOutcome : std::uint8_t {
	SUCCESS,      // moved to the chosen target
	REFUSED,      // BTM rejected or not answered: the STA hangs on
	ROAM_TIMEOUT, // accepted but never arrived
};
constexpr int ROAM_THR_REFUSED_DB = -2;  // roam it later
constexpr int ROAM_THR_TIMEOUT_DB = -1;
constexpr int ROAM_THR_BIG_GAIN_DB = 15; // success this much better: it waited too long
constexpr int ROAM_THR_EARLIER_DB = 1;
constexpr Millis ROAM_THR_DECAY_MS = 600000U; // no event this long: 1 dB back towards rssi_low
// New threshold after an RSSI steer of the STA. gainDb: target level minus
// the STA's level when the steer started (SUCCESS only).
int updateRoamThrOutcome(const PolicyConfig &p, int learnedDbm, RoamOutcome o, int gainDb) noexcept;
// New threshold after the STA roamed to another AP by itself, leaving this
// one at leftAtDbm: a quarter of the way towards that level.
int updateRoamThrSelf(const PolicyConfig &p, int learnedDbm, int leftAtDbm) noexcept;
// One decay step towards rssi_low.
int decayRoamThr(const PolicyConfig &p, int learnedDbm) noexcept;

// ---- Q-learning: when to roam ----
// State of a STA at a fresh sample, actions WAIT / STEER, Q values x256 in
// a fixed table. Integer only; the caller supplies the random number.
enum class RlMode : std::uint8_t { OFF = 0, SHADOW = 1, ACTIVE = 2 };
enum class RlAction : std::uint8_t { WAIT = 0, STEER = 1 };
struct RlFeatures {
	int rssi{0};          // smoothed dBm
	int slope{0};         // dB since the previous fresh sample
	int gapDb{0};         // best known neighbour level - rssi
	bool gapKnown{false}; // a neighbour level measured in the last 2 min
	int refusals{0};      // steer failures in a row
	bool lowStreak{false}; // lowCount >= rssi_low_count (below its threshold)
};
constexpr std::size_t RL_RSSI_BINS = 6U;  // >=-60, -65, -70, -75, -80, below
constexpr std::size_t RL_TREND_BINS = 3U; // falling (<= -1 dB), stable, rising (>= +1 dB)
constexpr std::size_t RL_GAP_BINS = 4U;   // unknown, < 0, 0..7, >= 8 dB
constexpr std::size_t RL_REF_BINS = 3U;   // 0, 1, >= 2 refusals
constexpr std::size_t RL_STREAK_BINS = 2U;
constexpr std::size_t RL_STATES = RL_RSSI_BINS * RL_TREND_BINS * RL_GAP_BINS * RL_REF_BINS * RL_STREAK_BINS;
constexpr int RL_ONE = 256;               // fixed point
constexpr int RL_GAMMA = 205;             // 0.8 x 256
constexpr std::uint32_t RL_ALPHA_N = 8U;  // alpha = 1/(n+1) up to 1/8
constexpr int RL_MIN_RSSI = -60;          // stronger: always WAIT, no decision recorded
// Rewards (x RL_ONE when applied).
constexpr int RL_R_SUCCESS = 8;           // + gain in dB, gain capped at RL_R_GAIN_MAX
constexpr int RL_R_GAIN_MAX = 24;
constexpr int RL_R_WRONG_TARGET = 4;
constexpr int RL_R_REFUSED = -10;
constexpr int RL_R_ROAM_TIMEOUT = -6;
constexpr int RL_R_NO_CANDIDATE = -2;
constexpr int RL_R_LINK_DROP = -20;
constexpr int RL_WAIT_FREE_DBM = -70;     // waiting above this costs nothing

struct RlTable {
	std::array<std::array<int, 2U>, RL_STATES> q{};
	std::array<std::array<std::uint32_t, 2U>, RL_STATES> n{};
};
std::size_t rlState(const RlFeatures &f) noexcept;
// The prior: STEER preferred exactly where the rule-based RSSI trigger
// fires (below -75 dBm with a low streak), so a fresh table behaves as today.
void rlInit(RlTable &t) noexcept;
// Greedy action; with probability eps% (rnd 0..99) the other one, but STEER
// only in "safe" states (below -65 dBm, a neighbour not known to be worse).
RlAction rlChoose(const RlTable &t, std::size_t s, int epsPct, std::uint32_t rnd, bool &explored) noexcept;
// Q(s,a) += alpha (r + gamma max Q(next) - Q(s,a)); terminal: no next.
void rlUpdate(RlTable &t, std::size_t s, RlAction a, int rewardDb, bool terminal, std::size_t next) noexcept;
int rlRewardSteer(arcp::SteerOutcome o, int gainDb) noexcept;   // in dB units
int rlRewardWait(int rssi) noexcept;                            // per fresh poll while waiting
// Bin labels for the RL command, e.g. "-75..-80".
std::string_view rlRssiBinName(std::size_t bin) noexcept;
// hostapd's signal is the level of the STA's last received frame. A poll
// sample is fresh only when that frame came within the last poll interval
// (inactive_msec, 0 when hostapd does not report it): an idle STA's old
// value must not count again on every poll.
bool isSignalFresh(std::uint32_t inactiveMs, int pollMs) noexcept;

// Uplink -> downlink offset of one BSS: downlink (the STA's 11k level of
// the BSS) minus uplink (the BSS's radio hearing the STA), learned from
// STAs measured both ways. It covers the TX power and antenna asymmetry
// between AP and STAs that one global amon_rssi_offset cannot.
struct UlDlOffset {
	int offset16{0};      // mean offset x 16 (dB)
	std::uint32_t n{0U};  // samples accepted
};
constexpr int ULDL_MAX_DELTA = 30; // |downlink - uplink| above this: not one link, dropped
constexpr int ULDL_OUTLIER = 12;   // once calibrated, a sample this far from the mean is dropped
constexpr std::uint32_t ULDL_AVG_N = 8U; // cumulative mean up to 8 samples, then EWMA 1/8
// Adds one paired sample; false if it was rejected as an outlier.
bool addUlDlSample(const PolicyConfig &p, UlDlOffset &o, int downlinkDbm, int uplinkDbm) noexcept;
// Downlink estimate of an uplink level: the learned offset once the BSS has
// amon_offset_min_samples samples (and learning is on), else amon_rssi_offset.
int uplinkToDownlink(const PolicyConfig &p, const UlDlOffset *o, int uplinkDbm) noexcept;
bool isUlDlCalibrated(const PolicyConfig &p, const UlDlOffset &o) noexcept;
bool isBandTriggered(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept;
bool isBssOverloaded(const PolicyConfig &p, int utilPct, int staCount, int maxSta) noexcept;
bool isLbStaEligible(const PolicyConfig &p, std::uint32_t tputKbps) noexcept;
// Did offloading a STA lower the source BSS's utilisation enough (by
// lb_min_drop_pct points)? Unknown utilisation (-1) on either side: no
// judgement, true.
bool isLbMoveEffective(const PolicyConfig &p, int utilBeforePct, int utilNowPct) noexcept;
// Target-side admission control for STEER_REQ.
arcp::SteerStatus admit(const PolicyConfig &p, int utilPct, int staCount, int reserved,
			int maxSta) noexcept;
// Bands of a STA (rrm::BANDS_* masks).
struct StaBands {
	std::uint8_t advertised{0U}; // Supported Operating Classes, 0 = not sent
	std::uint8_t seen{0U};       // associated or measured on
	std::uint8_t blocked{0U};    // cannot join (6 GHz with a WPA2-PSK AKM)
};

// Can the STA use band? Blocked bands never; otherwise an advertised or
// seen band, or any band when it advertises nothing (the measurement then
// decides).
bool isBandUsable(const StaBands &b, std::uint8_t band) noexcept;
// May a band steer start from curBand? From 2.4 GHz: some higher band is
// usable. From 5 GHz: 6 GHz must be advertised or seen (and not blocked),
// not just unknown.
bool hasHigherBand(const StaBands &b, std::uint8_t curBand) noexcept;
// Exponential backoff after failed steering attempts.
int backoffMs(const PolicyConfig &p, int failures) noexcept;

// Order of the candidate pool when more BSSes qualify than one steer can
// measure (MAX_CAND): a BSS the STA was recently measured at comes first,
// the better the level (hintRcpi, 0..220; NO_HINT when none), then this
// AP's own BSSes (no negotiation needed), then the others. Higher is better.
constexpr int NO_HINT = -1;
int candidatePoolRank(bool local, int hintRcpi) noexcept;

// ---- low-power (IoT) device classification ----
//
// Running mean and variance (Welford, integer) of a STA's uplink and
// downlink rate in bytes/s. The mean is kept x16 (fixed point) so slow
// devices (a few bytes/s) do not truncate to zero; m2 is in (bytes/s)^2.
// Past TRAFFIC_WINDOW samples n and m2 are halved, which keeps the
// variance and turns "since the connection began" into a long memory that
// fits 64 bits.
constexpr std::uint32_t TRAFFIC_WINDOW = 1024U;
constexpr std::uint64_t TRAFFIC_RATE_MAX = 1U << 25U; // bytes/s (~268 Mbit/s)
// Behaviour score when the downlink never varies but the uplink does.
constexpr int LP_S_MAX = 1000000;
constexpr int LP_NO_EVIDENCE = -1;

struct RateStats {
	std::int64_t mean16{0}; // mean x 16
	std::uint64_t m2{0U};   // sum of squared deviations
};

// Weight of a new sample in TrafficStats::upRecent16 (1/8: ~8 polls).
constexpr std::int64_t TRAFFIC_RECENT_DIV = 8;

struct TrafficStats {
	std::uint32_t n{0U};
	RateStats up{};   // STA -> AP (hostapd rx_bytes)
	RateStats down{}; // AP -> STA (hostapd tx_bytes)
	// Moving average of the uplink rate x 16 over the last few polls: the
	// lp_max_mean_bps gate follows what the STA does now, not a mean over
	// the whole window (which would keep one big upload for minutes).
	std::int64_t upRecent16{0};
	// The latest sample moved data (either way). An idle poll still goes
	// into the statistics but is no evidence: otherwise one old uplink
	// burst (sigma_up > 0) and no downlink at all (sigma_down = 0) would
	// score S = inf on every idle poll, and any quiet STA would end up
	// low-power a minute later.
	bool lastActive{false};
};

void addTrafficSample(TrafficStats &t, std::uint64_t upBps, std::uint64_t downBps) noexcept;
// S x 100 = alpha(band) x sigma_up / sigma_down x 100; LP_S_MAX when only
// the uplink varies; LP_NO_EVIDENCE before lp_min_samples, when neither
// direction varies, or when the latest sample moved no data (an idle STA
// tells nothing).
int lpBehaviourScore(const PolicyConfig &p, const TrafficStats &t, std::uint8_t band) noexcept;
// theta + 1 when S > 1, - 1 otherwise, kept in 0..lp_score_max; unchanged
// without evidence.
int updateLpScore(const PolicyConfig &p, int theta, int s100) noexcept;
// Low-power when theta > lp_threshold; once low-power it stays so until
// theta < lp_threshold - lp_hysteresis.
bool isLowPower(const PolicyConfig &p, int theta, bool wasLowPower) noexcept;
// True when phyCaps (arcp::CAP_*) holds a PHY that lp_exclude_vht/he/eht
// rules out for a low-power device.
bool isLpExcludedPhy(const PolicyConfig &p, std::uint8_t phyCaps) noexcept;
std::uint32_t isqrt(std::uint64_t v) noexcept;

} // namespace policy
} // namespace donghoa

#endif
