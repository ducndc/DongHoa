// SPDX-License-Identifier: MIT
// Steering and load-balancing decisions. Pure functions, no I/O.
#ifndef DONGHOA_POLICY_HPP
#define DONGHOA_POLICY_HPP

#include <cstdint>
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

bool isRssiTriggered(const PolicyConfig &p, int rssi, int lowCount) noexcept;
bool isBandTriggered(const PolicyConfig &p, std::uint8_t band, int rssi) noexcept;
bool isBssOverloaded(const PolicyConfig &p, int utilPct, int staCount, int maxSta) noexcept;
bool isLbStaEligible(const PolicyConfig &p, std::uint32_t tputKbps) noexcept;
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
};

void addTrafficSample(TrafficStats &t, std::uint64_t upBps, std::uint64_t downBps) noexcept;
// S x 100 = alpha(band) x sigma_up / sigma_down x 100; LP_S_MAX when only
// the uplink varies; LP_NO_EVIDENCE before lp_min_samples or when neither
// direction varies (an idle STA tells nothing).
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
