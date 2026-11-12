// SPDX-License-Identifier: MIT
// Outcome counters (feature 12): what the steering engine, load balancing
// and ARCP did since start-up, for the METRICS control command. Pure: the
// counters, the update rule and the text form (Prometheus text exposition,
// readable by node_exporter's textfile collector and most monitoring
// agents). Counters only grow; they restart at zero with the daemon.
#ifndef DONGHOA_METRICS_HPP
#define DONGHOA_METRICS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "proto.hpp"
#include "text.hpp"
#include "types.hpp"

namespace donghoa {
namespace metrics {

constexpr std::size_t REASONS = 4U; // arcp::SteerReason 1..4

// How a steering transaction ended: arcp::SteerOutcome, plus "no
// candidate" (MEASURE found none that qualifies).
constexpr std::size_t RESULTS = 7U;
constexpr std::size_t RESULT_NO_CANDIDATE = 6U;

// One source BSS, one trigger.
struct SteerCounters {
	std::uint32_t started{0U};
	std::uint32_t noPool{0U}; // trigger fired, but no BSS to measure at all
	std::array<std::uint32_t, RESULTS> result{};
	std::uint32_t btmSent{0U};
	std::uint32_t btmAccept{0U};
	std::uint32_t btmReject{0U}; // each rejection, also when the next candidate is tried
	std::uint32_t gainCount{0U}; // successes with a known level gain
	std::int64_t gainSumDb{0};   // target level - level when the steer started
	std::uint64_t durSumMs{0U};  // start to association, successes only
};

// Target side of one local BSS: STEER_REQ answers by status, outcomes.
struct SteerInCounters {
	std::array<std::uint32_t, 6U> status{}; // arcp::SteerStatus
	std::uint32_t success{0U};
	std::uint32_t failed{0U};
};

struct LbCounters {
	std::uint32_t offloads{0U};
	std::uint32_t effective{0U}; // utilisation dropped by lb_min_drop_pct
	std::uint32_t futile{0U};
	std::uint32_t noVerdict{0U}; // the STA disconnected instead of moving
	std::uint32_t pauses{0U};
};

struct BssCounters {
	std::array<SteerCounters, REASONS> steer{};
	SteerInCounters in{};
	LbCounters lb{};
};

struct ArcpCounters {
	std::uint64_t rx{0U};          // frames accepted into processing
	std::uint64_t rxBadHeader{0U};
	std::uint64_t rxAuthFail{0U};  // HMAC
	std::uint64_t rxSigFail{0U};   // Ed25519 (unlisted origin or bad signature)
	std::uint64_t rxUntrusted{0U}; // enrollment: origin not in the trust table
	std::uint64_t rxUnverified{0U}; // liveness check: boot not verified yet
	std::uint64_t rxDuplicate{0U}; // replay window
	std::uint64_t tx{0U};          // messages sent (once per message, not per port)
	std::uint64_t retransmit{0U};
	std::uint64_t ackTimeout{0U};  // reliable unicast given up
	std::uint64_t queueFull{0U};   // no room to keep a message for retransmission
	std::uint32_t steerInUnknownBss{0U};
};

// Index of a reason in BssCounters::steer; REASONS for an invalid one.
std::size_t reasonIndex(arcp::SteerReason r) noexcept;

// Records how a transaction ended. gainKnown/gainDb/durMs count only for
// SUCCESS.
void addOutcome(SteerCounters &c, arcp::SteerOutcome o, bool gainKnown, int gainDb, Millis durMs) noexcept;

// Prometheus text form. Lines with a zero value are left out to keep the
// reply inside one control datagram; a series appears with its first
// event.
using Text = FixedString<8192U>;
void formatBss(Text &out, std::string_view bss, const BssCounters &c) noexcept;
void formatArcp(Text &out, const ArcpCounters &c) noexcept;

} // namespace metrics
} // namespace donghoa

#endif
