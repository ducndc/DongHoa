// SPDX-License-Identifier: MIT
#include "metrics.hpp"

namespace donghoa {
namespace metrics {

namespace {

constexpr std::array<std::string_view, REASONS> REASON_NAMES{"rssi", "load", "band", "manual"};
constexpr std::array<std::string_view, RESULTS> RESULT_NAMES{
	"success", "btm_reject", "btm_timeout", "roam_timeout", "wrong_target", "aborted", "no_candidate"};
constexpr std::array<std::string_view, 6U> STATUS_NAMES{"accept", "unknown_bss", "capacity",
							"load",   "busy",        "policy"};

// One sample: name{labels} value, when the value is not zero.
template <typename T>
void put(Text &out, std::string_view name, std::string_view labels, T value) noexcept
{
	// formatTo has no brace escapes: a '{' not followed by '}' is literal.
	if ((value != 0) && labels.empty()) {
		formatTo(out, "donghoa_{} {}\n", name, value);
	} else if (value != 0) {
		formatTo(out, "donghoa_{}{{}} {}\n", name, labels, value);
	} else {
		// zero: left out
	}
}

} // namespace

std::size_t reasonIndex(arcp::SteerReason r) noexcept
{
	const std::size_t i = static_cast<std::size_t>(r);
	return ((i >= 1U) && (i <= REASONS)) ? (i - 1U) : REASONS;
}

void addOutcome(SteerCounters &c, arcp::SteerOutcome o, bool gainKnown, int gainDb, Millis durMs) noexcept
{
	const std::size_t i = static_cast<std::size_t>(o);
	if (i < RESULT_NO_CANDIDATE) {
		c.result[i]++;
	}
	if (o == arcp::SteerOutcome::SUCCESS) {
		c.durSumMs += durMs;
		if (gainKnown) {
			c.gainCount++;
			c.gainSumDb += gainDb;
		}
	}
}

void formatBss(Text &out, std::string_view bss, const BssCounters &c) noexcept
{
	for (std::size_t r = 0U; r < REASONS; r++) {
		const SteerCounters &s = c.steer[r];
		FixedString<96U> l;
		formatTo(l, "bss=\"{}\",reason=\"{}\"", bss, REASON_NAMES[r]);
		put(out, "steer_started_total", l.view(), s.started);
		put(out, "steer_no_pool_total", l.view(), s.noPool);
		for (std::size_t k = 0U; k < RESULTS; k++) {
			FixedString<128U> lr;
			formatTo(lr, "{},result=\"{}\"", l, RESULT_NAMES[k]);
			put(out, "steer_total", lr.view(), s.result[k]);
		}
		put(out, "btm_sent_total", l.view(), s.btmSent);
		put(out, "btm_accept_total", l.view(), s.btmAccept);
		put(out, "btm_reject_total", l.view(), s.btmReject);
		put(out, "steer_gain_db_sum", l.view(), s.gainSumDb);
		put(out, "steer_gain_db_count", l.view(), s.gainCount);
		put(out, "steer_duration_ms_sum", l.view(), s.durSumMs);
	}
	FixedString<64U> lb;
	formatTo(lb, "bss=\"{}\"", bss);
	for (std::size_t k = 0U; k < STATUS_NAMES.size(); k++) {
		FixedString<96U> ls;
		formatTo(ls, "{},status=\"{}\"", lb, STATUS_NAMES[k]);
		put(out, "steer_in_total", ls.view(), c.in.status[k]);
	}
	put(out, "steer_in_success_total", lb.view(), c.in.success);
	put(out, "steer_in_failed_total", lb.view(), c.in.failed);
	put(out, "lb_offload_total", lb.view(), c.lb.offloads);
	put(out, "lb_effective_total", lb.view(), c.lb.effective);
	put(out, "lb_futile_total", lb.view(), c.lb.futile);
	put(out, "lb_no_verdict_total", lb.view(), c.lb.noVerdict);
	put(out, "lb_pause_total", lb.view(), c.lb.pauses);
}

void formatArcp(Text &out, const ArcpCounters &c) noexcept
{
	put(out, "arcp_rx_total", "", c.rx);
	put(out, "arcp_drop_total", "reason=\"bad_header\"", c.rxBadHeader);
	put(out, "arcp_drop_total", "reason=\"auth\"", c.rxAuthFail);
	put(out, "arcp_drop_total", "reason=\"signature\"", c.rxSigFail);
	put(out, "arcp_drop_total", "reason=\"untrusted\"", c.rxUntrusted);
	put(out, "arcp_drop_total", "reason=\"unverified_boot\"", c.rxUnverified);
	put(out, "arcp_drop_total", "reason=\"duplicate\"", c.rxDuplicate);
	put(out, "arcp_tx_total", "", c.tx);
	put(out, "arcp_retransmit_total", "", c.retransmit);
	put(out, "arcp_ack_timeout_total", "", c.ackTimeout);
	put(out, "arcp_queue_full_total", "", c.queueFull);
	put(out, "steer_in_total", "bss=\"?\",status=\"unknown_bss\"", c.steerInUnknownBss);
}

} // namespace metrics
} // namespace donghoa
