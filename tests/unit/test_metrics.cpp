// SPDX-License-Identifier: MIT
// Unit tests: outcome counters (src/core/metrics).
#include <string_view>

#include "unit.hpp"

#include "core/metrics.hpp"
#include "core/proto.hpp"

using namespace donghoa;

void testMetrics()
{
	using namespace metrics;
	CHECK(reasonIndex(arcp::SteerReason::RSSI) == 0U);
	CHECK(reasonIndex(arcp::SteerReason::MANUAL) == 3U);
	CHECK(reasonIndex(static_cast<arcp::SteerReason>(0U)) == REASONS);
	CHECK(reasonIndex(static_cast<arcp::SteerReason>(9U)) == REASONS);

	BssCounters c;
	SteerCounters &r = c.steer[reasonIndex(arcp::SteerReason::RSSI)];
	r.started = 3U;
	addOutcome(r, arcp::SteerOutcome::SUCCESS, true, 12, 800U);
	addOutcome(r, arcp::SteerOutcome::SUCCESS, false, 0, 1200U);
	addOutcome(r, arcp::SteerOutcome::BTM_REJECT, true, 20, 300U);
	CHECK(r.result[0] == 2U && r.result[1] == 1U);
	CHECK(r.gainCount == 1U && r.gainSumDb == 12 && r.durSumMs == 2000U);
	r.result[RESULT_NO_CANDIDATE]++;
	c.in.status[0] = 2U;
	c.lb.futile = 1U;

	Text t;
	formatBss(t, "wlan0", c);
	const std::string_view v = t.view();
	CHECK(v.find("donghoa_steer_started_total{bss=\"wlan0\",reason=\"rssi\"} 3\n") != std::string_view::npos);
	CHECK(v.find("donghoa_steer_total{bss=\"wlan0\",reason=\"rssi\",result=\"success\"} 2\n") !=
	      std::string_view::npos);
	CHECK(v.find("result=\"no_candidate\"} 1\n") != std::string_view::npos);
	CHECK(v.find("donghoa_steer_gain_db_sum{bss=\"wlan0\",reason=\"rssi\"} 12\n") != std::string_view::npos);
	CHECK(v.find("donghoa_steer_in_total{bss=\"wlan0\",status=\"accept\"} 2\n") != std::string_view::npos);
	CHECK(v.find("donghoa_lb_futile_total{bss=\"wlan0\"} 1\n") != std::string_view::npos);
	// zero values are left out
	CHECK(v.find("reason=\"load\"") == std::string_view::npos);
	CHECK(v.find("btm_timeout") == std::string_view::npos);

	ArcpCounters a;
	a.rx = 5U;
	a.rxAuthFail = 2U;
	Text u;
	formatArcp(u, a);
	CHECK(u.view() == "donghoa_arcp_rx_total 5\ndonghoa_arcp_drop_total{reason=\"auth\"} 2\n");
	// negative gain sums print signed
	SteerCounters n;
	addOutcome(n, arcp::SteerOutcome::SUCCESS, true, -4, 10U);
	BssCounters nc;
	nc.steer[0] = n;
	Text w;
	formatBss(w, "x", nc);
	CHECK(w.view().find("steer_gain_db_sum{bss=\"x\",reason=\"rssi\"} -4\n") != std::string_view::npos);
}
