// SPDX-License-Identifier: MIT
// Learning used by steering, off by default: Q-learning of when to roam
// (feature 15) and the contextual bandit for the target choice (feature 16).
// The update rules are pure, in policy.cpp; this file holds the daemon
// side: modes, the random source, crediting outcomes, ping-pong watches.
#include "daemon/daemon.hpp"
#include "base/log.hpp"
#include "core/policy.hpp"
#include "daemon/steer_util.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};

} // namespace

// ---- Q-learning of when to roam ----

policy::RlMode Daemon::rlMode() const noexcept
{
	const int m = (mRlModeOverride >= 0) ? mRlModeOverride : mCfg.pol.rlRoam;
	return (m == 2) ? policy::RlMode::ACTIVE : ((m == 1) ? policy::RlMode::SHADOW : policy::RlMode::OFF);
}

std::uint32_t Daemon::nextRandom() noexcept
{
	// xorshift32: exploration only, no security role
	mRng ^= mRng << 13U;
	mRng ^= mRng >> 17U;
	mRng ^= mRng << 5U;
	return mRng;
}

void Daemon::rlLearn(const Mac &sta, std::size_t s, policy::RlAction a, int rewardDb, bool terminal,
		     std::size_t next) noexcept
{
	if (!mRlInit) {
		policy::rlInit(mRl);
		mRlInit = true;
	}
	const std::size_t ai = (a == policy::RlAction::STEER) ? 1U : 0U;
	const int before = mRl.q[s][ai];
	policy::rlUpdate(mRl, s, a, rewardDb, terminal, next);
	mRlStats.updates++;
	logging::dbg(LOG_MODULE, "rl sta {}: state {} {} reward {} -> Q {} -> {} (x256)", sta, s,
		     (a == policy::RlAction::STEER) ? "steer" : "wait", rewardDb, before, mRl.q[s][ai]);
}

void Daemon::rlEndWait(Sta &s, int rewardDb, std::string_view why) noexcept
{
	if (s.rlWaiting) {
		logging::dbg(LOG_MODULE, "rl sta {}: waiting ended ({})", s.addr, why);
		rlLearn(s.addr, s.rlState, policy::RlAction::WAIT, rewardDb, true, 0U);
		s.rlWaiting = false;
	}
}

// ---- contextual bandit: target choice ----

policy::RlMode Daemon::banditMode() const noexcept
{
	const int m = (mBanditModeOverride >= 0) ? mBanditModeOverride : mCfg.pol.banditTarget;
	return (m == 2) ? policy::RlMode::ACTIVE : ((m == 1) ? policy::RlMode::SHADOW : policy::RlMode::OFF);
}

void Daemon::banditCredit(const Candidate &c, int rewardDb, std::string_view why) noexcept
{
	if (banditMode() == policy::RlMode::OFF) {
		return;
	}
	const int before = mBandit.q[c.banditCtx];
	policy::banditUpdate(mBandit, c.banditCtx, rewardDb);
	mBanditStats.updates++;
	logging::dbg(LOG_MODULE, "bandit {}: context {} reward {} ({}) -> mean {} -> {} (x256)", c.bssid,
		     c.banditCtx, rewardDb, why, before, mBandit.q[c.banditCtx]);
}

void Daemon::banditWatchPingPong(const SteerTxn &t) noexcept
{
	PingPongWatch *w = nullptr;
	PingPongWatch *oldest = nullptr;
	for (PingPongWatch &x : mPingPong) {
		if ((w == nullptr) && (!x.used || (x.sta == t.sta))) {
			w = &x;
		}
		if ((oldest == nullptr) || (x.ts < oldest->ts)) {
			oldest = &x;
		}
	}
	w = (w != nullptr) ? w : oldest;
	w->used = true;
	w->sta = t.sta;
	w->srcBss = t.bss;
	w->ctx = t.cand[t.cur].banditCtx;
	w->ts = os::nowMs();
}

void Daemon::banditCheckPingPong(std::size_t bss, const Mac &sta) noexcept
{
	for (PingPongWatch &w : mPingPong) {
		if (!w.used || (w.sta != sta)) {
			continue;
		}
		if ((w.srcBss == bss) && ((os::nowMs() - w.ts) < policy::BANDIT_PING_PONG_MS) &&
		    (banditMode() != policy::RlMode::OFF)) {
			policy::banditUpdate(mBandit, w.ctx, policy::BANDIT_R_PING_PONG);
			mBanditStats.updates++;
			logging::info(LOG_MODULE,
				      "sta {} back on the BSS it was steered away from: ping-pong", sta);
		}
		w.used = false;
	}
}

} // namespace donghoa
