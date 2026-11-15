// SPDX-License-Identifier: MIT
// When to steer: the per-STA triggers checked at every poll (signal level,
// band, the learned decisions) and the load-balancing rounds. Both end in
// startSteer (steer.cpp).
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "steer_util.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};
constexpr Millis LB_ROAM_MS = 2000U;          // roam time allowed before judging an offload

} // namespace

void Daemon::onStaPoll(Sta &s) noexcept
{
	const PolicyConfig &p = mCfg.pol;

	if (s.away || (os::nowMs() < s.nextSteerMs) || ((s.flags & arcp::STA_F11V) == 0U) ||
	    (findTxnBySta(s.addr) != nullptr) || (s.lowPower && p.lpNoSteer)) {
		return;
	}
	const std::uint8_t band = mBss[s.bss].info.band;
	// The learned threshold drifts back towards rssi_low when nothing new
	// is learned (not shared: a decay step is not an event).
	if (p.roamThrLearn && (s.roamThr != 0) && ((os::nowMs() - s.roamThrTs) > policy::ROAM_THR_DECAY_MS)) {
		s.roamThr = policy::decayRoamThr(p, s.roamThr);
		s.roamThrTs = os::nowMs();
	}
	const int roamThr = policy::roamThreshold(p, s.roamThr);
	const bool rssiTrig = policy::isRssiTriggered(p, s.rssi, s.lowCount, roamThr);
	const policy::RlMode mode = rlMode();
	bool steer = rssiTrig;
	bool rec = false;
	std::size_t st = 0U;
	// Q-learning: a decision on each fresh sample (shadow: also when the rule
	// fires on an old one, to learn from every steer it makes).
	if ((mode != policy::RlMode::OFF) && !s.mld && (s.rssi != 0) &&
	    (s.sampleFresh || ((mode == policy::RlMode::SHADOW) && rssiTrig))) {
		policy::RlFeatures f;
		f.rssi = s.rssi;
		f.slope = s.rssi - s.rssiPrev;
		f.refusals = s.steerFailures;
		f.lowStreak = s.lowCount >= p.rssiLowCount;
		for (std::size_t i = 0U; i < s.nMeas; i++) {
			const Measurement &m = s.meas[i];
			if ((m.bssid != mBss[s.bss].info.bssid) && (m.rcpi <= 220U) &&
			    ((os::nowMs() - m.ts) < steer::POOL_HINT_MS)) {
				const int g = rrm::rcpiToDbm(m.rcpi) - s.rssi;
				f.gapDb = (!f.gapKnown || (g > f.gapDb)) ? g : f.gapDb;
				f.gapKnown = true;
			}
		}
		st = policy::rlState(f);
		if (s.rlWaiting) {
			rlLearn(s.addr, s.rlState, policy::RlAction::WAIT, policy::rlRewardWait(s.rssi),
				false, st);
			s.rlWaiting = false;
		}
		if (s.rssi < policy::RL_MIN_RSSI) {
			if (mode == policy::RlMode::ACTIVE) {
				bool explored = false;
				steer = policy::rlChoose(mRl, st, p.rlEpsilonPct, nextRandom(), explored) ==
					policy::RlAction::STEER;
				mRlStats.explored += explored ? 1U : 0U;
			}
			rec = true;
			mRlStats.decisions++;
		} else if (mode == policy::RlMode::ACTIVE) {
			steer = false; // strong signal: always wait
		} else {
			// shadow: the rule decides
		}
	} else if ((mode == policy::RlMode::ACTIVE) && !s.mld) {
		steer = false; // active: decisions only on fresh samples
	} else {
		// off, MLD STA (rule), or shadow without a fresh sample
	}
	s.sampleFresh = false;
	if (steer) {
		mRlNextArmed = rec;
		mRlNextState = st;
		mRlStats.steers += rec ? 1U : 0U;
		if (!startSteer(s, arcp::SteerReason::RSSI, nullptr) && mRlNextArmed) {
			// no transaction at all (empty pool): nothing to move to
			rlLearn(s.addr, st, policy::RlAction::STEER, policy::RL_R_NO_CANDIDATE, true, 0U);
		}
		mRlNextArmed = false;
	} else if (rec) {
		s.rlWaiting = true;
		s.rlState = st;
	} else {
		// no recorded decision
	}
	if (steer) {
		// RSSI steer started (or tried)
	} else if (!s.mld && policy::isBandTriggered(p, band, s.rssi) && (os::nowMs() >= s.nextBandMs) &&
		   policy::hasHigherBand(policy::StaBands{s.bandsAdv, s.bandsSeen, s.bandsBlocked}, band)) {
		(void)startSteer(s, arcp::SteerReason::BAND, nullptr);
	} else {
		// no trigger
	}
}

void Daemon::runLbRound() noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Millis now = os::nowMs();
	// Time for the smoothed utilisation to follow a move (EWMA 1/4 per poll)
	// plus the roam itself.
	const Millis settle = (5U * static_cast<Millis>(mCfg.staPollMs)) + LB_ROAM_MS;

	for (std::size_t b = 0U; b < mNBss; b++) {
		LocalBss &lb = mBss[b];
		Sta *pick = nullptr;
		const int utilPct = policy::utilToPct(lb.load.util);

		if (!lb.up || (now < lb.lbHoldUntil)) {
			continue;
		}
		if (lb.lbCheck) {
			// Judge the last offload before starting another one.
			// Moved = seen associated elsewhere: on another local BSS, or
			// reported by a peer. A STA that just disconnected left no
			// evidence about the offload: no verdict either way.
			const Sta *const prev = findSta(lb.lbSta);
			const bool elsewhere = (prev != nullptr) ? ((prev->bss != b) || prev->away)
								 : (findRemoteSta(lb.lbSta) != nullptr);
			const bool gone = (prev == nullptr) && !elsewhere;
			const bool moved = elsewhere;
			const bool running = findTxnBySta(lb.lbSta) != nullptr;
			if (running || (moved && (now < (lb.lbStartMs + settle)))) {
				continue; // too early to tell
			}
			lb.lbCheck = false;
			if (gone) {
				mMetrics[b].lb.noVerdict++;
				logging::info(LOG_MODULE,
					      "bss {}: {} disconnected instead of moving: no verdict on the "
					      "offload", lb.cfg->ifname, lb.lbSta);
			}
			if (moved && lb.lbByUtil) {
				if (policy::isLbMoveEffective(p, lb.lbUtilBefore, utilPct)) {
					lb.lbFutile = 0;
					mMetrics[b].lb.effective++;
				} else {
					lb.lbFutile++;
					mMetrics[b].lb.futile++;
					logging::info(LOG_MODULE,
						      "bss {}: offloading {} did not lower utilisation ({}% "
						      "-> {}%), {} in a row",
						      lb.cfg->ifname, lb.lbSta, lb.lbUtilBefore, utilPct,
						      lb.lbFutile);
					if (lb.lbFutile >= p.lbMaxFutile) {
						lb.lbFutile = 0;
						mMetrics[b].lb.pauses++;
						lb.lbHoldUntil = now + static_cast<Millis>(p.lbHoldMs);
						logging::warn(LOG_MODULE,
							      "bss {}: load balancing paused for {} s: "
							      "moving STAs does not lower "
							      "utilisation (airtime of other networks or "
							      "interference?)",
							      lb.cfg->ifname, p.lbHoldMs / 1000);
						continue;
					}
				}
			}
		}
		if (!policy::isBssOverloaded(p, utilPct, lb.load.staCount, lb.cfg->maxSta)) {
			lb.lbFutile = 0;
			continue;
		}
		// Weakest eligible STA first: it costs the most airtime per bit.
		for (Sta &s : mSta) {
			const bool eligible = s.used && !s.away && (s.bss == b) && (s.rssi != 0) &&
					      (now >= s.nextSteerMs) && ((s.flags & arcp::STA_F11V) != 0U) &&
					      (findTxnBySta(s.addr) == nullptr) && !(s.lowPower &&
										     p.lpNoSteer) &&
					      policy::isLbStaEligible(p, s.tputKbps);
			if (eligible && ((pick == nullptr) || (s.rssi < pick->rssi))) {
				pick = &s;
			}
		}
		if (pick != nullptr) {
			logging::info(LOG_MODULE, "bss {} overloaded (util {}%, {} STA): offloading {}",
				      lb.cfg->ifname, utilPct, lb.load.staCount, pick->addr);
			if (startSteer(*pick, arcp::SteerReason::LOAD, nullptr)) {
				mMetrics[b].lb.offloads++;
				const bool byCount = (lb.cfg->maxSta != 0) &&
						     (lb.load.staCount >= lb.cfg->maxSta);
				lb.lbCheck = true;
				lb.lbSta = pick->addr;
				lb.lbStartMs = now;
				lb.lbUtilBefore = utilPct;
				lb.lbByUtil = !byCount;
			}
		}
	}
}

} // namespace donghoa
