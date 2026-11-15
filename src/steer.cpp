// SPDX-License-Identifier: MIT
// Steering transaction state machine (source AP). See docs/SDD.md section 6.6.
//
//   IDLE -> MEASURE (11k beacon request + air monitors) -> NEGOTIATE
//   (STEER_REQ/RESP with the target AP; skipped for local BSSes) -> BTM
//   (11v BSS TM Request) -> ROAM (wait for the association) -> done
//
// This file: start, candidate walk, BTM, the end of a transaction, the
// events and timers that move it (the reservation clean-up of the target
// side included, where one event serves both sides). The rest of steering:
//   steer_trigger.cpp  when to steer: per-STA triggers, load-balancing rounds
//   steer_measure.cpp  MEASURE: candidate pool, 11k / air-monitor requests, levels
//   steer_target.cpp   target AP: admission of STEER_REQ, reservations
//   steer_learn.cpp    Q-learning of when to roam, bandit for the target choice
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "steer_util.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};
constexpr Millis REMOTE_HOLD_SLACK_MS = 1500U; // covers ARCP retransmissions
constexpr Millis AMON_REPORT_SLACK_MS = 500U; // monitor report delivery after the watch
constexpr Millis SELF_ROAM_FRESH_MS = 5000U; // own roam: last RSSI here at most this old
constexpr std::uint8_t NO_STATUS = 0xffU;

constexpr std::array<std::string_view, 6U> OUTCOME_NAMES{"success",      "btm-reject",   "btm-timeout",
							"roam-timeout", "wrong-target", "aborted"};

// METRICS counters of a source BSS and trigger; nullptr if out of range.
metrics::SteerCounters *steerCounters(std::array<metrics::BssCounters, MAX_BSS> &m, std::size_t bss,
				      arcp::SteerReason r) noexcept
{
	const std::size_t ri = metrics::reasonIndex(r);
	return ((bss < m.size()) && (ri < metrics::REASONS)) ? &m[bss].steer[ri] : nullptr;
}

// Best score first. Insertion sort: at most MAX_CAND entries, stable, and
// no comparator subtraction that could overflow.
void sortCandidates(std::array<Candidate, MAX_CAND> &c, std::size_t n) noexcept
{
	for (std::size_t i = 1U; i < n; i++) {
		const Candidate key = c[i];
		std::size_t j = i;
		while ((j > 0U) && (c[j - 1U].score < key.score)) {
			c[j] = c[j - 1U];
			j--;
		}
		c[j] = key;
	}
}

} // namespace

namespace steer {

std::string_view reasonName(arcp::SteerReason r) noexcept
{
	std::string_view n = "?";
	switch (r) {
	case arcp::SteerReason::RSSI: n = "rssi"; break;
	case arcp::SteerReason::LOAD: n = "load"; break;
	case arcp::SteerReason::BAND: n = "band"; break;
	case arcp::SteerReason::MANUAL: n = "manual"; break;
	default: break;
	}
	return n;
}

std::string_view reasonNameRaw(std::uint8_t r) noexcept
{
	return ((r >= 1U) && (r <= 4U)) ? reasonName(static_cast<arcp::SteerReason>(r)) : "?";
}

std::string_view outcomeName(std::uint8_t o) noexcept
{
	std::string_view name{"?"};
	if (o < OUTCOME_NAMES.size()) {
		name = OUTCOME_NAMES[o];
	}
	return name;
}

} // namespace steer

std::string_view steerStateName(SteerState s) noexcept
{
	std::string_view n = "?";
	switch (s) {
	case SteerState::IDLE: n = "IDLE"; break;
	case SteerState::MEASURE: n = "MEASURE"; break;
	case SteerState::NEGOTIATE: n = "NEGOTIATE"; break;
	case SteerState::BTM: n = "BTM"; break;
	case SteerState::ROAM: n = "ROAM"; break;
	default: break;
	}
	return n;
}

const arcp::BssInfo *Daemon::findBssInfo(const Mac &bssid) noexcept
{
	const std::optional<std::size_t> b = findLocalBss(bssid);
	const RemoteBss *const rb = b.has_value() ? nullptr : lookupRemoteBss(bssid, nullptr);
	return b.has_value() ? &mBss[*b].info : ((rb != nullptr) ? &rb->info : nullptr);
}

SteerTxn *Daemon::findTxnBySta(const Mac &sta) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : mTxn) {
		if ((r == nullptr) && t.used && (t.sta == sta)) {
			r = &t;
		}
	}
	return r;
}

SteerTxn *Daemon::findTxnById(std::uint32_t id) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : mTxn) {
		if ((r == nullptr) && t.used && (t.id == id)) {
			r = &t;
		}
	}
	return r;
}

// ---- transaction end ----

void Daemon::sendResult(const SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus) noexcept
{
	// Once a STEER_REQ went out (NEGOTIATE on), the target may hold a
	// reservation: tell it how the steer ended, aborted included.
	if ((t.cur < t.nCand) && !t.cand[t.cur].local && (t.state >= SteerState::NEGOTIATE)) {
		arcp::SteerResult r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.outcome = steer::raw(outcome);
		r.btmStatus = btmStatus;
		beginMsg(m, arcp::MsgType::STEER_RESULT, arcp::FLAG_ACK_REQ);
		(void)m.add(r);
		(void)unicast(t.cand[t.cur].ap, m);
	}
}

void Daemon::endTxn(SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus,
		     bool countFailure) noexcept
{
	Sta *const s = findSta(t.sta);
	const Millis now = os::nowMs();

	logging::notice(LOG_MODULE, "steer #{} {} ({}) finished: {} after {} ms", t.id, t.sta,
		        steer::reasonName(t.reason), steer::outcomeName(steer::raw(outcome)),
		        now - t.started);
	sendResult(t, outcome, btmStatus);
	metrics::SteerCounters *const mc = steerCounters(mMetrics, t.bss, t.reason);
	if (mc != nullptr) {
		const bool gainKnown =
			(t.cur < t.nCand) && (t.cand[t.cur].rcpi <= 220U) && (t.startRssi != 0);
		const int gainDb = gainKnown ? (rrm::rcpiToDbm(t.cand[t.cur].rcpi) - t.startRssi) : 0;
		metrics::addOutcome(*mc, outcome, gainKnown, gainDb, now - t.started);
	}
	// Contextual bandit: the outcome of the candidate tried last.
	if ((outcome != arcp::SteerOutcome::ABORTED) && (t.cur < t.nCand) && (t.state >= SteerState::BTM)) {
		int g = 0;
		if ((t.cand[t.cur].rcpi <= 220U) && (t.startRssi != 0)) {
			g = rrm::rcpiToDbm(t.cand[t.cur].rcpi) - t.startRssi;
		}
		banditCredit(t.cand[t.cur], policy::rlRewardSteer(outcome, g),
			     steer::outcomeName(steer::raw(outcome)));
		if (outcome == arcp::SteerOutcome::SUCCESS) {
			banditWatchPingPong(t);
		}
	}
	if (t.rlArmed && (outcome != arcp::SteerOutcome::ABORTED)) {
		int g = 0;
		if ((t.cur < t.nCand) && (t.cand[t.cur].rcpi <= 220U) && (t.startRssi != 0)) {
			g = rrm::rcpiToDbm(t.cand[t.cur].rcpi) - t.startRssi;
		}
		rlLearn(t.sta, t.rlState, policy::RlAction::STEER, policy::rlRewardSteer(outcome, g), true,
			0U);
	}
	// Per-STA roaming threshold: only RSSI steers say something about the
	// level at which this STA should roam.
	if ((s != nullptr) && (t.reason == arcp::SteerReason::RSSI)) {
		const bool tgt = t.cur < t.nCand;
		int gain = 0;
		if (tgt && (t.cand[t.cur].rcpi <= 220U) && (t.startRssi != 0)) {
			gain = rrm::rcpiToDbm(t.cand[t.cur].rcpi) - t.startRssi;
		}
		if (outcome == arcp::SteerOutcome::SUCCESS) {
			noteRoamThr(*s, policy::updateRoamThrOutcome(mCfg.pol, s->roamThr,
								     policy::RoamOutcome::SUCCESS, gain),
				    (gain >= policy::ROAM_THR_BIG_GAIN_DB) ? "roamed, big gain" : "roamed");
		} else if ((outcome == arcp::SteerOutcome::BTM_REJECT) ||
			   (outcome == arcp::SteerOutcome::BTM_TIMEOUT)) {
			noteRoamThr(*s, policy::updateRoamThrOutcome(mCfg.pol, s->roamThr,
								     policy::RoamOutcome::REFUSED, 0),
				    "BTM refused");
		} else if (outcome == arcp::SteerOutcome::ROAM_TIMEOUT) {
			noteRoamThr(*s, policy::updateRoamThrOutcome(mCfg.pol, s->roamThr,
								     policy::RoamOutcome::ROAM_TIMEOUT, 0),
				    "roam timeout");
		} else {
			// wrong target / aborted: no lesson about the level
		}
	}
	if (s != nullptr) {
		if ((outcome == arcp::SteerOutcome::SUCCESS) ||
		    (outcome == arcp::SteerOutcome::WRONG_TARGET)) {
			s->steerFailures = 0;
			s->nextSteerMs = now + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		} else {
			if (countFailure) {
				s->steerFailures++;
			}
			s->nextSteerMs = now + static_cast<Millis>(policy::backoffMs(mCfg.pol,
										     s->steerFailures));
		}
	}
	t.used = false;
}

// No candidate at all: wait a cooldown; not a STA failure. A band steer
// in which no candidate was measured at all says nothing about the STA's
// bands, but repeating it every cooldown wastes airtime: back off
// exponentially until a higher-band level shows up.
void Daemon::failTxnNoCandidate(SteerTxn &t) noexcept
{
	Sta *const s = findSta(t.sta);
	const Millis now = os::nowMs();

	logging::notice(LOG_MODULE, "steer #{} {} ({}): no suitable candidate", t.id, t.sta,
			steer::reasonName(t.reason));
	metrics::SteerCounters *const mc = steerCounters(mMetrics, t.bss, t.reason);
	if (mc != nullptr) {
		mc->result[metrics::RESULT_NO_CANDIDATE]++;
	}
	if (t.rlArmed) {
		rlLearn(t.sta, t.rlState, policy::RlAction::STEER, policy::RL_R_NO_CANDIDATE, true, 0U);
	}
	if (s != nullptr) {
		s->nextSteerMs = now + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		if (t.reason == arcp::SteerReason::BAND) {
			if (!t.anyMeasured) {
				s->bandEmpty++;
			}
			const int wait = policy::backoffMs(mCfg.pol, s->bandEmpty);
			s->nextBandMs = now + static_cast<Millis>(wait);
			if (!t.anyMeasured) {
				logging::info(LOG_MODULE,
					      "sta {}: no higher-band level ({} in a row), next band steer "
					      "in {} ms", t.sta, s->bandEmpty, wait);
			}
		}
	}
	t.used = false;
}

// ---- 11v BSS Transition Management Request ----

void Daemon::sendBtm(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	LocalBss &src = mBss[t.bss];
	const Candidate &c = t.cand[t.cur];
	FixedString<512U> cmd;
	hapd::Reply reply;
	std::uint32_t bi = c.info.bssidInfo;

	if ((c.info.mdid != 0U) && (c.info.mdid == src.info.mdid)) {
		bi |= rrm::BI_MOBILITY_DOMAIN;
	}
	formatTo(cmd, "BSS_TM_REQ {} pref=1 abridged=1 valid_int={}", t.sta, p.btmValidInt);
	if (p.disassocImminent) {
		formatTo(cmd, " disassoc_imminent=1 disassoc_timer={}", p.disassocTimer);
	}
	// neighbor=<BSSID>,<BSSID Info>,<Op Class>,<Channel>,<PHY type>[,<subelems>]
	// Subelement 3 = BSS Transition Candidate Preference (255 = best).
	formatTo(cmd, " neighbor={},0x{},{},{},{},0301ff", c.bssid, hex(bi, 8U), c.info.opClass,
		  c.info.channel, c.info.phyType);
	if (!src.hapd.runCommand(cmd.view(), reply) || !startsWith(reply.view(), "OK")) {
		logging::warn(LOG_MODULE, "steer #{}: BSS_TM_REQ rejected by hostapd (bss_transition=1?)",
			      t.id);
		t.state = SteerState::BTM; // so the target gets a STEER_RESULT
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, true);
		return;
	}
	logging::info(LOG_MODULE, "steer #{} {}: BTM request -> {} ch {} (score {})", t.id, t.sta, c.bssid,
		      c.info.channel, c.score);
	metrics::SteerCounters *const mc = steerCounters(mMetrics, t.bss, t.reason);
	if (mc != nullptr) {
		mc->btmSent++;
	}
	t.state = SteerState::BTM;
	t.deadline = os::nowMs() + static_cast<Millis>(p.btmTimeoutMs);
}

// ---- candidate walk ----

void Daemon::advance(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;

	for (; t.cur < t.nCand; t.cur++) {
		const Candidate &c = t.cand[t.cur];
		const Sta *const s = findSta(t.sta);

		if (c.local) {
			const std::optional<std::size_t> b = findLocalBss(c.bssid);
			if (b.has_value() &&
			    (policy::admit(p, policy::utilToPct(mBss[*b].load.util), mBss[*b].load.staCount,
					   countReservations(*b, os::nowMs()), mBss[*b].cfg->maxSta) ==
			     arcp::SteerStatus::ACCEPT)) {
				sendBtm(t);
				return;
			}
			continue;
		}
		arcp::SteerReq r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.srcBssid = mBss[t.bss].info.bssid;
		r.tgtBssid = c.bssid;
		r.reason = static_cast<std::uint8_t>(t.reason);
		r.rcpi = c.rcpi;
		r.staFlags = (s != nullptr) ? s->flags : 0U;
		r.curRssi = static_cast<std::int8_t>((s != nullptr) ? s->rssi : 0);
		beginMsg(m, arcp::MsgType::STEER_REQ, arcp::FLAG_ACK_REQ);
		(void)m.add(r);
		if (!unicast(c.ap, m)) {
			continue;
		}
		logging::info(LOG_MODULE, "steer #{} {}: asking AP {} for {}", t.id, t.sta, c.ap, c.bssid);
		t.state = SteerState::NEGOTIATE;
		t.deadline = os::nowMs() + static_cast<Millis>(p.steerRespTimeoutMs) + REMOTE_HOLD_SLACK_MS;
		return;
	}
	if (t.state == SteerState::MEASURE) {
		failTxnNoCandidate(t);
	} else {
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
	}
}

void Daemon::evaluate(SteerTxn &t) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Sta *const s = findSta(t.sta);
	policy::SteerCtx ctx;
	std::size_t n = 0U;

	if (s == nullptr) {
		endTxn(t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
		return;
	}
	const LocalBss &src = mBss[t.bss];
	ctx.reason = t.reason;
	ctx.curRssi = s->rssi;
	ctx.curBand = src.info.band;
	ctx.curUtilPct = policy::utilToPct(src.load.util);
	ctx.curPeakMbps = policy::computePeakMbps(src.info.caps, src.info.bw, p.staNss);
	if (p.scoreModel == ScoreModel::TPUT) {
		// Compare like with like: the STA's own downlink measurement of
		// the serving BSS, as for the candidates, when it has one.
		const Measurement *const cur = steer::bcnLookup(*s, src.info.bssid);
		if (cur != nullptr) {
			ctx.curRssi = rrm::rcpiToDbm(cur->rcpi);
		}
	}
	for (std::size_t i = 0U; i < t.nCand; i++) {
		Candidate &c = t.cand[i];
		const Measurement *const be = steer::levelLookup(*s, c.bssid);
		policy::CandInput in;
		bool known = true;

		in.band = c.info.band;
		in.peakMbps = policy::computePeakMbps(c.info.caps, c.info.bw, p.staNss);
		in.estRssi = (be != nullptr) ? rrm::rcpiToDbm(be->rcpi) : policy::RSSI_UNKNOWN;
		t.anyMeasured = t.anyMeasured || (be != nullptr);
		c.rcpi = (be != nullptr) ? be->rcpi : 255U;
		if (in.estRssi == policy::RSSI_UNKNOWN) {
			if (t.reason == arcp::SteerReason::MANUAL) {
				in.estRssi = p.rssiMinTarget; // operator decided
			} else if ((t.reason == arcp::SteerReason::RSSI) &&
				   ((s->bandsAdv & rrm::bandBit(c.info.band)) != 0U)) {
				// The current band is already known bad (that is why this
				// steer started) and the STA advertised this candidate's
				// band in its Supported Operating Classes element. Trust
				// that capability rather than refuse for lack of a fresh
				// 11k/air monitor measurement, which a STA at the edge of
				// range often never answers in time. Floor, not a real
				// estimate: the lowest level that still clears score()'s
				// eligibility checks, so a measured candidate always wins.
				const int floor = ctx.curRssi + p.rssiHysteresis;
				in.estRssi = (floor > p.rssiMinTarget) ? floor : p.rssiMinTarget;
			} else {
				// unknown level: score() makes the candidate ineligible
			}
		}
		if (c.local) {
			const std::optional<std::size_t> b = findLocalBss(c.bssid);
			known = b.has_value();
			if (known) {
				in.utilPct = policy::utilToPct(mBss[*b].load.util);
				const int reserved = countReservations(*b, os::nowMs());
				in.staCount = static_cast<int>(mBss[*b].load.staCount) + reserved;
				in.maxSta = mBss[*b].cfg->maxSta;
			}
		} else {
			const RemoteBss *const rb = lookupRemoteBss(c.bssid, nullptr);
			known = rb != nullptr;
			if (known && rb->hasLoad) {
				in.utilPct = policy::utilToPct(rb->load.util);
				in.staCount = static_cast<int>(rb->load.staCount);
				in.maxSta = static_cast<int>(rb->load.maxSta);
				in.accepting = (rb->load.flags & arcp::LOAD_ACCEPTING) != 0U;
			}
		}
		if (!known) {
			continue;
		}
		c.score = policy::score(p, ctx, in);
		if (in.estRssi != policy::RSSI_UNKNOWN) {
			policy::BanditFeatures bf;
			bf.levelDbm = in.estRssi;
			bf.bandDelta = (c.info.band > ctx.curBand) ? 1 : ((c.info.band < ctx.curBand) ? -1 :
									  0);
			bf.local = c.local;
			bf.utilPct = in.utilPct;
			if (be == nullptr) {
				bf.src = policy::BanditSrc::UNMEASURED;
			} else if (be->src == MeasSrc::STA_11K) {
				bf.src = policy::BanditSrc::STA_11K;
			} else {
				bf.src = policy::BanditSrc::AP_SIDE;
			}
			c.banditCtx = policy::banditCtx(bf);
			c.banditPrior = policy::banditPriorDb(in.estRssi - ctx.curRssi);
		}
		logging::dbg(LOG_MODULE, "steer #{} cand {} rssi {} ({}) util {}% -> {}", t.id, c.bssid,
			     in.estRssi, (be == nullptr) ? "unmeasured"
					     : ((be->src == MeasSrc::STA_11K) ? "11k" : "air monitor"),
			     in.utilPct, (c.score == policy::INELIGIBLE) ? -9999 : c.score);
		if (c.score != policy::INELIGIBLE) {
			t.cand[n] = c;
			n++;
		}
	}
	t.nCand = n;
	sortCandidates(t.cand, n);
	// Contextual bandit (active): the eligible candidates in order of learned
	// value instead of score; now and then the top two swapped (exploration).
	if ((banditMode() == policy::RlMode::ACTIVE) && (n > 1U)) {
		const Mac first = t.cand[0U].bssid;
		for (std::size_t i = 1U; i < n; i++) {
			const Candidate c = t.cand[i];
			const int v = policy::banditValue(mBandit, c.banditCtx, c.banditPrior);
			std::size_t j = i;
			while ((j > 0U) &&
			       (policy::banditValue(mBandit, t.cand[j - 1U].banditCtx,
						    t.cand[j - 1U].banditPrior) < v)) {
				t.cand[j] = t.cand[j - 1U];
				j--;
			}
			t.cand[j] = c;
		}
		if ((p.banditEpsilonPct > 0) &&
		    (static_cast<int>(nextRandom() % 100U) < p.banditEpsilonPct)) {
			const Candidate c = t.cand[0U];
			t.cand[0U] = t.cand[1U];
			t.cand[1U] = c;
			mBanditStats.explored++;
		}
		if (t.cand[0U].bssid != first) {
			mBanditStats.reordered++;
			logging::info(LOG_MODULE, "steer #{}: bandit puts {} first (score order: {})", t.id,
				      t.cand[0U].bssid, first);
		}
	}
	t.cur = 0U;
	advance(t);
}

// ---- start ----

bool Daemon::startSteer(Sta &s, arcp::SteerReason reason, const Mac *target) noexcept
{
	SteerTxn *t = nullptr;

	if ((findTxnBySta(s.addr) != nullptr) || !mBss[s.bss].up) {
		return false;
	}
	for (SteerTxn &x : mTxn) {
		if ((t == nullptr) && !x.used) {
			t = &x;
		}
	}
	if (t == nullptr) {
		return false;
	}
	*t = SteerTxn{};
	mNextTxn++;
	t->id = mNextTxn;
	t->sta = s.addr;
	t->bss = s.bss;
	t->reason = reason;
	t->started = os::nowMs();
	t->staMld = s.mld;
	t->startRssi = s.rssi;
	t->rlArmed = mRlNextArmed && (reason == arcp::SteerReason::RSSI);
	t->rlState = mRlNextState;
	mRlNextArmed = false;
	if (target != nullptr) {
		t->forcedTarget = *target;
	}
	buildPool(*t);
	metrics::SteerCounters *const mc = steerCounters(mMetrics, s.bss, reason);
	if (t->nCand == 0U) {
		s.nextSteerMs = os::nowMs() + static_cast<Millis>(mCfg.pol.steerCooldownMs);
		if (mc != nullptr) {
			mc->noPool++;
		}
		return false;
	}
	if (mc != nullptr) {
		mc->started++;
	}
	t->used = true;
	t->state = SteerState::MEASURE;
	logging::info(LOG_MODULE, "steer #{} {} start: reason {}, rssi {}, {} candidate BSS", t->id, s.addr,
		      steer::reasonName(reason), s.rssi, t->nCand);

	// 11k (STA-measured) and air monitors (AP-measured) in parallel: a STA
	// without 11k, or too busy to answer, is still measured.
	if (((s.flags & arcp::STA_F11K) != 0U) && requestBeacons(*t, s)) {
		t->bcnOutstanding = true;
		t->deadline = os::nowMs() + static_cast<Millis>(mCfg.pol.beaconReqTimeoutMs);
	}
	if (requestMonitors(*t, s) > 0U) {
		const Millis dl = os::nowMs() + static_cast<Millis>(mCfg.pol.amonDurationMs) +
				  AMON_REPORT_SLACK_MS;
		t->amonPending = true;
		if (dl > t->deadline) {
			t->deadline = dl;
		}
	}
	if (!t->bcnOutstanding && !t->amonPending) {
		evaluate(*t);
	}
	return true;
}

// ---- events into the source-side state machine ----

void Daemon::onBtmResp(const hapd::BtmResp &r) noexcept
{
	SteerTxn *const t = findTxnBySta(r.addr);

	if ((t == nullptr) || (t->state != SteerState::BTM)) {
		return;
	}
	metrics::SteerCounters *const mc = steerCounters(mMetrics, t->bss, t->reason);
	if (mc != nullptr) {
		if (r.status != 0) {
			mc->btmReject++;
		} else {
			mc->btmAccept++;
		}
	}
	if (r.status != 0) {
		// 802.11v status: 1 reject, 2 insufficient beacons, 3 capacity,
		// 5 delay requested, 6 candidate list provided, 7 no candidates
		logging::info(LOG_MODULE, "steer #{} {}: BTM rejected, status {}", t->id, r.addr, r.status);
		if ((t->cur + 1U) < t->nCand) {
			// This candidate said no; try the next one before giving up.
			banditCredit(t->cand[t->cur], policy::RL_R_REFUSED, "BTM rejected");
			sendResult(*t, arcp::SteerOutcome::BTM_REJECT, static_cast<std::uint8_t>(r.status));
			t->cur++;
			advance(*t);
		} else {
			endTxn(*t, arcp::SteerOutcome::BTM_REJECT, static_cast<std::uint8_t>(r.status), true);
		}
		return;
	}
	if (r.hasTarget && (t->cur < t->nCand) && (r.target != t->cand[t->cur].bssid)) {
		logging::info(LOG_MODULE, "steer #{}: STA chose {} instead", t->id, r.target);
	}
	t->state = SteerState::ROAM;
	t->deadline = os::nowMs() + static_cast<Millis>(mCfg.pol.roamTimeoutMs);
}

void Daemon::onStaEvent(const Mac &ap, const arcp::StaEvent &e) noexcept
{
	if (e.event != static_cast<std::uint8_t>(arcp::StaEventType::ASSOC)) {
		return;
	}
	// Target side: a reservation for this STA is consumed.
	for (Reservation &r : mResv) {
		if (r.used && (r.sta == e.sta) && (ap == mApId)) {
			r.used = false;
		}
	}
	// After a roam (esp. FT) the old hostapd keeps the STA until its
	// inactivity timer fires: stop reporting and steering it meanwhile.
	if (ap != mApId) {
		Sta *const s = findSta(e.sta);
		if ((s != nullptr) && !s->away && s->rlWaiting) {
			rlEndWait(*s, 0, "roamed by itself");
		}
		// Roamed by itself (no steer of ours): the level it left at is its
		// own roaming point.
		if ((s != nullptr) && !s->away && (findTxnBySta(e.sta) == nullptr) && (s->rssi != 0) &&
		    ((os::nowMs() - s->lastPollMs) < SELF_ROAM_FRESH_MS)) {
			noteRoamThr(*s, policy::updateRoamThrSelf(mCfg.pol, s->roamThr, s->rssi), "own roam");
		} else if ((s == nullptr) && (findTxnBySta(e.sta) == nullptr)) {
			noteOwnRoamFromRecord(e.sta); // it left here first
		} else {
			// steered by us (the outcome teaches), or already away
		}
		if ((s != nullptr) && !s->away) {
			logging::info(LOG_MODULE, "sta {} now served by AP {}", e.sta, ap);
			s->away = true;
		}
	}
	SteerTxn *const t = findTxnBySta(e.sta);
	if ((t == nullptr) || ((t->state != SteerState::BTM) && (t->state != SteerState::ROAM)) ||
	    (t->cur >= t->nCand)) {
		return;
	}
	// Where the STA went; an MLD STA may (re)associate through any link of
	// an AP MLD, so a link of the chosen (or the source) AP MLD counts.
	// (A legacy STA can be steered between the affiliated BSSes of one AP
	// MLD: for it only the exact BSSID counts.)
	const arcp::BssInfo *const at = t->staMld ? findBssInfo(e.bssid) : nullptr;
	const arcp::BssInfo &src = mBss[t->bss].info;
	const bool backHome = (e.bssid == src.bssid) || ((at != nullptr) && arcp::isSameMld(*at, src));
	if (backHome) {
		return; // reassociated to the source
	}
	const bool onTarget = (e.bssid == t->cand[t->cur].bssid) ||
			      ((at != nullptr) && arcp::isSameMld(*at, t->cand[t->cur].info));
	endTxn(*t, onTarget ? arcp::SteerOutcome::SUCCESS : arcp::SteerOutcome::WRONG_TARGET, 0U, false);
}

void Daemon::onLocalDisassoc(const Mac &sta) noexcept
{
	SteerTxn *const t = findTxnBySta(sta);
	// In BTM/ROAM the STA leaving is expected; wait for its association.
	if ((t != nullptr) && ((t->state == SteerState::MEASURE) || (t->state == SteerState::NEGOTIATE))) {
		endTxn(*t, arcp::SteerOutcome::ABORTED, NO_STATUS, false);
	}
}

void Daemon::onSteerResp(const Peer &from, const arcp::SteerResp &r) noexcept
{
	SteerTxn *const t = findTxnById(r.txn);

	if ((t == nullptr) || (t->state != SteerState::NEGOTIATE) || (t->cur >= t->nCand) ||
	    (t->cand[t->cur].ap != from.id)) {
		return;
	}
	if (r.status == static_cast<std::uint8_t>(arcp::SteerStatus::ACCEPT)) {
		sendBtm(*t);
		return;
	}
	logging::info(LOG_MODULE, "steer #{}: AP {} refused (status {})", t->id, from.id, r.status);
	banditCredit(t->cand[t->cur], policy::BANDIT_R_TARGET_REFUSED, "target refused");
	t->cur++;
	advance(*t);
}

void Daemon::onPeerLost(const Peer &p) noexcept
{
	for (SteerTxn &t : mTxn) {
		if (t.used && (t.state == SteerState::NEGOTIATE) && (t.cur < t.nCand) &&
		    (t.cand[t.cur].ap == p.id)) {
			t.cur++;
			advance(t);
		}
	}
	for (Reservation &r : mResv) {
		if (r.used && (r.srcAp == p.id)) {
			r.used = false;
		}
	}
}

// ---- timers ----

void Daemon::tickSteer(Millis now) noexcept
{
	for (SteerTxn &t : mTxn) {
		if (t.used && (t.state == SteerState::MEASURE) && t.bcnOutstanding &&
		    (t.bcnQuietUntil != 0U) && (now >= t.bcnQuietUntil) && (now < t.deadline)) {
			t.bcnOutstanding = false;
			t.bcnQuietUntil = 0U;
			logging::dbg(LOG_MODULE,
				     "steer #{}: no more beacon reports for {} ms, 11k measurement over",
				     t.id, t.bcnQuietMs);
			const Sta *const s = findSta(t.sta);
			if (!t.amonPending || ((s != nullptr) && isMeasureComplete(t, *s))) {
				evaluate(t);
				continue;
			}
		}
		if (!t.used || (now < t.deadline)) {
			continue;
		}
		switch (t.state) {
		case SteerState::MEASURE:
			// Step 3 timeout: an AP that has not answered counts as
			// unable to measure.
			for (std::size_t i = 0U; i < t.nMonWait; i++) {
				logging::info(LOG_MODULE, "steer #{}: no measurement answer from AP {}", t.id,
					      t.monWait[i]);
			}
			t.nMonWait = 0U;
			evaluate(t);
			break;
		case SteerState::NEGOTIATE:
			logging::info(LOG_MODULE, "steer #{}: no STEER_RESP from {}", t.id,
				      (t.cur < t.nCand) ? t.cand[t.cur].ap : Mac{});
			// It may have accepted (its answer lost): release that slot.
			if (t.cur < t.nCand) {
				banditCredit(t.cand[t.cur], policy::BANDIT_R_TARGET_REFUSED,
					     "no answer from the target");
			}
			sendResult(t, arcp::SteerOutcome::ABORTED, NO_STATUS);
			t.cur++;
			advance(t);
			break;
		case SteerState::BTM:
			if ((t.cur + 1U) < t.nCand) {
				// No BTM response from this candidate; try the next one
				// before giving up on the whole steer.
				logging::info(LOG_MODULE,
					      "steer #{}: no BTM response from {}, trying next candidate",
					      t.id, t.cand[t.cur].bssid);
				banditCredit(t.cand[t.cur], policy::RL_R_REFUSED, "no BTM response");
				sendResult(t, arcp::SteerOutcome::BTM_TIMEOUT, NO_STATUS);
				t.cur++;
				advance(t);
			} else {
				endTxn(t, arcp::SteerOutcome::BTM_TIMEOUT, NO_STATUS, true);
			}
			break;
		case SteerState::ROAM:
			endTxn(t, arcp::SteerOutcome::ROAM_TIMEOUT, 0U, true);
			break;
		default:
			t.used = false;
			break;
		}
	}
	for (Reservation &r : mResv) {
		if (r.used && (r.expiry <= now)) {
			r.used = false;
		}
	}
}

} // namespace donghoa
