// SPDX-License-Identifier: MIT
// Steering transaction state machine (source AP) and admission control
// (target AP). See docs/SDD.md section 6.6.
//
//   IDLE -> MEASURE (11k beacon request + air monitors) -> NEGOTIATE
//   (STEER_REQ/RESP with the target AP; skipped for local BSSes) -> BTM
//   (11v BSS TM Request) -> ROAM (wait for the association) -> done
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"

namespace donghoa {

namespace {

constexpr LogModule kMod{LogModule::steer};
constexpr Millis kMeasFreshMs = 10000U;
constexpr Millis kRemoteHoldSlackMs = 1500U; // covers ARCP retransmissions
constexpr Millis kAmonReportSlackMs = 500U;  // monitor report delivery after the watch
constexpr std::uint8_t kNoStatus = 0xffU;

std::string_view reason_name(arcp::SteerReason r) noexcept
{
	std::string_view n = "?";
	switch (r) {
	case arcp::SteerReason::rssi: n = "rssi"; break;
	case arcp::SteerReason::load: n = "load"; break;
	case arcp::SteerReason::band: n = "band"; break;
	case arcp::SteerReason::manual: n = "manual"; break;
	default: break;
	}
	return n;
}

std::string_view reason_name_raw(std::uint8_t r) noexcept
{
	return ((r >= 1U) && (r <= 4U)) ? reason_name(static_cast<arcp::SteerReason>(r)) : "?";
}

constexpr std::array<std::string_view, 6U> kOutcomeNames{"success",      "btm-reject",   "btm-timeout",
							"roam-timeout", "wrong-target", "aborted"};

std::string_view outcome_name(std::uint8_t o) noexcept
{
	std::string_view name{"?"};
	if (o < kOutcomeNames.size()) {
		name = kOutcomeNames[o];
	}
	return name;
}

std::uint8_t raw(arcp::SteerOutcome o) noexcept
{
	return static_cast<std::uint8_t>(o);
}

const Measurement *meas_lookup(const Sta &s, const Mac &bssid, MeasSrc src) noexcept
{
	const Millis now = os::now_ms();
	const Measurement *r = nullptr;
	for (std::size_t i = 0U; (i < s.n_meas) && (r == nullptr); i++) {
		const Measurement &m = s.meas[i];
		if ((m.src == src) && (m.bssid == bssid) && ((now - m.ts) < kMeasFreshMs)) {
			r = &m;
		}
	}
	return r;
}

// STA-measured (11k beacon report) level of bssid.
const Measurement *bcn_lookup(const Sta &s, const Mac &bssid) noexcept
{
	return meas_lookup(s, bssid, MeasSrc::sta_11k);
}

// Best available level: the STA's own report, else an air monitor's.
const Measurement *level_lookup(const Sta &s, const Mac &bssid) noexcept
{
	const Measurement *m = meas_lookup(s, bssid, MeasSrc::sta_11k);
	return (m != nullptr) ? m : meas_lookup(s, bssid, MeasSrc::air_monitor);
}

bool fresh_since(const Measurement *m, Millis since) noexcept
{
	return (m != nullptr) && (m->ts >= since);
}

// Best score first. Insertion sort: at most kMaxCand entries, stable, and
// no comparator subtraction that could overflow.
void sort_candidates(std::array<Candidate, kMaxCand> &c, std::size_t n) noexcept
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

std::string_view steer_state_name(SteerState s) noexcept
{
	std::string_view n = "?";
	switch (s) {
	case SteerState::idle: n = "IDLE"; break;
	case SteerState::measure: n = "MEASURE"; break;
	case SteerState::negotiate: n = "NEGOTIATE"; break;
	case SteerState::btm: n = "BTM"; break;
	case SteerState::roam: n = "ROAM"; break;
	default: break;
	}
	return n;
}

SteerTxn *Daemon::txn_find_sta(const Mac &sta) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : txn_) {
		if ((r == nullptr) && t.used && (t.sta == sta)) {
			r = &t;
		}
	}
	return r;
}

SteerTxn *Daemon::txn_find_id(std::uint32_t id) noexcept
{
	SteerTxn *r = nullptr;
	for (SteerTxn &t : txn_) {
		if ((r == nullptr) && t.used && (t.id == id)) {
			r = &t;
		}
	}
	return r;
}

int Daemon::resv_count(std::size_t bss, Millis now) const noexcept
{
	int n = 0;
	for (const Reservation &r : resv_) {
		if (r.used && (r.bss == bss) && (r.expiry > now)) {
			n++;
		}
	}
	return n;
}

void Daemon::meas_store(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
			std::uint8_t op_class, std::uint8_t channel, Millis ts) noexcept
{
	Measurement *e = nullptr;
	for (std::size_t i = 0U; (i < s.n_meas) && (e == nullptr); i++) {
		if ((s.meas[i].src == src) && (s.meas[i].bssid == bssid)) {
			e = &s.meas[i];
		}
	}
	if (e == nullptr) {
		if (s.n_meas < s.meas.size()) {
			e = &s.meas[s.n_meas];
			s.n_meas++;
		} else {
			e = &s.meas[0U];
			for (std::size_t i = 1U; i < s.n_meas; i++) {
				if (s.meas[i].ts < e->ts) {
					e = &s.meas[i];
				}
			}
		}
	}
	e->bssid = bssid;
	e->src = src;
	e->rcpi = rcpi;
	e->op_class = op_class;
	e->channel = channel;
	e->ts = ts;
}

// ---- transaction end ----

void Daemon::send_result(const SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btm_status) noexcept
{
	if ((t.cur < t.n_cand) && !t.cand[t.cur].local && (t.state >= SteerState::btm)) {
		arcp::SteerResult r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.outcome = raw(outcome);
		r.btm_status = btm_status;
		msg_begin(m, arcp::MsgType::steer_result, arcp::kFlagAckReq);
		(void)m.add(r);
		(void)unicast(t.cand[t.cur].ap, m);
	}
}

void Daemon::txn_end(SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btm_status,
		     bool count_failure) noexcept
{
	Sta *const s = sta_find(t.sta);
	const Millis now = os::now_ms();

	logging::info(kMod, "steer #{} {} ({}) finished: {} after {} ms", t.id, t.sta, reason_name(t.reason),
		      outcome_name(raw(outcome)), now - t.started);
	send_result(t, outcome, btm_status);
	if (s != nullptr) {
		if ((outcome == arcp::SteerOutcome::success) || (outcome == arcp::SteerOutcome::wrong_target)) {
			s->steer_failures = 0;
			s->next_steer_ms = now + static_cast<Millis>(cfg_.pol.steer_cooldown_ms);
		} else {
			if (count_failure) {
				s->steer_failures++;
			}
			s->next_steer_ms = now + static_cast<Millis>(policy::backoff_ms(cfg_.pol, s->steer_failures));
		}
	}
	t.used = false;
}

// No candidate at all: wait a cooldown; not a STA failure.
void Daemon::txn_no_candidate(SteerTxn &t) noexcept
{
	Sta *const s = sta_find(t.sta);

	logging::info(kMod, "steer #{} {} ({}): no suitable candidate", t.id, t.sta, reason_name(t.reason));
	if (s != nullptr) {
		s->next_steer_ms = os::now_ms() + static_cast<Millis>(cfg_.pol.steer_cooldown_ms);
	}
	t.used = false;
}

// ---- 11v BSS Transition Management Request ----

void Daemon::send_btm(SteerTxn &t) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	LocalBss &src = bss_[t.bss];
	const Candidate &c = t.cand[t.cur];
	FixedString<512U> cmd;
	hapd::Reply reply;
	std::uint32_t bi = c.info.bssid_info;

	if ((c.info.mdid != 0U) && (c.info.mdid == src.info.mdid)) {
		bi |= rrm::kBiMobilityDomain;
	}
	format_to(cmd, "BSS_TM_REQ {} pref=1 abridged=1 valid_int={}", t.sta, p.btm_valid_int);
	if (p.disassoc_imminent) {
		format_to(cmd, " disassoc_imminent=1 disassoc_timer={}", p.disassoc_timer);
	}
	// neighbor=<BSSID>,<BSSID Info>,<Op Class>,<Channel>,<PHY type>[,<subelems>]
	// Subelement 3 = BSS Transition Candidate Preference (255 = best).
	format_to(cmd, " neighbor={},0x{},{},{},{},0301ff", c.bssid, hex(bi, 8U), c.info.op_class,
		  c.info.channel, c.info.phy_type);
	if (!src.hapd.cmd(cmd.view(), reply) || !starts_with(reply.view(), "OK")) {
		logging::warn(kMod, "steer #{}: BSS_TM_REQ rejected by hostapd (bss_transition=1?)", t.id);
		t.state = SteerState::btm; // so the target gets a STEER_RESULT
		txn_end(t, arcp::SteerOutcome::aborted, kNoStatus, true);
		return;
	}
	logging::info(kMod, "steer #{} {}: BTM request -> {} ch {} (score {})", t.id, t.sta, c.bssid,
		      c.info.channel, c.score);
	t.state = SteerState::btm;
	t.deadline = os::now_ms() + static_cast<Millis>(p.btm_timeout_ms);
}

// ---- candidate walk ----

void Daemon::advance(SteerTxn &t) noexcept
{
	const PolicyConfig &p = cfg_.pol;

	for (; t.cur < t.n_cand; t.cur++) {
		const Candidate &c = t.cand[t.cur];
		const Sta *const s = sta_find(t.sta);

		if (c.local) {
			const std::optional<std::size_t> b = local_bss_by_bssid(c.bssid);
			if (b.has_value() &&
			    (policy::admit(p, policy::util_to_pct(bss_[*b].load.util), bss_[*b].load.sta_count,
					   resv_count(*b, os::now_ms()), bss_[*b].cfg->max_sta) ==
			     arcp::SteerStatus::accept)) {
				send_btm(t);
				return;
			}
			continue;
		}
		arcp::SteerReq r;
		arcp::Message m;
		r.txn = t.id;
		r.sta = t.sta;
		r.src_bssid = bss_[t.bss].info.bssid;
		r.tgt_bssid = c.bssid;
		r.reason = static_cast<std::uint8_t>(t.reason);
		r.rcpi = c.rcpi;
		r.sta_flags = (s != nullptr) ? s->flags : 0U;
		r.cur_rssi = static_cast<std::int8_t>((s != nullptr) ? s->rssi : 0);
		msg_begin(m, arcp::MsgType::steer_req, arcp::kFlagAckReq);
		(void)m.add(r);
		if (!unicast(c.ap, m)) {
			continue;
		}
		logging::info(kMod, "steer #{} {}: asking AP {} for {}", t.id, t.sta, c.ap, c.bssid);
		t.state = SteerState::negotiate;
		t.deadline = os::now_ms() + static_cast<Millis>(p.steer_resp_timeout_ms) + kRemoteHoldSlackMs;
		return;
	}
	if (t.state == SteerState::measure) {
		txn_no_candidate(t);
	} else {
		txn_end(t, arcp::SteerOutcome::aborted, kNoStatus, false);
	}
}

void Daemon::evaluate(SteerTxn &t) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	const Sta *const s = sta_find(t.sta);
	policy::SteerCtx ctx;
	std::size_t n = 0U;

	if (s == nullptr) {
		txn_end(t, arcp::SteerOutcome::aborted, kNoStatus, false);
		return;
	}
	const LocalBss &src = bss_[t.bss];
	ctx.reason = t.reason;
	ctx.cur_rssi = s->rssi;
	ctx.cur_band = src.info.band;
	ctx.cur_util_pct = policy::util_to_pct(src.load.util);
	ctx.cur_peak_mbps = policy::peak_mbps(src.info.caps, src.info.bw, p.sta_nss);
	if (p.score_model == ScoreModel::tput) {
		// Compare like with like: the STA's own downlink measurement of
		// the serving BSS, as for the candidates, when it has one.
		const Measurement *const cur = bcn_lookup(*s, src.info.bssid);
		if (cur != nullptr) {
			ctx.cur_rssi = rrm::rcpi_to_dbm(cur->rcpi);
		}
	}
	for (std::size_t i = 0U; i < t.n_cand; i++) {
		Candidate &c = t.cand[i];
		const Measurement *const be = level_lookup(*s, c.bssid);
		policy::CandInput in;
		bool known = true;

		in.band = c.info.band;
		in.peak_mbps = policy::peak_mbps(c.info.caps, c.info.bw, p.sta_nss);
		in.est_rssi = (be != nullptr) ? rrm::rcpi_to_dbm(be->rcpi) : policy::kRssiUnknown;
		c.rcpi = (be != nullptr) ? be->rcpi : 255U;
		if ((in.est_rssi == policy::kRssiUnknown) && (t.reason == arcp::SteerReason::manual)) {
			in.est_rssi = p.rssi_min_target; // operator decided
		}
		if (c.local) {
			const std::optional<std::size_t> b = local_bss_by_bssid(c.bssid);
			known = b.has_value();
			if (known) {
				in.util_pct = policy::util_to_pct(bss_[*b].load.util);
				in.sta_count = static_cast<int>(bss_[*b].load.sta_count) + resv_count(*b, os::now_ms());
				in.max_sta = bss_[*b].cfg->max_sta;
			}
		} else {
			const RemoteBss *const rb = remote_bss_lookup(c.bssid, nullptr);
			known = rb != nullptr;
			if (known && rb->has_load) {
				in.util_pct = policy::util_to_pct(rb->load.util);
				in.sta_count = static_cast<int>(rb->load.sta_count);
				in.max_sta = static_cast<int>(rb->load.max_sta);
				in.accepting = (rb->load.flags & arcp::kLoadAccepting) != 0U;
			}
		}
		if (!known) {
			continue;
		}
		c.score = policy::score(p, ctx, in);
		logging::dbg(kMod, "steer #{} cand {} rssi {} ({}) util {}% -> {}", t.id, c.bssid, in.est_rssi,
			     (be == nullptr) ? "unmeasured"
					     : ((be->src == MeasSrc::sta_11k) ? "11k" : "air monitor"),
			     in.util_pct, (c.score == policy::kIneligible) ? -9999 : c.score);
		if (c.score != policy::kIneligible) {
			t.cand[n] = c;
			n++;
		}
	}
	t.n_cand = n;
	sort_candidates(t.cand, n);
	t.cur = 0U;
	advance(t);
}

// ---- start ----

void Daemon::build_pool(SteerTxn &t) noexcept
{
	const arcp::BssInfo &cur = bss_[t.bss].info;
	const auto add = [&t](const arcp::BssInfo &bi, const Mac &ap, bool local) {
		if ((t.n_cand < t.cand.size()) && (t.forced_target.is_zero() || (t.forced_target == bi.bssid))) {
			Candidate &c = t.cand[t.n_cand];
			c = Candidate{};
			c.bssid = bi.bssid;
			c.ap = ap;
			c.local = local;
			c.info = bi;
			t.n_cand++;
		}
	};
	const bool band = t.reason == arcp::SteerReason::band;

	t.n_cand = 0U;
	for (std::size_t i = 0U; i < n_bss_; i++) {
		if ((i != t.bss) && bss_[i].up && arcp::same_ess(bss_[i].info, cur) &&
		    (!band || (bss_[i].info.band > cur.band))) {
			add(bss_[i].info, ap_id_, true);
		}
	}
	for (const Peer &p : peers_) {
		if (!p.used) {
			continue;
		}
		for (const RemoteBss &rb : p.bss) {
			if (rb.used && arcp::same_ess(rb.info, cur) && (!band || (rb.info.band > cur.band))) {
				add(rb.info, p.id, false);
			}
		}
	}
}

bool Daemon::request_beacons(SteerTxn &t, Sta &s) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	LocalBss &src = bss_[t.bss];
	rrm::OpChanList chans{};
	std::size_t n = 0U;
	FixedString<256U> hexreq;
	FixedString<320U> cmd;
	hapd::Reply reply;

	// The tput model also measures the serving channel (first).
	const bool serving = p.score_model == ScoreModel::tput;
	for (std::size_t i = 0U; (i < (t.n_cand + (serving ? 1U : 0U))) && (n < chans.size()); i++) {
		const arcp::BssInfo &bi = (serving && (i == 0U)) ? src.info : t.cand[serving ? (i - 1U) : i].info;
		bool dup = false;
		for (std::size_t k = 0U; k < n; k++) {
			dup = dup || ((chans[k].op_class == bi.op_class) && (chans[k].channel == bi.channel));
		}
		if (!dup) {
			chans[n] = rrm::OpChan{bi.op_class, bi.channel};
			n++;
		}
	}
	// One request for all channels: a STA refuses a second beacon
	// measurement while the first runs. hostapd refuses (FAIL, nothing
	// sent) a mode the STA did not advertise in its RM Enabled
	// Capabilities, which the control interface does not expose: try the
	// configured mode, then active, then passive, and remember the first
	// accepted. Table mode only repeats cached results: not a fallback.
	std::array<rrm::BeaconMode, 3U> modes{p.beacon_mode, rrm::BeaconMode::active, rrm::BeaconMode::passive};
	std::size_t n_modes = modes.size();
	if (s.bcn_mode.has_value()) {
		modes[0U] = *s.bcn_mode;
		n_modes = 1U;
	}
	for (std::size_t i = 0U; i < n_modes; i++) {
		const rrm::BeaconMode mode = modes[i];
		bool tried = false;
		for (std::size_t k = 0U; k < i; k++) {
			tried = tried || (modes[k] == mode);
		}
		if (tried) {
			continue;
		}
		std::uint16_t dur = static_cast<std::uint16_t>(p.beacon_duration);
		if ((mode == rrm::BeaconMode::passive) && (dur < rrm::kPassiveMinTu)) {
			dur = rrm::kPassiveMinTu;
		}
		if (!rrm::bcn_req_build_hex(chans, n, mode, dur, nullptr, src.info.ssid_view(), hexreq)) {
			return false;
		}
		cmd.clear();
		format_to(cmd, "REQ_BEACON {} {}", s.addr, hexreq);
		if (!src.hapd.cmd(cmd.view(), reply)) {
			return false;
		}
		if (!starts_with(reply.view(), "FAIL")) {
			if (!(s.bcn_mode.has_value() && (*s.bcn_mode == mode))) {
				logging::info(kMod, "sta {}: {} beacon reports", s.addr, rrm::beacon_mode_name(mode));
			}
			s.bcn_mode = mode;
			return true;
		}
	}
	logging::info(kMod, "sta {}: beacon report not supported (no active or passive mode)", s.addr);
	s.bcn_mode.reset();
	s.bcn_unsupported = true;
	s.flags = static_cast<std::uint8_t>(s.flags & static_cast<std::uint8_t>(~arcp::kStaF11k));
	return false;
}

// Ask every candidate owner that has an air monitor to listen for the STA.
// Returns the number of requests (local watch included).
std::size_t Daemon::request_monitors(const SteerTxn &t, const Sta &s) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	const arcp::BssInfo &src = bss_[t.bss].info;
	std::array<Mac, kMaxCand> asked{};
	std::size_t n_asked = 0U;
	std::size_t sent = 0U;

	if (!p.amon_request) {
		return 0U;
	}
	arcp::StaMonitorReq r;
	r.txn = t.id;
	r.sta = s.addr;
	r.duration_ms = static_cast<std::uint16_t>(p.amon_duration_ms);
	r.op_class = src.op_class;
	r.channel = src.channel;
	for (std::size_t i = 0U; i < t.n_cand; i++) {
		const Candidate &c = t.cand[i];
		bool dup = false;
		for (std::size_t k = 0U; k < n_asked; k++) {
			dup = dup || (asked[k] == c.ap);
		}
		if (dup) {
			continue;
		}
		asked[n_asked] = c.ap;
		n_asked++;
		if (c.local) {
			if (amon_watch_start(s.addr, ap_id_, t.id, p.amon_duration_ms)) {
				sent++;
			}
			continue;
		}
		const Peer *const pe = peer_find(c.ap);
		if ((pe == nullptr) || ((pe->flags & arcp::kApFlagAirMonitor) == 0U)) {
			continue;
		}
		arcp::Message m;
		msg_begin(m, arcp::MsgType::sta_monitor_req, arcp::kFlagAckReq);
		(void)m.add(r);
		if (unicast(c.ap, m)) {
			sent++;
		}
	}
	if (sent > 0U) {
		logging::info(kMod, "steer #{} {}: {} air monitor request(s)", t.id, s.addr, sent);
	}
	return sent;
}

bool Daemon::steer_start(Sta &s, arcp::SteerReason reason, const Mac *target) noexcept
{
	SteerTxn *t = nullptr;

	if ((txn_find_sta(s.addr) != nullptr) || !bss_[s.bss].up) {
		return false;
	}
	for (SteerTxn &x : txn_) {
		if ((t == nullptr) && !x.used) {
			t = &x;
		}
	}
	if (t == nullptr) {
		return false;
	}
	*t = SteerTxn{};
	next_txn_++;
	t->id = next_txn_;
	t->sta = s.addr;
	t->bss = s.bss;
	t->reason = reason;
	t->started = os::now_ms();
	if (target != nullptr) {
		t->forced_target = *target;
	}
	build_pool(*t);
	if (t->n_cand == 0U) {
		s.next_steer_ms = os::now_ms() + static_cast<Millis>(cfg_.pol.steer_cooldown_ms);
		return false;
	}
	t->used = true;
	t->state = SteerState::measure;
	logging::info(kMod, "steer #{} {} start: reason {}, rssi {}, {} candidate BSS", t->id, s.addr,
		      reason_name(reason), s.rssi, t->n_cand);

	// 11k (STA-measured) and air monitors (AP-measured) in parallel: a STA
	// without 11k, or too busy to answer, is still measured.
	if (((s.flags & arcp::kStaF11k) != 0U) && request_beacons(*t, s)) {
		t->bcn_outstanding = true;
		t->deadline = os::now_ms() + static_cast<Millis>(cfg_.pol.beacon_req_timeout_ms);
	}
	if (request_monitors(*t, s) > 0U) {
		const Millis dl = os::now_ms() + static_cast<Millis>(cfg_.pol.amon_duration_ms) + kAmonReportSlackMs;
		t->amon_pending = true;
		if (dl > t->deadline) {
			t->deadline = dl;
		}
	}
	if (!t->bcn_outstanding && !t->amon_pending) {
		evaluate(*t);
	}
	return true;
}

// ---- triggers ----

void Daemon::steer_on_sta_poll(Sta &s) noexcept
{
	const PolicyConfig &p = cfg_.pol;

	if (s.away || (os::now_ms() < s.next_steer_ms) || ((s.flags & arcp::kStaF11v) == 0U) ||
	    (txn_find_sta(s.addr) != nullptr)) {
		return;
	}
	if (policy::rssi_trigger(p, s.rssi, s.low_count)) {
		(void)steer_start(s, arcp::SteerReason::rssi, nullptr);
	} else if (policy::band_trigger(p, bss_[s.bss].info.band, s.rssi)) {
		(void)steer_start(s, arcp::SteerReason::band, nullptr);
	} else {
		// no trigger
	}
}

void Daemon::steer_lb_round() noexcept
{
	const PolicyConfig &p = cfg_.pol;
	const Millis now = os::now_ms();

	for (std::size_t b = 0U; b < n_bss_; b++) {
		const LocalBss &lb = bss_[b];
		Sta *pick = nullptr;

		if (!lb.up || !policy::bss_overloaded(p, policy::util_to_pct(lb.load.util), lb.load.sta_count,
						       lb.cfg->max_sta)) {
			continue;
		}
		// Weakest eligible STA first: it costs the most airtime per bit.
		for (Sta &s : sta_) {
			const bool eligible = s.used && !s.away && (s.bss == b) && (s.rssi != 0) &&
					      (now >= s.next_steer_ms) && ((s.flags & arcp::kStaF11v) != 0U) &&
					      (txn_find_sta(s.addr) == nullptr) &&
					      policy::lb_sta_eligible(p, s.tput_kbps);
			if (eligible && ((pick == nullptr) || (s.rssi < pick->rssi))) {
				pick = &s;
			}
		}
		if (pick != nullptr) {
			logging::info(kMod, "bss {} overloaded (util {}%, {} STA): offloading {}", lb.cfg->ifname,
				      policy::util_to_pct(lb.load.util), lb.load.sta_count, pick->addr);
			(void)steer_start(*pick, arcp::SteerReason::load, nullptr);
		}
	}
}

// ---- events into the source-side state machine ----

// True when MEASURE can end before its deadline.
bool Daemon::measure_complete(const SteerTxn &t, const Sta &s) const noexcept
{
	bool all_11k = true;
	bool all_any = true;

	for (std::size_t i = 0U; i < t.n_cand; i++) {
		all_11k = all_11k && fresh_since(bcn_lookup(s, t.cand[i].bssid), t.started);
		all_any = all_any && fresh_since(level_lookup(s, t.cand[i].bssid), t.started);
	}
	// The tput model also needs the STA's own level of the serving BSS.
	if ((cfg_.pol.score_model == ScoreModel::tput) && t.bcn_outstanding &&
	    !fresh_since(bcn_lookup(s, bss_[t.bss].info.bssid), t.started)) {
		all_11k = false;
	}
	// STA-measured levels win; monitor levels only once 11k is over.
	return all_11k || (!t.bcn_outstanding && all_any);
}

void Daemon::steer_on_beacon_report(Sta &s, const std::optional<rrm::BeaconReport> &r) noexcept
{
	SteerTxn *const t = txn_find_sta(s.addr);

	if (r.has_value()) {
		meas_store(s, r->bssid, MeasSrc::sta_11k, r->rcpi, r->op_class, r->channel, os::now_ms());
	}
	if ((t == nullptr) || (t->state != SteerState::measure)) {
		return;
	}
	if (!r.has_value()) {
		// Refused or empty report: the one 11k measurement is over.
		// Without monitor reports to wait for, evaluate now.
		t->bcn_outstanding = false;
		if (!t->amon_pending || measure_complete(*t, s)) {
			evaluate(*t);
		}
	} else if (measure_complete(*t, s)) {
		evaluate(*t);
	} else {
		// wait for more reports
	}
}

void Daemon::steer_on_monitor_result(Sta &s) noexcept
{
	SteerTxn *const t = txn_find_sta(s.addr);
	if ((t != nullptr) && (t->state == SteerState::measure) && measure_complete(*t, s)) {
		evaluate(*t);
	}
}

void Daemon::steer_on_btm_resp(const hapd::BtmResp &r) noexcept
{
	SteerTxn *const t = txn_find_sta(r.addr);

	if ((t == nullptr) || (t->state != SteerState::btm)) {
		return;
	}
	if (r.status != 0) {
		// 802.11v status: 1 reject, 2 insufficient beacons, 3 capacity,
		// 5 delay requested, 6 candidate list provided, 7 no candidates
		logging::info(kMod, "steer #{} {}: BTM rejected, status {}", t->id, r.addr, r.status);
		txn_end(*t, arcp::SteerOutcome::btm_reject, static_cast<std::uint8_t>(r.status), true);
		return;
	}
	if (r.has_target && (t->cur < t->n_cand) && (r.target != t->cand[t->cur].bssid)) {
		logging::info(kMod, "steer #{}: STA chose {} instead", t->id, r.target);
	}
	t->state = SteerState::roam;
	t->deadline = os::now_ms() + static_cast<Millis>(cfg_.pol.roam_timeout_ms);
}

void Daemon::steer_on_sta_event(const Mac &ap, const arcp::StaEvent &e) noexcept
{
	if (e.event != static_cast<std::uint8_t>(arcp::StaEventType::assoc)) {
		return;
	}
	// Target side: a reservation for this STA is consumed.
	for (Reservation &r : resv_) {
		if (r.used && (r.sta == e.sta) && (ap == ap_id_)) {
			r.used = false;
		}
	}
	// After a roam (esp. FT) the old hostapd keeps the STA until its
	// inactivity timer fires: stop reporting and steering it meanwhile.
	if (ap != ap_id_) {
		Sta *const s = sta_find(e.sta);
		if ((s != nullptr) && !s->away) {
			logging::info(kMod, "sta {} now served by AP {}", e.sta, ap);
			s->away = true;
		}
	}
	SteerTxn *const t = txn_find_sta(e.sta);
	if ((t == nullptr) || ((t->state != SteerState::btm) && (t->state != SteerState::roam)) ||
	    (t->cur >= t->n_cand)) {
		return;
	}
	if (e.bssid == bss_[t->bss].info.bssid) {
		return; // reassociated to the source
	}
	txn_end(*t, (e.bssid == t->cand[t->cur].bssid) ? arcp::SteerOutcome::success : arcp::SteerOutcome::wrong_target,
		0U, false);
}

void Daemon::steer_on_local_disassoc(const Mac &sta) noexcept
{
	SteerTxn *const t = txn_find_sta(sta);
	// In BTM/ROAM the STA leaving is expected; wait for its association.
	if ((t != nullptr) && ((t->state == SteerState::measure) || (t->state == SteerState::negotiate))) {
		txn_end(*t, arcp::SteerOutcome::aborted, kNoStatus, false);
	}
}

void Daemon::steer_on_resp(const Peer &from, const arcp::SteerResp &r) noexcept
{
	SteerTxn *const t = txn_find_id(r.txn);

	if ((t == nullptr) || (t->state != SteerState::negotiate) || (t->cur >= t->n_cand) ||
	    (t->cand[t->cur].ap != from.id)) {
		return;
	}
	if (r.status == static_cast<std::uint8_t>(arcp::SteerStatus::accept)) {
		send_btm(*t);
		return;
	}
	logging::info(kMod, "steer #{}: AP {} refused (status {})", t->id, from.id, r.status);
	t->cur++;
	advance(*t);
}

void Daemon::steer_on_peer_lost(const Peer &p) noexcept
{
	for (SteerTxn &t : txn_) {
		if (t.used && (t.state == SteerState::negotiate) && (t.cur < t.n_cand) && (t.cand[t.cur].ap == p.id)) {
			t.cur++;
			advance(t);
		}
	}
	for (Reservation &r : resv_) {
		if (r.used && (r.src_ap == p.id)) {
			r.used = false;
		}
	}
}

// ---- target side ----

void Daemon::steer_on_req(const Peer &from, const arcp::SteerReq &r) noexcept
{
	const PolicyConfig &p = cfg_.pol;
	const Millis now = os::now_ms();
	const std::optional<std::size_t> b = local_bss_by_bssid(r.tgt_bssid);
	arcp::SteerStatus status = arcp::SteerStatus::accept;
	arcp::SteerResp resp;
	arcp::Message m;

	resp.txn = r.txn;
	if (!b.has_value()) {
		status = arcp::SteerStatus::unknown_bss;
	} else if (txn_find_sta(r.sta) != nullptr) {
		status = arcp::SteerStatus::busy;
	} else {
		status = policy::admit(p, policy::util_to_pct(bss_[*b].load.util), bss_[*b].load.sta_count,
				       resv_count(*b, now), bss_[*b].cfg->max_sta);
	}
	if (status == arcp::SteerStatus::accept) {
		Reservation *rv = nullptr;
		for (Reservation &x : resv_) {
			if ((rv == nullptr) && (!x.used || (x.expiry <= now))) {
				rv = &x;
			}
		}
		if (rv == nullptr) {
			status = arcp::SteerStatus::busy;
		} else {
			rv->used = true;
			rv->sta = r.sta;
			rv->src_ap = from.id;
			rv->bss = *b;
			rv->txn = r.txn;
			rv->expiry = now + static_cast<Millis>(p.reserve_hold_ms);
			resp.hold_ms = static_cast<std::uint16_t>(p.reserve_hold_ms);
		}
	}
	resp.status = static_cast<std::uint8_t>(status);
	logging::info(kMod, "steer-in request #{} from {}: sta {} -> {} ({}, rcpi {}): {}", r.txn, from.id,
		      r.sta, r.tgt_bssid, reason_name_raw(r.reason), r.rcpi,
		      (status == arcp::SteerStatus::accept) ? "accept" : "reject");
	msg_begin(m, arcp::MsgType::steer_resp, arcp::kFlagAckReq);
	(void)m.add(resp);
	(void)unicast(from.id, m);
}

void Daemon::steer_on_result(const Peer &from, const arcp::SteerResult &r) noexcept
{
	for (Reservation &rv : resv_) {
		if (rv.used && (rv.txn == r.txn) && (rv.src_ap == from.id)) {
			rv.used = false;
		}
	}
	logging::info(kMod, "steer #{} from {} sta {}: {}", r.txn, from.id, r.sta, outcome_name(r.outcome));
}

// ---- timers ----

void Daemon::steer_tick(Millis now) noexcept
{
	for (SteerTxn &t : txn_) {
		if (!t.used || (now < t.deadline)) {
			continue;
		}
		switch (t.state) {
		case SteerState::measure:
			evaluate(t);
			break;
		case SteerState::negotiate:
			logging::info(kMod, "steer #{}: no STEER_RESP from {}", t.id,
				      (t.cur < t.n_cand) ? t.cand[t.cur].ap : Mac{});
			t.cur++;
			advance(t);
			break;
		case SteerState::btm:
			txn_end(t, arcp::SteerOutcome::btm_timeout, kNoStatus, true);
			break;
		case SteerState::roam:
			txn_end(t, arcp::SteerOutcome::roam_timeout, 0U, true);
			break;
		default:
			t.used = false;
			break;
		}
	}
	for (Reservation &r : resv_) {
		if (r.used && (r.expiry <= now)) {
			r.used = false;
		}
	}
}

} // namespace donghoa
