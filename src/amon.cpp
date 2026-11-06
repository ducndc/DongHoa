// SPDX-License-Identifier: MIT
// Air monitor: measure the RSSI of STAs from the frames they send, on
// radiotap monitor interfaces. Used when a STA gives no 802.11k beacon
// report (no 11k support, or too busy to answer).
//
// Two ways to measure: radiotap monitor interfaces (the frames' RSSI), and
// the driver's per-STA RSSI API (vendor_rssi.cpp, sta_rssi_api), which is
// given the STA's MAC address and measures it on a BSS's radio.
//
// A source AP multicasts STA_MONITOR_REQ to every peer. Each AP watches the
// STA for the requested time and answers (reliable unicast) with one
// STA_MONITOR_RESULT per local BSS that heard the STA, and always one
// STA_MONITOR_STATUS: measured, not heard, or why it could not measure
// (no monitor or API, watch table full, driver error); the last ones at once.
// A stock radio hears only its own channel: uplink data of STAs on that
// channel, probe requests of scanning STAs.
#include "daemon.hpp"
#include "log.hpp"
#include "vendor_rssi.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::AMON};
constexpr int MAX_DURATION_MS = 5000;

} // namespace

void Daemon::initAmon() noexcept
{
	vendor::useSimFile(mCfg.staRssiSim.view());
	if (mCfg.staRssiApi) {
		logging::info(LOG_MODULE, "driver per-STA RSSI API {}", mCfg.staRssiSim.view().empty() ? "on" : "simulated");
	}
	mNAmon = 0U;
	for (std::size_t i = 0U; i < mCfg.nMonitors; i++) {
		AmonPort &p = mAmon[mNAmon];
		p.fd = os::openMonitor(mCfg.monitors[i].cStr());
		if (p.fd.valid()) {
			p.sim = false;
			p.name = mCfg.monitors[i];
			logging::info(LOG_MODULE, "listening on {}", p.name);
			mNAmon++;
		} else {
			// A missing monitor is not fatal: this AP just cannot measure.
			logging::err(LOG_MODULE, "{}: {} (a monitor interface: iw phy <phy> interface add {} type monitor)",
				     mCfg.monitors[i], os::lastError(), mCfg.monitors[i]);
		}
	}
	if (mCfg.monitorSimPort != 0U) {
		// Test input: radiotap frames in UDP datagrams on loopback.
		AmonPort &p = mAmon[mNAmon];
		p.fd = os::bindUdpLoopback(mCfg.monitorSimPort);
		if (p.fd.valid()) {
			p.sim = true;
			p.name.clear();
			formatTo(p.name, "amonsim{}", mCfg.monitorSimPort);
			logging::info(LOG_MODULE, "sim input on udp {}", mCfg.monitorSimPort);
			mNAmon++;
		} else {
			logging::err(LOG_MODULE, "sim port {}: {}", mCfg.monitorSimPort, os::lastError());
		}
	}
}

void Daemon::addAmonSample(const rrm::AirFrame &f) noexcept
{
	const Millis now = os::nowMs();

	for (AmonWatch &w : mWatch) {
		if (!w.used || (w.sta != f.ta) || (now >= w.until)) {
			continue;
		}
		AmonAcc *a = nullptr;
		for (AmonAcc &x : w.acc) {
			if ((a == nullptr) && (x.n != 0) && (x.freq == f.freq)) {
				a = &x;
			}
		}
		for (AmonAcc &x : w.acc) {
			if ((a == nullptr) && (x.n == 0)) {
				a = &x;
			}
		}
		if (a != nullptr) {
			a->freq = f.freq;
			a->sum += f.signal;
			a->n++;
			a->last = now;
		}
	}
}

void Daemon::receiveAmon(std::size_t port) noexcept
{
	std::array<std::uint8_t, 512U> buf{};
	bool more = port < mNAmon;

	while (more) {
		std::size_t n = 0U;
		more = os::recvNowait(mAmon[port].fd, spanOf(buf), n) == os::Rx::DATA;
		if (more) {
			const std::optional<rrm::AirFrame> f = rrm::parseRadiotap(viewOf(buf).first(n));
			if (f.has_value()) {
				addAmonSample(*f);
			}
		}
	}
}

bool Daemon::canMeasureStas() const noexcept
{
	return (mNAmon > 0U) || mCfg.staRssiApi;
}

arcp::MonitorStatus Daemon::startAmonWatch(const Mac &sta, const Mac &requester, std::uint32_t txn,
					   int durationMs, std::uint8_t opClass, std::uint8_t channel) noexcept
{
	AmonWatch *w = nullptr;
	const int dur = ((durationMs <= 0) || (durationMs > MAX_DURATION_MS)) ? mCfg.pol.amonDurationMs
									       : durationMs;

	if (!canMeasureStas()) {
		return arcp::MonitorStatus::UNSUPPORTED;
	}
	for (AmonWatch &x : mWatch) {
		if ((w == nullptr) && !x.used) {
			w = &x;
		}
	}
	if (w == nullptr) {
		logging::warn(LOG_MODULE, "watch table full, {} not measured", sta);
		return arcp::MonitorStatus::BUSY;
	}
	std::uint32_t vendorBss = 0U;
	bool vendorFailed = false;
	if (mCfg.staRssiApi) {
		for (std::size_t b = 0U; b < mNBss; b++) {
			const std::string_view ifn = mBss[b].cfg->ifname.view();
			if (!mBss[b].up || !vendor::isStaRssiSupported(ifn)) {
				continue;
			}
			const vendor::RssiStatus st =
				vendor::startStaRssi(ifn, sta, opClass, channel, static_cast<std::uint16_t>(dur));
			if (st == vendor::RssiStatus::OK) {
				vendorBss |= 1U << b;
			} else {
				vendorFailed = vendorFailed || (st == vendor::RssiStatus::FAILED);
				vendor::stopStaRssi(ifn, sta);
			}
		}
	}
	if ((mNAmon == 0U) && (vendorBss == 0U)) {
		logging::dbg(LOG_MODULE, "{}: driver RSSI API {}", sta, vendorFailed ? "failed" : "not available");
		return vendorFailed ? arcp::MonitorStatus::FAILED : arcp::MonitorStatus::UNSUPPORTED;
	}
	*w = AmonWatch{};
	w->used = true;
	w->sta = sta;
	w->requester = requester;
	w->txn = txn;
	w->until = os::nowMs() + static_cast<Millis>(dur);
	w->vendorBss = vendorBss;
	w->vendorFailed = vendorFailed;
	logging::dbg(LOG_MODULE, "watching {} for {} ms (txn {}, {} monitor(s), driver API BSS mask {})", sta,
		     dur, txn, mNAmon, hex(vendorBss, 2U));
	return arcp::MonitorStatus::MEASURED;
}

void Daemon::onAmonReq(const Peer &from, const arcp::StaMonitorReq &r) noexcept
{
	const arcp::MonitorStatus st = startAmonWatch(r.sta, from.id, r.txn, static_cast<int>(r.durationMs),
						      r.opClass, r.channel);
	if (st == arcp::MonitorStatus::MEASURED) {
		logging::info(LOG_MODULE, "{} asks to measure {} (ch {})", from.id, r.sta, r.channel);
		return;
	}
	// Cannot measure: say so now, so the source does not wait for us.
	arcp::Message m;
	arcp::StaMonitorStatus ms;
	ms.txn = r.txn;
	ms.sta = r.sta;
	ms.status = static_cast<std::uint8_t>(st);
	beginMsg(m, arcp::MsgType::STA_MONITOR_REPORT, arcp::FLAG_ACK_REQ);
	(void)m.add(ms);
	(void)unicast(from.id, m);
	logging::info(LOG_MODULE, "{} asks to measure {}: {}", from.id, r.sta, arcp::monitorStatusName(ms.status));
}

// Watch over: one result per local BSS that heard the STA (the driver API's
// own value for its BSSes, else the monitor's on the BSS's frequency), then
// the status. Results go first: the source evaluates on the status.
void Daemon::finishAmonWatch(AmonWatch &w, Millis now) noexcept
{
	const bool local = w.requester == mApId;
	arcp::Message m;
	std::size_t n = 0U;
	bool vendorFailed = w.vendorFailed;

	if (!local) {
		beginMsg(m, arcp::MsgType::STA_MONITOR_REPORT, arcp::FLAG_ACK_REQ);
	}
	for (std::size_t b = 0U; b < mNBss; b++) {
		if (!mBss[b].up) {
			continue;
		}
		arcp::StaMonitorResult r;
		bool have = false;
		const std::string_view ifn = mBss[b].cfg->ifname.view();
		if ((w.vendorBss & (1U << b)) != 0U) {
			vendor::RssiSample vs;
			const vendor::RssiStatus st = vendor::readStaRssi(ifn, w.sta, vs);
			vendor::stopStaRssi(ifn, w.sta);
			if ((st == vendor::RssiStatus::OK) && (vs.samples > 0U)) {
				r.rssi = vs.rssi;
				r.samples = vs.samples;
				r.ageMs = vs.ageMs;
				have = true;
			}
			vendorFailed = vendorFailed || (st == vendor::RssiStatus::FAILED);
		}
		for (const AmonAcc &a : w.acc) {
			if (!have && (a.n != 0) && (static_cast<int>(mBss[b].info.freq) == a.freq)) {
				const Millis age = now - a.last;
				r.rssi = static_cast<std::int8_t>(a.sum / a.n);
				r.samples = static_cast<std::uint16_t>((a.n > 65535) ? 65535 : a.n);
				r.ageMs = static_cast<std::uint16_t>((age > 65535U) ? 65535U : age);
				have = true;
			}
		}
		if (!have) {
			continue;
		}
		r.txn = w.txn;
		r.sta = w.sta;
		r.bssid = mBss[b].info.bssid;
		if (local) {
			onAmonResult(mApId, r);
		} else {
			(void)m.add(r);
		}
		n++;
	}
	arcp::StaMonitorStatus ms;
	ms.txn = w.txn;
	ms.sta = w.sta;
	if (n > 0U) {
		ms.status = static_cast<std::uint8_t>(arcp::MonitorStatus::MEASURED);
	} else if (vendorFailed && (mNAmon == 0U)) {
		ms.status = static_cast<std::uint8_t>(arcp::MonitorStatus::FAILED);
	} else {
		ms.status = static_cast<std::uint8_t>(arcp::MonitorStatus::NOT_HEARD);
	}
	logging::dbg(LOG_MODULE, "{}: {} ({} BSS)", w.sta, arcp::monitorStatusName(ms.status), n);
	w.used = false;
	if (local) {
		onAmonStatus(mApId, ms);
	} else {
		(void)m.add(ms);
		(void)unicast(w.requester, m);
	}
}

void Daemon::tickAmon(Millis now) noexcept
{
	for (AmonWatch &w : mWatch) {
		if (w.used && (now >= w.until)) {
			finishAmonWatch(w, now);
		}
	}
}

void Daemon::onAmonResult(const Mac &from, const arcp::StaMonitorResult &r) noexcept
{
	Sta *const s = findSta(r.sta);
	const RemoteBss *const rb = lookupRemoteBss(r.bssid, nullptr);
	const std::optional<std::size_t> b = findLocalBss(r.bssid);
	const arcp::BssInfo *const bi = (rb != nullptr) ? &rb->info : (b.has_value() ? &mBss[*b].info : nullptr);

	logging::info(LOG_MODULE, "{} heard by {} (AP {}): {} dBm, {} samples", r.sta, r.bssid, from, r.rssi, r.samples);
	if ((s != nullptr) && (bi != nullptr)) {
		storeMeasurement(*s, r.bssid, MeasSrc::AIR_MONITOR,
			   rrm::dbmToRcpi(static_cast<int>(r.rssi) + mCfg.pol.amonRssiOffset), bi->opClass,
			   bi->channel, os::nowMs() - r.ageMs);
		onMonitorResult(*s);
	}
}

void Daemon::onAmonStatus(const Mac &from, const arcp::StaMonitorStatus &r) noexcept
{
	SteerTxn *const t = findTxnBySta(r.sta);
	if ((t == nullptr) || (t->id != r.txn) || (t->state != SteerState::MEASURE)) {
		return;
	}
	bool found = false;
	for (std::size_t i = 0U; (i < t->nMonWait) && !found; i++) {
		if (t->monWait[i] == from) {
			t->nMonWait--;
			t->monWait[i] = t->monWait[t->nMonWait];
			found = true;
		}
	}
	if (from != mApId) {
		logging::info(LOG_MODULE, "{}: AP {} {}", r.sta, from, arcp::monitorStatusName(r.status));
	}
	if (found && (t->nMonWait == 0U)) {
		t->amonPending = false;
		Sta *const s = findSta(r.sta);
		logging::dbg(LOG_MODULE, "steer #{} {}: every AP asked has answered", t->id, r.sta);
		if (!t->bcnOutstanding || ((s != nullptr) && isMeasureComplete(*t, *s))) {
			evaluate(*t);
		}
	}
}

} // namespace donghoa
