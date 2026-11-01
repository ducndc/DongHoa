// SPDX-License-Identifier: MIT
// Air monitor: measure the RSSI of STAs from the frames they send, on
// radiotap monitor interfaces. Used when a STA gives no 802.11k beacon
// report (no 11k support, or too busy to answer).
//
// A source AP asks with STA_MONITOR_REQ; this AP watches the STA for the
// requested time and answers with one STA_MONITOR_RESULT per local BSS on
// whose frequency the STA was heard. A stock radio hears only its own
// channel: uplink data of STAs on that channel, probe requests of scanning
// STAs.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::AMON};
constexpr int MAX_DURATION_MS = 5000;

} // namespace

void Daemon::initAmon() noexcept
{
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

bool Daemon::startAmonWatch(const Mac &sta, const Mac &requester, std::uint32_t txn,
			      int durationMs) noexcept
{
	AmonWatch *w = nullptr;
	const int dur = ((durationMs <= 0) || (durationMs > MAX_DURATION_MS)) ? mCfg.pol.amonDurationMs
									       : durationMs;

	if (mNAmon == 0U) {
		return false;
	}
	for (AmonWatch &x : mWatch) {
		if ((w == nullptr) && !x.used) {
			w = &x;
		}
	}
	if (w == nullptr) {
		logging::warn(LOG_MODULE, "watch table full, {} not measured", sta);
		return false;
	}
	*w = AmonWatch{};
	w->used = true;
	w->sta = sta;
	w->requester = requester;
	w->txn = txn;
	w->until = os::nowMs() + static_cast<Millis>(dur);
	logging::dbg(LOG_MODULE, "watching {} for {} ms (txn {})", sta, dur, txn);
	return true;
}

void Daemon::onAmonReq(const Peer &from, const arcp::StaMonitorReq &r) noexcept
{
	if (startAmonWatch(r.sta, from.id, r.txn, static_cast<int>(r.durationMs))) {
		logging::info(LOG_MODULE, "{} asks to measure {} (ch {})", from.id, r.sta, r.channel);
	}
}

// Watch over: one result per local BSS on a frequency the STA was heard on.
void Daemon::finishAmonWatch(AmonWatch &w, Millis now) noexcept
{
	const bool local = w.requester == mApId;
	arcp::Message m;
	std::size_t n = 0U;

	if (!local) {
		beginMsg(m, arcp::MsgType::STA_MONITOR_REPORT, arcp::FLAG_ACK_REQ);
	}
	for (const AmonAcc &a : w.acc) {
		if (a.n == 0) {
			continue;
		}
		for (std::size_t b = 0U; b < mNBss; b++) {
			if (!mBss[b].up || (static_cast<int>(mBss[b].info.freq) != a.freq)) {
				continue;
			}
			const Millis age = now - a.last;
			arcp::StaMonitorResult r;
			r.txn = w.txn;
			r.sta = w.sta;
			r.bssid = mBss[b].info.bssid;
			r.rssi = static_cast<std::int8_t>(a.sum / a.n);
			r.samples = static_cast<std::uint16_t>((a.n > 65535) ? 65535 : a.n);
			r.ageMs = static_cast<std::uint16_t>((age > 65535U) ? 65535U : age);
			if (local) {
				onAmonResult(mApId, r);
			} else {
				(void)m.add(r);
			}
			n++;
		}
	}
	if (n == 0U) {
		logging::dbg(LOG_MODULE, "{} not heard", w.sta);
	} else if (!local) {
		(void)unicast(w.requester, m);
	} else {
		// local results already stored
	}
	w.used = false;
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

} // namespace donghoa
