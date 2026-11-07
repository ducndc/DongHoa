// SPDX-License-Identifier: MIT
// Local control socket (UNIX datagram), used by donghoa_cli and tests.
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::CTRL};
using Out = FixedString<8192U>;

// rrm::BANDS_* mask as text, "-" for none.
std::string_view bandsName(std::uint8_t bands) noexcept
{
	constexpr std::array<std::string_view, 8U> NAMES{"-",  "2g",    "5g",    "2g,5g",
							  "6g", "2g,6g", "5g,6g", "2g,5g,6g"};
	return NAMES[static_cast<std::size_t>(bands & 0x07U)];
}

// single/dual/tri from the bands a STA can use; "unknown" when it
// advertised no operating classes (every band is then tried).
std::string_view bandClass(std::uint8_t advertised, std::uint8_t usable) noexcept
{
	constexpr std::array<std::string_view, 4U> NAMES{"none", "single", "dual", "tri"};
	std::size_t n = 0U;
	for (std::uint8_t b = usable & 0x07U; b != 0U; b = static_cast<std::uint8_t>(b & (b - 1U))) {
		n++;
	}
	return (advertised == 0U) ? std::string_view("unknown") : NAMES[n];
}

// arcp::CAP_* mask as a comma-joined capability string, "-" for none.
void capsName(std::uint16_t caps, FixedString<64U> &out) noexcept
{
	struct Bit {
		std::uint16_t mask;
		std::string_view name;
	};
	constexpr std::array<Bit, 9U> BITS{{
		{arcp::CAP_FT, "ft"},
		{arcp::CAP_BTM, "btm"},
		{arcp::CAP_RRM_NR, "rrm_nr"},
		{arcp::CAP_RRM_BCN, "rrm_bcn"},
		{arcp::CAP_HT, "ht"},
		{arcp::CAP_VHT, "vht"},
		{arcp::CAP_HE, "he"},
		{arcp::CAP_EHT, "eht"},
		{arcp::CAP_FT_OVER_DS, "ft_ds"},
	}};
	bool any = false;

	out.clear();
	for (const Bit &x : BITS) {
		if ((caps & x.mask) != 0U) {
			formatTo(out, "{}{}", any ? "," : "", x.name);
			any = true;
		}
	}
	if (!any) {
		formatTo(out, "-");
	}
}

void putBss(Out &o, const arcp::BssInfo &bi, const arcp::BssLoad *bl) noexcept
{
	FixedString<64U> caps;

	capsName(bi.caps, caps);
	formatTo(o, "  bss {} ssid={} ch={} band={} op_class={} mdid={} caps={}", bi.bssid,
		  SsidText{bi.ssidView()}, bi.channel, bi.band, bi.opClass, hex(bi.mdid, 4U), caps.view());
	if (bi.isMldLink()) {
		formatTo(o, " mld={} link={}", bi.mldAddr, bi.linkId);
	}
	if (bl != nullptr) {
		formatTo(o, " sta={} util={}% noise={} accepting={}", bl->staCount, policy::utilToPct(bl->util),
			  bl->noise, ((bl->flags & arcp::LOAD_ACCEPTING) != 0U) ? 1 : 0);
	}
	formatTo(o, "\n");
}

// LOG                       show the level of every module
// LOG <level>               set every module
// LOG <level> <module>...   set the named modules
void cmdLog(Out &o, std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view a;

	if (t.next(a)) {
		const std::optional<LogLevel> lvl = logging::parseLevel(a);
		if (!lvl.has_value()) {
			formatTo(o, "FAIL usage: LOG [err|warn|info|debug [<module>...]]\n");
			return;
		}
		std::string_view m;
		bool any = false;
		while (t.next(m)) {
			const std::optional<LogModule> mod = logging::parseModule(m);
			if (!mod.has_value()) {
				formatTo(o, "FAIL unknown module {}\n", m);
				return;
			}
			logging::setLevel(*mod, *lvl);
			any = true;
		}
		if (!any) {
			logging::setAll(*lvl);
		}
	}
	for (std::size_t i = 0U; i < logging::MODULES; i++) {
		const LogModule mod = logging::moduleAt(i);
		formatTo(o, "{}={}\n", logging::moduleName(mod), logging::levelName(logging::level(mod)));
	}
}

} // namespace

bool Daemon::openCtrl() noexcept
{
	bool ok = true;
	if (!mCfg.ctrlSocket.empty()) {
		mCtrlFd = os::bindUnix(mCfg.ctrlSocket.cStr(), true);
		ok = mCtrlFd.valid();
		if (!ok) {
			logging::err(LOG_MODULE, "bind {}: {}", mCfg.ctrlSocket, os::lastError());
		}
	}
	return ok;
}

void Daemon::closeCtrl() noexcept
{
	if (mCtrlFd.valid()) {
		mCtrlFd.reset();
		os::removeFile(mCfg.ctrlSocket.cStr());
	}
}

void Daemon::runCtrlCommand(std::string_view req, Out &o) noexcept
{
	const Millis now = os::nowMs();

	if (req == "PING") {
		formatTo(o, "PONG\n");
	} else if (req == "STATUS") {
		formatTo(o, "ap_id={}\nname={}\nboot_id={}\n", mApId, mCfg.name, hex(mBootId, 8U));
		for (std::size_t i = 0U; i < mL2.size(); i++) {
			formatTo(o, "port={}\n", mL2.port(i).name);
		}
		for (std::size_t i = 0U; i < mNAmon; i++) {
			formatTo(o, "air_monitor={}\n", mAmon[i].name);
		}
		if (mSurvey.isOpen()) {
			const SurveyStats &ss = mSurvey.stats();
			formatTo(o, "survey=nl80211 radios={} dumps={} last_us={} max_us={} timeouts={} errors={}\n",
				  ss.radios, ss.dumps, ss.lastUs, ss.maxUs, ss.timeouts, ss.errors);
			formatTo(o, "station_dump=nl80211 dumps={} last_us={} max_us={}\n", ss.staDumps, ss.staLastUs,
				  ss.staMaxUs);
		} else {
			formatTo(o, "survey=off (hostapd chan_util_avg only)\n");
		}
		for (std::size_t i = 0U; i < mNBss; i++) {
			formatTo(o, "{} {}\n", mBss[i].cfg->ifname, mBss[i].up ? "up" : "down");
			if (mBss[i].up) {
				putBss(o, mBss[i].info, &mBss[i].load);
				const LocalBss::UtilSrc us = mBss[i].utilSrc;
				formatTo(o, "  util_src={}\n",
					 (us == LocalBss::UtilSrc::SURVEY)
						 ? "survey (nl80211 busy time)"
						 : ((us == LocalBss::UtilSrc::HOSTAPD) ? "hostapd (chan_util_avg)" : "none"));
				formatTo(o, "  sta_src={}\n",
					 mBss[i].nlActive ? "nl80211 station dump (hostapd resync every 10 s)"
							  : "hostapd STA-FIRST/NEXT");
			}
		}
	} else if (req == "PEERS") {
		for (const Peer &p : mPeers) {
			if (!p.used) {
				continue;
			}
			formatTo(o, "peer {} name={} port={} age={}ms\n", p.id, p.name,
				  p.port.has_value() ? mL2.port(*p.port).name.view() : std::string_view("-"),
				  now - p.lastSeen);
			for (const RemoteBss &b : p.bss) {
				if (b.used) {
					putBss(o, b.info, b.hasLoad ? &b.load : nullptr);
				}
			}
			for (std::size_t k = 0U; k < p.nRf; k++) {
				const arcp::RfInfo &rf = p.rf[k];
				formatTo(o, "  radio {} freq={} ch={} util={}% noise={} txpower={}\n", rf.radioId, rf.freq,
					  rf.channel, policy::utilToPct(rf.util), rf.noise, rf.txPower);
			}
		}
	} else if (req == "STAS") {
		for (const Sta &s : mSta) {
			if (!s.used) {
				continue;
			}
			const std::string_view bcn = s.bcnUnsupported ? std::string_view("none")
						     : (s.bcnMode.has_value() ? rrm::beaconModeName(*s.bcnMode)
									      : std::string_view("unknown"));
			const std::int64_t backoff = static_cast<std::int64_t>(s.nextSteerMs) - static_cast<std::int64_t>(now);
			const std::uint8_t usable = static_cast<std::uint8_t>(
				static_cast<std::uint8_t>(s.bandsAdv | s.bandsSeen) & static_cast<std::uint8_t>(~s.bandsBlocked));
			formatTo(o, "sta {} bss={}{} rssi={} tput={}kbps flags={}{}{} bcn={} bands={}({}) adv={} seen={}{}",
				  s.addr, mBss[s.bss].cfg->ifname, s.away ? "(away)" : "", s.rssi, s.tputKbps,
				  ((s.flags & arcp::STA_F11K) != 0U) ? "k" : "", ((s.flags & arcp::STA_F11V) != 0U) ? "v" : "",
				  ((s.flags & arcp::STA_F11R) != 0U) ? "r" : "", bcn, bandsName(usable),
				  bandClass(s.bandsAdv, usable), bandsName(s.bandsAdv), bandsName(s.bandsSeen),
				  ((s.bandsBlocked & rrm::BANDS_6G) != 0U) ? " no6g=wpa2-psk" : "");
			// MLD STA: every link as <bss>:<link id>:<rssi>, best link first in bss=
			if (s.mld) {
				formatTo(o, " mld links=");
				const char *sep = "";
				for (const StaLink &l : s.links) {
					if (l.used) {
						formatTo(o, "{}{}:{}:{}", sep, mBss[l.bss].cfg->ifname, mBss[l.bss].info.linkId,
							  l.rssi);
						sep = ",";
					}
				}
				formatTo(o, " max_simul_links={}", s.maxSimulLinks);
			}
			FixedString<16U> sText;
			formatScore(sText, s.lpS100);
			formatTo(o, " class={} lp_score={}/{} s={}", s.lowPower ? "low-power" : "normal", s.lpScore,
				  mCfg.pol.lpThreshold, sText);
			formatTo(o, " roam_thr={}({})", policy::roamThreshold(mCfg.pol, s.roamThr),
				  (s.roamEvents > 0U) ? "learned" : "default");
			if (s.roamEvents > 0U) {
				formatTo(o, " roam_events={}", s.roamEvents);
			}
			formatTo(o, " backoff={}ms\n", backoff);
		}
		for (const RemoteSta &r : mRsta) {
			if (r.used) {
				formatTo(o, "remote {} ap={} bss={} rssi={}{}\n", r.sta, r.ap, r.bssid, r.rssi,
					  ((r.flags & arcp::STA_F_LOW_POWER) != 0U) ? " class=low-power" : "");
			}
		}
	} else if (req == "DEVCLASS") {
		// Device class records: learned here or received from peers.
		for (const DevClassRec &r : mDevClass) {
			if (r.used) {
				formatTo(o, "devclass {} class={} score={} samples={} from={} age={}s", r.sta,
					  r.lowPower ? "low-power" : "normal", r.score, r.samples, r.source,
					  (now - r.ts) / 1000U);
				if (r.roamEvents > 0U) {
					formatTo(o, " roam_thr={} roam_events={}", r.roamThr, r.roamEvents);
				}
				formatTo(o, "\n");
			}
		}
	} else if ((req == "RL") || startsWith(req, "RL ")) {
		cmdRl(o, (req.size() > 3U) ? subView(req, 3U) : std::string_view());
	} else if (req == "CALIB") {
		// Learned uplink -> downlink offsets used for AP-side levels.
		formatTo(o, "default amon_rssi_offset={} learn={} min_samples={}\n", mCfg.pol.amonRssiOffset,
			  mCfg.pol.amonOffsetLearn ? 1 : 0, mCfg.pol.amonOffsetMinSamples);
		for (const UlDlCal &c : mCal) {
			if (c.used) {
				FixedString<16U> off;
				formatOffset16(off, c.off.offset16);
				formatTo(o, "calib {} offset={}dB samples={} used={} age={}s\n", c.bssid, off, c.off.n,
					  policy::isUlDlCalibrated(mCfg.pol, c.off) ? "yes" : "no", (now - c.ts) / 1000U);
			}
		}
	} else if (req == "STEERS") {
		for (const SteerTxn &t : mTxn) {
			if (t.used) {
				const long cur = (t.cur >= MAX_CAND) ? -1L : static_cast<long>(t.cur);
				formatTo(o, "txn {} sta {} state={} cand={}/{}\n", t.id, t.sta, steerStateName(t.state), cur,
					  t.nCand);
			}
		}
		for (const Reservation &r : mResv) {
			if (r.used) {
				formatTo(o, "reservation sta {} bss={} txn={}\n", r.sta, mBss[r.bss].cfg->ifname, r.txn);
			}
		}
	} else if (startsWith(req, "STEER ")) {
		Tokens t(subView(req, 6U), " ");
		std::string_view a;
		std::string_view b;
		const bool hasA = t.next(a);
		const bool hasB = t.next(b);
		const std::optional<Mac> sta = hasA ? parseMac(a) : std::optional<Mac>();
		const std::optional<Mac> tgt = hasB ? parseMac(b) : std::optional<Mac>();
		if (!sta.has_value() || (hasB && !tgt.has_value())) {
			formatTo(o, "FAIL usage: STEER <sta> [<bssid>]\n");
		} else {
			Sta *const s = findSta(*sta);
			if (s == nullptr) {
				formatTo(o, "FAIL unknown sta\n");
			} else {
				s->nextSteerMs = 0U;
				const bool ok = startSteer(*s, arcp::SteerReason::MANUAL, tgt.has_value() ? &*tgt : nullptr);
				formatTo(o, ok ? "OK\n" : "FAIL\n");
			}
		}
	} else if (startsWith(req, "MONITOR ")) {
		// Measure a STA with this AP's air monitors; the result goes to the
		// log (and to the STA's measurements when it is associated here).
		Tokens t(subView(req, 8U), " ");
		std::string_view a;
		std::string_view b;
		const bool hasA = t.next(a);
		const bool hasB = t.next(b);
		const std::optional<Mac> sta = hasA ? parseMac(a) : std::optional<Mac>();
		const std::optional<long> ms = hasB ? parseLong(b, 10, 1, 5000)
						     : std::optional<long>(static_cast<long>(mCfg.pol.amonDurationMs));
		if (!sta.has_value() || !ms.has_value()) {
			formatTo(o, "FAIL usage: MONITOR <sta> [<ms 1..5000>]\n");
		} else if (!canMeasureStas()) {
			formatTo(o, "FAIL no air_monitor or sta_rssi_api configured\n");
		} else {
			const arcp::MonitorStatus st = startAmonWatch(*sta, mApId, 0U, static_cast<int>(*ms), 0U, 0U);
			if (st == arcp::MonitorStatus::MEASURED) {
				formatTo(o, "OK result in the log after the watch (logread -e donghoa)\n");
			} else {
				formatTo(o, "FAIL {}\n", arcp::monitorStatusName(static_cast<std::uint8_t>(st)));
			}
		}
	} else if (req == "LOG") {
		cmdLog(o, std::string_view());
	} else if (startsWith(req, "LOG ")) {
		cmdLog(o, subView(req, 4U));
	} else {
		formatTo(o, "UNKNOWN COMMAND\n");
	}
}

namespace {

// Q value x256 as "+12.3" / "-1.0".
void formatQ(FixedString<16U> &out, int q256) noexcept
{
	const int a = (q256 < 0) ? -q256 : q256;
	const int tenths = ((a * 10) + 128) / 256;
	formatTo(out, "{}{}.{}", (q256 < 0) ? "-" : "+", tenths / 10, tenths % 10);
}

} // namespace

void Daemon::cmdRl(Out &o, std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view a;
	std::string_view b;
	const bool hasA = t.next(a);
	const bool hasB = t.next(b);
	constexpr std::array<std::string_view, 3U> MODES{"off", "shadow", "active"};

	if (hasA && (a == "reset")) {
		policy::rlInit(mRl);
		mRlStats = RlStats{};
		formatTo(o, "OK table reset to the rule-based prior\n");
		return;
	}
	if (hasA && (a == "mode")) {
		const std::optional<long> m = hasB ? parseLong(b, 10, 0, 2) : std::optional<long>();
		if (!m.has_value()) {
			formatTo(o, "FAIL usage: RL mode <0 off|1 shadow|2 active>\n");
		} else {
			mRlModeOverride = static_cast<int>(*m);
			formatTo(o, "OK mode {}\n", MODES[static_cast<std::size_t>(*m)]);
		}
		return;
	}
	if (hasA) {
		formatTo(o, "FAIL usage: RL [mode <0|1|2> | reset]\n");
		return;
	}
	const std::size_t mi = static_cast<std::size_t>(rlMode());
	formatTo(o, "rl mode={} epsilon={}% decisions={} steers={} explored={} updates={}\n", MODES[mi],
		  mCfg.pol.rlEpsilonPct, mRlStats.decisions, mRlStats.steers, mRlStats.explored, mRlStats.updates);
	constexpr std::array<std::string_view, 3U> TREND{"falling", "stable", "rising"};
	constexpr std::array<std::string_view, 4U> GAP{"unknown", "worse", "0..7", ">=8"};
	for (std::size_t s = 0U; s < policy::RL_STATES; s++) {
		if ((mRl.n[s][0U] == 0U) && (mRl.n[s][1U] == 0U)) {
			continue; // never visited: still the prior
		}
		const std::size_t streak = s % policy::RL_STREAK_BINS;
		const std::size_t ref = (s / policy::RL_STREAK_BINS) % policy::RL_REF_BINS;
		const std::size_t gap = (s / (policy::RL_STREAK_BINS * policy::RL_REF_BINS)) % policy::RL_GAP_BINS;
		const std::size_t tr =
			(s / (policy::RL_STREAK_BINS * policy::RL_REF_BINS * policy::RL_GAP_BINS)) % policy::RL_TREND_BINS;
		const std::size_t rb = s / (policy::RL_STREAK_BINS * policy::RL_REF_BINS * policy::RL_GAP_BINS *
					    policy::RL_TREND_BINS);
		FixedString<16U> qw;
		FixedString<16U> qs;
		formatQ(qw, mRl.q[s][0U]);
		formatQ(qs, mRl.q[s][1U]);
		formatTo(o, "q {} rssi={} trend={} gap={} refusals={}{} streak={} wait={} steer={} n={}/{} greedy={}\n", s,
			 policy::rlRssiBinName(rb), TREND[tr], GAP[gap], ref, (ref == 2U) ? "+" : "", streak, qw, qs,
			 mRl.n[s][0U], mRl.n[s][1U], (mRl.q[s][1U] > mRl.q[s][0U]) ? "steer" : "wait");
	}
}

void Daemon::handleCtrl() noexcept
{
	std::array<std::uint8_t, 255U> buf{};
	bool more = mCtrlFd.valid();

	while (more) {
		std::size_t n = 0U;
		os::UnixAddr from;
		more = os::recvFrom(mCtrlFd, spanOf(buf), n, from) == os::Rx::DATA;
		if (more) {
			FixedString<255U> req;
			for (std::size_t i = 0U; i < n; i++) {
				(void)req.pushBack(static_cast<char>(buf[i]));
			}
			Out out;
			runCtrlCommand(trim(req.view()), out);
			if (out.empty()) {
				formatTo(out, "\n");
			}
			std::array<std::uint8_t, 8192U> reply{};
			const std::string_view text = out.view();
			for (std::size_t i = 0U; i < text.size(); i++) {
				reply[i] = static_cast<std::uint8_t>(text[i]);
			}
			os::sendTo(mCtrlFd, viewOf(reply).first(text.size()), from);
		}
	}
}

} // namespace donghoa
