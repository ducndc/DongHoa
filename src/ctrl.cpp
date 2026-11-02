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

void putBss(Out &o, const arcp::BssInfo &bi, const arcp::BssLoad *bl) noexcept
{
	formatTo(o, "  bss {} ssid={} ch={} band={} op_class={} mdid={} caps={}", bi.bssid,
		  SsidText{bi.ssidView()}, bi.channel, bi.band, bi.opClass, hex(bi.mdid, 4U), hex(bi.caps, 4U));
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
		for (std::size_t i = 0U; i < mNBss; i++) {
			formatTo(o, "{} {}\n", mBss[i].cfg->ifname, mBss[i].up ? "up" : "down");
			if (mBss[i].up) {
				putBss(o, mBss[i].info, &mBss[i].load);
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
			formatTo(o, "sta {} bss={}{} rssi={} tput={}kbps flags={}{}{} bcn={} bands={}({}) adv={} seen={}{} "
				    "backoff={}ms\n",
				  s.addr, mBss[s.bss].cfg->ifname, s.away ? "(away)" : "", s.rssi, s.tputKbps,
				  ((s.flags & arcp::STA_F11K) != 0U) ? "k" : "", ((s.flags & arcp::STA_F11V) != 0U) ? "v" : "",
				  ((s.flags & arcp::STA_F11R) != 0U) ? "r" : "", bcn, bandsName(usable),
				  bandClass(s.bandsAdv, usable), bandsName(s.bandsAdv), bandsName(s.bandsSeen),
				  ((s.bandsBlocked & rrm::BANDS_6G) != 0U) ? " no6g=wpa2-psk" : "", backoff);
		}
		for (const RemoteSta &r : mRsta) {
			if (r.used) {
				formatTo(o, "remote {} ap={} bss={} rssi={}\n", r.sta, r.ap, r.bssid, r.rssi);
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
		} else if (mNAmon == 0U) {
			formatTo(o, "FAIL no air_monitor configured\n");
		} else {
			formatTo(o, startAmonWatch(*sta, mApId, 0U, static_cast<int>(*ms))
					     ? "OK result in the log after the watch (logread -e donghoa)\n"
					     : "FAIL\n");
		}
	} else if (req == "LOG") {
		cmdLog(o, std::string_view());
	} else if (startsWith(req, "LOG ")) {
		cmdLog(o, subView(req, 4U));
	} else {
		formatTo(o, "UNKNOWN COMMAND\n");
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
