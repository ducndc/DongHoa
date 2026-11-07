// SPDX-License-Identifier: MIT
// Local BSSes and STAs: hostapd polling and events, 802.11k neighbor DB.
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "text.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::LOCAL};
constexpr Millis RECONNECT_MS = 5000U;
// Full hostapd STA listing while the per-poll metrics come from nl80211
// station dumps: capabilities that change, and STAs whose events were missed.
constexpr Millis STA_RESYNC_MS = 10000U;

// ifindex of the netdev behind a hostapd control socket name ("<netdev>"
// or, for an AP MLD link, "<netdev>_link<id>"); 0 if there is none.
int netdevIndex(const IfName &ctrlName) noexcept
{
	IfName dev;
	(void)dev.assign(hapd::netdevName(ctrlName.view()));
	return os::ifnameToIndex(dev.cStr());
}

// MLD STA: its RSSI is that of the best link, its BSS that link's, and it
// counts as weak only when every measured link is (lowCount = minimum).
void aggregateLinks(Sta &s) noexcept
{
	const StaLink *best = nullptr;
	int low = -1;
	for (const StaLink &l : s.links) {
		if (!l.used || (l.rssi == 0)) {
			continue;
		}
		if ((best == nullptr) || (l.rssi > best->rssi)) {
			best = &l;
		}
		low = ((low < 0) || (l.lowCount < low)) ? l.lowCount : low;
	}
	if (best != nullptr) {
		s.rssi = best->rssi;
		s.bss = best->bss;
		s.lowCount = low;
	}
}

} // namespace

void Daemon::initLocal() noexcept
{
	mNBss = mCfg.nBss;
	if (mCfg.nBssSkipped > 0U) {
		logging::warn(LOG_MODULE, "{} bss line(s) beyond the limit of {} ignored (first: {}); "
					  "list the BSSes to manage with bss lines in the configuration",
			      mCfg.nBssSkipped, MAX_BSS, mCfg.bssSkippedFirst);
	}
	for (std::size_t i = 0U; i < mNBss; i++) {
		LocalBss &b = mBss[i];
		b.cfg = &mCfg.bss[i];
		b.ifindex = netdevIndex(b.cfg->ifname);
		b.hapdUtil = -1;
	}
	(void)mSurvey.open();
}

std::optional<std::size_t> Daemon::findLocalBss(const Mac &bssid) const noexcept
{
	std::optional<std::size_t> r;
	for (std::size_t i = 0U; (i < mNBss) && !r.has_value(); i++) {
		if (mBss[i].up && (mBss[i].info.bssid == bssid)) {
			r = i;
		}
	}
	return r;
}

// ---- STA table ----

Sta *Daemon::findSta(const Mac &addr) noexcept
{
	Sta *r = nullptr;
	for (Sta &s : mSta) {
		if ((r == nullptr) && s.used && (s.addr == addr)) {
			r = &s;
		}
	}
	return r;
}

Sta *Daemon::getSta(const Mac &addr, std::size_t bss) noexcept
{
	Sta *r = findSta(addr);

	if (r != nullptr) {
		// An MLD STA shows up on every link of the AP MLD: not a move.
		const bool otherLink = r->mld && isSameApMld(r->bss, bss);
		if ((r->bss != bss) && !otherLink) {
			// Moved between local BSSes (e.g. band steering).
			r->bss = bss;
			r->rssi = 0;
			r->lowCount = 0;
			r->nMeas = 0U;
			r->mld = false;
			r->links = {};
		}
	} else {
		for (Sta &s : mSta) {
			if ((r == nullptr) && !s.used) {
				s = Sta{};
				s.used = true;
				s.addr = addr;
				s.bss = bss;
				// Do not steer a STA right after it joined.
				s.nextSteerMs = os::nowMs() + static_cast<Millis>(mCfg.pol.steerCooldownMs);
				restoreDevClass(s);
				r = &s;
			}
		}
		if (r == nullptr) {
			logging::warn(LOG_MODULE, "STA table full");
		}
	}
	return r;
}

arcp::StaEntry Daemon::fillEntry(const Sta &s) const noexcept
{
	arcp::StaEntry e;

	e.sta = s.addr;
	e.bssid = mBss[s.bss].info.bssid;
	e.rssi = static_cast<std::int8_t>(s.rssi);
	e.flags = s.flags;
	if (s.tputKbps < static_cast<std::uint32_t>(mCfg.pol.idleKbps)) {
		e.flags = static_cast<std::uint8_t>(e.flags | arcp::STA_F_IDLE);
	}
	if (s.lowPower) {
		e.flags = static_cast<std::uint8_t>(e.flags | arcp::STA_F_LOW_POWER);
	}
	for (const SteerTxn &t : mTxn) {
		if (t.used && (t.sta == s.addr)) {
			e.flags = static_cast<std::uint8_t>(e.flags | arcp::STA_F_STEERING);
		}
	}
	e.connectedS = s.connectedS;
	e.inactiveMs = s.inactiveMs;
	e.txRateMbps = s.txRate;
	e.rxRateMbps = s.rxRate;
	e.tputKbps = s.tputKbps;
	return e;
}

bool Daemon::isSameApMld(std::size_t a, std::size_t b) const noexcept
{
	return (a < mNBss) && (b < mNBss) && arcp::isSameMld(mBss[a].info, mBss[b].info);
}

void Daemon::updateStaLink(Sta &s, const hapd::Sta &h, std::size_t bss, Millis now) noexcept
{
	StaLink *l = nullptr;
	for (StaLink &x : s.links) {
		if ((l == nullptr) && x.used && (x.bss == bss)) {
			l = &x;
		}
	}
	for (StaLink &x : s.links) {
		if ((l == nullptr) && !x.used) {
			x = StaLink{};
			x.used = true;
			x.bss = bss;
			l = &x;
		}
	}
	if (l == nullptr) {
		return; // more links than MAX_STA_LINKS
	}
	l->lastPollMs = now;
	if ((h.signal != 0) && policy::isSignalFresh(h.inactiveMs, mCfg.staPollMs)) {
		l->rssi = (l->rssi != 0) ? (((3 * l->rssi) + h.signal) - 2) / 4 : h.signal;
		l->lowCount = (h.signal < mCfg.pol.rssiLow) ? (l->lowCount + 1) : 0;
	}
	aggregateLinks(s);
}

bool Daemon::pruneStaLinks(Sta &s, std::size_t bss, Millis start) noexcept
{
	std::array<StaLink, MAX_STA_LINKS> kept{};
	std::size_t n = 0U;
	for (const StaLink &l : s.links) {
		const bool stale = (l.bss == bss) && (l.lastPollMs < start) && (l.lastPollMs != 0U);
		if (l.used && !stale) {
			kept[n] = l;
			n++;
		}
	}
	s.links = kept;
	aggregateLinks(s);
	return n > 0U;
}

void Daemon::applyStaSignal(Sta &s, int signal, std::uint32_t inactiveMs) noexcept
{
	if ((signal != 0) && ((s.rssi == 0) || policy::isSignalFresh(inactiveMs, mCfg.staPollMs))) {
		s.rssi = (s.rssi != 0) ? (((3 * s.rssi) + signal) - 2) / 4 : signal;
		s.lowCount = (signal < mCfg.pol.rssiLow) ? (s.lowCount + 1) : 0;
	} else {
		// No signal, or the same old frame's (idle STA): neither the
		// average nor the low count moves.
	}
}

void Daemon::applyStaTraffic(Sta &s, std::uint64_t rxBytes, std::uint64_t txBytes, std::uint32_t inactiveMs,
			     std::uint32_t connectedS, std::uint16_t rxRate, std::uint16_t txRate, Millis now) noexcept
{
	const std::uint64_t total = rxBytes + txBytes;
	const std::uint64_t prev = s.rxBytes + s.txBytes;
	if ((s.bytesTs != 0U) && (now > s.bytesTs) && (total >= prev)) {
		s.tputKbps = static_cast<std::uint32_t>(((total - prev) * 8U) / (now - s.bytesTs));
		// counted from the AP: rx = uplink, tx = downlink
		if ((rxBytes >= s.rxBytes) && (txBytes >= s.txBytes)) {
			sampleTraffic(s, rxBytes - s.rxBytes, txBytes - s.txBytes, now - s.bytesTs);
		}
	}
	s.rxBytes = rxBytes;
	s.txBytes = txBytes;
	s.bytesTs = now;
	s.inactiveMs = inactiveMs;
	s.connectedS = connectedS;
	s.txRate = txRate;
	s.rxRate = rxRate;
}

void Daemon::applyStaSample(Sta &s, const hapd::Sta &h, std::size_t bss) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Millis now = os::nowMs();
	const bool assume = p.assumeKvr;

	if (h.mld) {
		s.mld = true;
		s.maxSimulLinks = h.maxSimulLinks;
		updateStaLink(s, h, bss, now);
	} else {
		applyStaSignal(s, h.signal, h.inactiveMs);
	}
	// An MLD STA is listed on each link: take traffic counters from one
	// link only (the first one seen), or the deltas mix two sources.
	const bool counters = !s.mld || (s.links[0U].used && (s.links[0U].bss == bss));
	if (counters) {
		applyStaTraffic(s, h.rxBytes, h.txBytes, h.inactiveMs, h.connectedS, h.rxRateMbps, h.txRateMbps, now);
	}
	if (h.bands != 0U) {
		s.bandsAdv = h.bands;
	}
	if (h.phyCaps != 0U) {
		s.phyCaps = h.phyCaps;
	}
	s.bandsBlocked = h.akmNo6g ? rrm::BANDS_6G : static_cast<std::uint8_t>(0U);
	s.bandsSeen = static_cast<std::uint8_t>(s.bandsSeen | rrm::bandBit(mBss[bss].info.band));
	s.flags = 0U;
	if (h.btmKnown ? h.btm : assume) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::STA_F11V);
	}
	if (h.ftKnown ? h.ft : (assume && (mBss[bss].cfg->mdid != 0U))) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::STA_F11R);
	}
	// No STA 11k indicator in ctrl output; hostapd refusing REQ_BEACON in
	// every mode marks the STA as lacking beacon reports.
	if (assume && !s.bcnUnsupported) {
		s.flags = static_cast<std::uint8_t>(s.flags | arcp::STA_F11K);
	}
	s.capsKnown = true;
	s.lastPollMs = now;
}

// ---- BSS polling ----

void Daemon::markBssDown(std::size_t i) noexcept
{
	LocalBss &b = mBss[i];

	if (b.up) {
		logging::warn(LOG_MODULE, "bss {} down", b.cfg->ifname);
	}
	b.up = false;
	b.nextReconnectMs = os::nowMs() + RECONNECT_MS;
	for (Sta &s : mSta) {
		if (s.used && (s.bss == i)) {
			saveDevClass(s);
			s.used = false;
		}
	}
}

void Daemon::refreshBss(std::size_t i) noexcept
{
	LocalBss &b = mBss[i];
	hapd::Reply reply;
	const arcp::BssInfo old = b.info;
	const bool wasUp = b.up;
	std::optional<hapd::Status> st;

	if (b.hapd.runCommand("STATUS", reply)) {
		st = hapd::parseStatus(reply.view(), b.cfg->ifname.view());
	}
	if (!st.has_value()) {
		markBssDown(i);
		return;
	}
	if (!wasUp) {
		// hostapd may have recreated the interface: look it up again
		b.ifindex = netdevIndex(b.cfg->ifname);
		b.wiphy = mSurvey.findWiphy(b.ifindex);
		b.surveyPrev = SurveySample{};
		if (b.wiphy.has_value()) {
			logging::dbg(LOG_MODULE, "bss {}: ifindex {} on wiphy {}", b.cfg->ifname, b.ifindex, *b.wiphy);
		}
	}
	if (!wasUp && b.hapd.runCommand("GET_CONFIG", reply)) {
		const std::optional<long> wpa = getKvInt(reply.view(), "wpa");
		b.secured = wpa.has_value() && (*wpa != 0);
		if ((b.cfg->mdid != 0U) && (reply.view().find("FT-") == std::string_view::npos)) {
			logging::warn(LOG_MODULE, "bss {}: mdid configured but hostapd key_mgmt has no FT AKM",
				      b.cfg->ifname);
		}
	}

	b.info = arcp::BssInfo{};
	b.info.bssid = st->bssid;
	b.info.freq = static_cast<std::uint16_t>(st->freq);
	b.info.channel = st->channel;
	b.info.band = st->band;
	b.info.bw = st->bw;
	b.info.opClass = rrm::opClass20mhz(st->band, st->channel);
	// 11k/11v must be enabled in hostapd (see README).
	b.info.caps = static_cast<std::uint16_t>(st->caps | arcp::CAP_BTM | arcp::CAP_RRM_NR | arcp::CAP_RRM_BCN);
	if (b.cfg->mdid != 0U) {
		b.info.caps = static_cast<std::uint16_t>(b.info.caps | arcp::CAP_FT);
	}
	if (b.cfg->ftOverDs) {
		b.info.caps = static_cast<std::uint16_t>(b.info.caps | arcp::CAP_FT_OVER_DS);
	}
	b.info.mdid = b.cfg->mdid;
	b.info.phyType = rrm::phyTypeFromCaps(b.info.caps, st->band);
	b.info.bssidInfo = rrm::buildBssidInfo(b.info.caps, b.secured);
	b.info.ssidLen = st->ssidLen;
	b.info.ssid = st->ssid;
	if (st->linkId >= 0) {
		b.info.mldAddr = st->mldAddr;
		b.info.linkId = static_cast<std::uint8_t>(st->linkId);
	}

	// Utilisation from the radio's survey (asynchronous: the dump asked on
	// the previous poll), else from hostapd's chan_util_avg. A survey that
	// is fresh but has no new dump yet keeps the last value.
	b.hapdUtil = st->chanUtil;
	int util = -1;
	const Millis now = os::nowMs();
	const Millis stale = (3U * static_cast<Millis>(mCfg.staPollMs)) + Survey::DUMP_TIMEOUT_MS;
	const SurveySample *const cur = b.wiphy.has_value() ? mSurvey.find(*b.wiphy, st->freq) : nullptr;
	const bool fromSurvey = (cur != nullptr) && ((now - cur->ts) < stale);
	bool newSample = false;
	if (fromSurvey && (cur->ts != b.surveyPrev.ts)) {
		newSample = true;
		util = Survey::util(b.surveyPrev, *cur);
		if (util >= 0) {
			b.utilSrc = LocalBss::UtilSrc::SURVEY;
		}
		b.surveyPrev = *cur;
		b.load.noise = cur->noise;
	}
	// No survey, or counters that do not grow (a driver that clears them on read)
	if ((util < 0) && (!fromSurvey || newSample)) {
		util = b.hapdUtil;
		b.utilSrc = (util >= 0) ? LocalBss::UtilSrc::HOSTAPD : LocalBss::UtilSrc::NONE;
	}
	if (b.wiphy.has_value()) {
		mSurvey.request(*b.wiphy, b.ifindex); // one dump per radio per round
	}
	if (util > 254) {
		util = 254; // 255 means "unknown" on the wire
	}
	if (util >= 0) {
		b.load.util = (!wasUp || (b.load.util == 255U))
				      ? static_cast<std::uint8_t>(util)
				      : static_cast<std::uint8_t>(((3 * static_cast<int>(b.load.util)) + util + 2) / 4);
	} else if (!wasUp) {
		b.load.util = 255U;
	} else {
		// keep the last value
	}
	b.load.bssid = st->bssid;
	b.load.staCount = static_cast<std::uint16_t>(st->numSta);
	b.load.maxSta = static_cast<std::uint16_t>(b.cfg->maxSta);
	b.load.txPower = static_cast<std::int8_t>(st->maxTxpower);
	b.load.flags = (policy::admit(mCfg.pol, policy::utilToPct(b.load.util), st->numSta,
				      countReservations(i, os::nowMs()), b.cfg->maxSta) == arcp::SteerStatus::ACCEPT)
			       ? arcp::LOAD_ACCEPTING
			       : 0U;
	b.up = true;
	if (!wasUp) {
		logging::info(LOG_MODULE, "bss {} up: {} ch {} band {} ssid '{}'{}", b.cfg->ifname, b.info.bssid,
			      b.info.channel, b.info.band, SsidText{b.info.ssidView()},
			      (b.info.mdid != 0U) ? " FT" : "");
	}
	if (!wasUp || (old != b.info)) {
		// Sibling neighbor entries depend on this BSS: reinstall all.
		for (Peer &p : mPeers) {
			for (RemoteBss &rb : p.bss) {
				rb.nrInstalled = false;
			}
		}
		syncNeighbors();
	}
}

void Daemon::pollBss() noexcept
{
	const Millis now = os::nowMs();

	for (std::size_t i = 0U; i < mNBss; i++) {
		LocalBss &b = mBss[i];
		bool ready = b.hapd.isOpen();

		if (!ready && (now >= b.nextReconnectMs)) {
			ready = b.hapd.open(mCfg.hostapdDir, b.cfg->ifname);
			if (!ready) {
				markBssDown(i);
			}
		}
		if (ready) {
			refreshBss(i);
		}
	}
}

// Full hostapd listing of one BSS (STA-FIRST / STA-NEXT): capabilities
// and metrics of every STA, one blocking round trip per STA.
void Daemon::listStasFromHapd(std::size_t i, Millis start) noexcept
{
	LocalBss &b = mBss[i];
	hapd::Reply reply;
	FixedString<64U> cmd{"STA-FIRST"};

	for (std::size_t guard = 0U; guard < MAX_STA; guard++) {
		std::optional<hapd::Sta> h;
		if (b.hapd.runCommand(cmd.view(), reply) && !reply.empty()) {
			h = hapd::parseSta(reply.view());
		}
		if (!h.has_value()) {
			break;
		}
		cmd.clear();
		formatTo(cmd, "STA-NEXT {}", h->addr);
		if (h->authorized) {
			Sta *const s = getSta(h->addr, i);
			if (s != nullptr) {
				applyStaSample(*s, *h, i);
			}
		}
	}
	if (!b.hapd.isOpen()) {
		markBssDown(i);
		return;
	}
	pruneUnlisted(i, start);
}

// Drop STAs of a BSS that the listing since start did not report (missed
// events); for an MLD STA only the link on this BSS, the STA when no link
// is left.
void Daemon::pruneUnlisted(std::size_t i, Millis start) noexcept
{
	for (Sta &s : mSta) {
		if (!s.used) {
			continue;
		}
		const bool gone = s.mld ? !pruneStaLinks(s, i, start)
					: ((s.bss == i) && (s.lastPollMs < start) && (s.lastPollMs != 0U));
		if (gone) {
			onLocalDisassoc(s.addr);
			saveDevClass(s);
			s.used = false;
		}
	}
}

void Daemon::pollStas() noexcept
{
	const Millis start = os::nowMs();

	for (std::size_t i = 0U; i < mNBss; i++) {
		LocalBss &b = mBss[i];
		if (!b.up) {
			continue;
		}
		// The previous poll's dump should be done by now; twice not: fall
		// back to hostapd for this poll.
		if (b.nlAsked && (mSurvey.stationGen(b.ifindex) == b.nlGenAsked)) {
			b.nlMissed++;
		} else {
			b.nlMissed = 0;
		}
		const bool nl = mSurvey.isOpen() && (b.ifindex > 0) && !b.info.isMldLink() &&
				(start < b.nextHapdListMs) && (b.nlMissed < 2);
		if (nl) {
			b.nlGenAsked = mSurvey.stationGen(b.ifindex);
			b.nlAsked = true;
			b.nlActive = true;
			mSurvey.requestStations(b.ifindex); // processStationDumps() applies it
			continue;
		}
		if (b.nlMissed >= 2) {
			logging::warn(LOG_MODULE, "bss {}: station dumps not completing, polling hostapd", b.cfg->ifname);
			b.nlMissed = 0;
		}
		b.nlAsked = false;
		b.nlActive = false;
		listStasFromHapd(i, start);
		b.nextHapdListMs = start + STA_RESYNC_MS;
	}
	for (Sta &s : mSta) {
		if (s.used && (s.lastPollMs >= start)) {
			onStaPoll(s);
		}
	}
}

void Daemon::processStationDumps() noexcept
{
	for (std::size_t i = 0U; i < mNBss; i++) {
		LocalBss &b = mBss[i];
		const std::uint32_t gen = (b.up && (b.ifindex > 0)) ? mSurvey.stationGen(b.ifindex) : 0U;
		if ((gen == 0U) || (gen == b.nlGenSeen)) {
			continue;
		}
		b.nlGenSeen = gen;
		if (!b.nlActive) {
			continue; // this BSS is on the hostapd path now
		}
		const Millis start = os::nowMs();
		for (std::size_t k = 0U; k < mSurvey.stationCount(); k++) {
			if (mSurvey.stationIfindex(k) != b.ifindex) {
				continue;
			}
			const nl::Station &n = mSurvey.station(k);
			if (!n.authorized) {
				continue;
			}
			Sta *s = findSta(n.addr);
			if ((s == nullptr) || (s->bss != i) || !s->capsKnown || s->mld) {
				// First sight on this BSS: capabilities from hostapd, once.
				hapd::Reply reply;
				FixedString<64U> cmd;
				formatTo(cmd, "STA {}", n.addr);
				const std::optional<hapd::Sta> h = (b.hapd.runCommand(cmd.view(), reply) && !reply.empty())
									   ? hapd::parseSta(reply.view())
									   : std::optional<hapd::Sta>();
				s = (h.has_value() && h->authorized) ? getSta(h->addr, i) : nullptr;
				if (s != nullptr) {
					applyStaSample(*s, *h, i);
				}
				continue;
			}
			// The kernel's per-frame average where it has one.
			applyStaSignal(*s, (n.signalAvg != 0) ? n.signalAvg : n.signal, n.inactiveMs);
			applyStaTraffic(*s, n.rxBytes, n.txBytes, n.inactiveMs, n.connectedS, n.rxRateMbps, n.txRateMbps,
					start);
			s->lastPollMs = start;
		}
		if (!b.hapd.isOpen()) {
			markBssDown(i);
			continue;
		}
		pruneUnlisted(i, start);
		for (Sta &s : mSta) {
			if (s.used && (s.bss == i) && (s.lastPollMs >= start)) {
				onStaPoll(s);
			}
		}
	}
}

// ---- hostapd events ----

void Daemon::onHapdConnected(std::size_t bss, const Mac &addr) noexcept
{
	Sta *const s = getSta(addr, bss);

	logging::info(LOG_MODULE, "sta {} associated to {}", addr, mBss[bss].cfg->ifname);
	if (s != nullptr) {
		arcp::StaEvent e;
		s->away = false;
		forgetRemoteSta(addr);
		sendStaEvent(addr, bss, arcp::StaEventType::ASSOC, 0U);
		e.sta = addr;
		e.bssid = mBss[bss].info.bssid;
		e.event = static_cast<std::uint8_t>(arcp::StaEventType::ASSOC);
		onStaEvent(mApId, e);
	}
}

void Daemon::onHapdDisconnected(std::size_t bss, const Mac &addr) noexcept
{
	Sta *const s = findSta(addr);

	logging::info(LOG_MODULE, "sta {} disassociated from {}", addr, mBss[bss].cfg->ifname);
	// A STA moving between local BSSes may report CONNECTED first. An MLD
	// STA leaving any link of its AP MLD leaves the AP MLD.
	const bool ownLink = (s != nullptr) && s->mld && isSameApMld(s->bss, bss);
	if ((s == nullptr) || (s->bss == bss) || ownLink) {
		sendStaEvent(addr, bss, arcp::StaEventType::DISASSOC, 0U);
		onLocalDisassoc(addr);
		if (s != nullptr) {
			saveDevClass(*s);
			s->used = false;
		}
	}
}

// "<addr> <token> <rep_mode> <report hex>"
void Daemon::onHapdBeaconResp(std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view addr;
	std::string_view tok;
	std::string_view mode;
	std::string_view hex;

	if (!(t.next(addr) && t.next(tok) && t.next(mode))) {
		return;
	}
	const bool haveHex = t.next(hex);
	const std::optional<Mac> a = parseMac(addr);
	Sta *const s = a.has_value() ? findSta(*a) : nullptr;
	if (s == nullptr) {
		return;
	}
	// Non-zero report mode = late/incapable/refused (no report body).
	const std::optional<long> repMode = parseLong(mode, 16, 0, 255);
	const std::optional<rrm::BeaconReport> r = (repMode.has_value() && (*repMode == 0) && haveHex)
						      ? rrm::parseBcnRepHex(hex)
						      : std::optional<rrm::BeaconReport>();
	if (!r.has_value()) {
		logging::dbg(LOG_MODULE, "sta {} beacon report mode {}", *a, mode);
	} else {
		logging::dbg(LOG_MODULE, "sta {} sees {} ch {} rcpi {} ({} dBm)", *a, r->bssid, r->channel, r->rcpi,
			     rrm::rcpiToDbm(r->rcpi));
	}
	onBeaconReport(*s, r);
}

void Daemon::handleEvent(std::size_t bss, std::string_view ev) noexcept
{
	constexpr std::string_view CONN = "AP-STA-CONNECTED ";
	constexpr std::string_view DISC = "AP-STA-DISCONNECTED ";
	constexpr std::string_view BCN = "BEACON-RESP-RX ";
	constexpr std::string_view BTM = "BSS-TM-RESP ";

	logging::dbg(LOG_MODULE, "hapd[{}] < {}", mBss[bss].cfg->ifname, ev);
	if (startsWith(ev, CONN)) {
		const std::optional<Mac> a = parseMacPrefix(subView(ev, CONN.size()));
		if (a.has_value() && mBss[bss].up) {
			onHapdConnected(bss, *a);
		}
	} else if (startsWith(ev, DISC)) {
		const std::optional<Mac> a = parseMacPrefix(subView(ev, DISC.size()));
		if (a.has_value()) {
			onHapdDisconnected(bss, *a);
		}
	} else if (startsWith(ev, BCN)) {
		onHapdBeaconResp(subView(ev, BCN.size()));
	} else if (startsWith(ev, BTM)) {
		const std::optional<hapd::BtmResp> r = hapd::parseBtmResp(ev);
		if (r.has_value()) {
			onBtmResp(*r);
		}
	} else {
		// other hostapd events are not used
	}
}

// ---- 802.11k neighbor database (hostapd SET_NEIGHBOR) ----

void Daemon::setNeighbor(LocalBss &lb, const arcp::BssInfo &bi) noexcept
{
	FixedString<64U> nr;
	FixedString<256U> cmd;
	hapd::Reply reply;

	if (rrm::buildNrHex(bi, lb.info.mdid, nr)) {
		formatTo(cmd, "SET_NEIGHBOR {} ssid={} nr={}", bi.bssid, HexBytes{bi.ssidView()}, nr);
		if (!lb.hapd.runCommand(cmd.view(), reply) || !startsWith(reply.view(), "OK")) {
			logging::warn(LOG_MODULE, "bss {}: SET_NEIGHBOR {} failed (rrm_neighbor_report=1?)",
				      lb.cfg->ifname, bi.bssid);
		}
	}
}

void Daemon::removeNeighbor(const arcp::BssInfo &bi) noexcept
{
	FixedString<160U> cmd;
	hapd::Reply reply;

	formatTo(cmd, "REMOVE_NEIGHBOR {} ssid={}", bi.bssid, HexBytes{bi.ssidView()});
	for (std::size_t i = 0U; i < mNBss; i++) {
		if (mBss[i].up && arcp::isSameEss(mBss[i].info, bi)) {
			(void)mBss[i].hapd.runCommand(cmd.view(), reply);
		}
	}
}

void Daemon::syncNeighbors() noexcept
{
	// Local siblings (other radios of this AP). Idempotent in hostapd.
	for (std::size_t i = 0U; i < mNBss; i++) {
		for (std::size_t j = 0U; j < mNBss; j++) {
			if ((i != j) && mBss[i].up && mBss[j].up && arcp::isSameEss(mBss[i].info, mBss[j].info)) {
				setNeighbor(mBss[i], mBss[j].info);
			}
		}
	}
	for (Peer &p : mPeers) {
		if (!p.used) {
			continue;
		}
		for (RemoteBss &rb : p.bss) {
			if (rb.used && !rb.nrInstalled) {
				for (std::size_t i = 0U; i < mNBss; i++) {
					if (mBss[i].up && arcp::isSameEss(mBss[i].info, rb.info)) {
						setNeighbor(mBss[i], rb.info);
					}
				}
				rb.nrInstalled = true;
			}
		}
	}
}

} // namespace donghoa
