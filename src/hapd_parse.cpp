// SPDX-License-Identifier: MIT
#include "hapd_parse.hpp"

#include "proto.hpp"
#include "rrm.hpp"
#include "text.hpp"

namespace donghoa {
namespace hapd {

namespace {

// "<name>[<i>]"
FixedString<32U> indexed(std::string_view name, std::size_t i) noexcept
{
	FixedString<32U> k;
	formatTo(k, "{}[{}]", name, i);
	return k;
}

bool flagSet(std::string_view buf, std::string_view key) noexcept
{
	const std::optional<long> n = getKvInt(buf, key);
	return n.has_value() && (*n != 0);
}

} // namespace

std::string_view netdevName(std::string_view ctrlName) noexcept
{
	constexpr std::string_view LINK = "_link";
	const std::size_t at = ctrlName.rfind(LINK);
	std::string_view r = ctrlName;
	if ((at != std::string_view::npos) && (at > 0U)) {
		const std::string_view id = subView(ctrlName, at + LINK.size());
		if (parseLong(id, 10, 0, 14).has_value()) {
			r = subView(ctrlName, 0U, at);
		}
	}
	return r;
}

std::optional<int> ctrlLinkId(std::string_view ctrlName) noexcept
{
	constexpr std::string_view LINK = "_link";
	std::optional<int> r;
	const std::string_view base = netdevName(ctrlName);
	if (base.size() < ctrlName.size()) {
		const std::optional<long> id = parseLong(subView(ctrlName, base.size() + LINK.size()), 10, 0,
							 14);
		if (id.has_value()) {
			r = static_cast<int>(*id);
		}
	}
	return r;
}

std::optional<Status> parseStatus(std::string_view buf, std::string_view ifname) noexcept
{
	std::optional<Status> r;
	Status st;
	const std::optional<long> freq = getKvInt(buf, "freq");
	std::optional<rrm::ChanBand> cb;

	if (freq.has_value()) {
		st.freq = static_cast<int>(*freq);
		cb = rrm::freqToChan(st.freq);
	}
	if (cb.has_value()) {
		std::size_t idx = 0U;
		bool found = false;

		st.channel = cb->channel;
		st.band = cb->band;
		const std::string_view base = netdevName(ifname);
		const std::optional<int> link = ctrlLinkId(ifname);
		for (std::size_t i = 0U; (i < 16U) && !found; i++) {
			const std::optional<std::string_view> v = getKv(buf, indexed("bss", i).view());
			if (!v.has_value()) {
				break;
			}
			if (*v == ifname) {
				idx = i;
				found = true;
			} else if (link.has_value() && (*v == base)) {
				// AP MLD link: several links share the netdev name
				const std::optional<long> li = getKvInt(buf, indexed("mld_link_id",
										     i).view());
				if (!li.has_value() || (*li == *link)) {
					idx = i;
					found = true;
				}
			} else {
				// another BSS
			}
		}
		const std::optional<std::string_view> bssid = getKv(buf, indexed("bssid", idx).view());
		const std::optional<Mac> mac = bssid.has_value() ? parseMac(*bssid) : std::optional<Mac>();
		if (mac.has_value()) {
			st.bssid = *mac;
			const std::optional<std::string_view> ssid = getKv(buf, indexed("ssid", idx).view());
			if (ssid.has_value()) {
				const std::size_t n = (ssid->size() > 32U) ? 32U : ssid->size();
				for (std::size_t i = 0U; i < n; i++) {
					st.ssid[i] = static_cast<std::uint8_t>((*ssid)[i]);
				}
				st.ssidLen = static_cast<std::uint8_t>(n);
			}
			const std::optional<std::string_view> mld = getKv(buf, indexed("mld_addr",
										       idx).view());
			const std::optional<Mac> mldMac = mld.has_value() ? parseMac(*mld) :
							  std::optional<Mac>();
			const std::optional<long> mldLink = getKvInt(buf, indexed("mld_link_id", idx).view());
			if (mldMac.has_value() && mldLink.has_value() && (*mldLink >= 0) &&
			    (*mldLink <= 14)) {
				st.mldAddr = *mldMac;
				st.linkId = static_cast<int>(*mldLink);
			}
			const std::optional<long> nsta = getKvInt(buf, indexed("num_sta", idx).view());
			if (nsta.has_value()) {
				st.numSta = static_cast<int>(*nsta);
			}
			const std::optional<long> txp = getKvInt(buf, "max_txpower");
			if (txp.has_value()) {
				st.maxTxpower = static_cast<int>(*txp);
			}
			// Not printed by every hostapd build; the nl80211 survey is preferred.
			const std::optional<long> cu = getKvInt(buf, "chan_util_avg");
			if (cu.has_value()) {
				st.chanUtil = static_cast<int>(*cu);
			}
			if (flagSet(buf, "ieee80211n")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::CAP_HT);
			}
			if (flagSet(buf, "ieee80211ac")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::CAP_VHT);
			}
			if (flagSet(buf, "ieee80211ax")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::CAP_HE);
			}
			if (flagSet(buf, "ieee80211be")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::CAP_EHT);
			}
			st.bw = arcp::BW20;
			if (flagSet(buf, "secondary_channel")) {
				st.bw = arcp::BW40;
			}
			// CONF_OPER_CHWIDTH: 1 = 80, 2 = 160, 3 = 80+80
			std::optional<long> cw = getKvInt(buf, "he_oper_chwidth");
			if (!(cw.has_value() && (*cw != 0))) {
				cw = getKvInt(buf, "vht_oper_chwidth");
			}
			if (cw.has_value() && (*cw != 0)) {
				st.bw = (*cw == 1) ? arcp::BW80 : arcp::BW160;
			}
			r = st;
		}
	}
	return r;
}

std::optional<Sta> parseSta(std::string_view buf) noexcept
{
	std::optional<Sta> r;
	const std::size_t eol = buf.find('\n');
	const std::string_view first = (eol == std::string_view::npos) ? buf : subView(buf, 0U, eol);
	const std::optional<Mac> addr = ((first.size() > 0U) && (first.size() < 32U))
						? parseMac(first)
						: std::optional<Mac>();

	if (addr.has_value()) {
		Sta s;
		s.addr = *addr;
		const std::optional<std::string_view> flags = getKv(buf, "flags");
		if (flags.has_value()) {
			s.authorized = flags->find("[AUTHORIZED]") != std::string_view::npos;
			if (flags->find("[VHT]") != std::string_view::npos) {
				s.phyCaps = static_cast<std::uint8_t>(s.phyCaps | arcp::CAP_VHT);
			}
			if (flags->find("[HE]") != std::string_view::npos) {
				s.phyCaps = static_cast<std::uint8_t>(s.phyCaps | arcp::CAP_HE);
			}
			if (flags->find("[EHT]") != std::string_view::npos) {
				s.phyCaps = static_cast<std::uint8_t>(s.phyCaps | arcp::CAP_EHT);
			}
		}
		const std::optional<long> sig = getKvInt(buf, "signal");
		if (sig.has_value()) {
			s.signal = static_cast<int>(*sig);
		}
		const std::optional<std::string_view> rxb = getKv(buf, "rx_bytes");
		const std::optional<std::uint64_t> rx = rxb.has_value() ? parseU64(*rxb)
									 : std::optional<std::uint64_t>();
		if (rx.has_value()) {
			s.rxBytes = *rx;
		}
		const std::optional<std::string_view> txb = getKv(buf, "tx_bytes");
		const std::optional<std::uint64_t> tx = txb.has_value() ? parseU64(*txb)
									 : std::optional<std::uint64_t>();
		if (tx.has_value()) {
			s.txBytes = *tx;
		}
		const std::optional<long> inact = getKvInt(buf, "inactive_msec");
		if (inact.has_value()) {
			s.inactiveMs = static_cast<std::uint32_t>(*inact);
		}
		const std::optional<long> conn = getKvInt(buf, "connected_time");
		if (conn.has_value()) {
			s.connectedS = static_cast<std::uint32_t>(*conn);
		}
		// *_rate_info is in units of 100 kbps, followed by MCS info
		const std::optional<long> rxr = getKvInt(buf, "rx_rate_info");
		if (rxr.has_value()) {
			s.rxRateMbps = static_cast<std::uint16_t>(*rxr / 10);
		}
		const std::optional<long> txr = getKvInt(buf, "tx_rate_info");
		if (txr.has_value()) {
			s.txRateMbps = static_cast<std::uint16_t>(*txr / 10);
		}
		const std::optional<std::string_view> ext = getKv(buf, "ext_capab");
		if (ext.has_value()) {
			std::array<std::uint8_t, 64U> e{};
			const std::optional<std::size_t> n = hexDecode(*ext, spanOf(e));
			if (n.has_value()) {
				s.btmKnown = true;
				s.btm = rrm::hasBtmCapab(viewOf(e).first(*n));
			}
		}
		const std::optional<std::string_view> soc = getKv(buf, "supp_op_classes");
		if (soc.has_value()) {
			std::array<std::uint8_t, 255U> oc{};
			const std::optional<std::size_t> n = hexDecode(*soc, spanOf(oc));
			if (n.has_value()) {
				s.bands = rrm::bandsFromOpClasses(viewOf(oc).first(*n));
			}
		}
		const std::optional<std::string_view> akm = getKv(buf, "AKMSuiteSelector");
		if (akm.has_value()) {
			s.ftKnown = true;
			s.ft = rrm::isFtAkm(*akm);
			s.akmNo6g = rrm::isAkmForbidden6g(*akm);
		}
		for (std::size_t i = 0U; i < 15U; i++) {
			const std::optional<std::string_view> pa = getKv(buf, indexed("peer_addr", i).view());
			if (pa.has_value() && parseMac(*pa).has_value()) {
				s.mld = true;
				s.linkMask = static_cast<std::uint16_t>(s.linkMask | (1U << i));
			}
		}
		const std::optional<long> msl = getKvInt(buf, "max_simul_links");
		if (msl.has_value()) {
			s.maxSimulLinks = static_cast<int>(*msl);
		}
		r = s;
	}
	return r;
}

std::optional<BtmResp> parseBtmResp(std::string_view ev) noexcept
{
	constexpr std::string_view PREFIX = "BSS-TM-RESP ";
	std::optional<BtmResp> r;

	if (startsWith(ev, PREFIX)) {
		const std::optional<Mac> addr = parseMacPrefix(subView(ev, PREFIX.size()));
		const std::size_t sc = ev.find("status_code=");
		const std::optional<long> status = (addr.has_value() && (sc != std::string_view::npos))
							   ? parseLongTok(subView(ev, sc + 12U), 10, 0, 255)
							   : std::optional<long>();
		if (status.has_value()) {
			BtmResp b;
			b.addr = *addr;
			b.status = static_cast<int>(*status);
			const std::size_t tb = ev.find("target_bssid=");
			if (tb != std::string_view::npos) {
				const std::optional<Mac> t = parseMacPrefix(subView(ev, tb + 13U));
				if (t.has_value()) {
					b.target = *t;
					b.hasTarget = true;
				}
			}
			r = b;
		}
	}
	return r;
}

} // namespace hapd
} // namespace donghoa
