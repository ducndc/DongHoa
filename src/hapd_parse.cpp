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
	format_to(k, "{}[{}]", name, i);
	return k;
}

bool flag_set(std::string_view buf, std::string_view key) noexcept
{
	const std::optional<long> n = kv_get_int(buf, key);
	return n.has_value() && (*n != 0);
}

} // namespace

std::optional<Status> parse_status(std::string_view buf, std::string_view ifname) noexcept
{
	std::optional<Status> r;
	Status st;
	const std::optional<long> freq = kv_get_int(buf, "freq");
	std::optional<rrm::ChanBand> cb;

	if (freq.has_value()) {
		st.freq = static_cast<int>(*freq);
		cb = rrm::freq_to_chan(st.freq);
	}
	if (cb.has_value()) {
		std::size_t idx = 0U;
		bool found = false;

		st.channel = cb->channel;
		st.band = cb->band;
		for (std::size_t i = 0U; (i < 16U) && !found; i++) {
			const std::optional<std::string_view> v = kv_get(buf, indexed("bss", i).view());
			if (!v.has_value()) {
				break;
			}
			if (*v == ifname) {
				idx = i;
				found = true;
			}
		}
		const std::optional<std::string_view> bssid = kv_get(buf, indexed("bssid", idx).view());
		const std::optional<Mac> mac = bssid.has_value() ? parse_mac(*bssid) : std::optional<Mac>();
		if (mac.has_value()) {
			st.bssid = *mac;
			const std::optional<std::string_view> ssid = kv_get(buf, indexed("ssid", idx).view());
			if (ssid.has_value()) {
				const std::size_t n = (ssid->size() > 32U) ? 32U : ssid->size();
				for (std::size_t i = 0U; i < n; i++) {
					st.ssid[i] = static_cast<std::uint8_t>((*ssid)[i]);
				}
				st.ssid_len = static_cast<std::uint8_t>(n);
			}
			const std::optional<long> nsta = kv_get_int(buf, indexed("num_sta", idx).view());
			if (nsta.has_value()) {
				st.num_sta = static_cast<int>(*nsta);
			}
			const std::optional<long> txp = kv_get_int(buf, "max_txpower");
			if (txp.has_value()) {
				st.max_txpower = static_cast<int>(*txp);
			}
			// Not printed by every hostapd build; the nl80211 survey is preferred.
			const std::optional<long> cu = kv_get_int(buf, "chan_util_avg");
			if (cu.has_value()) {
				st.chan_util = static_cast<int>(*cu);
			}
			if (flag_set(buf, "ieee80211n")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::kCapHt);
			}
			if (flag_set(buf, "ieee80211ac")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::kCapVht);
			}
			if (flag_set(buf, "ieee80211ax")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::kCapHe);
			}
			if (flag_set(buf, "ieee80211be")) {
				st.caps = static_cast<std::uint16_t>(st.caps | arcp::kCapEht);
			}
			st.bw = arcp::kBw20;
			if (flag_set(buf, "secondary_channel")) {
				st.bw = arcp::kBw40;
			}
			// CONF_OPER_CHWIDTH: 1 = 80, 2 = 160, 3 = 80+80
			std::optional<long> cw = kv_get_int(buf, "he_oper_chwidth");
			if (!(cw.has_value() && (*cw != 0))) {
				cw = kv_get_int(buf, "vht_oper_chwidth");
			}
			if (cw.has_value() && (*cw != 0)) {
				st.bw = (*cw == 1) ? arcp::kBw80 : arcp::kBw160;
			}
			r = st;
		}
	}
	return r;
}

std::optional<Sta> parse_sta(std::string_view buf) noexcept
{
	std::optional<Sta> r;
	const std::size_t eol = buf.find('\n');
	const std::string_view first = (eol == std::string_view::npos) ? buf : sub_view(buf, 0U, eol);
	const std::optional<Mac> addr = ((first.size() > 0U) && (first.size() < 32U))
						? parse_mac(first)
						: std::optional<Mac>();

	if (addr.has_value()) {
		Sta s;
		s.addr = *addr;
		const std::optional<std::string_view> flags = kv_get(buf, "flags");
		if (flags.has_value()) {
			s.authorized = flags->find("[AUTHORIZED]") != std::string_view::npos;
		}
		const std::optional<long> sig = kv_get_int(buf, "signal");
		if (sig.has_value()) {
			s.signal = static_cast<int>(*sig);
		}
		const std::optional<std::string_view> rxb = kv_get(buf, "rx_bytes");
		const std::optional<std::uint64_t> rx = rxb.has_value() ? parse_u64(*rxb)
									 : std::optional<std::uint64_t>();
		if (rx.has_value()) {
			s.rx_bytes = *rx;
		}
		const std::optional<std::string_view> txb = kv_get(buf, "tx_bytes");
		const std::optional<std::uint64_t> tx = txb.has_value() ? parse_u64(*txb)
									 : std::optional<std::uint64_t>();
		if (tx.has_value()) {
			s.tx_bytes = *tx;
		}
		const std::optional<long> inact = kv_get_int(buf, "inactive_msec");
		if (inact.has_value()) {
			s.inactive_ms = static_cast<std::uint32_t>(*inact);
		}
		const std::optional<long> conn = kv_get_int(buf, "connected_time");
		if (conn.has_value()) {
			s.connected_s = static_cast<std::uint32_t>(*conn);
		}
		// *_rate_info is in units of 100 kbps, followed by MCS info
		const std::optional<long> rxr = kv_get_int(buf, "rx_rate_info");
		if (rxr.has_value()) {
			s.rx_rate_mbps = static_cast<std::uint16_t>(*rxr / 10);
		}
		const std::optional<long> txr = kv_get_int(buf, "tx_rate_info");
		if (txr.has_value()) {
			s.tx_rate_mbps = static_cast<std::uint16_t>(*txr / 10);
		}
		const std::optional<std::string_view> ext = kv_get(buf, "ext_capab");
		if (ext.has_value()) {
			std::array<std::uint8_t, 64U> e{};
			const std::optional<std::size_t> n = hex_decode(*ext, span_of(e));
			if (n.has_value()) {
				s.btm_known = true;
				s.btm = rrm::ext_capab_has_btm(view_of(e).first(*n));
			}
		}
		const std::optional<std::string_view> akm = kv_get(buf, "AKMSuiteSelector");
		if (akm.has_value()) {
			s.ft_known = true;
			s.ft = rrm::akm_is_ft(*akm);
		}
		r = s;
	}
	return r;
}

std::optional<BtmResp> parse_btm_resp(std::string_view ev) noexcept
{
	constexpr std::string_view kPrefix = "BSS-TM-RESP ";
	std::optional<BtmResp> r;

	if (starts_with(ev, kPrefix)) {
		const std::optional<Mac> addr = parse_mac_prefix(sub_view(ev, kPrefix.size()));
		const std::size_t sc = ev.find("status_code=");
		const std::optional<long> status = (addr.has_value() && (sc != std::string_view::npos))
							   ? parse_long_tok(sub_view(ev, sc + 12U), 10, 0, 255)
							   : std::optional<long>();
		if (status.has_value()) {
			BtmResp b;
			b.addr = *addr;
			b.status = static_cast<int>(*status);
			const std::size_t tb = ev.find("target_bssid=");
			if (tb != std::string_view::npos) {
				const std::optional<Mac> t = parse_mac_prefix(sub_view(ev, tb + 13U));
				if (t.has_value()) {
					b.target = *t;
					b.has_target = true;
				}
			}
			r = b;
		}
	}
	return r;
}

} // namespace hapd
} // namespace donghoa
