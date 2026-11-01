// SPDX-License-Identifier: MIT
#include "rrm.hpp"

#include "text.hpp"

namespace donghoa {
namespace rrm {

std::string_view beacon_mode_name(BeaconMode m) noexcept
{
	std::string_view n = "?";
	switch (m) {
	case BeaconMode::passive: n = "passive"; break;
	case BeaconMode::active: n = "active"; break;
	case BeaconMode::table: n = "table"; break;
	default: break;
	}
	return n;
}

std::optional<ChanBand> freq_to_chan(int freq) noexcept
{
	std::optional<ChanBand> r;
	if (freq == 2484) {
		r = ChanBand{14U, arcp::kBand2g};
	} else if ((freq >= 2412) && (freq <= 2472)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 2407) / 5), arcp::kBand2g};
	} else if ((freq >= 5955) && (freq <= 7115)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 5950) / 5), arcp::kBand6g};
	} else if ((freq >= 5160) && (freq <= 5885)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 5000) / 5), arcp::kBand5g};
	} else {
		// unknown band
	}
	return r;
}

std::uint8_t op_class_20mhz(std::uint8_t band, std::uint8_t chan) noexcept
{
	std::uint8_t oc = 0U;
	if (band == arcp::kBand2g) {
		oc = (chan == 14U) ? 82U : 81U;
	} else if (band == arcp::kBand5g) {
		if ((chan >= 36U) && (chan <= 48U)) {
			oc = 115U;
		} else if ((chan >= 52U) && (chan <= 64U)) {
			oc = 118U;
		} else if ((chan >= 100U) && (chan <= 144U)) {
			oc = 121U;
		} else if ((chan >= 149U) && (chan <= 161U)) {
			oc = 124U;
		} else if ((chan >= 165U) && (chan <= 177U)) {
			oc = 125U;
		} else {
			// unknown 5 GHz channel
		}
	} else if (band == arcp::kBand6g) {
		oc = 131U;
	} else {
		// unknown band
	}
	return oc;
}

std::uint8_t phy_type_from_caps(std::uint16_t caps, std::uint8_t band) noexcept
{
	std::uint8_t p = (band == arcp::kBand2g) ? kPhyErp : kPhyOfdm;
	// An EHT BSS is also HE; advertise HE as the condensed PHY type.
	if ((caps & (arcp::kCapHe | arcp::kCapEht)) != 0U) {
		p = kPhyHe;
	} else if ((caps & arcp::kCapVht) != 0U) {
		p = kPhyVht;
	} else if ((caps & arcp::kCapHt) != 0U) {
		p = kPhyHt;
	} else {
		// legacy PHY
	}
	return p;
}

std::uint32_t bssid_info_build(std::uint16_t caps, bool secured) noexcept
{
	std::uint32_t bi = kBiReachable | kBiQos | kBiImmBa;
	if (secured) {
		bi |= kBiSecurity | kBiKeyScope;
	}
	if ((caps & (arcp::kCapRrmNr | arcp::kCapRrmBcn)) != 0U) {
		bi |= kBiRrm;
	}
	if ((caps & arcp::kCapHt) != 0U) {
		bi |= kBiHt;
	}
	if ((caps & arcp::kCapVht) != 0U) {
		bi |= kBiVht;
	}
	if ((caps & arcp::kCapHe) != 0U) {
		bi |= kBiHe;
	}
	// The Mobility Domain bit is set per receiver, see nr_build_hex().
	return bi;
}

int rcpi_to_dbm(std::uint8_t rcpi) noexcept
{
	return (rcpi > 220U) ? -128 : ((static_cast<int>(rcpi) / 2) - 110);
}

std::uint8_t dbm_to_rcpi(int dbm) noexcept
{
	std::uint8_t r = 220U;
	if (dbm <= -110) {
		r = 0U;
	} else if (dbm < 0) {
		r = static_cast<std::uint8_t>(2 * (dbm + 110));
	} else {
		// 0 dBm or more: maximum
	}
	return r;
}

bool nr_build_hex(const arcp::BssInfo &b, std::uint16_t local_mdid, FixedString<64U> &out) noexcept
{
	std::array<std::uint8_t, 13U> nr{};
	std::uint32_t bi = b.bssid_info;

	if ((b.mdid != 0U) && (b.mdid == local_mdid)) {
		bi |= kBiMobilityDomain;
	}
	for (std::size_t i = 0U; i < b.bssid.b.size(); i++) {
		nr[i] = b.bssid.b[i];
	}
	put_le32(span_of(nr), 6U, bi);
	nr[10U] = b.op_class;
	nr[11U] = b.channel;
	nr[12U] = b.phy_type;
	out.clear();
	return hex_encode(view_of(nr), out);
}

bool bcn_req_build_hex(const OpChanList &chans, std::size_t n, BeaconMode mode,
		       std::uint16_t duration, const Mac *bssid, ByteView ssid,
		       FixedString<256U> &out) noexcept
{
	// fixed 13, SSID 2+32, Reporting Detail 3, AP Channel Reports 3 each
	std::array<std::uint8_t, 13U + 2U + 32U + 3U + (kMaxBeaconChannels * 3U)> r{};
	std::size_t k = 0U;
	bool ok = (n >= 1U) && (n <= kMaxBeaconChannels);

	if (ok) {
		const Mac wildcard{{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU}};
		const Mac &target = (bssid != nullptr) ? *bssid : wildcard;
		const std::size_t sl = (ssid.size() > 32U) ? 32U : ssid.size();

		r[k] = chans[0U].op_class;
		k++;
		r[k] = (n == 1U) ? chans[0U].channel : 255U; // 255: AP Channel Reports
		k++;
		r[k] = 0U; // Randomization Interval (LE)
		k++;
		r[k] = 0U;
		k++;
		put_le16(span_of(r), k, duration); // Measurement Duration (TUs)
		k += 2U;
		r[k] = static_cast<std::uint8_t>(mode);
		k++;
		for (const std::uint8_t x : target.b) {
			r[k] = x;
			k++;
		}
		if (sl > 0U) {
			r[k] = 0U; // SSID subelement
			k++;
			r[k] = static_cast<std::uint8_t>(sl);
			k++;
			for (std::size_t i = 0U; i < sl; i++) {
				r[k] = ssid[i];
				k++;
			}
		}
		r[k] = 2U; // Reporting Detail subelement: no fixed fields/elements
		k++;
		r[k] = 1U;
		k++;
		r[k] = 0U;
		k++;
		// AP Channel Report subelements (ID 51), one per operating class
		for (std::size_t i = 0U; (n > 1U) && (i < n); i++) {
			bool seen = false;
			for (std::size_t j = 0U; j < i; j++) {
				seen = seen || (chans[j].op_class == chans[i].op_class);
			}
			if (!seen) {
				r[k] = 51U;
				k++;
				const std::size_t len_at = k;
				k++;
				r[k] = chans[i].op_class;
				k++;
				for (std::size_t j = i; j < n; j++) {
					if (chans[j].op_class == chans[i].op_class) {
						r[k] = chans[j].channel;
						k++;
					}
				}
				r[len_at] = static_cast<std::uint8_t>(k - len_at - 1U);
			}
		}
		out.clear();
		ok = hex_encode(view_of(r).first(k), out);
	}
	return ok;
}

std::optional<BeaconReport> bcn_rep_parse_hex(std::string_view hex) noexcept
{
	std::array<std::uint8_t, 512U> b{};
	std::optional<BeaconReport> r;
	const std::optional<std::size_t> n = hex_decode(hex, span_of(b));

	// op(1) ch(1) start(8) dur(2) info(1) rcpi(1) rsni(1) bssid(6) ant(1) tsf(4)
	if (n.has_value() && (*n >= 26U)) {
		BeaconReport rep;
		rep.op_class = b[0U];
		rep.channel = b[1U];
		rep.duration = get_le16(view_of(b), 10U);
		rep.frame_info = b[12U];
		rep.rcpi = b[13U];
		rep.rsni = b[14U];
		for (std::size_t i = 0U; i < rep.bssid.b.size(); i++) {
			rep.bssid.b[i] = b[15U + i];
		}
		r = rep;
	}
	return r;
}

std::optional<AirFrame> radiotap_parse(ByteView buf) noexcept
{
	// Radiotap fields before bit 6, in bit order: size and alignment
	constexpr std::array<std::size_t, 6U> kSize{8U, 1U, 1U, 4U, 2U, 1U};
	constexpr std::array<std::size_t, 6U> kAlign{8U, 1U, 1U, 2U, 1U, 1U};
	std::optional<AirFrame> r;
	AirFrame f;
	bool ok = (buf.size() >= 8U) && (buf[0U] == 0U);
	bool have_signal = false;
	std::size_t rt_len = 0U;
	std::uint32_t present = 0U;
	std::size_t off = 8U;

	if (ok) {
		rt_len = get_le16(buf, 2U);
		present = static_cast<std::uint32_t>(get_le16(buf, 4U)) |
			  (static_cast<std::uint32_t>(get_le16(buf, 6U)) << 16U);
		// Extended present words come before the fields.
		std::uint32_t p = present;
		while (ok && ((p & 0x80000000U) != 0U)) {
			ok = ((off + 4U) <= rt_len) && ((off + 4U) <= buf.size());
			if (ok) {
				p = static_cast<std::uint32_t>(buf[off + 3U]) << 24U;
				off += 4U;
			}
		}
	}
	for (std::size_t bit = 0U; ok && (bit < kSize.size()); bit++) {
		if ((present & (1U << bit)) != 0U) {
			off = (off + kAlign[bit] - 1U) & ~(kAlign[bit] - 1U);
			ok = ((off + kSize[bit]) <= rt_len) && ((off + kSize[bit]) <= buf.size());
			if (ok) {
				if ((bit == 1U) && ((buf[off] & 0x40U) != 0U)) {
					ok = false; // Flags: bad FCS
				} else if (bit == 3U) {
					f.freq = static_cast<int>(get_le16(buf, off));
				} else if (bit == 5U) {
					f.signal = static_cast<int>(static_cast<std::int8_t>(buf[off]));
					have_signal = true;
				} else {
					// field not used
				}
				off += kSize[bit];
			}
		}
	}
	if (ok && have_signal && ((rt_len + 24U) <= buf.size())) {
		const std::uint8_t fc0 = buf[rt_len];
		const std::uint8_t fc1 = buf[rt_len + 1U];

		if (fc0 == 0x40U) {
			f.probe = true; // probe request
			ok = true;
		} else {
			// data (incl. QoS null) with ToDS and not FromDS
			ok = ((fc0 & 0x0cU) == 0x08U) && ((fc1 & 0x03U) == 0x01U);
		}
		if (ok) {
			for (std::size_t i = 0U; i < f.ta.b.size(); i++) {
				f.ta.b[i] = buf[rt_len + 10U + i];
			}
			r = f;
		}
	}
	return r;
}

bool ext_capab_has_btm(ByteView ext) noexcept
{
	return (ext.size() > 2U) && ((ext[2U] & 0x08U) != 0U);
}

bool akm_is_ft(std::string_view akm) noexcept
{
	// 00-0F-AC: 3 FT-802.1X, 4 FT-PSK, 9 FT-SAE, 13 FT-802.1X-SHA384,
	// 19 FT-PSK-SHA384, 25 FT-SAE-EXT-KEY
	constexpr std::array<long, 6U> kFt{3, 4, 9, 13, 19, 25};
	constexpr std::string_view kOui = "00-0f-ac-";
	bool ft = false;

	if (akm.size() > kOui.size()) {
		bool oui = true;
		for (std::size_t i = 0U; i < kOui.size(); i++) {
			const char c = akm[i];
			const char lc = ((c >= 'A') && (c <= 'F')) ? static_cast<char>((c - 'A') + 'a') : c;
			oui = oui && (lc == kOui[i]);
		}
		const std::optional<long> s =
			oui ? parse_long(sub_view(akm, kOui.size()), 10, 0, 255) : std::optional<long>();
		for (const long x : kFt) {
			ft = ft || (s.has_value() && (*s == x));
		}
	}
	return ft;
}

} // namespace rrm
} // namespace donghoa
