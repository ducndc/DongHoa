// SPDX-License-Identifier: MIT
#include "rrm.hpp"

#include "text.hpp"

namespace donghoa {
namespace rrm {

std::string_view beaconModeName(BeaconMode m) noexcept
{
	std::string_view n = "?";
	switch (m) {
	case BeaconMode::PASSIVE: n = "passive"; break;
	case BeaconMode::ACTIVE: n = "active"; break;
	case BeaconMode::TABLE: n = "table"; break;
	default: break;
	}
	return n;
}

std::optional<ChanBand> freqToChan(int freq) noexcept
{
	std::optional<ChanBand> r;
	if (freq == 2484) {
		r = ChanBand{14U, arcp::BAND_2G};
	} else if ((freq >= 2412) && (freq <= 2472)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 2407) / 5), arcp::BAND_2G};
	} else if ((freq >= 5955) && (freq <= 7115)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 5950) / 5), arcp::BAND_6G};
	} else if ((freq >= 5160) && (freq <= 5885)) {
		r = ChanBand{static_cast<std::uint8_t>((freq - 5000) / 5), arcp::BAND_5G};
	} else {
		// unknown band
	}
	return r;
}

std::uint8_t opClass20mhz(std::uint8_t band, std::uint8_t chan) noexcept
{
	std::uint8_t oc = 0U;
	if (band == arcp::BAND_2G) {
		oc = (chan == 14U) ? 82U : 81U;
	} else if (band == arcp::BAND_5G) {
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
	} else if (band == arcp::BAND_6G) {
		oc = 131U;
	} else {
		// unknown band
	}
	return oc;
}

std::uint8_t phyTypeFromCaps(std::uint16_t caps, std::uint8_t band) noexcept
{
	std::uint8_t p = (band == arcp::BAND_2G) ? PHY_ERP : PHY_OFDM;
	// An EHT BSS is also HE; advertise HE as the condensed PHY type.
	if ((caps & (arcp::CAP_HE | arcp::CAP_EHT)) != 0U) {
		p = PHY_HE;
	} else if ((caps & arcp::CAP_VHT) != 0U) {
		p = PHY_VHT;
	} else if ((caps & arcp::CAP_HT) != 0U) {
		p = PHY_HT;
	} else {
		// legacy PHY
	}
	return p;
}

std::uint32_t buildBssidInfo(std::uint16_t caps, bool secured) noexcept
{
	std::uint32_t bi = BI_REACHABLE | BI_QOS | BI_IMM_BA;
	if (secured) {
		bi |= BI_SECURITY | BI_KEY_SCOPE;
	}
	if ((caps & (arcp::CAP_RRM_NR | arcp::CAP_RRM_BCN)) != 0U) {
		bi |= BI_RRM;
	}
	if ((caps & arcp::CAP_HT) != 0U) {
		bi |= BI_HT;
	}
	if ((caps & arcp::CAP_VHT) != 0U) {
		bi |= BI_VHT;
	}
	if ((caps & arcp::CAP_HE) != 0U) {
		bi |= BI_HE;
	}
	// The Mobility Domain bit is set per receiver, see buildNrHex().
	return bi;
}

int rcpiToDbm(std::uint8_t rcpi) noexcept
{
	return (rcpi > 220U) ? -128 : ((static_cast<int>(rcpi) / 2) - 110);
}

std::uint8_t dbmToRcpi(int dbm) noexcept
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

bool buildNrHex(const arcp::BssInfo &b, std::uint16_t localMdid, FixedString<64U> &out) noexcept
{
	std::array<std::uint8_t, 13U> nr{};
	std::uint32_t bi = b.bssidInfo;

	if ((b.mdid != 0U) && (b.mdid == localMdid)) {
		bi |= BI_MOBILITY_DOMAIN;
	}
	for (std::size_t i = 0U; i < b.bssid.b.size(); i++) {
		nr[i] = b.bssid.b[i];
	}
	putLe32(spanOf(nr), 6U, bi);
	nr[10U] = b.opClass;
	nr[11U] = b.channel;
	nr[12U] = b.phyType;
	out.clear();
	return hexEncode(viewOf(nr), out);
}

bool buildBcnReqHex(const OpChanList &chans, std::size_t n, BeaconMode mode,
		       std::uint16_t duration, const Mac *bssid, ByteView ssid,
		       FixedString<256U> &out) noexcept
{
	// fixed 13, SSID 2+32, Reporting Detail 3, AP Channel Reports 3 each
	std::array<std::uint8_t, 13U + 2U + 32U + 3U + (MAX_BEACON_CHANNELS * 3U)> r{};
	std::size_t k = 0U;
	bool ok = (n >= 1U) && (n <= MAX_BEACON_CHANNELS);

	if (ok) {
		const Mac wildcard{{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU}};
		const Mac &target = (bssid != nullptr) ? *bssid : wildcard;
		const std::size_t sl = (ssid.size() > 32U) ? 32U : ssid.size();

		r[k] = chans[0U].opClass;
		k++;
		r[k] = (n == 1U) ? chans[0U].channel : 255U; // 255: AP Channel Reports
		k++;
		r[k] = 0U; // Randomization Interval (LE)
		k++;
		r[k] = 0U;
		k++;
		putLe16(spanOf(r), k, duration); // Measurement Duration (TUs)
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
				seen = seen || (chans[j].opClass == chans[i].opClass);
			}
			if (!seen) {
				r[k] = 51U;
				k++;
				const std::size_t lenAt = k;
				k++;
				r[k] = chans[i].opClass;
				k++;
				for (std::size_t j = i; j < n; j++) {
					if (chans[j].opClass == chans[i].opClass) {
						r[k] = chans[j].channel;
						k++;
					}
				}
				r[lenAt] = static_cast<std::uint8_t>(k - lenAt - 1U);
			}
		}
		out.clear();
		ok = hexEncode(viewOf(r).first(k), out);
	}
	return ok;
}

std::optional<BeaconReport> parseBcnRepHex(std::string_view hex) noexcept
{
	std::array<std::uint8_t, 512U> b{};
	std::optional<BeaconReport> r;
	const std::optional<std::size_t> n = hexDecode(hex, spanOf(b));

	// op(1) ch(1) start(8) dur(2) info(1) rcpi(1) rsni(1) bssid(6) ant(1) tsf(4)
	if (n.has_value() && (*n >= 26U)) {
		BeaconReport rep;
		rep.opClass = b[0U];
		rep.channel = b[1U];
		rep.duration = getLe16(viewOf(b), 10U);
		rep.frameInfo = b[12U];
		rep.rcpi = b[13U];
		rep.rsni = b[14U];
		for (std::size_t i = 0U; i < rep.bssid.b.size(); i++) {
			rep.bssid.b[i] = b[15U + i];
		}
		r = rep;
	}
	return r;
}

std::optional<BeaconRequest> parseBcnReqHex(std::string_view hex) noexcept
{
	std::array<std::uint8_t, 256U> b{};
	std::optional<BeaconRequest> r;
	const std::optional<std::size_t> n = hexDecode(hex, spanOf(b));

	// op(1) ch(1) rand(2) dur(2) mode(1) bssid(6), then subelements
	if (n.has_value() && (*n >= 13U)) {
		const ByteView v = viewOf(b).first(*n);
		BeaconRequest q;
		q.opClass = v[0U];
		q.channel = v[1U];
		q.randInt = getLe16(v, 2U);
		q.duration = getLe16(v, 4U);
		q.mode = v[6U];
		for (std::size_t i = 0U; i < q.bssid.b.size(); i++) {
			q.bssid.b[i] = v[7U + i];
		}
		bool ok = true;
		std::size_t k = 13U;
		while (ok && ((k + 2U) <= v.size())) {
			const std::uint8_t id = v[k];
			const std::size_t len = v[k + 1U];
			const ByteView body = v.sub(k + 2U, len);
			ok = (body.size() == len);
			if (!ok) {
				// truncated subelement: keep what was decoded
			} else if (id == 0U) {
				q.hasSsid = true;
				q.ssidLen = (len > q.ssid.size()) ? q.ssid.size() : len;
				for (std::size_t i = 0U; i < q.ssidLen; i++) {
					q.ssid[i] = body[i];
				}
			} else if ((id == 2U) && (len >= 1U)) {
				q.detail = static_cast<int>(body[0U]);
			} else if ((id == 51U) && (len >= 1U)) {
				for (std::size_t i = 1U; (i < len) && (q.nChans < q.chans.size()); i++) {
					q.chans[q.nChans] = OpChan{body[0U], body[i]};
					q.nChans++;
				}
			} else {
				// other subelements are not decoded
			}
			k += 2U + len;
		}
		r = q;
	}
	return r;
}

std::optional<NeighborReport> parseNrHex(std::string_view hex) noexcept
{
	std::array<std::uint8_t, 64U> b{};
	std::optional<NeighborReport> r;
	const std::optional<std::size_t> n = hexDecode(hex, spanOf(b));

	// bssid(6) bssid_info(4, LE) op(1) ch(1) phy(1) [subelements]
	if (n.has_value() && (*n >= 13U)) {
		NeighborReport nr;
		for (std::size_t i = 0U; i < nr.bssid.b.size(); i++) {
			nr.bssid.b[i] = b[i];
		}
		nr.bssidInfo = getLe32(viewOf(b), 6U);
		nr.opClass = b[10U];
		nr.channel = b[11U];
		nr.phyType = b[12U];
		r = nr;
	}
	return r;
}

void describeBssidInfo(std::uint32_t bi, FixedString<96U> &out) noexcept
{
	struct Bit {
		std::uint32_t mask;
		std::string_view name;
	};
	constexpr std::array<Bit, 9U> BITS{{
		{BI_SECURITY, "sec"},
		{BI_KEY_SCOPE, "key_scope"},
		{BI_QOS, "qos"},
		{BI_RRM, "rrm"},
		{BI_IMM_BA, "imm_ba"},
		{BI_MOBILITY_DOMAIN, "md"},
		{BI_HT, "ht"},
		{BI_VHT, "vht"},
		{BI_HE, "he"},
	}};
	out.clear();
	formatTo(out, "reach={}", bi & BI_REACHABLE);
	for (const Bit &x : BITS) {
		if ((bi & x.mask) != 0U) {
			formatTo(out, " {}", x.name);
		}
	}
}

std::string_view reportModeName(std::uint8_t mode) noexcept
{
	std::string_view n = "ok";
	if ((mode & 0x04U) != 0U) {
		n = "refused";
	} else if ((mode & 0x02U) != 0U) {
		n = "incapable";
	} else if ((mode & 0x01U) != 0U) {
		n = "late";
	} else {
		// report follows
	}
	return n;
}

std::string_view btmStatusName(int status) noexcept
{
	constexpr std::array<std::string_view, 9U> NAMES{
		"accept",
		"reject: unspecified",
		"reject: insufficient beacons",
		"reject: insufficient capacity",
		"reject: BSS termination undesired",
		"reject: BSS termination delay requested",
		"reject: STA candidate list provided",
		"reject: no suitable candidates",
		"reject: leaving ESS",
	};
	return ((status >= 0) && (status < static_cast<int>(NAMES.size()))) ? NAMES[static_cast<std::size_t>(status)]
									     : std::string_view("reserved");
}

std::optional<AirFrame> parseRadiotap(ByteView buf) noexcept
{
	// Radiotap fields before bit 6, in bit order: size and alignment
	constexpr std::array<std::size_t, 6U> SIZE{8U, 1U, 1U, 4U, 2U, 1U};
	constexpr std::array<std::size_t, 6U> ALIGN{8U, 1U, 1U, 2U, 1U, 1U};
	std::optional<AirFrame> r;
	AirFrame f;
	bool ok = (buf.size() >= 8U) && (buf[0U] == 0U);
	bool haveSignal = false;
	std::size_t rtLen = 0U;
	std::uint32_t present = 0U;
	std::size_t off = 8U;

	if (ok) {
		rtLen = getLe16(buf, 2U);
		present = static_cast<std::uint32_t>(getLe16(buf, 4U)) |
			  (static_cast<std::uint32_t>(getLe16(buf, 6U)) << 16U);
		// Extended present words come before the fields.
		std::uint32_t p = present;
		while (ok && ((p & 0x80000000U) != 0U)) {
			ok = ((off + 4U) <= rtLen) && ((off + 4U) <= buf.size());
			if (ok) {
				p = static_cast<std::uint32_t>(buf[off + 3U]) << 24U;
				off += 4U;
			}
		}
	}
	for (std::size_t bit = 0U; ok && (bit < SIZE.size()); bit++) {
		if ((present & (1U << bit)) != 0U) {
			off = (off + ALIGN[bit] - 1U) & ~(ALIGN[bit] - 1U);
			ok = ((off + SIZE[bit]) <= rtLen) && ((off + SIZE[bit]) <= buf.size());
			if (ok) {
				if ((bit == 1U) && ((buf[off] & 0x40U) != 0U)) {
					ok = false; // Flags: bad FCS
				} else if (bit == 3U) {
					f.freq = static_cast<int>(getLe16(buf, off));
				} else if (bit == 5U) {
					f.signal = static_cast<int>(static_cast<std::int8_t>(buf[off]));
					haveSignal = true;
				} else {
					// field not used
				}
				off += SIZE[bit];
			}
		}
	}
	if (ok && haveSignal && ((rtLen + 24U) <= buf.size())) {
		const std::uint8_t fc0 = buf[rtLen];
		const std::uint8_t fc1 = buf[rtLen + 1U];

		if (fc0 == 0x40U) {
			f.probe = true; // probe request
			ok = true;
		} else {
			// data (incl. QoS null) with ToDS and not FromDS
			ok = ((fc0 & 0x0cU) == 0x08U) && ((fc1 & 0x03U) == 0x01U);
		}
		if (ok) {
			for (std::size_t i = 0U; i < f.ta.b.size(); i++) {
				f.ta.b[i] = buf[rtLen + 10U + i];
			}
			r = f;
		}
	}
	return r;
}

bool hasBtmCapab(ByteView ext) noexcept
{
	return (ext.size() > 2U) && ((ext[2U] & 0x08U) != 0U);
}

std::uint8_t bandBit(std::uint8_t band) noexcept
{
	std::uint8_t b = 0U;
	if (band == arcp::BAND_2G) {
		b = BANDS_2G;
	} else if (band == arcp::BAND_5G) {
		b = BANDS_5G;
	} else if (band == arcp::BAND_6G) {
		b = BANDS_6G;
	} else {
		// unknown band
	}
	return b;
}

std::uint8_t opClassBandBit(std::uint8_t opClass) noexcept
{
	std::uint8_t b = 0U;
	if ((opClass >= 81U) && (opClass <= 84U)) {
		b = BANDS_2G;
	} else if ((opClass >= 115U) && (opClass <= 130U)) {
		b = BANDS_5G;
	} else if ((opClass >= 131U) && (opClass <= 137U)) {
		b = BANDS_6G;
	} else {
		// country-specific, 60 GHz or unknown class
	}
	return b;
}

std::uint8_t bandsFromOpClasses(ByteView body) noexcept
{
	std::uint8_t bands = 0U;
	if (!body.empty()) {
		bands = opClassBandBit(body[0U]); // Current Operating Class
		bool end = false;
		for (std::size_t i = 1U; (i < body.size()) && !end; i++) {
			const std::uint8_t oc = body[i];
			if ((oc == 0U) || (oc == 130U)) {
				end = true;
			} else {
				bands = static_cast<std::uint8_t>(bands | opClassBandBit(oc));
			}
		}
	}
	return bands;
}

namespace {

// Suite type of an IEEE 802.11 (00-0f-ac) AKM selector as printed by
// hostapd; empty for another OUI or a malformed selector.
std::optional<long> ieeeAkmSuite(std::string_view akm) noexcept
{
	constexpr std::string_view OUI = "00-0f-ac-";
	std::optional<long> s;

	if (akm.size() > OUI.size()) {
		bool oui = true;
		for (std::size_t i = 0U; i < OUI.size(); i++) {
			const char c = akm[i];
			const char lc = ((c >= 'A') && (c <= 'F')) ? static_cast<char>((c - 'A') + 'a') : c;
			oui = oui && (lc == OUI[i]);
		}
		if (oui) {
			s = parseLong(subView(akm, OUI.size()), 10, 0, 255);
		}
	}
	return s;
}

template <std::size_t N>
bool isAkmIn(std::string_view akm, const std::array<long, N> &suites) noexcept
{
	const std::optional<long> s = ieeeAkmSuite(akm);
	bool in = false;
	for (const long x : suites) {
		in = in || (s.has_value() && (*s == x));
	}
	return in;
}

} // namespace

bool isFtAkm(std::string_view akm) noexcept
{
	// 00-0F-AC: 3 FT-802.1X, 4 FT-PSK, 9 FT-SAE, 13 FT-802.1X-SHA384,
	// 19 FT-PSK-SHA384, 25 FT-SAE-EXT-KEY
	constexpr std::array<long, 6U> FT{3, 4, 9, 13, 19, 25};
	return isAkmIn(akm, FT);
}

bool isAkmForbidden6g(std::string_view akm) noexcept
{
	// 00-0F-AC: 2 PSK, 4 FT-PSK, 6 PSK-SHA256: WPA2-Personal. hostapd
	// refuses these on a 6 GHz BSS (hostapd_config_check_bss_6g).
	constexpr std::array<long, 3U> PSK{2, 4, 6};
	return isAkmIn(akm, PSK);
}

} // namespace rrm
} // namespace donghoa
