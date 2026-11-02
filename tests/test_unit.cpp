// SPDX-License-Identifier: MIT
// Unit tests for the pure modules. Test code is exempt from the no-macro
// rule (docs/CODING_CONVENTION.md section 2): CHECK reports file and line.
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string_view>

#include "config.hpp"
#include "hapd_parse.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "proto.hpp"
#include "rrm.hpp"
#include "sha256.hpp"
#include "text.hpp"

using namespace donghoa;

namespace {

int sFails = 0;
int sChecks = 0;

void check(bool ok, const char *expr, int line)
{
	sChecks++;
	if (!ok) {
		sFails++;
		(void)std::fprintf(stderr, "test_unit.cpp:%d: CHECK(%s) failed\n", line, expr);
	}
}

#define CHECK(c) check(static_cast<bool>(c), #c, __LINE__)

// String literal as bytes (tests only).
template <std::size_t N>
std::array<std::uint8_t, N - 1U> bytesOf(const char (&s)[N])
{
	std::array<std::uint8_t, N - 1U> b{};
	for (std::size_t i = 0U; i + 1U < N; i++) {
		b[i] = static_cast<std::uint8_t>(s[i]);
	}
	return b;
}

Mac mac(std::string_view s)
{
	const std::optional<Mac> m = parseMac(s);
	return m.has_value() ? *m : Mac{};
}

template <std::size_t N>
FixedString<2U * N> hexs(const std::array<std::uint8_t, N> &a)
{
	FixedString<2U * N> h;
	(void)hexEncode(viewOf(a), h);
	return h;
}

void testSha256()
{
	const auto abc = bytesOf("abc");
	CHECK(hexs(computeSha256(viewOf(abc))).view() ==
	      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	// RFC 4231 test case 2
	const auto key = bytesOf("Jefe");
	const auto msg = bytesOf("what do ya want for nothing?");
	CHECK(hexs(computeHmacSha256(viewOf(key), viewOf(msg))).view() ==
	      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

void testProtoRoundtrip()
{
	const Mac origin{{2U, 0U, 0U, 0U, 0U, 1U}};
	std::array<std::uint8_t, 32U> key{{1U, 2U, 3U}};
	arcp::Message m;
	arcp::ApInfo ai;
	arcp::BssInfo bi;
	arcp::BssLoad bl;
	int seen = 0;

	ai.helloMs = 2000U;
	ai.numBss = 1U;
	(void)ai.name.assign("ap-1");
	bi.bssid = mac("02:11:22:33:44:55");
	bi.freq = 5180U;
	bi.channel = 36U;
	bi.opClass = 115U;
	bi.band = arcp::BAND_5G;
	bi.caps = arcp::CAP_FT | arcp::CAP_BTM;
	bi.mdid = 0xa1b2U;
	bi.bssidInfo = 0x1234U;
	bi.ssidLen = 4U;
	bi.ssid[0] = 'h';
	bi.ssid[1] = 'o';
	bi.ssid[2] = 'm';
	bi.ssid[3] = 'e';
	bl.bssid = bi.bssid;
	bl.staCount = 7U;
	bl.maxSta = 64U;
	bl.util = 128U;
	bl.noise = -95;
	bl.txPower = 20;
	bl.flags = arcp::LOAD_ACCEPTING;

	m.begin(arcp::MsgType::BSS_STATUS, arcp::FLAG_ACK_REQ, origin, 0xdeadbeefU, 42U);
	CHECK(m.add(ai));
	CHECK(m.add(bi));
	CHECK(m.add(bl));
	CHECK(m.finish(viewOf(key)));

	std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value());
	if (!h.has_value()) {
		return;
	}
	CHECK(h->type == arcp::raw(arcp::MsgType::BSS_STATUS) && h->msgId == 42U &&
	      h->bootId == 0xdeadbeefU);
	CHECK(h->origin == origin);
	CHECK(((h->flags & arcp::FLAG_AUTH) != 0U) && ((h->flags & arcp::FLAG_ACK_REQ) != 0U));
	CHECK(arcp::verify(m.bytes(), *h, viewOf(key)));
	CHECK(!arcp::verify(m.bytes(), *h, ByteView())); // unexpected AUTH

	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	while (rd.next(t, v)) {
		if (t == arcp::raw(arcp::Tlv::BSS_INFO)) {
			arcp::BssInfo bo;
			CHECK(arcp::decode(v, bo));
			CHECK(bo == bi && bo.ssidLen == 4U && bo.bssidInfo == 0x1234U);
			seen |= 1;
		} else if (t == arcp::raw(arcp::Tlv::BSS_LOAD)) {
			arcp::BssLoad blo;
			CHECK(arcp::decode(v, blo));
			CHECK(blo.staCount == 7U && blo.util == 128U && blo.noise == -95);
			seen |= 2;
		} else if (t == arcp::raw(arcp::Tlv::AP_INFO)) {
			arcp::ApInfo ao;
			CHECK(arcp::decode(v, ao) && ao.name.view() == "ap-1");
			seen |= 4;
		} else {
			// AUTH
		}
	}
	CHECK(seen == 7);

	// Tamper with one body byte: authentication must fail.
	std::array<std::uint8_t, arcp::MAX_PAYLOAD> copy{};
	const std::size_t n = copyBytes(spanOf(copy), m.bytes());
	copy[arcp::HDR_LEN + 5U] = static_cast<std::uint8_t>(copy[arcp::HDR_LEN + 5U] ^ 1U);
	CHECK(!arcp::verify(viewOf(copy).first(n), *h, viewOf(key)));
	// Wrong key
	std::array<std::uint8_t, 32U> k2{{9U}};
	CHECK(!arcp::verify(m.bytes(), *h, viewOf(k2)));
	// Truncated frame
	CHECK(!arcp::parseHeader(m.bytes().first(m.bytes().size() - 1U)).has_value());
}

void testProtoOverflow()
{
	const Mac origin{{2U}};
	arcp::Message m;
	const arcp::StaEntry e;
	int n = 0;

	m.begin(arcp::MsgType::STA_STATUS, 0U, origin, 1U, 1U);
	while (m.room() >= (arcp::TLV_HDR_LEN + arcp::STA_ENTRY_LEN)) {
		CHECK(m.add(e));
		n++;
	}
	CHECK(n > 30);
	CHECK(!m.add(e));
	CHECK(!m.finish(ByteView()));
}

void testSteerTlvs()
{
	const Mac origin{{2U}};
	arcp::Message m;
	arcp::SteerReq r;

	r.txn = 77U;
	r.reason = static_cast<std::uint8_t>(arcp::SteerReason::RSSI);
	r.rcpi = 140U;
	r.staFlags = arcp::STA_F11K | arcp::STA_F11V;
	r.curRssi = -80;
	r.sta = mac("aa:bb:cc:dd:ee:ff");
	m.begin(arcp::MsgType::STEER_REQ, arcp::FLAG_ACK_REQ, origin, 1U, 2U);
	(void)m.add(r);
	CHECK(m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value() && arcp::verify(m.bytes(), *h, ByteView()));
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::STEER_REQ));
	arcp::SteerReq ro;
	CHECK(arcp::decode(v, ro));
	CHECK(ro.txn == 77U && ro.rcpi == 140U && ro.curRssi == -80 && ro.sta == r.sta);
	CHECK(!rd.next(t, v));
}

void testRrm()
{
	arcp::BssInfo b;
	FixedString<64U> nr;
	FixedString<256U> hex;

	const std::optional<rrm::ChanBand> c1 = rrm::freqToChan(2437);
	CHECK(c1.has_value() && c1->channel == 6U && c1->band == arcp::BAND_2G);
	const std::optional<rrm::ChanBand> c2 = rrm::freqToChan(5180);
	CHECK(c2.has_value() && c2->channel == 36U && c2->band == arcp::BAND_5G);
	const std::optional<rrm::ChanBand> c3 = rrm::freqToChan(5955);
	CHECK(c3.has_value() && c3->channel == 1U && c3->band == arcp::BAND_6G);
	CHECK(rrm::opClass20mhz(arcp::BAND_2G, 6U) == 81U);
	CHECK(rrm::opClass20mhz(arcp::BAND_5G, 36U) == 115U);
	CHECK(rrm::opClass20mhz(arcp::BAND_5G, 149U) == 124U);
	CHECK(rrm::opClass20mhz(arcp::BAND_6G, 37U) == 131U);
	CHECK(rrm::rcpiToDbm(rrm::dbmToRcpi(-60)) == -60);
	CHECK(rrm::dbmToRcpi(-110) == 0U && rrm::rcpiToDbm(255U) == -128);

	b.bssid = mac("02:00:00:00:01:00");
	b.bssidInfo = rrm::buildBssidInfo(arcp::CAP_HT | arcp::CAP_VHT | arcp::CAP_RRM_NR, true);
	b.opClass = 115U;
	b.channel = 36U;
	b.phyType = rrm::PHY_VHT;
	b.mdid = 0xa1b2U;
	// BSSID | BSSID Info LE (0x1eaf incl. Mobility Domain) | 115 | 36 | 9
	CHECK(rrm::buildNrHex(b, 0xa1b2U, nr) && nr.view() == "020000000100af1e0000732409");
	CHECK(rrm::buildNrHex(b, 0x1111U, nr) && nr.view() == "020000000100af1a0000732409");

	const auto home = bytesOf("home");
	rrm::OpChanList one{};
	one[0] = rrm::OpChan{115U, 36U};
	CHECK(rrm::buildBcnReqHex(one, 1U, rrm::BeaconMode::ACTIVE, 50U, nullptr, viewOf(home), hex));
	CHECK(hex.view() == "7324000032000" "1ffffffffffff" "0004686f6d65" "020100");
	// Several channels: Channel 255 + one AP Channel Report (51) per op class
	rrm::OpChanList three{};
	three[0] = rrm::OpChan{81U, 1U};
	three[1] = rrm::OpChan{115U, 36U};
	three[2] = rrm::OpChan{115U, 40U};
	CHECK(rrm::buildBcnReqHex(three, 3U, rrm::BeaconMode::ACTIVE, 50U, nullptr, viewOf(home), hex));
	CHECK(hex.view() == "51ff000032000" "1ffffffffffff" "0004686f6d65" "020100"
			    "33025101" "3303732428");
	CHECK(!rrm::buildBcnReqHex(three, 0U, rrm::BeaconMode::ACTIVE, 50U, nullptr, ByteView(), hex));

	// op 115 ch 36 | start 8 | dur 50 | info 0 | rcpi 120 | rsni 0 | bssid | ant | tsf
	const std::optional<rrm::BeaconReport> r = rrm::parseBcnRepHex(
		"7324" "0000000000000000" "3200" "00" "78" "00" "020000000100" "00" "00000000");
	CHECK(r.has_value() && r->opClass == 115U && r->channel == 36U && r->rcpi == 120U &&
	      r->duration == 50U);
	CHECK(r.has_value() && r->bssid == b.bssid && rrm::rcpiToDbm(r->rcpi) == -50);
	CHECK(!rrm::parseBcnRepHex("7324").has_value());

	CHECK(rrm::isFtAkm("00-0f-ac-4") && rrm::isFtAkm("00-0f-ac-9") && !rrm::isFtAkm("00-0f-ac-2") &&
	      !rrm::isFtAkm("000fac-4"));
	const std::array<std::uint8_t, 3U> ext{{0U, 0U, 0x08U}};
	CHECK(rrm::hasBtmCapab(viewOf(ext)) && !rrm::hasBtmCapab(viewOf(ext).first(2U)));
	CHECK(rrm::isAkmForbidden6g("00-0f-ac-2") && rrm::isAkmForbidden6g("00-0F-AC-4") &&
	      rrm::isAkmForbidden6g("00-0f-ac-6"));
	CHECK(!rrm::isAkmForbidden6g("00-0f-ac-8") && !rrm::isAkmForbidden6g("00-0f-ac-18") &&
	      !rrm::isAkmForbidden6g("00-0f-ac-5") && !rrm::isAkmForbidden6g("50-6f-9a-2") &&
	      !rrm::isAkmForbidden6g(""));

	// Supported Operating Classes: current class first, then the list up
	// to the 130 or 0 delimiter
	CHECK(rrm::bandBit(arcp::BAND_5G) == rrm::BANDS_5G && rrm::bandBit(0U) == 0U);
	CHECK(rrm::opClassBandBit(81U) == rrm::BANDS_2G && rrm::opClassBandBit(128U) == rrm::BANDS_5G &&
	      rrm::opClassBandBit(134U) == rrm::BANDS_6G && rrm::opClassBandBit(12U) == 0U);
	const std::array<std::uint8_t, 3U> only2g{{81U, 81U, 83U}};
	CHECK(rrm::bandsFromOpClasses(viewOf(only2g)) == rrm::BANDS_2G);
	const std::array<std::uint8_t, 6U> tri{{115U, 81U, 115U, 128U, 131U, 134U}};
	CHECK(rrm::bandsFromOpClasses(viewOf(tri)) == (rrm::BANDS_2G | rrm::BANDS_5G | rrm::BANDS_6G));
	// 6 GHz class after the OneHundredAndThirty delimiter is not a class
	const std::array<std::uint8_t, 5U> delim{{81U, 81U, 130U, 131U, 0U}};
	CHECK(rrm::bandsFromOpClasses(viewOf(delim)) == rrm::BANDS_2G);
	const std::array<std::uint8_t, 4U> zero{{81U, 0U, 115U, 131U}};
	CHECK(rrm::bandsFromOpClasses(viewOf(zero)) == rrm::BANDS_2G);
	CHECK(rrm::bandsFromOpClasses(ByteView()) == 0U);
}

void testHapdParsers()
{
	constexpr std::string_view status =
		"state=ENABLED\nphy=phy1\nfreq=5180\nnum_sta_non_erp=0\n"
		"ieee80211n=1\nieee80211ac=1\nieee80211ax=0\nsecondary_channel=1\n"
		"vht_oper_chwidth=1\nchannel=36\nmax_txpower=23\n"
		"bss[0]=wlan1\nbssid[0]=02:00:00:00:01:00\nssid[0]=home\nnum_sta[0]=3\n"
		"bss[1]=wlan1-1\nbssid[1]=02:00:00:00:01:01\nssid[1]=guest\nnum_sta[1]=1\n";
	constexpr std::string_view sta =
		"aa:bb:cc:dd:ee:01\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][HT][VHT]\n"
		"aid=1\ncapability=0x11\nlisten_interval=10\nrx_bytes=1000\ntx_bytes=2000\n"
		"inactive_msec=120\nsignal=-67\nrx_rate_info=8667 vhtmcs 9\n"
		"tx_rate_info=4333\nconnected_time=42\next_capab=0400080000000040\n"
		"AKMSuiteSelector=00-0f-ac-4\nsupp_op_classes=5151537376\n";

	std::optional<hapd::Status> st = hapd::parseStatus(status, "wlan1-1");
	CHECK(st.has_value());
	if (st.has_value()) {
		CHECK(st->freq == 5180 && st->channel == 36U && st->band == arcp::BAND_5G);
		CHECK(st->numSta == 1 && st->ssidLen == 5U && st->ssid[0] == 'g' && st->ssid[4] == 't');
		CHECK(st->bssid.b[5] == 1U && st->bw == arcp::BW80 && st->maxTxpower == 23);
		CHECK(((st->caps & arcp::CAP_VHT) != 0U) && ((st->caps & arcp::CAP_HE) == 0U) &&
		      st->chanUtil == -1);
	}
	st = hapd::parseStatus(status, "wlan1");
	CHECK(st.has_value() && st->numSta == 3);

	const std::optional<hapd::Sta> s = hapd::parseSta(sta);
	CHECK(s.has_value());
	if (s.has_value()) {
		CHECK(s->authorized && s->signal == -67 && s->rxBytes == 1000U && s->txBytes == 2000U);
		CHECK(s->inactiveMs == 120U && s->connectedS == 42U);
		CHECK(s->rxRateMbps == 866U && s->txRateMbps == 433U);
		CHECK(s->btmKnown && s->btm && s->ftKnown && s->ft);
		CHECK(s->bands == (rrm::BANDS_2G | rrm::BANDS_5G));
		CHECK(s->akmNo6g); // FT-PSK
	}
	const std::optional<hapd::Sta> s2 = hapd::parseSta("aa:bb:cc:dd:ee:02\nsignal=-40\n");
	CHECK(s2.has_value() && (s2->bands == 0U));
	CHECK(!hapd::parseSta("FAIL\n").has_value());
	CHECK(!hapd::parseSta("").has_value());

	std::optional<hapd::BtmResp> br = hapd::parseBtmResp(
		"BSS-TM-RESP aa:bb:cc:dd:ee:01 dialog_token=3 status_code=0 bss_termination_delay=0 "
		"target_bssid=02:00:00:00:02:00");
	CHECK(br.has_value() && br->status == 0 && br->hasTarget && br->target.b[4] == 2U);
	br = hapd::parseBtmResp("BSS-TM-RESP aa:bb:cc:dd:ee:01 dialog_token=3 status_code=7 "
				  "bss_termination_delay=0");
	CHECK(br.has_value() && br->status == 7 && !br->hasTarget);
}

void testPolicy()
{
	Config c;
	const PolicyConfig &p = c.pol;
	policy::SteerCtx ctx;
	policy::CandInput in;

	ctx.reason = arcp::SteerReason::RSSI;
	ctx.curRssi = -80;
	ctx.curBand = arcp::BAND_5G;
	in.band = arcp::BAND_5G;
	in.estRssi = -65;
	in.utilPct = 20;
	CHECK(policy::score(p, ctx, in) == (-65 + 5 - ((2 * 20) / 10)));
	in.estRssi = -75; // only 5 dB better: below hysteresis
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.estRssi = policy::RSSI_UNKNOWN;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.estRssi = -60;
	in.utilPct = 85; // target too busy
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.utilPct = 20;
	in.maxSta = 10;
	in.staCount = 10;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.maxSta = 0;

	// Load balancing tolerates a small RSSI loss but needs a quiet target.
	ctx.reason = arcp::SteerReason::LOAD;
	ctx.curRssi = -60;
	in.estRssi = -64;
	in.utilPct = 30;
	CHECK(policy::score(p, ctx, in) != policy::INELIGIBLE);
	in.utilPct = 60; // > util_high - lb_margin = 55
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);
	in.utilPct = 30;
	in.estRssi = -68; // 8 dB loss > tolerance
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);

	// Band steering only towards a higher band
	ctx.reason = arcp::SteerReason::BAND;
	ctx.curBand = arcp::BAND_2G;
	ctx.curRssi = -50;
	in.band = arcp::BAND_5G;
	in.estRssi = -62;
	CHECK(policy::score(p, ctx, in) != policy::INELIGIBLE);
	in.band = arcp::BAND_2G;
	CHECK(policy::score(p, ctx, in) == policy::INELIGIBLE);

	CHECK(policy::isRssiTriggered(p, -80, 3) && !policy::isRssiTriggered(p, -80, 2));
	CHECK(!policy::isRssiTriggered(p, -70, 5) && !policy::isRssiTriggered(p, 0, 5));
	CHECK(policy::isBandTriggered(p, arcp::BAND_2G, -50) && policy::isBandTriggered(p, arcp::BAND_5G, -50));
	CHECK(!policy::isBandTriggered(p, arcp::BAND_5G, -60) && !policy::isBandTriggered(p, arcp::BAND_6G, -40));
	{
		Config c6;
		c6.pol.bandSteer6g = false;
		CHECK(policy::isBandTriggered(c6.pol, arcp::BAND_2G, -50) &&
		      !policy::isBandTriggered(c6.pol, arcp::BAND_5G, -50));
	}
	CHECK(policy::isBssOverloaded(p, 75, 1, 0) && !policy::isBssOverloaded(p, 50, 1, 0));
	CHECK(policy::isBssOverloaded(p, -1, 32, 32));
	CHECK(policy::admit(p, 50, 5, 0, 0) == arcp::SteerStatus::ACCEPT);
	CHECK(policy::admit(p, 50, 9, 1, 10) == arcp::SteerStatus::CAPACITY);
	CHECK(policy::admit(p, 90, 1, 0, 0) == arcp::SteerStatus::LOAD);
	// Band usability: unknown counts as usable; seen overrides advertised;
	// blocked (6 GHz, WPA2-PSK) always wins
	using B = policy::StaBands;
	constexpr std::uint8_t ALL = rrm::BANDS_2G | rrm::BANDS_5G | rrm::BANDS_6G;
	CHECK(policy::isBandUsable(B{0U, 0U, 0U}, arcp::BAND_6G));
	CHECK(!policy::isBandUsable(B{rrm::BANDS_2G, rrm::BANDS_2G, 0U}, arcp::BAND_5G));
	CHECK(policy::isBandUsable(B{rrm::BANDS_2G, rrm::BANDS_5G, 0U}, arcp::BAND_5G));
	CHECK(!policy::isBandUsable(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_6G));
	CHECK(!policy::isBandUsable(B{0U, 0U, rrm::BANDS_6G}, arcp::BAND_6G));
	CHECK(policy::isBandUsable(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{rrm::BANDS_2G, rrm::BANDS_2G, 0U}, arcp::BAND_2G));
	CHECK(policy::hasHigherBand(B{rrm::BANDS_2G | rrm::BANDS_6G, 0U, 0U}, arcp::BAND_2G));
	CHECK(policy::hasHigherBand(B{0U, 0U, 0U}, arcp::BAND_2G));
	// From 5 GHz only with 6 GHz advertised or seen, and not blocked
	CHECK(policy::hasHigherBand(B{ALL, 0U, 0U}, arcp::BAND_5G));
	CHECK(policy::hasHigherBand(B{0U, rrm::BANDS_6G, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{0U, 0U, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{rrm::BANDS_2G | rrm::BANDS_5G, 0U, 0U}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{ALL, 0U, rrm::BANDS_6G}, arcp::BAND_5G));
	CHECK(!policy::hasHigherBand(B{ALL, 0U, 0U}, arcp::BAND_6G));
	CHECK(policy::backoffMs(p, 0) == 30000 && policy::backoffMs(p, 2) == 120000);
	CHECK(policy::backoffMs(p, 20) == p.steerBackoffMaxMs);
	CHECK(policy::utilToPct(255) == -1 && policy::utilToPct(128) == 50 && policy::utilToPct(0) == 0);
}

// Expected-throughput model: the scenarios of the design note.
void testPolicyTput()
{
	Config c;
	PolicyConfig &p = c.pol;
	const std::uint16_t ht = arcp::CAP_HT;
	const std::uint16_t vht = arcp::CAP_HT | arcp::CAP_VHT;

	p.scoreModel = ScoreModel::TPUT;

	// Sigmoid quality: 500 at the midpoint, monotonic, saturating
	CHECK(policy::computeLinkQuality(p, -72) == 500);
	CHECK(policy::computeLinkQuality(p, -80) == 83 && policy::computeLinkQuality(p, -55) == 994);
	CHECK(policy::computeLinkQuality(p, -120) == 0 && policy::computeLinkQuality(p, -20) == 1000);
	CHECK(policy::computeLinkQuality(p, 0) == 0 && policy::computeLinkQuality(p, policy::RSSI_UNKNOWN) == 0);
	for (int r = -105; r < -35; r++) {
		CHECK(policy::computeLinkQuality(p, r) <= policy::computeLinkQuality(p, r + 1));
	}

	// Peak PHY rate: top MCS, short GI, x streams
	CHECK(policy::computePeakMbps(ht, arcp::BW20, 2) == 144);
	CHECK(policy::computePeakMbps(vht, arcp::BW80, 2) == 866);
	CHECK(policy::computePeakMbps(vht | arcp::CAP_HE, arcp::BW80, 2) == 1202);
	CHECK(policy::computePeakMbps(0U, arcp::BW20, 2) == 54);
	CHECK(policy::computeExpectedKbps(p, -60, 866, 40) == ((973 * 866 * 60) / 100));
	CHECK(policy::computeExpectedKbps(p, -60, 866, -1) == (973 * 866));

	policy::SteerCtx ctx;
	policy::CandInput a;
	policy::CandInput b;

	// 1. Weak 5 GHz STA: the louder 2.4 GHz BSS loses to a fast 5 GHz one
	ctx.reason = arcp::SteerReason::RSSI;
	ctx.curRssi = -80;
	ctx.curBand = arcp::BAND_5G;
	ctx.curUtilPct = 30;
	ctx.curPeakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	a.band = arcp::BAND_5G;
	a.estRssi = -60;
	a.utilPct = 40;
	a.peakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	b.band = arcp::BAND_2G;
	b.estRssi = -55;
	b.utilPct = 20;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, a) > policy::score(p, ctx, b));
	CHECK(policy::score(p, ctx, b) != policy::INELIGIBLE);
	p.scoreModel = ScoreModel::LINEAR;
	CHECK(policy::score(p, ctx, a) < policy::score(p, ctx, b));
	p.scoreModel = ScoreModel::TPUT;

	// 2. A louder but slower target that would cut throughput is refused
	ctx.curRssi = -77;
	ctx.curUtilPct = 10;
	b.estRssi = -69;
	b.utilPct = 50;
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	p.scoreModel = ScoreModel::LINEAR;
	CHECK(policy::score(p, ctx, b) != policy::INELIGIBLE);
	p.scoreModel = ScoreModel::TPUT;

	// 3/4. Band steering only when 5 GHz is really faster
	ctx.reason = arcp::SteerReason::BAND;
	ctx.curRssi = -50;
	ctx.curBand = arcp::BAND_2G;
	ctx.curUtilPct = 20;
	ctx.curPeakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	a.estRssi = -58;
	a.utilPct = 30;
	CHECK(policy::score(p, ctx, a) != policy::INELIGIBLE);
	b = policy::CandInput{};
	b.band = arcp::BAND_5G;
	b.estRssi = -58;
	b.utilPct = 70;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	ctx.curRssi = -45;
	ctx.curUtilPct = 0;
	b.estRssi = -50;
	b.utilPct = 0; // same width, idle: < tput_gain_pct
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);

	// 5. Load balancing: the STA must not lose throughput
	ctx = policy::SteerCtx{};
	ctx.reason = arcp::SteerReason::LOAD;
	ctx.curRssi = -60;
	ctx.curBand = arcp::BAND_5G;
	ctx.curUtilPct = 90;
	ctx.curPeakMbps = policy::computePeakMbps(vht, arcp::BW80, 2);
	a.estRssi = -64;
	a.utilPct = 30;
	CHECK(policy::score(p, ctx, a) != policy::INELIGIBLE);
	b = policy::CandInput{};
	b.band = arcp::BAND_2G;
	b.estRssi = -62;
	b.utilPct = 40;
	b.peakMbps = policy::computePeakMbps(ht, arcp::BW20, 2);
	CHECK(policy::score(p, ctx, b) == policy::INELIGIBLE);
	a.utilPct = 60; // still needs a quiet target
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);

	// Hard gates apply in both models
	ctx.reason = arcp::SteerReason::MANUAL;
	a.utilPct = 30;
	a.estRssi = -75; // below rssi_min_target
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
	a.estRssi = -60;
	a.accepting = false;
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
	a.accepting = true;
	a.utilPct = 85; // >= util_admit_max
	CHECK(policy::score(p, ctx, a) == policy::INELIGIBLE);
}

template <std::size_t N>
std::array<std::uint8_t, N + 24U> airFrame(const std::array<std::uint8_t, N> &rt, std::uint8_t fc0,
					     std::uint8_t fc1, const Mac &ta)
{
	std::array<std::uint8_t, N + 24U> b{};
	for (std::size_t i = 0U; i < N; i++) {
		b[i] = rt[i];
	}
	b[N] = fc0;
	b[N + 1U] = fc1;
	for (std::size_t i = 0U; i < 6U; i++) {
		b[N + 10U + i] = ta.b[i];
	}
	return b;
}

// Air monitor: radiotap/802.11 parsing and the monitor TLVs
void testAirMonitor()
{
	const Mac ta = mac("aa:bb:cc:dd:ee:02");
	// flags | channel 5745 MHz | dBm signal -55; it_len 15
	const std::array<std::uint8_t, 15U> rt{{0, 0, 15, 0, 0x2a, 0, 0, 0, 0x00, 0, 0x71, 0x16, 0, 1, 0xc9}};
	// + TSFT: channel aligned after 8-byte TSFT and flags; it_len 23
	const std::array<std::uint8_t, 23U> rtTsft{{0, 0, 23, 0, 0x2b, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
						      0x00, 0, 0x6c, 0x09, 0, 1, 0xd0}};
	// extended present word: fields start after the second word; it_len 19
	const std::array<std::uint8_t, 19U> rtExt{{0, 0, 19, 0, 0x2a, 0, 0, 0x80, 0, 0, 0, 0,
						     0x00, 0, 0x71, 0x16, 0, 1, 0xc9}};
	const std::array<std::uint8_t, 15U> rtBadfcs{{0, 0, 15, 0, 0x2a, 0, 0, 0, 0x40, 0, 0x71, 0x16, 0, 1, 0xc9}};
	const std::array<std::uint8_t, 14U> rtNosig{{0, 0, 14, 0, 0x0a, 0, 0, 0, 0x00, 0, 0x71, 0x16, 0, 1}};

	auto f = rrm::parseRadiotap(viewOf(airFrame(rt, 0x08U, 0x01U, ta))); // data, ToDS
	CHECK(f.has_value() && f->freq == 5745 && f->signal == -55 && !f->probe && f->ta == ta);
	CHECK(rrm::parseRadiotap(viewOf(airFrame(rt, 0xc8U, 0x11U, ta))).has_value()); // QoS null
	f = rrm::parseRadiotap(viewOf(airFrame(rt, 0x40U, 0x00U, ta))); // probe request
	CHECK(f.has_value() && f->probe);
	f = rrm::parseRadiotap(viewOf(airFrame(rtTsft, 0x08U, 0x01U, ta)));
	CHECK(f.has_value() && f->freq == 2412 && f->signal == -48);
	f = rrm::parseRadiotap(viewOf(airFrame(rtExt, 0x08U, 0x01U, ta)));
	CHECK(f.has_value() && f->freq == 5745 && f->signal == -55);
	CHECK(!rrm::parseRadiotap(viewOf(airFrame(rt, 0x08U, 0x02U, ta))).has_value()); // FromDS
	CHECK(!rrm::parseRadiotap(viewOf(airFrame(rt, 0x80U, 0x00U, ta))).has_value()); // beacon
	CHECK(!rrm::parseRadiotap(viewOf(airFrame(rtBadfcs, 0x08U, 0x01U, ta))).has_value());
	CHECK(!rrm::parseRadiotap(viewOf(airFrame(rtNosig, 0x08U, 0x01U, ta))).has_value());
	const auto full = airFrame(rt, 0x08U, 0x01U, ta);
	CHECK(!rrm::parseRadiotap(viewOf(full).first(full.size() - 1U)).has_value()); // truncated

	// STA_MONITOR_REQ / RESULT round trip
	const Mac origin{{2U, 0U, 0U, 0U, 0U, 1U}};
	arcp::StaMonitorReq rq;
	arcp::StaMonitorResult rs;
	arcp::Message m;

	rq.txn = 9U;
	rq.durationMs = 1000U;
	rq.opClass = 115U;
	rq.channel = 36U;
	rq.sta = ta;
	rs.txn = 9U;
	rs.rssi = -61;
	rs.samples = 42U;
	rs.ageMs = 120U;
	rs.sta = ta;
	rs.bssid = origin;
	m.begin(arcp::MsgType::STA_MONITOR_REPORT, 0U, origin, 1U, 1U);
	CHECK(m.add(rq) && m.add(rs));
	CHECK(m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value());
	if (h.has_value()) {
		arcp::TlvReader rd(m.bytes(), *h);
		std::uint8_t t = 0U;
		ByteView v;
		arcp::StaMonitorReq rqo;
		arcp::StaMonitorResult rso;
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::STA_MONITOR_REQ) && arcp::decode(v, rqo));
		CHECK(rqo.txn == 9U && rqo.durationMs == 1000U && rqo.channel == 36U && rqo.sta == ta);
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::STA_MONITOR_RESULT) && arcp::decode(v, rso));
		CHECK(rso.rssi == -61 && rso.samples == 42U && rso.ageMs == 120U && rso.bssid == origin);
		CHECK(!arcp::decode(v.first(20U), rso));
	}
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::STA_MONITOR_REQ)) == "STA_MONITOR_REQ");

	// config
	Config c;
	CHECK(c.pol.amonRequest && c.pol.amonDurationMs == 1000);
	CHECK(parseConfigLine(c, "air_monitor mon0") && c.nMonitors == 1U && c.monitors[0].view() == "mon0");
	CHECK(parseConfigLine(c, "air_monitor_sim 31000") && c.monitorSimPort == 31000U);
	CHECK(parseConfigLine(c, "amon_duration_ms 500") && c.pol.amonDurationMs == 500);
}

// Robustness: checked number parsing, field-wise struct comparison
void testRobustness()
{
	CHECK(parseLong("42", 10, 0, 100) == std::optional<long>(42));
	CHECK(parseLong("-75", 10, -128, 0) == std::optional<long>(-75));
	CHECK(parseLong("a1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(parseLong("0xa1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(!parseLong("", 10, 0, 100).has_value());          // empty
	CHECK(!parseLong("12x", 10, 0, 100).has_value());       // junk
	CHECK(!parseLong("12 34", 10, 0, 100).has_value());     // two values
	CHECK(!parseLong("101", 10, 0, 100).has_value());       // range
	CHECK(!parseLong("99999999999999999999", 10, std::numeric_limits<long>::min(),
			  std::numeric_limits<long>::max()).has_value());
	CHECK(parseLongTok("217 mcs 2 shortGI", 10, 0, 100000) == std::optional<long>(217));
	CHECK(parseLongTok("7", 10, 0, 255) == std::optional<long>(7));
	CHECK(!parseLongTok("7x bss", 10, 0, 255).has_value());
	CHECK(parseU64("18446744073709551615") ==
	      std::optional<std::uint64_t>(std::numeric_limits<std::uint64_t>::max()));
	CHECK(!parseU64("18446744073709551616").has_value()); // overflow
	CHECK(!parseU64("-1").has_value() && !parseU64("12a").has_value() && !parseU64("").has_value());
	CHECK(parseMac("a:b:c:d:e:f").has_value() && !parseMac("aa:bb:cc:dd:ee").has_value() &&
	      !parseMac("aa:bb:cc:dd:ee:ff:00").has_value() && !parseMac("aa:bb:cc:dd:ee:fg").has_value());

	// Config values that used to become 0 silently are rejected
	Config c;
	CHECK(!parseConfigLine(c, "sim_port abc") && !parseConfigLine(c, "sim_port 70000") &&
	      !parseConfigLine(c, "sim_port 0"));
	CHECK(!parseConfigLine(c, "bss wlan0 mdid=xyz") && !parseConfigLine(c, "bss wlan0 max_sta=12abc"));
	CHECK(!parseConfigLine(c, "rssi_low 99999999999"));
	CHECK(parseConfigLine(c, "air_monitor_sim 31000") && c.monitorSimPort == 31000U);
	CHECK(parseConfigLine(c, "bss wlan1 mdid=A1B2 max_sta=64") && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].maxSta == 64);

	// hostapd fields that do not parse are ignored or rejected
	CHECK(!hapd::parseBtmResp("BSS-TM-RESP aa:bb:cc:dd:ee:01 status_code=x7").has_value());
	const std::optional<hapd::Sta> st = hapd::parseSta("aa:bb:cc:dd:ee:01\nrx_bytes=-5\ntx_bytes=12\n");
	CHECK(st.has_value() && st->rxBytes == 0U && st->txBytes == 12U);
	CHECK(!rrm::isFtAkm("00-0f-ac-4x") && !rrm::isFtAkm("00-0f-ac-"));

	// BssInfo equality ignores SSID bytes beyond ssidLen
	arcp::BssInfo a;
	arcp::BssInfo b;
	a.freq = 5180U;
	b.freq = 5180U;
	a.channel = 36U;
	b.channel = 36U;
	a.ssidLen = 4U;
	b.ssidLen = 4U;
	for (std::size_t i = 0U; i < 4U; i++) {
		a.ssid[i] = static_cast<std::uint8_t>("home"[i]);
		b.ssid[i] = static_cast<std::uint8_t>("home"[i]);
	}
	b.ssid[10] = 0xa5U; // beyond ssidLen
	CHECK(a == b);
	b.channel = 40U;
	CHECK(a != b);
	b.channel = 36U;
	b.ssid[3] = 'x';
	CHECK(a != b);
}

// Per-module log levels and config keys
void testLog()
{
	Config c;

	CHECK(logging::parseLevel("debug") == std::optional<LogLevel>(LogLevel::DEBUG));
	CHECK(logging::parseLevel("err") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(!logging::parseLevel("verbose").has_value());
	CHECK(logging::parseModule("steer") == std::optional<LogModule>(LogModule::STEER));
	CHECK(logging::parseModule("config") == std::optional<LogModule>(LogModule::CONFIG));
	CHECK(!logging::parseModule("nosuch").has_value());
	CHECK(logging::moduleName(LogModule::AMON) == "amon" && logging::levelName(LogLevel::WARN) == "warn");

	logging::setAll(LogLevel::INFO);
	logging::setLevel(LogModule::STEER, LogLevel::DEBUG);
	CHECK(logging::level(LogModule::STEER) == LogLevel::DEBUG && logging::level(LogModule::MSG) == LogLevel::INFO);
	CHECK(logging::enabled(LogModule::STEER, LogLevel::DEBUG) &&
	      !logging::enabled(LogModule::MSG, LogLevel::DEBUG) &&
	      logging::enabled(LogModule::MSG, LogLevel::INFO));
	logging::setAll(LogLevel::ERR);
	CHECK(!logging::enabled(LogModule::STEER, LogLevel::WARN) &&
	      logging::enabled(LogModule::CONFIG, LogLevel::ERR));
	logging::setAll(LogLevel::INFO);

	CHECK(c.logLevel == LogLevel::INFO && c.logDebugMask == 0U);
	CHECK(parseConfigLine(c, "log_level warn") && c.logLevel == LogLevel::WARN);
	CHECK(parseConfigLine(c, "log_debug steer,amon msg") &&
	      c.logDebugMask == ((1U << static_cast<std::uint32_t>(LogModule::STEER)) |
				   (1U << static_cast<std::uint32_t>(LogModule::AMON)) |
				   (1U << static_cast<std::uint32_t>(LogModule::MSG))));
	CHECK(!parseConfigLine(c, "log_level verbose") && !parseConfigLine(c, "log_debug nosuch"));

	// type-safe formatting
	Line l;
	formatTo(l, "a {} b {} c {} d {} e {}", -5, 7U, mac("02:00:00:00:00:01"), hex(0x1aU, 4U),
		  std::string_view("x"));
	CHECK(l.view() == "a -5 b 7 c 02:00:00:00:00:01 d 001a e x");
	l.clear();
	formatTo(l, "{} {}", std::numeric_limits<std::int64_t>::min(), "extra {}");
	CHECK(l.view() == "-9223372036854775808 extra {}");
}

void testConfig()
{
	Config c;

	CHECK(parseConfigLine(c, "iface br-lan") && c.nIfaces == 1U && c.ifaces[0].view() == "br-lan");
	CHECK(parseConfigLine(c, "bss wlan0 mdid=a1b2 max_sta=32") && c.nBss == 1U && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].maxSta == 32);
	CHECK(parseConfigLine(c, "rssi_low -72  # comment") && c.pol.rssiLow == -72);
	CHECK(parseConfigLine(c, "lb_only_idle 0") && !c.pol.lbOnlyIdle);
	CHECK(parseConfigLine(c, "key hex:00112233445566778899aabbccddeeff") && c.keyLen == 16U);
	CHECK(!parseConfigLine(c, "bogus 1"));
	CHECK(!parseConfigLine(c, "key short"));
	CHECK(parseConfigLine(c, "ap_id 02:00:00:00:00:01") && c.apIdSet && c.apId.b[5] == 1U);
	CHECK(c.pol.scoreModel == ScoreModel::LINEAR && c.pol.staNss == 2);
	CHECK(parseConfigLine(c, "score_model 1") && c.pol.scoreModel == ScoreModel::TPUT);
	CHECK(parseConfigLine(c, "tput_gain_pct 200") && c.pol.tputGainPct == 200);
	CHECK(parseConfigLine(c, "beacon_mode 0") && c.pol.beaconMode == rrm::BeaconMode::PASSIVE);
	CHECK(!parseConfigLine(c, "beacon_mode 3"));
	CHECK(parseConfigLine(c, "key a-long-passphrase") && c.keyLen == 32U);
}

} // namespace

int main()
{
	testSha256();
	testProtoRoundtrip();
	testProtoOverflow();
	testSteerTlvs();
	testRrm();
	testHapdParsers();
	testPolicy();
	testPolicyTput();
	testAirMonitor();
	testRobustness();
	testLog();
	testConfig();
	(void)std::printf("%d/%d checks passed\n", sChecks - sFails, sChecks);
	return (sFails != 0) ? 1 : 0;
}
