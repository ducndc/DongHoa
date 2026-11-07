// SPDX-License-Identifier: MIT
// Unit tests for the pure modules. Test code is exempt from the no-macro
// rule (docs/CODING_CONVENTION.md section 2): CHECK reports file and line.
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string_view>
#include <vector>

#include <linux/nl80211.h>

#include "config.hpp"
#include "hapd_parse.hpp"
#include "log.hpp"
#include "nlparse.hpp"
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

	// Decoders for the rrm log: the inverse of the builders
	{
		const std::optional<rrm::BeaconRequest> q = rrm::parseBcnReqHex(hex.view());
		CHECK(q.has_value());
		if (q.has_value()) {
			CHECK(q->opClass == 81U && q->channel == 255U && q->duration == 50U && q->randInt == 0U &&
			      q->mode == static_cast<std::uint8_t>(rrm::BeaconMode::ACTIVE));
			CHECK(q->bssid.b[0] == 0xffU && q->hasSsid && q->ssidLen == 4U && q->ssid[0] == 'h' &&
			      q->detail == 0);
			CHECK(q->nChans == 3U && q->chans[0].opClass == 81U && q->chans[0].channel == 1U &&
			      q->chans[2].opClass == 115U && q->chans[2].channel == 40U);
		}
		CHECK(rrm::buildBcnReqHex(one, 1U, rrm::BeaconMode::PASSIVE, 120U, &b.bssid, ByteView(), hex));
		const std::optional<rrm::BeaconRequest> q1 = rrm::parseBcnReqHex(hex.view());
		CHECK(q1.has_value() && q1->channel == 36U && q1->duration == 120U && q1->mode == 0U &&
		      q1->bssid == b.bssid && !q1->hasSsid && q1->nChans == 0U);
		// truncated subelement: fixed fields still decoded
		const std::optional<rrm::BeaconRequest> q2 = rrm::parseBcnReqHex("7324000032000" "1ffffffffffff" "0008686f");
		CHECK(q2.has_value() && q2->channel == 36U && !q2->hasSsid);
		CHECK(!rrm::parseBcnReqHex("7324").has_value() && !rrm::parseBcnReqHex("zz").has_value());

		CHECK(rrm::buildNrHex(b, 0xa1b2U, nr));
		const std::optional<rrm::NeighborReport> n = rrm::parseNrHex(nr.view());
		CHECK(n.has_value() && n->bssid == b.bssid && n->opClass == 115U && n->channel == 36U &&
		      n->phyType == rrm::PHY_VHT && n->bssidInfo == 0x1eafU);
		CHECK(!rrm::parseNrHex("0200").has_value());
		FixedString<96U> info;
		rrm::describeBssidInfo(0x1eafU, info);
		CHECK(info.view() == "reach=3 sec key_scope qos rrm imm_ba md ht vht");
		rrm::describeBssidInfo(0U, info);
		CHECK(info.view() == "reach=0");

		CHECK(rrm::reportModeName(0U) == "ok" && rrm::reportModeName(1U) == "late" &&
		      rrm::reportModeName(2U) == "incapable" && rrm::reportModeName(4U) == "refused" &&
		      rrm::reportModeName(6U) == "refused");
		CHECK(rrm::btmStatusName(0) == "accept" && rrm::btmStatusName(7) == "reject: no suitable candidates" &&
		      rrm::btmStatusName(9) == "reserved" && rrm::btmStatusName(-1) == "reserved");
	}

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
		CHECK(s->phyCaps == arcp::CAP_VHT); // [HT][VHT]: HT is not tracked, no [HE]/[EHT]
	}
	const std::optional<hapd::Sta> s2 = hapd::parseSta("aa:bb:cc:dd:ee:02\nsignal=-40\n");
	CHECK(s2.has_value() && (s2->bands == 0U) && (s2->phyCaps == 0U));
	const std::optional<hapd::Sta> s3 =
		hapd::parseSta("aa:bb:cc:dd:ee:03\nflags=[AUTH][ASSOC][AUTHORIZED][HE][EHT]\n");
	CHECK(s3.has_value() && (s3->phyCaps == (arcp::CAP_HE | arcp::CAP_EHT)));
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

	CHECK(policy::isRssiTriggered(p, -80, 3, p.rssiLow) && !policy::isRssiTriggered(p, -80, 2, p.rssiLow));
	CHECK(!policy::isRssiTriggered(p, -70, 5, p.rssiLow) && !policy::isRssiTriggered(p, 0, 5, p.rssiLow));
	CHECK(!policy::isRssiTriggered(p, -80, 5, -82)); // a STA with a lower threshold hangs on
	CHECK(policy::isRssiTriggered(p, -70, 5, -65));  // a higher one roams earlier

	// Q-learning of when to roam
	{
		// state encoding: every combination maps to a distinct index
		std::array<bool, policy::RL_STATES> seen{};
		bool unique = true;
		const std::array<int, 6U> rssis{{-55, -62, -68, -73, -78, -85}};
		for (const int r : rssis) {
			for (int sl = -1; sl <= 1; sl++) {
				for (int g = 0; g < 4; g++) {
					for (int rf = 0; rf < 3; rf++) {
						for (int k = 0; k < 2; k++) {
							policy::RlFeatures f;
							f.rssi = r;
							f.slope = sl;
							f.gapKnown = g != 0;
							f.gapDb = (g == 1) ? -3 : ((g == 2) ? 4 : 12);
							f.refusals = rf;
							f.lowStreak = k == 1;
							const std::size_t i = policy::rlState(f);
							unique = unique && (i < policy::RL_STATES) && !seen[i];
							if (i < policy::RL_STATES) {
								seen[i] = true;
							}
						}
					}
				}
			}
		}
		CHECK(unique);
		// the prior reproduces the rule: steer below -75 dBm with a low streak
		policy::RlTable t;
		policy::rlInit(t);
		bool explored = false;
		policy::RlFeatures w;
		w.rssi = -78;
		w.lowStreak = true;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::STEER);
		w.lowStreak = false;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::WAIT);
		w.rssi = -72;
		w.lowStreak = true;
		CHECK(policy::rlChoose(t, policy::rlState(w), 0, 0U, explored) == policy::RlAction::WAIT);
		// exploration: STEER only where safe (below -65, neighbour not known worse)
		w.rssi = -72;
		CHECK((policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::STEER) && explored);
		w.gapKnown = true;
		w.gapDb = -4;
		CHECK((policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::WAIT) && !explored);
		w.rssi = -62;
		w.gapKnown = false;
		CHECK(policy::rlChoose(t, policy::rlState(w), 100, 0U, explored) == policy::RlAction::WAIT);
		CHECK(policy::rlChoose(t, policy::rlState(w), 1, 50U, explored) == policy::RlAction::WAIT); // rnd 50 >= 1%
		// learning: a STA that refuses at -78 makes STEER worse than WAIT there
		policy::RlFeatures r78;
		r78.rssi = -78;
		r78.lowStreak = true;
		const std::size_t s78 = policy::rlState(r78);
		policy::rlUpdate(t, s78, policy::RlAction::STEER, policy::RL_R_REFUSED, true, 0U);
		CHECK(t.q[s78][1U] == (policy::RL_R_REFUSED * policy::RL_ONE)); // alpha 1 on the first visit
		CHECK(policy::rlChoose(t, s78, 0, 0U, explored) == policy::RlAction::WAIT);
		for (int i = 0; i < 40; i++) {
			policy::rlUpdate(t, s78, policy::RlAction::STEER, 20, true, 0U); // later: big successes
		}
		CHECK((t.q[s78][1U] > (18 * policy::RL_ONE)) && (t.n[s78][1U] == 41U));
		CHECK(policy::rlChoose(t, s78, 0, 0U, explored) == policy::RlAction::STEER);
		// non-terminal: discounted best of the next state
		policy::RlTable u;
		policy::rlInit(u);
		u.q[3][1U] = 10 * policy::RL_ONE;
		policy::rlUpdate(u, 1U, policy::RlAction::WAIT, -2, false, 3U);
		CHECK(u.q[1][0U] == ((-2 * policy::RL_ONE) + ((10 * policy::RL_ONE * policy::RL_GAMMA) / policy::RL_ONE)));
		// rewards
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::SUCCESS, 30) == (policy::RL_R_SUCCESS + policy::RL_R_GAIN_MAX));
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::BTM_REJECT, 0) == policy::RL_R_REFUSED);
		CHECK(policy::rlRewardSteer(arcp::SteerOutcome::ABORTED, 0) == 0);
		CHECK((policy::rlRewardWait(-65) == 0) && (policy::rlRewardWait(-82) == -3) && (policy::rlRewardWait(0) == 0));
		Config c;
		CHECK(c.pol.rlRoam == 1); // shadow by default
		CHECK(parseConfigLine(c, "rl_roam 2") && (c.pol.rlRoam == 2) && !parseConfigLine(c, "rl_roam 3"));
	}
	// per-STA roaming threshold
	{
		PolicyConfig q; // rssi_low -75, range -82..-65, learning on
		CHECK(policy::roamThreshold(q, 0) == -75);             // not learned: rssi_low
		CHECK(policy::roamThreshold(q, -79) == -79);
		CHECK(policy::roamThreshold(q, -90) == -82);           // clamped
		CHECK(policy::updateRoamThrOutcome(q, 0, policy::RoamOutcome::REFUSED, 0) == -77);
		CHECK(policy::updateRoamThrOutcome(q, -77, policy::RoamOutcome::ROAM_TIMEOUT, 0) == -78);
		CHECK(policy::updateRoamThrOutcome(q, -78, policy::RoamOutcome::SUCCESS, 20) == -77); // big gain: earlier
		CHECK(policy::updateRoamThrOutcome(q, -78, policy::RoamOutcome::SUCCESS, 10) == -78); // modest: kept
		int t = 0;
		for (int i = 0; i < 10; i++) {
			t = policy::updateRoamThrOutcome(q, t, policy::RoamOutcome::REFUSED, 0);
		}
		CHECK(t == -82);                                        // floor
		CHECK(policy::updateRoamThrSelf(q, -75, -67) == -73);   // quarter of the way
		CHECK(policy::updateRoamThrSelf(q, -75, -77) == -76);   // at least 1 dB
		CHECK(policy::updateRoamThrSelf(q, -75, -75) == -75);
		CHECK(policy::updateRoamThrSelf(q, -66, -40) == -65);   // ceiling
		CHECK((policy::decayRoamThr(q, -80) == -79) && (policy::decayRoamThr(q, -70) == -71) &&
		      (policy::decayRoamThr(q, -75) == -75));
		q.roamThrLearn = false;
		CHECK(policy::roamThreshold(q, -80) == -75);            // learning off: rssi_low
		Config c;
		CHECK(parseConfigLine(c, "roam_thr_min -85") && (c.pol.roamThrMin == -85));
		CHECK(parseConfigLine(c, "roam_thr_learn 0") && !c.pol.roamThrLearn);
		// STA_ROAM TLV round trip; a longer TLV from a newer peer decodes
		arcp::StaRoam r;
		r.sta = mac("02:00:00:00:02:09");
		r.thresholdDbm = -79;
		r.events = 7U;
		arcp::Message m;
		m.begin(arcp::MsgType::STA_CLASS, 0U, r.sta, 1U, 1U);
		CHECK(m.add(r) && m.finish(ByteView()));
		const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
		if (h.has_value()) {
			arcp::TlvReader rd(m.bytes(), *h);
			std::uint8_t ty = 0U;
			ByteView v;
			arcp::StaRoam o;
			CHECK(rd.next(ty, v) && (ty == arcp::raw(arcp::Tlv::STA_ROAM)) && arcp::decode(v, o));
			CHECK((o.sta == r.sta) && (o.thresholdDbm == -79) && (o.events == 7U));
			CHECK(!arcp::decode(v.first(10U), o));
		}
		CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::STA_ROAM)) == "STA_ROAM");
	}
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
	arcp::StaMonitorStatus st;
	st.txn = 9U;
	st.sta = ta;
	st.status = static_cast<std::uint8_t>(arcp::MonitorStatus::UNSUPPORTED);
	m.begin(arcp::MsgType::STA_MONITOR_REPORT, 0U, origin, 1U, 1U);
	CHECK(m.add(rq) && m.add(rs) && m.add(st));
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
		arcp::StaMonitorStatus sto;
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::STA_MONITOR_STATUS) && arcp::decode(v, sto));
		CHECK(sto.txn == 9U && sto.sta == ta &&
		      sto.status == static_cast<std::uint8_t>(arcp::MonitorStatus::UNSUPPORTED));
		CHECK(!arcp::decode(v.first(10U), sto));
	}
	// a longer STA_MONITOR_STATUS from a newer peer still decodes
	{
		std::array<std::uint8_t, 14U> longer{};
		longer[3U] = 7U; // txn 7
		longer[10U] = static_cast<std::uint8_t>(arcp::MonitorStatus::BUSY);
		arcp::StaMonitorStatus sto;
		CHECK(arcp::decode(viewOf(longer), sto) && sto.txn == 7U &&
		      sto.status == static_cast<std::uint8_t>(arcp::MonitorStatus::BUSY));
	}
	CHECK(arcp::monitorStatusName(static_cast<std::uint8_t>(arcp::MonitorStatus::NOT_HEARD)) == "not heard");
	CHECK(arcp::monitorStatusName(99U) == "?");
	CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::STA_MONITOR_STATUS)) == "STA_MONITOR_STATUS");
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::STA_MONITOR_REQ)) == "STA_MONITOR_REQ");

	// config
	Config c;
	CHECK(c.pol.amonRequest && c.pol.amonDurationMs == 1000);
	CHECK(parseConfigLine(c, "air_monitor mon0") && c.nMonitors == 1U && c.monitors[0].view() == "mon0");
	CHECK(parseConfigLine(c, "air_monitor_sim 31000") && c.monitorSimPort == 31000U);
	CHECK(parseConfigLine(c, "amon_duration_ms 500") && c.pol.amonDurationMs == 500);
	// bss lines: up to MAX_BSS managed, valid extra lines skipped (counted),
	// an invalid line still rejected
	{
		Config cb;
		bool all = true;
		for (std::size_t i = 0U; i < (MAX_BSS + 2U); i++) {
			FixedString<64U> line;
			formatTo(line, "bss wlan{} mdid=a1b2", i);
			all = parseConfigLine(cb, line.view()) && all;
		}
		CHECK(all && (cb.nBss == MAX_BSS) && (cb.nBssSkipped == 2U));
		CHECK(cb.bssSkippedFirst.view() == "wlan16");
		CHECK(!parseConfigLine(cb, "bss wlan99 mdid=zz")); // still validated
	}
	// HELLO and BSS_STATUS with MAX_BSS worst-case BSSes fit one message
	{
		const std::array<std::uint8_t, 4U> key{{1U, 2U, 3U, 4U}};
		arcp::ApInfo ai;
		(void)ai.name.assign("0123456789abcdef0123456789abcdef");
		arcp::BssInfo bi;
		bi.ssidLen = 32U;
		bi.mldAddr = mac("02:00:00:00:00:99");
		bi.linkId = 1U;
		arcp::BssLoad bl;
		arcp::Message hello;
		arcp::Message status;
		hello.begin(arcp::MsgType::HELLO, 0U, bi.mldAddr, 1U, 1U);
		status.begin(arcp::MsgType::BSS_STATUS, 0U, bi.mldAddr, 1U, 1U);
		bool ok = hello.add(ai);
		for (std::size_t i = 0U; i < MAX_BSS; i++) {
			ok = hello.add(bi) && status.add(bi) && status.add(bl) && ok;
		}
		CHECK(ok && hello.finish(viewOf(key)) && status.finish(viewOf(key)));
		CHECK(status.bytes().size() <= arcp::MAX_PAYLOAD);
	}
	CHECK(!c.staRssiApi);
	CHECK(parseConfigLine(c, "sta_rssi_api 1") && c.staRssiApi);
	CHECK(!parseConfigLine(c, "sta_rssi_api 2"));
	Config c2;
	CHECK(parseConfigLine(c2, "sta_rssi_sim /tmp/rssi") && c2.staRssiApi && c2.staRssiSim.view() == "/tmp/rssi");
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
	CHECK(logging::parseModule("rrm") == std::optional<LogModule>(LogModule::RRM));
	// Every module, the last one included, starts at info
	CHECK(logging::level(LogModule::RRM) == LogLevel::INFO && logging::level(LogModule::MAIN) == LogLevel::INFO);
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

// Wi-Fi 7 MLO: AP MLD links in BSS_INFO and hostapd output, MLD STAs
void testMlo()
{
	// BSS_INFO: optional MLO trailer, round trip; an older peer's TLV
	// (no trailer) decodes as "not an MLD link"
	arcp::BssInfo bi;
	bi.bssid = mac("02:00:00:00:01:10");
	bi.band = arcp::BAND_5G;
	bi.ssidLen = 4U;
	bi.ssid[0] = 'h';
	bi.mldAddr = mac("02:00:00:00:01:1f");
	bi.linkId = 1U;
	CHECK(bi.isMldLink());
	arcp::Message m;
	m.begin(arcp::MsgType::HELLO, 0U, mac("02:00:00:00:00:01"), 1U, 1U);
	CHECK(m.add(bi) && m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value());
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	CHECK(rd.next(t, v) && (t == arcp::raw(arcp::Tlv::BSS_INFO)) && (v.size() == (22U + 4U + 7U)));
	arcp::BssInfo bo;
	CHECK(arcp::decode(v, bo) && (bo == bi) && (bo.mldAddr == bi.mldAddr) && (bo.linkId == 1U));
	arcp::BssInfo old;
	CHECK(arcp::decode(v.first(22U + 4U), old) && !old.isMldLink() && (old.linkId == arcp::LINK_NONE));
	// a non-MLD BSS sends no trailer at all
	arcp::BssInfo plain = bi;
	plain.mldAddr = Mac{};
	plain.linkId = arcp::LINK_NONE;
	arcp::Message m2;
	m2.begin(arcp::MsgType::HELLO, 0U, mac("02:00:00:00:00:01"), 1U, 2U);
	CHECK(m2.add(plain) && m2.finish(ByteView()));
	const std::optional<arcp::Header> h2 = arcp::parseHeader(m2.bytes());
	CHECK(h2.has_value());
	if (!h2.has_value()) {
		return;
	}
	arcp::TlvReader rd2(m2.bytes(), *h2);
	CHECK(rd2.next(t, v) && (v.size() == (22U + 4U)));
	arcp::BssInfo other = bi;
	other.bssid = mac("02:00:00:00:01:11");
	other.linkId = 0U;
	CHECK(arcp::isSameMld(bi, other) && !arcp::isSameMld(bi, plain) && !arcp::isSameMld(plain, plain));

	// control socket names of AP MLD links
	CHECK(hapd::netdevName("ap-mld0_link1") == "ap-mld0" && hapd::netdevName("wlan0") == "wlan0");
	CHECK(hapd::netdevName("my_link") == "my_link" && hapd::netdevName("ap_link99") == "ap_link99");
	CHECK(hapd::ctrlLinkId("ap-mld0_link1") == std::optional<int>(1) && !hapd::ctrlLinkId("wlan0").has_value());
	CHECK(hapd::ctrlLinkId("ap-mld0_link14") == std::optional<int>(14));

	// STATUS of one AP MLD link: bss[0] is the netdev, link ID tells it apart
	constexpr std::string_view status =
		"state=ENABLED\nfreq=5220\nchannel=44\nieee80211n=1\nieee80211ax=1\nieee80211be=1\n"
		"num_links=2\nlink_id=1\nlink_addr=02:00:00:00:01:11\npartner_link[0]=02:00:00:00:01:10\n"
		"bss[0]=ap-mld0\nbssid[0]=02:00:00:00:01:11\nssid[0]=home\nnum_sta[0]=1\n"
		"mld_addr[0]=02:00:00:00:01:1f\nmld_id[0]=0\nmld_link_id[0]=1\n";
	std::optional<hapd::Status> st = hapd::parseStatus(status, "ap-mld0_link1");
	CHECK(st.has_value() && (st->bssid == mac("02:00:00:00:01:11")) && (st->linkId == 1) &&
	      (st->mldAddr == mac("02:00:00:00:01:1f")) && ((st->caps & arcp::CAP_EHT) != 0U));
	// two links of one netdev listed together: each socket picks its own
	constexpr std::string_view both =
		"freq=5220\nbss[0]=ap-mld0\nbssid[0]=02:00:00:00:01:10\nssid[0]=home\n"
		"mld_addr[0]=02:00:00:00:01:1f\nmld_link_id[0]=0\n"
		"bss[1]=ap-mld0\nbssid[1]=02:00:00:00:01:11\nssid[1]=home\n"
		"mld_addr[1]=02:00:00:00:01:1f\nmld_link_id[1]=1\n";
	st = hapd::parseStatus(both, "ap-mld0_link1");
	CHECK(st.has_value() && (st->bssid == mac("02:00:00:00:01:11")) && (st->linkId == 1));
	st = hapd::parseStatus(both, "ap-mld0_link0");
	CHECK(st.has_value() && (st->bssid == mac("02:00:00:00:01:10")) && (st->linkId == 0));
	// a plain BSS stays a plain BSS
	st = hapd::parseStatus("freq=2412\nbss[0]=wlan0\nbssid[0]=02:00:00:00:01:00\nssid[0]=x\n", "wlan0");
	CHECK(st.has_value() && (st->linkId == -1) && st->mldAddr.isZero());

	// MLD STA: addr is the MLD address, links as peer_addr[<link id>]
	const std::optional<hapd::Sta> ms = hapd::parseSta(
		"aa:bb:cc:dd:ee:10\nflags=[AUTH][ASSOC][AUTHORIZED]\nsignal=-45\n"
		"peer_addr[0]=aa:bb:cc:dd:ee:20\npeer_addr[1]=aa:bb:cc:dd:ee:21\nmax_simul_links=1\n");
	CHECK(ms.has_value() && ms->mld && (ms->linkMask == 0x3U) && (ms->maxSimulLinks == 1) &&
	      (ms->addr == mac("aa:bb:cc:dd:ee:10")));
	const std::optional<hapd::Sta> ls = hapd::parseSta("aa:bb:cc:dd:ee:11\nsignal=-45\n");
	CHECK(ls.has_value() && !ls->mld && (ls->linkMask == 0U) && (ls->maxSimulLinks == -1));
}

// Low-power (IoT) classification: integer statistics, score, theta, class
// record TLV and config keys.
void testLowPower()
{
	CHECK(policy::isqrt(0U) == 0U);
	CHECK(policy::isqrt(15U) == 3U);
	CHECK(policy::isqrt(16U) == 4U);
	CHECK(policy::isqrt(static_cast<std::uint64_t>(1U) << 62U) == (1U << 31U));
	CHECK(policy::isqrt(~static_cast<std::uint64_t>(0U)) == 0xffffffffU);

	// Welford: down alternates 0 / 1000 B/s (mean 500, variance 250000),
	// up stays 0.
	policy::TrafficStats t;
	for (int i = 0; i < 200; i++) {
		policy::addTrafficSample(t, 0U, ((i % 2) == 0) ? 0U : 1000U);
	}
	CHECK(t.n == 200U);
	CHECK((t.down.mean16 / 16) == 500);
	const std::uint64_t var = t.down.m2 / t.n;
	CHECK((var > 247500U) && (var < 252500U));
	CHECK(t.up.m2 == 0U);
	// past the window n halves and the variance stays
	for (int i = 0; i < 5000; i++) {
		policy::addTrafficSample(t, 0U, ((i % 2) == 0) ? 0U : 1000U);
	}
	CHECK(t.n <= policy::TRAFFIC_WINDOW);
	const std::uint64_t var2 = t.down.m2 / t.n;
	CHECK((var2 > 247500U) && (var2 < 252500U));
	// a slow device (0 / 10 B/s) does not truncate to zero
	policy::TrafficStats slow;
	for (int i = 0; i < 100; i++) {
		policy::addTrafficSample(slow, ((i % 2) == 0) ? 0U : 10U, 0U);
	}
	CHECK((slow.up.m2 / slow.n) >= 20U);
	// rates above TRAFFIC_RATE_MAX are clamped
	policy::TrafficStats big;
	policy::addTrafficSample(big, ~static_cast<std::uint64_t>(0U), 0U);
	CHECK((big.up.mean16 / 16) == static_cast<std::int64_t>(policy::TRAFFIC_RATE_MAX));

	// S = alpha x sigma_up / sigma_down
	PolicyConfig p;
	policy::TrafficStats u;
	for (int i = 0; i < 100; i++) {
		const bool odd = (i % 2) != 0;
		policy::addTrafficSample(u, odd ? 1000U : 0U, odd ? 500U : 0U); // sigma 500 / 250
	}
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_2G) == 200);
	p.lpAlpha2g = 40;
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_2G) == 80);
	CHECK(policy::lpBehaviourScore(p, u, arcp::BAND_5G) == 200); // alpha per band
	p.lpAlpha2g = 100;
	// no evidence: too few samples, or nothing varies (idle)
	policy::TrafficStats few;
	policy::addTrafficSample(few, 0U, 0U);
	policy::addTrafficSample(few, 1000U, 0U);
	CHECK(policy::lpBehaviourScore(p, few, arcp::BAND_2G) == policy::LP_NO_EVIDENCE);
	policy::TrafficStats idle;
	for (int i = 0; i < 50; i++) {
		policy::addTrafficSample(idle, 0U, 0U);
	}
	CHECK(policy::lpBehaviourScore(p, idle, arcp::BAND_2G) == policy::LP_NO_EVIDENCE);
	// only the uplink varies
	policy::TrafficStats uponly;
	for (int i = 0; i < 50; i++) {
		policy::addTrafficSample(uponly, ((i % 2) == 0) ? 0U : 300U, 100U);
	}
	CHECK(policy::lpBehaviourScore(p, uponly, arcp::BAND_2G) == policy::LP_S_MAX);
	// Found on the QEMU testbed: a STA idle after one small uplink burst.
	// The window still has sigma_up > 0 and sigma_down = 0, but an idle
	// poll is no evidence, so theta does not climb while nothing is sent.
	policy::TrafficStats quiet;
	int thQ = 0;
	policy::addTrafficSample(quiet, 4000U, 0U);
	for (int i = 0; i < 300; i++) {
		policy::addTrafficSample(quiet, 0U, 0U);
		thQ = policy::updateLpScore(p, thQ, policy::lpBehaviourScore(p, quiet, arcp::BAND_2G));
	}
	CHECK((quiet.up.m2 > 0U) && (quiet.down.m2 == 0U) && !quiet.lastActive);
	CHECK(thQ == 0);
	policy::addTrafficSample(quiet, 40U, 0U); // the next real frame counts again
	CHECK(policy::lpBehaviourScore(p, quiet, arcp::BAND_2G) == policy::LP_S_MAX);

	// load-balancing feedback: utilisation must drop by lb_min_drop_pct (3)
	{
		PolicyConfig q;
		CHECK(policy::isLbMoveEffective(q, 90, 87));
		CHECK(!policy::isLbMoveEffective(q, 90, 88));
		CHECK(!policy::isLbMoveEffective(q, 90, 95));
		CHECK(policy::isLbMoveEffective(q, -1, 95)); // unknown: no judgement
		CHECK(policy::isLbMoveEffective(q, 90, -1));
		Config c;
		CHECK(parseConfigLine(c, "lb_max_futile 3") && (c.pol.lbMaxFutile == 3));
		CHECK(parseConfigLine(c, "lb_hold_ms 60000") && (c.pol.lbHoldMs == 60000));
		CHECK(parseConfigLine(c, "lb_min_drop_pct 5") && (c.pol.lbMinDropPct == 5));
	}
	// uplink -> downlink offset learning
	{
		PolicyConfig q; // learn on, 3 samples, amon_rssi_offset 0
		policy::UlDlOffset o;
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);     // nothing learned: global offset
		q.amonRssiOffset = 2;
		CHECK(policy::uplinkToDownlink(q, nullptr, -70) == -68);
		q.amonRssiOffset = 0;
		CHECK(policy::addUlDlSample(q, o, -55, -63)); // +8
		CHECK(policy::addUlDlSample(q, o, -56, -63)); // +7
		CHECK(!policy::isUlDlCalibrated(q, o));
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);     // 2 samples: not used yet
		CHECK(policy::addUlDlSample(q, o, -54, -63)); // +9
		CHECK(policy::isUlDlCalibrated(q, o) && (o.n == 3U));
		CHECK(o.offset16 == 128);                               // cumulative mean +8.0
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -62);
		CHECK(!policy::addUlDlSample(q, o, -40, -63));          // +23: 15 dB from the mean, outlier
		CHECK(o.n == 3U);
		CHECK(!policy::addUlDlSample(q, o, -20, -60));          // +40: not one link
		CHECK(!policy::addUlDlSample(q, o, 0, -60));            // no level
		policy::UlDlOffset neg;
		for (int i = 0; i < 20; i++) {
			(void)policy::addUlDlSample(q, neg, -66, -62);  // -4
		}
		CHECK((neg.offset16 == -64) && (policy::uplinkToDownlink(q, &neg, -60) == -64));
		q.amonOffsetLearn = false;                               // learning off: global offset
		CHECK(policy::uplinkToDownlink(q, &o, -70) == -70);
		Config c;
		CHECK(parseConfigLine(c, "amon_offset_learn 0") && !c.pol.amonOffsetLearn);
		CHECK(parseConfigLine(c, "amon_offset_min_samples 5") && (c.pol.amonOffsetMinSamples == 5));
	}
	// signal freshness: only a frame within the last poll counts
	CHECK(policy::isSignalFresh(0U, 1000));     // hostapd gave no inactive_msec
	CHECK(policy::isSignalFresh(999U, 1000));
	CHECK(!policy::isSignalFresh(1000U, 1000));
	CHECK(!policy::isSignalFresh(30000U, 1000)); // idle STA: old value
	// candidate pool order: measured (by level) > own BSS > unknown remote
	CHECK(policy::candidatePoolRank(false, 150) > policy::candidatePoolRank(false, 100));
	CHECK(policy::candidatePoolRank(false, 0) > policy::candidatePoolRank(true, policy::NO_HINT));
	CHECK(policy::candidatePoolRank(true, policy::NO_HINT) > policy::candidatePoolRank(false, policy::NO_HINT));
	CHECK(policy::candidatePoolRank(false, 255) == policy::candidatePoolRank(false, policy::NO_HINT)); // RCPI unknown

	// theta: +1 / -1, clamped to 0..lp_score_max, unchanged without evidence
	CHECK(policy::updateLpScore(p, 0, 50) == 0);
	CHECK(policy::updateLpScore(p, 5, 100) == 4); // S = 1 is not > 1
	CHECK(policy::updateLpScore(p, 5, 101) == 6);
	CHECK(policy::updateLpScore(p, 120, 300) == 120);
	CHECK(policy::updateLpScore(p, 7, policy::LP_NO_EVIDENCE) == 7);
	// class with hysteresis: in above 60, out below 50
	CHECK(!policy::isLowPower(p, 60, false));
	CHECK(policy::isLowPower(p, 61, false));
	CHECK(policy::isLowPower(p, 50, true));
	CHECK(!policy::isLowPower(p, 49, true));

	// End to end on synthetic traffic, one sample per second: a sensor
	// (bursty upload, little download) becomes low-power after
	// lp_min_samples + lp_threshold samples; a phone (bursty download) never.
	policy::TrafficStats sensor;
	policy::TrafficStats phone;
	int thS = 0;
	int thP = 0;
	bool lowS = false;
	bool lowP = false;
	int when = -1;
	for (int i = 0; i < 300; i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(sensor, burst ? 4000U : 40U, burst ? 200U : 20U);
		policy::addTrafficSample(phone, burst ? 2000U : 100U, burst ? 900000U : 3000U);
		thS = policy::updateLpScore(p, thS, policy::lpBehaviourScore(p, sensor, arcp::BAND_2G));
		thP = policy::updateLpScore(p, thP, policy::lpBehaviourScore(p, phone, arcp::BAND_2G));
		const bool l = policy::isLowPower(p, thS, lowS);
		if (l && !lowS && (when < 0)) {
			when = i + 1;
		}
		lowS = l;
		lowP = policy::isLowPower(p, thP, lowP);
	}
	CHECK(lowS && !lowP && (thP == 0));
	CHECK(when == (p.lpMinSamples - 1) + p.lpThreshold + 1);

	// A big, bursty upload (device backup, AirDrop) has the same shape as
	// the sensor above (bursty up, quiet down, S > 1 on every burst) but
	// moves 500x the data: never low-power, because lp_max_mean_bps gates
	// on the mean uplink rate actually seen, not just its shape.
	policy::TrafficStats bigUpload;
	int thU = 0;
	bool lowU = false;
	for (int i = 0; i < 300; i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(bigUpload, burst ? 2000000U : 1000U, burst ? 200U : 20U);
		thU = policy::updateLpScore(p, thU, policy::lpBehaviourScore(p, bigUpload, arcp::BAND_2G));
		lowU = policy::isLowPower(p, thU, lowU);
	}
	CHECK(!lowU && (thU == 0));
	// The gate follows the recent rate: once the upload stops and the STA
	// is back to sensor-sized traffic, S counts again within a few polls
	// (a whole-window mean would hold the 2 MB/s bursts for minutes).
	int firstEvidence = -1;
	for (int i = 0; (i < 100) && (firstEvidence < 0); i++) {
		const bool burst = (i % 5) == 0;
		policy::addTrafficSample(bigUpload, burst ? 4000U : 0U, burst ? 200U : 20U);
		if (policy::lpBehaviourScore(p, bigUpload, arcp::BAND_2G) != policy::LP_NO_EVIDENCE) {
			firstEvidence = i;
		}
	}
	CHECK((firstEvidence > 5) && (firstEvidence < 40)); // not at once, not minutes

	// PHY exclusion: VHT and EHT by default, not HE (Wi-Fi 6 IoT uses TWT)
	CHECK(policy::isLpExcludedPhy(p, arcp::CAP_VHT));
	CHECK(policy::isLpExcludedPhy(p, arcp::CAP_EHT));
	CHECK(!policy::isLpExcludedPhy(p, arcp::CAP_HE));
	CHECK(!policy::isLpExcludedPhy(p, 0U));
	PolicyConfig pHe = p;
	pHe.lpExcludeHe = true;
	pHe.lpExcludeVht = false;
	CHECK(policy::isLpExcludedPhy(pHe, arcp::CAP_HE) && !policy::isLpExcludedPhy(pHe, arcp::CAP_VHT));

	// STA_CLASS TLV round trip; a longer TLV from a newer peer decodes
	arcp::StaClass c;
	c.sta = mac("02:00:00:00:02:07");
	c.devClass = static_cast<std::uint8_t>(arcp::DevClass::LOW_POWER);
	c.score = 77;
	c.samples = 123456U;
	arcp::Message m;
	m.begin(arcp::MsgType::STA_CLASS, arcp::FLAG_ACK_REQ, mac("02:00:00:00:00:01"), 1U, 1U);
	CHECK(m.add(c) && m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value() && (h->type == arcp::raw(arcp::MsgType::STA_CLASS)));
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t ty = 0U;
	ByteView v;
	CHECK(rd.next(ty, v) && (ty == arcp::raw(arcp::Tlv::STA_CLASS)) && (v.size() == 15U));
	arcp::StaClass o;
	CHECK(arcp::decode(v, o) && (o.sta == c.sta) && (o.devClass == c.devClass) && (o.score == 77) &&
	      (o.samples == 123456U));
	std::array<std::uint8_t, 20U> longer{};
	for (std::size_t i = 0U; i < v.size(); i++) {
		longer[i] = v[i];
	}
	arcp::StaClass o2;
	CHECK(arcp::decode(viewOf(longer), o2) && (o2.samples == 123456U));
	CHECK(!arcp::decode(v.first(14U), o2));
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::STA_CLASS)) == "STA_CLASS");
	CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::STA_CLASS)) == "STA_CLASS");

	// config keys
	Config cfg;
	CHECK(cfg.pol.lpClassify && cfg.pol.lpNoSteer && (cfg.pol.lpThreshold == 60));
	CHECK(parseConfigLine(cfg, "lp_threshold 30") && (cfg.pol.lpThreshold == 30));
	CHECK(parseConfigLine(cfg, "lp_no_steer 0") && !cfg.pol.lpNoSteer);
	CHECK(parseConfigLine(cfg, "lp_classify 0") && !cfg.pol.lpClassify);
	CHECK(parseConfigLine(cfg, "lp_alpha_5g 80") && (cfg.pol.lpAlpha5g == 80));
	CHECK(parseConfigLine(cfg, "lp_min_samples 5") && (cfg.pol.lpMinSamples == 5));
	CHECK(!parseConfigLine(cfg, "lp_threshold x"));
}

// nl80211 station dump entry (synthetic kernel message, host byte order)
namespace {

void putAttr(std::vector<std::uint8_t> &out, std::uint16_t type, const std::vector<std::uint8_t> &data)
{
	const std::size_t len = 4U + data.size();
	out.push_back(static_cast<std::uint8_t>(len & 0xffU));
	out.push_back(static_cast<std::uint8_t>(len >> 8U));
	out.push_back(static_cast<std::uint8_t>(type & 0xffU));
	out.push_back(static_cast<std::uint8_t>(type >> 8U));
	out.insert(out.end(), data.begin(), data.end());
	while ((out.size() % 4U) != 0U) {
		out.push_back(0U);
	}
}

std::vector<std::uint8_t> le(std::uint64_t v, std::size_t n)
{
	std::vector<std::uint8_t> r;
	for (std::size_t i = 0U; i < n; i++) {
		r.push_back(static_cast<std::uint8_t>((v >> (8U * i)) & 0xffU));
	}
	return r;
}

std::vector<std::uint8_t> nlMessage(const std::vector<std::uint8_t> &attrs)
{
	std::vector<std::uint8_t> m(20U, 0U); // nlmsghdr + genlmsghdr
	m.insert(m.end(), attrs.begin(), attrs.end());
	const std::vector<std::uint8_t> len = le(m.size(), 4U);
	for (std::size_t i = 0U; i < 4U; i++) {
		m[i] = len[i];
	}
	return m;
}

} // namespace

void testNlParse()
{
	std::vector<std::uint8_t> rate;
	putAttr(rate, NL80211_RATE_INFO_BITRATE32, le(8667U, 4U)); // 866.7 Mbit/s
	std::vector<std::uint8_t> rate16;
	putAttr(rate16, NL80211_RATE_INFO_BITRATE, le(540U, 2U)); // 54 Mbit/s, legacy u16
	const std::uint32_t auth = 1U << static_cast<unsigned>(NL80211_STA_FLAG_AUTHORIZED);
	std::vector<std::uint8_t> flags = le(auth, 4U);
	const std::vector<std::uint8_t> set = le(auth, 4U);
	flags.insert(flags.end(), set.begin(), set.end());
	std::vector<std::uint8_t> info;
	putAttr(info, NL80211_STA_INFO_INACTIVE_TIME, le(1170U, 4U));
	putAttr(info, NL80211_STA_INFO_RX_BYTES64, le(5000000000ULL, 8U)); // > 32 bits
	putAttr(info, NL80211_STA_INFO_TX_BYTES, le(1234U, 4U));            // only the u32 form
	putAttr(info, NL80211_STA_INFO_SIGNAL, le(static_cast<std::uint8_t>(-61), 1U));
	putAttr(info, NL80211_STA_INFO_SIGNAL_AVG, le(static_cast<std::uint8_t>(-58), 1U));
	putAttr(info, NL80211_STA_INFO_TX_BITRATE, rate);
	putAttr(info, NL80211_STA_INFO_RX_BITRATE, rate16);
	putAttr(info, NL80211_STA_INFO_CONNECTED_TIME, le(42U, 4U));
	putAttr(info, NL80211_STA_INFO_STA_FLAGS, flags);
	putAttr(info, 0x7ff0U, le(1U, 4U)); // unknown attribute from a newer kernel: skipped
	std::vector<std::uint8_t> attrs;
	putAttr(attrs, NL80211_ATTR_IFINDEX, le(7U, 4U));
	putAttr(attrs, NL80211_ATTR_MAC, {0x02U, 0x00U, 0x00U, 0x00U, 0x02U, 0x00U});
	putAttr(attrs, NL80211_ATTR_STA_INFO, info);
	const std::vector<std::uint8_t> msg = nlMessage(attrs);

	const std::optional<nl::Station> st = nl::parseStation(ByteView(msg.data(), msg.size()));
	CHECK(st.has_value());
	if (st.has_value()) {
		CHECK(st->addr == mac("02:00:00:00:02:00"));
		CHECK(st->authorized);
		CHECK((st->signal == -61) && (st->signalAvg == -58));
		CHECK(st->inactiveMs == 1170U);
		CHECK(st->rxBytes == 5000000000ULL);
		CHECK(st->txBytes == 1234U);
		CHECK((st->txRateMbps == 866U) && (st->rxRateMbps == 54U));
		CHECK(st->connectedS == 42U);
	}
	// not authorized: the flag is in the mask but not set
	std::vector<std::uint8_t> info2;
	std::vector<std::uint8_t> half = le(auth, 4U);
	const std::vector<std::uint8_t> zero = le(0U, 4U);
	half.insert(half.end(), zero.begin(), zero.end());
	putAttr(info2, NL80211_STA_INFO_STA_FLAGS, half);
	putAttr(info2, NL80211_STA_INFO_SIGNAL, le(static_cast<std::uint8_t>(-70), 1U));
	std::vector<std::uint8_t> attrs2;
	putAttr(attrs2, NL80211_ATTR_MAC, {0x02U, 0x00U, 0x00U, 0x00U, 0x02U, 0x01U});
	putAttr(attrs2, NL80211_ATTR_STA_INFO, info2);
	const std::vector<std::uint8_t> msg2 = nlMessage(attrs2);
	const std::optional<nl::Station> st2 = nl::parseStation(ByteView(msg2.data(), msg2.size()));
	CHECK(st2.has_value() && !st2->authorized && (st2->signalAvg == 0) && (st2->rxBytes == 0U));
	// no MAC or no STA_INFO: not a station entry; truncated: no crash
	std::vector<std::uint8_t> attrs3;
	putAttr(attrs3, NL80211_ATTR_STA_INFO, info);
	const std::vector<std::uint8_t> msg3 = nlMessage(attrs3);
	CHECK(!nl::parseStation(ByteView(msg3.data(), msg3.size())).has_value());
	for (std::size_t cut = 0U; cut < msg.size(); cut += 7U) {
		(void)nl::parseStation(ByteView(msg.data(), cut)); // must not read past the end
	}
	CHECK(!nl::parseStation(ByteView(msg.data(), 10U)).has_value());
}

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
	testMlo();
	testLowPower();
	testNlParse();
	(void)std::printf("%d/%d checks passed\n", sChecks - sFails, sChecks);
	return (sFails != 0) ? 1 : 0;
}
