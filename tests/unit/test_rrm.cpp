// SPDX-License-Identifier: MIT
// Unit tests: 802.11 structures and the radiotap parser (src/core/rrm).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "unit.hpp"

#include "core/config.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"

using namespace donghoa;

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

namespace {

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

} // namespace

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
