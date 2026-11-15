// SPDX-License-Identifier: MIT
// Unit tests: hostapd reply parsers, MLO (src/core/hapd_parse).
#include <cstdint>
#include <optional>
#include <string_view>

#include "unit.hpp"

#include "core/hapd_parse.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"

using namespace donghoa;

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
