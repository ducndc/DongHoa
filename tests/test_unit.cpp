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

int g_fails = 0;
int g_checks = 0;

void check(bool ok, const char *expr, int line)
{
	g_checks++;
	if (!ok) {
		g_fails++;
		(void)std::fprintf(stderr, "test_unit.cpp:%d: CHECK(%s) failed\n", line, expr);
	}
}

#define CHECK(c) check(static_cast<bool>(c), #c, __LINE__)

// String literal as bytes (tests only).
template <std::size_t N>
std::array<std::uint8_t, N - 1U> bytes_of(const char (&s)[N])
{
	std::array<std::uint8_t, N - 1U> b{};
	for (std::size_t i = 0U; i + 1U < N; i++) {
		b[i] = static_cast<std::uint8_t>(s[i]);
	}
	return b;
}

Mac mac(std::string_view s)
{
	const std::optional<Mac> m = parse_mac(s);
	return m.has_value() ? *m : Mac{};
}

template <std::size_t N>
FixedString<2U * N> hexs(const std::array<std::uint8_t, N> &a)
{
	FixedString<2U * N> h;
	(void)hex_encode(view_of(a), h);
	return h;
}

void test_sha256()
{
	const auto abc = bytes_of("abc");
	CHECK(hexs(sha256(view_of(abc))).view() ==
	      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	// RFC 4231 test case 2
	const auto key = bytes_of("Jefe");
	const auto msg = bytes_of("what do ya want for nothing?");
	CHECK(hexs(hmac_sha256(view_of(key), view_of(msg))).view() ==
	      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

void test_proto_roundtrip()
{
	const Mac origin{{2U, 0U, 0U, 0U, 0U, 1U}};
	std::array<std::uint8_t, 32U> key{{1U, 2U, 3U}};
	arcp::Message m;
	arcp::ApInfo ai;
	arcp::BssInfo bi;
	arcp::BssLoad bl;
	int seen = 0;

	ai.hello_ms = 2000U;
	ai.num_bss = 1U;
	(void)ai.name.assign("ap-1");
	bi.bssid = mac("02:11:22:33:44:55");
	bi.freq = 5180U;
	bi.channel = 36U;
	bi.op_class = 115U;
	bi.band = arcp::kBand5g;
	bi.caps = arcp::kCapFt | arcp::kCapBtm;
	bi.mdid = 0xa1b2U;
	bi.bssid_info = 0x1234U;
	bi.ssid_len = 4U;
	bi.ssid[0] = 'h';
	bi.ssid[1] = 'o';
	bi.ssid[2] = 'm';
	bi.ssid[3] = 'e';
	bl.bssid = bi.bssid;
	bl.sta_count = 7U;
	bl.max_sta = 64U;
	bl.util = 128U;
	bl.noise = -95;
	bl.tx_power = 20;
	bl.flags = arcp::kLoadAccepting;

	m.begin(arcp::MsgType::bss_status, arcp::kFlagAckReq, origin, 0xdeadbeefU, 42U);
	CHECK(m.add(ai));
	CHECK(m.add(bi));
	CHECK(m.add(bl));
	CHECK(m.finish(view_of(key)));

	std::optional<arcp::Header> h = arcp::parse_header(m.bytes());
	CHECK(h.has_value());
	if (!h.has_value()) {
		return;
	}
	CHECK(h->type == arcp::raw(arcp::MsgType::bss_status) && h->msg_id == 42U &&
	      h->boot_id == 0xdeadbeefU);
	CHECK(h->origin == origin);
	CHECK(((h->flags & arcp::kFlagAuth) != 0U) && ((h->flags & arcp::kFlagAckReq) != 0U));
	CHECK(arcp::verify(m.bytes(), *h, view_of(key)));
	CHECK(!arcp::verify(m.bytes(), *h, ByteView())); // unexpected AUTH

	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	while (rd.next(t, v)) {
		if (t == arcp::raw(arcp::Tlv::bss_info)) {
			arcp::BssInfo bo;
			CHECK(arcp::decode(v, bo));
			CHECK(bo == bi && bo.ssid_len == 4U && bo.bssid_info == 0x1234U);
			seen |= 1;
		} else if (t == arcp::raw(arcp::Tlv::bss_load)) {
			arcp::BssLoad blo;
			CHECK(arcp::decode(v, blo));
			CHECK(blo.sta_count == 7U && blo.util == 128U && blo.noise == -95);
			seen |= 2;
		} else if (t == arcp::raw(arcp::Tlv::ap_info)) {
			arcp::ApInfo ao;
			CHECK(arcp::decode(v, ao) && ao.name.view() == "ap-1");
			seen |= 4;
		} else {
			// AUTH
		}
	}
	CHECK(seen == 7);

	// Tamper with one body byte: authentication must fail.
	std::array<std::uint8_t, arcp::kMaxPayload> copy{};
	const std::size_t n = copy_bytes(span_of(copy), m.bytes());
	copy[arcp::kHdrLen + 5U] = static_cast<std::uint8_t>(copy[arcp::kHdrLen + 5U] ^ 1U);
	CHECK(!arcp::verify(view_of(copy).first(n), *h, view_of(key)));
	// Wrong key
	std::array<std::uint8_t, 32U> k2{{9U}};
	CHECK(!arcp::verify(m.bytes(), *h, view_of(k2)));
	// Truncated frame
	CHECK(!arcp::parse_header(m.bytes().first(m.bytes().size() - 1U)).has_value());
}

void test_proto_overflow()
{
	const Mac origin{{2U}};
	arcp::Message m;
	const arcp::StaEntry e;
	int n = 0;

	m.begin(arcp::MsgType::sta_status, 0U, origin, 1U, 1U);
	while (m.room() >= (arcp::kTlvHdrLen + arcp::kStaEntryLen)) {
		CHECK(m.add(e));
		n++;
	}
	CHECK(n > 30);
	CHECK(!m.add(e));
	CHECK(!m.finish(ByteView()));
}

void test_steer_tlvs()
{
	const Mac origin{{2U}};
	arcp::Message m;
	arcp::SteerReq r;

	r.txn = 77U;
	r.reason = static_cast<std::uint8_t>(arcp::SteerReason::rssi);
	r.rcpi = 140U;
	r.sta_flags = arcp::kStaF11k | arcp::kStaF11v;
	r.cur_rssi = -80;
	r.sta = mac("aa:bb:cc:dd:ee:ff");
	m.begin(arcp::MsgType::steer_req, arcp::kFlagAckReq, origin, 1U, 2U);
	(void)m.add(r);
	CHECK(m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parse_header(m.bytes());
	CHECK(h.has_value() && arcp::verify(m.bytes(), *h, ByteView()));
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::steer_req));
	arcp::SteerReq ro;
	CHECK(arcp::decode(v, ro));
	CHECK(ro.txn == 77U && ro.rcpi == 140U && ro.cur_rssi == -80 && ro.sta == r.sta);
	CHECK(!rd.next(t, v));
}

void test_rrm()
{
	arcp::BssInfo b;
	FixedString<64U> nr;
	FixedString<256U> hex;

	const std::optional<rrm::ChanBand> c1 = rrm::freq_to_chan(2437);
	CHECK(c1.has_value() && c1->channel == 6U && c1->band == arcp::kBand2g);
	const std::optional<rrm::ChanBand> c2 = rrm::freq_to_chan(5180);
	CHECK(c2.has_value() && c2->channel == 36U && c2->band == arcp::kBand5g);
	const std::optional<rrm::ChanBand> c3 = rrm::freq_to_chan(5955);
	CHECK(c3.has_value() && c3->channel == 1U && c3->band == arcp::kBand6g);
	CHECK(rrm::op_class_20mhz(arcp::kBand2g, 6U) == 81U);
	CHECK(rrm::op_class_20mhz(arcp::kBand5g, 36U) == 115U);
	CHECK(rrm::op_class_20mhz(arcp::kBand5g, 149U) == 124U);
	CHECK(rrm::op_class_20mhz(arcp::kBand6g, 37U) == 131U);
	CHECK(rrm::rcpi_to_dbm(rrm::dbm_to_rcpi(-60)) == -60);
	CHECK(rrm::dbm_to_rcpi(-110) == 0U && rrm::rcpi_to_dbm(255U) == -128);

	b.bssid = mac("02:00:00:00:01:00");
	b.bssid_info = rrm::bssid_info_build(arcp::kCapHt | arcp::kCapVht | arcp::kCapRrmNr, true);
	b.op_class = 115U;
	b.channel = 36U;
	b.phy_type = rrm::kPhyVht;
	b.mdid = 0xa1b2U;
	// BSSID | BSSID Info LE (0x1eaf incl. Mobility Domain) | 115 | 36 | 9
	CHECK(rrm::nr_build_hex(b, 0xa1b2U, nr) && nr.view() == "020000000100af1e0000732409");
	CHECK(rrm::nr_build_hex(b, 0x1111U, nr) && nr.view() == "020000000100af1a0000732409");

	const auto home = bytes_of("home");
	rrm::OpChanList one{};
	one[0] = rrm::OpChan{115U, 36U};
	CHECK(rrm::bcn_req_build_hex(one, 1U, rrm::BeaconMode::active, 50U, nullptr, view_of(home), hex));
	CHECK(hex.view() == "7324000032000" "1ffffffffffff" "0004686f6d65" "020100");
	// Several channels: Channel 255 + one AP Channel Report (51) per op class
	rrm::OpChanList three{};
	three[0] = rrm::OpChan{81U, 1U};
	three[1] = rrm::OpChan{115U, 36U};
	three[2] = rrm::OpChan{115U, 40U};
	CHECK(rrm::bcn_req_build_hex(three, 3U, rrm::BeaconMode::active, 50U, nullptr, view_of(home), hex));
	CHECK(hex.view() == "51ff000032000" "1ffffffffffff" "0004686f6d65" "020100"
			    "33025101" "3303732428");
	CHECK(!rrm::bcn_req_build_hex(three, 0U, rrm::BeaconMode::active, 50U, nullptr, ByteView(), hex));

	// op 115 ch 36 | start 8 | dur 50 | info 0 | rcpi 120 | rsni 0 | bssid | ant | tsf
	const std::optional<rrm::BeaconReport> r = rrm::bcn_rep_parse_hex(
		"7324" "0000000000000000" "3200" "00" "78" "00" "020000000100" "00" "00000000");
	CHECK(r.has_value() && r->op_class == 115U && r->channel == 36U && r->rcpi == 120U &&
	      r->duration == 50U);
	CHECK(r.has_value() && r->bssid == b.bssid && rrm::rcpi_to_dbm(r->rcpi) == -50);
	CHECK(!rrm::bcn_rep_parse_hex("7324").has_value());

	CHECK(rrm::akm_is_ft("00-0f-ac-4") && rrm::akm_is_ft("00-0f-ac-9") && !rrm::akm_is_ft("00-0f-ac-2") &&
	      !rrm::akm_is_ft("000fac-4"));
	const std::array<std::uint8_t, 3U> ext{{0U, 0U, 0x08U}};
	CHECK(rrm::ext_capab_has_btm(view_of(ext)) && !rrm::ext_capab_has_btm(view_of(ext).first(2U)));
}

void test_hapd_parsers()
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
		"AKMSuiteSelector=00-0f-ac-4\n";

	std::optional<hapd::Status> st = hapd::parse_status(status, "wlan1-1");
	CHECK(st.has_value());
	if (st.has_value()) {
		CHECK(st->freq == 5180 && st->channel == 36U && st->band == arcp::kBand5g);
		CHECK(st->num_sta == 1 && st->ssid_len == 5U && st->ssid[0] == 'g' && st->ssid[4] == 't');
		CHECK(st->bssid.b[5] == 1U && st->bw == arcp::kBw80 && st->max_txpower == 23);
		CHECK(((st->caps & arcp::kCapVht) != 0U) && ((st->caps & arcp::kCapHe) == 0U) &&
		      st->chan_util == -1);
	}
	st = hapd::parse_status(status, "wlan1");
	CHECK(st.has_value() && st->num_sta == 3);

	const std::optional<hapd::Sta> s = hapd::parse_sta(sta);
	CHECK(s.has_value());
	if (s.has_value()) {
		CHECK(s->authorized && s->signal == -67 && s->rx_bytes == 1000U && s->tx_bytes == 2000U);
		CHECK(s->inactive_ms == 120U && s->connected_s == 42U);
		CHECK(s->rx_rate_mbps == 866U && s->tx_rate_mbps == 433U);
		CHECK(s->btm_known && s->btm && s->ft_known && s->ft);
	}
	CHECK(!hapd::parse_sta("FAIL\n").has_value());
	CHECK(!hapd::parse_sta("").has_value());

	std::optional<hapd::BtmResp> br = hapd::parse_btm_resp(
		"BSS-TM-RESP aa:bb:cc:dd:ee:01 dialog_token=3 status_code=0 bss_termination_delay=0 "
		"target_bssid=02:00:00:00:02:00");
	CHECK(br.has_value() && br->status == 0 && br->has_target && br->target.b[4] == 2U);
	br = hapd::parse_btm_resp("BSS-TM-RESP aa:bb:cc:dd:ee:01 dialog_token=3 status_code=7 "
				  "bss_termination_delay=0");
	CHECK(br.has_value() && br->status == 7 && !br->has_target);
}

void test_policy()
{
	Config c;
	const PolicyConfig &p = c.pol;
	policy::SteerCtx ctx;
	policy::CandInput in;

	ctx.reason = arcp::SteerReason::rssi;
	ctx.cur_rssi = -80;
	ctx.cur_band = arcp::kBand5g;
	in.band = arcp::kBand5g;
	in.est_rssi = -65;
	in.util_pct = 20;
	CHECK(policy::score(p, ctx, in) == (-65 + 5 - ((2 * 20) / 10)));
	in.est_rssi = -75; // only 5 dB better: below hysteresis
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);
	in.est_rssi = policy::kRssiUnknown;
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);
	in.est_rssi = -60;
	in.util_pct = 85; // target too busy
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);
	in.util_pct = 20;
	in.max_sta = 10;
	in.sta_count = 10;
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);
	in.max_sta = 0;

	// Load balancing tolerates a small RSSI loss but needs a quiet target.
	ctx.reason = arcp::SteerReason::load;
	ctx.cur_rssi = -60;
	in.est_rssi = -64;
	in.util_pct = 30;
	CHECK(policy::score(p, ctx, in) != policy::kIneligible);
	in.util_pct = 60; // > util_high - lb_margin = 55
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);
	in.util_pct = 30;
	in.est_rssi = -68; // 8 dB loss > tolerance
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);

	// Band steering only towards a higher band
	ctx.reason = arcp::SteerReason::band;
	ctx.cur_band = arcp::kBand2g;
	ctx.cur_rssi = -50;
	in.band = arcp::kBand5g;
	in.est_rssi = -62;
	CHECK(policy::score(p, ctx, in) != policy::kIneligible);
	in.band = arcp::kBand2g;
	CHECK(policy::score(p, ctx, in) == policy::kIneligible);

	CHECK(policy::rssi_trigger(p, -80, 3) && !policy::rssi_trigger(p, -80, 2));
	CHECK(!policy::rssi_trigger(p, -70, 5) && !policy::rssi_trigger(p, 0, 5));
	CHECK(policy::band_trigger(p, arcp::kBand2g, -50) && !policy::band_trigger(p, arcp::kBand5g, -50));
	CHECK(policy::bss_overloaded(p, 75, 1, 0) && !policy::bss_overloaded(p, 50, 1, 0));
	CHECK(policy::bss_overloaded(p, -1, 32, 32));
	CHECK(policy::admit(p, 50, 5, 0, 0) == arcp::SteerStatus::accept);
	CHECK(policy::admit(p, 50, 9, 1, 10) == arcp::SteerStatus::capacity);
	CHECK(policy::admit(p, 90, 1, 0, 0) == arcp::SteerStatus::load);
	CHECK(policy::backoff_ms(p, 0) == 30000 && policy::backoff_ms(p, 2) == 120000);
	CHECK(policy::backoff_ms(p, 20) == p.steer_backoff_max_ms);
	CHECK(policy::util_to_pct(255) == -1 && policy::util_to_pct(128) == 50 && policy::util_to_pct(0) == 0);
}

// Expected-throughput model: the scenarios of the design note.
void test_policy_tput()
{
	Config c;
	PolicyConfig &p = c.pol;
	const std::uint16_t ht = arcp::kCapHt;
	const std::uint16_t vht = arcp::kCapHt | arcp::kCapVht;

	p.score_model = ScoreModel::tput;

	// Sigmoid quality: 500 at the midpoint, monotonic, saturating
	CHECK(policy::link_quality(p, -72) == 500);
	CHECK(policy::link_quality(p, -80) == 83 && policy::link_quality(p, -55) == 994);
	CHECK(policy::link_quality(p, -120) == 0 && policy::link_quality(p, -20) == 1000);
	CHECK(policy::link_quality(p, 0) == 0 && policy::link_quality(p, policy::kRssiUnknown) == 0);
	for (int r = -105; r < -35; r++) {
		CHECK(policy::link_quality(p, r) <= policy::link_quality(p, r + 1));
	}

	// Peak PHY rate: top MCS, short GI, x streams
	CHECK(policy::peak_mbps(ht, arcp::kBw20, 2) == 144);
	CHECK(policy::peak_mbps(vht, arcp::kBw80, 2) == 866);
	CHECK(policy::peak_mbps(vht | arcp::kCapHe, arcp::kBw80, 2) == 1202);
	CHECK(policy::peak_mbps(0U, arcp::kBw20, 2) == 54);
	CHECK(policy::expected_kbps(p, -60, 866, 40) == ((973 * 866 * 60) / 100));
	CHECK(policy::expected_kbps(p, -60, 866, -1) == (973 * 866));

	policy::SteerCtx ctx;
	policy::CandInput a;
	policy::CandInput b;

	// 1. Weak 5 GHz STA: the louder 2.4 GHz BSS loses to a fast 5 GHz one
	ctx.reason = arcp::SteerReason::rssi;
	ctx.cur_rssi = -80;
	ctx.cur_band = arcp::kBand5g;
	ctx.cur_util_pct = 30;
	ctx.cur_peak_mbps = policy::peak_mbps(vht, arcp::kBw80, 2);
	a.band = arcp::kBand5g;
	a.est_rssi = -60;
	a.util_pct = 40;
	a.peak_mbps = policy::peak_mbps(vht, arcp::kBw80, 2);
	b.band = arcp::kBand2g;
	b.est_rssi = -55;
	b.util_pct = 20;
	b.peak_mbps = policy::peak_mbps(ht, arcp::kBw20, 2);
	CHECK(policy::score(p, ctx, a) > policy::score(p, ctx, b));
	CHECK(policy::score(p, ctx, b) != policy::kIneligible);
	p.score_model = ScoreModel::linear;
	CHECK(policy::score(p, ctx, a) < policy::score(p, ctx, b));
	p.score_model = ScoreModel::tput;

	// 2. A louder but slower target that would cut throughput is refused
	ctx.cur_rssi = -77;
	ctx.cur_util_pct = 10;
	b.est_rssi = -69;
	b.util_pct = 50;
	CHECK(policy::score(p, ctx, b) == policy::kIneligible);
	p.score_model = ScoreModel::linear;
	CHECK(policy::score(p, ctx, b) != policy::kIneligible);
	p.score_model = ScoreModel::tput;

	// 3/4. Band steering only when 5 GHz is really faster
	ctx.reason = arcp::SteerReason::band;
	ctx.cur_rssi = -50;
	ctx.cur_band = arcp::kBand2g;
	ctx.cur_util_pct = 20;
	ctx.cur_peak_mbps = policy::peak_mbps(ht, arcp::kBw20, 2);
	a.est_rssi = -58;
	a.util_pct = 30;
	CHECK(policy::score(p, ctx, a) != policy::kIneligible);
	b = policy::CandInput{};
	b.band = arcp::kBand5g;
	b.est_rssi = -58;
	b.util_pct = 70;
	b.peak_mbps = policy::peak_mbps(ht, arcp::kBw20, 2);
	CHECK(policy::score(p, ctx, b) == policy::kIneligible);
	ctx.cur_rssi = -45;
	ctx.cur_util_pct = 0;
	b.est_rssi = -50;
	b.util_pct = 0; // same width, idle: < tput_gain_pct
	CHECK(policy::score(p, ctx, b) == policy::kIneligible);

	// 5. Load balancing: the STA must not lose throughput
	ctx = policy::SteerCtx{};
	ctx.reason = arcp::SteerReason::load;
	ctx.cur_rssi = -60;
	ctx.cur_band = arcp::kBand5g;
	ctx.cur_util_pct = 90;
	ctx.cur_peak_mbps = policy::peak_mbps(vht, arcp::kBw80, 2);
	a.est_rssi = -64;
	a.util_pct = 30;
	CHECK(policy::score(p, ctx, a) != policy::kIneligible);
	b = policy::CandInput{};
	b.band = arcp::kBand2g;
	b.est_rssi = -62;
	b.util_pct = 40;
	b.peak_mbps = policy::peak_mbps(ht, arcp::kBw20, 2);
	CHECK(policy::score(p, ctx, b) == policy::kIneligible);
	a.util_pct = 60; // still needs a quiet target
	CHECK(policy::score(p, ctx, a) == policy::kIneligible);

	// Hard gates apply in both models
	ctx.reason = arcp::SteerReason::manual;
	a.util_pct = 30;
	a.est_rssi = -75; // below rssi_min_target
	CHECK(policy::score(p, ctx, a) == policy::kIneligible);
	a.est_rssi = -60;
	a.accepting = false;
	CHECK(policy::score(p, ctx, a) == policy::kIneligible);
	a.accepting = true;
	a.util_pct = 85; // >= util_admit_max
	CHECK(policy::score(p, ctx, a) == policy::kIneligible);
}

template <std::size_t N>
std::array<std::uint8_t, N + 24U> air_frame(const std::array<std::uint8_t, N> &rt, std::uint8_t fc0,
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
void test_air_monitor()
{
	const Mac ta = mac("aa:bb:cc:dd:ee:02");
	// flags | channel 5745 MHz | dBm signal -55; it_len 15
	const std::array<std::uint8_t, 15U> rt{{0, 0, 15, 0, 0x2a, 0, 0, 0, 0x00, 0, 0x71, 0x16, 0, 1, 0xc9}};
	// + TSFT: channel aligned after 8-byte TSFT and flags; it_len 23
	const std::array<std::uint8_t, 23U> rt_tsft{{0, 0, 23, 0, 0x2b, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
						      0x00, 0, 0x6c, 0x09, 0, 1, 0xd0}};
	// extended present word: fields start after the second word; it_len 19
	const std::array<std::uint8_t, 19U> rt_ext{{0, 0, 19, 0, 0x2a, 0, 0, 0x80, 0, 0, 0, 0,
						     0x00, 0, 0x71, 0x16, 0, 1, 0xc9}};
	const std::array<std::uint8_t, 15U> rt_badfcs{{0, 0, 15, 0, 0x2a, 0, 0, 0, 0x40, 0, 0x71, 0x16, 0, 1, 0xc9}};
	const std::array<std::uint8_t, 14U> rt_nosig{{0, 0, 14, 0, 0x0a, 0, 0, 0, 0x00, 0, 0x71, 0x16, 0, 1}};

	auto f = rrm::radiotap_parse(view_of(air_frame(rt, 0x08U, 0x01U, ta))); // data, ToDS
	CHECK(f.has_value() && f->freq == 5745 && f->signal == -55 && !f->probe && f->ta == ta);
	CHECK(rrm::radiotap_parse(view_of(air_frame(rt, 0xc8U, 0x11U, ta))).has_value()); // QoS null
	f = rrm::radiotap_parse(view_of(air_frame(rt, 0x40U, 0x00U, ta))); // probe request
	CHECK(f.has_value() && f->probe);
	f = rrm::radiotap_parse(view_of(air_frame(rt_tsft, 0x08U, 0x01U, ta)));
	CHECK(f.has_value() && f->freq == 2412 && f->signal == -48);
	f = rrm::radiotap_parse(view_of(air_frame(rt_ext, 0x08U, 0x01U, ta)));
	CHECK(f.has_value() && f->freq == 5745 && f->signal == -55);
	CHECK(!rrm::radiotap_parse(view_of(air_frame(rt, 0x08U, 0x02U, ta))).has_value()); // FromDS
	CHECK(!rrm::radiotap_parse(view_of(air_frame(rt, 0x80U, 0x00U, ta))).has_value()); // beacon
	CHECK(!rrm::radiotap_parse(view_of(air_frame(rt_badfcs, 0x08U, 0x01U, ta))).has_value());
	CHECK(!rrm::radiotap_parse(view_of(air_frame(rt_nosig, 0x08U, 0x01U, ta))).has_value());
	const auto full = air_frame(rt, 0x08U, 0x01U, ta);
	CHECK(!rrm::radiotap_parse(view_of(full).first(full.size() - 1U)).has_value()); // truncated

	// STA_MONITOR_REQ / RESULT round trip
	const Mac origin{{2U, 0U, 0U, 0U, 0U, 1U}};
	arcp::StaMonitorReq rq;
	arcp::StaMonitorResult rs;
	arcp::Message m;

	rq.txn = 9U;
	rq.duration_ms = 1000U;
	rq.op_class = 115U;
	rq.channel = 36U;
	rq.sta = ta;
	rs.txn = 9U;
	rs.rssi = -61;
	rs.samples = 42U;
	rs.age_ms = 120U;
	rs.sta = ta;
	rs.bssid = origin;
	m.begin(arcp::MsgType::sta_monitor_report, 0U, origin, 1U, 1U);
	CHECK(m.add(rq) && m.add(rs));
	CHECK(m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parse_header(m.bytes());
	CHECK(h.has_value());
	if (h.has_value()) {
		arcp::TlvReader rd(m.bytes(), *h);
		std::uint8_t t = 0U;
		ByteView v;
		arcp::StaMonitorReq rqo;
		arcp::StaMonitorResult rso;
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::sta_monitor_req) && arcp::decode(v, rqo));
		CHECK(rqo.txn == 9U && rqo.duration_ms == 1000U && rqo.channel == 36U && rqo.sta == ta);
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::sta_monitor_result) && arcp::decode(v, rso));
		CHECK(rso.rssi == -61 && rso.samples == 42U && rso.age_ms == 120U && rso.bssid == origin);
		CHECK(!arcp::decode(v.first(20U), rso));
	}
	CHECK(arcp::msg_name(arcp::raw(arcp::MsgType::sta_monitor_req)) == "STA_MONITOR_REQ");

	// config
	Config c;
	CHECK(c.pol.amon_request && c.pol.amon_duration_ms == 1000);
	CHECK(config_line(c, "air_monitor mon0") && c.n_monitors == 1U && c.monitors[0].view() == "mon0");
	CHECK(config_line(c, "air_monitor_sim 31000") && c.monitor_sim_port == 31000U);
	CHECK(config_line(c, "amon_duration_ms 500") && c.pol.amon_duration_ms == 500);
}

// Robustness: checked number parsing, field-wise struct comparison
void test_robustness()
{
	CHECK(parse_long("42", 10, 0, 100) == std::optional<long>(42));
	CHECK(parse_long("-75", 10, -128, 0) == std::optional<long>(-75));
	CHECK(parse_long("a1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(parse_long("0xa1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(!parse_long("", 10, 0, 100).has_value());          // empty
	CHECK(!parse_long("12x", 10, 0, 100).has_value());       // junk
	CHECK(!parse_long("12 34", 10, 0, 100).has_value());     // two values
	CHECK(!parse_long("101", 10, 0, 100).has_value());       // range
	CHECK(!parse_long("99999999999999999999", 10, std::numeric_limits<long>::min(),
			  std::numeric_limits<long>::max()).has_value());
	CHECK(parse_long_tok("217 mcs 2 shortGI", 10, 0, 100000) == std::optional<long>(217));
	CHECK(parse_long_tok("7", 10, 0, 255) == std::optional<long>(7));
	CHECK(!parse_long_tok("7x bss", 10, 0, 255).has_value());
	CHECK(parse_u64("18446744073709551615") ==
	      std::optional<std::uint64_t>(std::numeric_limits<std::uint64_t>::max()));
	CHECK(!parse_u64("18446744073709551616").has_value()); // overflow
	CHECK(!parse_u64("-1").has_value() && !parse_u64("12a").has_value() && !parse_u64("").has_value());
	CHECK(parse_mac("a:b:c:d:e:f").has_value() && !parse_mac("aa:bb:cc:dd:ee").has_value() &&
	      !parse_mac("aa:bb:cc:dd:ee:ff:00").has_value() && !parse_mac("aa:bb:cc:dd:ee:fg").has_value());

	// Config values that used to become 0 silently are rejected
	Config c;
	CHECK(!config_line(c, "sim_port abc") && !config_line(c, "sim_port 70000") &&
	      !config_line(c, "sim_port 0"));
	CHECK(!config_line(c, "bss wlan0 mdid=xyz") && !config_line(c, "bss wlan0 max_sta=12abc"));
	CHECK(!config_line(c, "rssi_low 99999999999"));
	CHECK(config_line(c, "air_monitor_sim 31000") && c.monitor_sim_port == 31000U);
	CHECK(config_line(c, "bss wlan1 mdid=A1B2 max_sta=64") && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].max_sta == 64);

	// hostapd fields that do not parse are ignored or rejected
	CHECK(!hapd::parse_btm_resp("BSS-TM-RESP aa:bb:cc:dd:ee:01 status_code=x7").has_value());
	const std::optional<hapd::Sta> st = hapd::parse_sta("aa:bb:cc:dd:ee:01\nrx_bytes=-5\ntx_bytes=12\n");
	CHECK(st.has_value() && st->rx_bytes == 0U && st->tx_bytes == 12U);
	CHECK(!rrm::akm_is_ft("00-0f-ac-4x") && !rrm::akm_is_ft("00-0f-ac-"));

	// BssInfo equality ignores SSID bytes beyond ssid_len
	arcp::BssInfo a;
	arcp::BssInfo b;
	a.freq = 5180U;
	b.freq = 5180U;
	a.channel = 36U;
	b.channel = 36U;
	a.ssid_len = 4U;
	b.ssid_len = 4U;
	for (std::size_t i = 0U; i < 4U; i++) {
		a.ssid[i] = static_cast<std::uint8_t>("home"[i]);
		b.ssid[i] = static_cast<std::uint8_t>("home"[i]);
	}
	b.ssid[10] = 0xa5U; // beyond ssid_len
	CHECK(a == b);
	b.channel = 40U;
	CHECK(a != b);
	b.channel = 36U;
	b.ssid[3] = 'x';
	CHECK(a != b);
}

// Per-module log levels and config keys
void test_log()
{
	Config c;

	CHECK(logging::parse_level("debug") == std::optional<LogLevel>(LogLevel::debug));
	CHECK(logging::parse_level("err") == std::optional<LogLevel>(LogLevel::err));
	CHECK(!logging::parse_level("verbose").has_value());
	CHECK(logging::parse_module("steer") == std::optional<LogModule>(LogModule::steer));
	CHECK(logging::parse_module("config") == std::optional<LogModule>(LogModule::config));
	CHECK(!logging::parse_module("nosuch").has_value());
	CHECK(logging::module_name(LogModule::amon) == "amon" && logging::level_name(LogLevel::warn) == "warn");

	logging::set_all(LogLevel::info);
	logging::set_level(LogModule::steer, LogLevel::debug);
	CHECK(logging::level(LogModule::steer) == LogLevel::debug && logging::level(LogModule::msg) == LogLevel::info);
	CHECK(logging::enabled(LogModule::steer, LogLevel::debug) &&
	      !logging::enabled(LogModule::msg, LogLevel::debug) &&
	      logging::enabled(LogModule::msg, LogLevel::info));
	logging::set_all(LogLevel::err);
	CHECK(!logging::enabled(LogModule::steer, LogLevel::warn) &&
	      logging::enabled(LogModule::config, LogLevel::err));
	logging::set_all(LogLevel::info);

	CHECK(c.log_level == LogLevel::info && c.log_debug_mask == 0U);
	CHECK(config_line(c, "log_level warn") && c.log_level == LogLevel::warn);
	CHECK(config_line(c, "log_debug steer,amon msg") &&
	      c.log_debug_mask == ((1U << static_cast<std::uint32_t>(LogModule::steer)) |
				   (1U << static_cast<std::uint32_t>(LogModule::amon)) |
				   (1U << static_cast<std::uint32_t>(LogModule::msg))));
	CHECK(!config_line(c, "log_level verbose") && !config_line(c, "log_debug nosuch"));

	// type-safe formatting
	Line l;
	format_to(l, "a {} b {} c {} d {} e {}", -5, 7U, mac("02:00:00:00:00:01"), hex(0x1aU, 4U),
		  std::string_view("x"));
	CHECK(l.view() == "a -5 b 7 c 02:00:00:00:00:01 d 001a e x");
	l.clear();
	format_to(l, "{} {}", std::numeric_limits<std::int64_t>::min(), "extra {}");
	CHECK(l.view() == "-9223372036854775808 extra {}");
}

void test_config()
{
	Config c;

	CHECK(config_line(c, "iface br-lan") && c.n_ifaces == 1U && c.ifaces[0].view() == "br-lan");
	CHECK(config_line(c, "bss wlan0 mdid=a1b2 max_sta=32") && c.n_bss == 1U && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].max_sta == 32);
	CHECK(config_line(c, "rssi_low -72  # comment") && c.pol.rssi_low == -72);
	CHECK(config_line(c, "lb_only_idle 0") && !c.pol.lb_only_idle);
	CHECK(config_line(c, "key hex:00112233445566778899aabbccddeeff") && c.key_len == 16U);
	CHECK(!config_line(c, "bogus 1"));
	CHECK(!config_line(c, "key short"));
	CHECK(config_line(c, "ap_id 02:00:00:00:00:01") && c.ap_id_set && c.ap_id.b[5] == 1U);
	CHECK(c.pol.score_model == ScoreModel::linear && c.pol.sta_nss == 2);
	CHECK(config_line(c, "score_model 1") && c.pol.score_model == ScoreModel::tput);
	CHECK(config_line(c, "tput_gain_pct 200") && c.pol.tput_gain_pct == 200);
	CHECK(config_line(c, "beacon_mode 0") && c.pol.beacon_mode == rrm::BeaconMode::passive);
	CHECK(!config_line(c, "beacon_mode 3"));
	CHECK(config_line(c, "key a-long-passphrase") && c.key_len == 32U);
}

} // namespace

int main()
{
	test_sha256();
	test_proto_roundtrip();
	test_proto_overflow();
	test_steer_tlvs();
	test_rrm();
	test_hapd_parsers();
	test_policy();
	test_policy_tput();
	test_air_monitor();
	test_robustness();
	test_log();
	test_config();
	(void)std::printf("%d/%d checks passed\n", g_checks - g_fails, g_checks);
	return (g_fails != 0) ? 1 : 0;
}
