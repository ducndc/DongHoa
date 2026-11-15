// SPDX-License-Identifier: MIT
// Unit tests: ARCP messages and TLVs, signatures, replay window (src/core/proto).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "unit.hpp"

#include "core/ed25519.hpp"
#include "core/proto.hpp"

using namespace donghoa;

// SIG TLV: signed by finish(), checked by verifySig(), alone or with AUTH.
void testSignedMessage()
{
	const Mac origin{{2U}};
	const ed25519::KeyPair kp = ed25519::keyPairFromSeed(unhex<32U>(
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
	const ed25519::KeyPair other = ed25519::keyPairFromSeed(unhex<32U>(
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"));
	const auto key = bytesOf("0123456789abcdef");
	arcp::StaEvent e;
	e.sta = mac("aa:bb:cc:dd:ee:ff");
	for (int withKey = 0; withKey < 2; withKey++) {
		const ByteView k = (withKey == 1) ? viewOf(key) : ByteView();
		arcp::Message m;
		m.begin(arcp::MsgType::STA_EVENT, 0U, origin, 7U, 3U);
		CHECK(m.add(e));
		CHECK(m.finish(k, &kp));
		std::array<std::uint8_t, arcp::MAX_PAYLOAD> f{};
		const std::size_t len = copyBytes(spanOf(f), m.bytes());
		const std::optional<arcp::Header> h = arcp::parseHeader(viewOf(f).first(len));
		CHECK(h.has_value());
		if (!h.has_value()) {
			return;
		}
		CHECK((h->flags & arcp::FLAG_SIG) != 0U);
		CHECK(arcp::verify(viewOf(f).first(len), *h, k));
		CHECK(arcp::verifySig(viewOf(f).first(len), *h, kp.pub));
		CHECK(!arcp::verifySig(viewOf(f).first(len), *h, other.pub));
		// the TLV reader still sees the payload TLV first
		arcp::TlvReader rd(viewOf(f).first(len), *h);
		std::uint8_t t = 0U;
		ByteView v;
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::STA_EVENT));
		CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::SIG) && v.size() == arcp::SIG_LEN);
		// a changed TLV byte breaks the signature
		f[arcp::HDR_LEN + 5U] = static_cast<std::uint8_t>(f[arcp::HDR_LEN + 5U] ^ 1U);
		CHECK(!arcp::verifySig(viewOf(f).first(len), *h, kp.pub));
	}
	// unsigned message: no SIG TLV to check
	arcp::Message u;
	u.begin(arcp::MsgType::STA_EVENT, 0U, origin, 7U, 4U);
	CHECK(u.add(e) && u.finish(viewOf(key)));
	const std::optional<arcp::Header> hu = arcp::parseHeader(u.bytes());
	CHECK(hu.has_value() && !arcp::verifySig(u.bytes(), *hu, kp.pub));
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

// Liveness CHALLENGE / RESPONSE: nonce TLVs round trip, short ones refused.
void testChallengeTlvs()
{
	const Mac origin{{2U}};
	arcp::Nonce n{};
	for (std::size_t i = 0U; i < n.size(); i++) {
		n[i] = static_cast<std::uint8_t>(0xa0U + i);
	}
	arcp::Message m;
	m.begin(arcp::MsgType::CHALLENGE, 0U, origin, 5U, 9U);
	CHECK(m.addNonce(arcp::Tlv::CHALLENGE, n));
	const auto key = bytesOf("0123456789abcdef");
	CHECK(m.finish(viewOf(key)));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value() && arcp::verify(m.bytes(), *h, viewOf(key)));
	if (!h.has_value()) {
		return;
	}
	CHECK(arcp::msgName(h->type) == "CHALLENGE");
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t t = 0U;
	ByteView v;
	CHECK(rd.next(t, v) && t == arcp::raw(arcp::Tlv::CHALLENGE) && v.size() == arcp::NONCE_LEN);
	arcp::Nonce o{};
	CHECK(arcp::decodeNonce(v, o) && arcp::ctEqual(viewOf(o), viewOf(n)));
	CHECK(!arcp::decodeNonce(v.first(15U), o));
	CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::RESPONSE)) == "RESPONSE");
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::RESPONSE)) == "RESPONSE");
	o[3] = static_cast<std::uint8_t>(o[3] ^ 1U);
	CHECK(!arcp::ctEqual(viewOf(o), viewOf(n)));
	CHECK(!arcp::ctEqual(viewOf(n).first(8U), viewOf(n)));
}

// Replay window (arcp::acceptSeq, behind acceptPeerSeq)
void testReplayWindow()
{
	arcp::ReplayWindow w;
	arcp::resetSeq(w, 7U, 100U);                    // boot verified by CHALLENGE / RESPONSE
	CHECK(!arcp::acceptSeq(w, 7U, 100U));            // duplicate (other port / retransmission)
	CHECK(arcp::acceptSeq(w, 7U, 101U));             // in order
	CHECK(arcp::acceptSeq(w, 7U, 105U));             // ahead, gap left
	CHECK(arcp::acceptSeq(w, 7U, 103U));             // late, inside the window, not seen
	CHECK(!arcp::acceptSeq(w, 7U, 103U));            // ... but only once
	CHECK(!arcp::acceptSeq(w, 7U, 101U));
	CHECK(arcp::acceptSeq(w, 7U, 105U + 63U));       // window slides
	CHECK(arcp::acceptSeq(w, 7U, 106U));             // still inside (62 back), unseen
	CHECK(!arcp::acceptSeq(w, 7U, 104U));            // 64 back: outside, dropped
	CHECK(arcp::acceptSeq(w, 7U, 105U + 63U + 200U)); // big jump clears the window
	CHECK(!arcp::acceptSeq(w, 7U, 105U + 63U));
	// Any other boot_id, earlier or later, is refused and leaves the window
	// alone: only a verified RESPONSE adopts a boot (resetSeq).
	CHECK(!arcp::acceptSeq(w, 6U, 500U) && w.bootId == 7U);
	CHECK(!arcp::acceptSeq(w, 9U, 1U) && w.bootId == 7U);
	CHECK(!arcp::acceptSeq(w, 7U, 105U + 63U));      // still a duplicate
	arcp::resetSeq(w, 9U, 1U);                      // the peer restarted, verified
	CHECK(w.bootId == 9U && w.seqHi == 1U && w.seqWin == 1U);
	CHECK(!arcp::acceptSeq(w, 9U, 1U) && arcp::acceptSeq(w, 9U, 2U));
	CHECK(!arcp::acceptSeq(w, 7U, 1000U));           // the old boot is gone
	CHECK(arcp::isSeqNew(w, 9U, 3U) && !arcp::isSeqNew(w, 9U, 2U) && !arcp::isSeqNew(w, 8U, 3U));
	CHECK(arcp::acceptSeq(w, 9U, 3U));               // isSeqNew changed nothing
	arcp::ReplayWindow fresh;                        // nothing verified yet
	CHECK(!arcp::acceptSeq(fresh, 0U, 1U) && !arcp::acceptSeq(fresh, 5U, 1U));
}
