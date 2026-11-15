// SPDX-License-Identifier: MIT
// Unit tests: enrollment trust table (src/core/trust).
#include <cstdint>
#include <optional>

#include "unit.hpp"

#include "core/ed25519.hpp"
#include "core/proto.hpp"
#include "core/trust.hpp"

using namespace donghoa;

// Enrollment trust table: last-writer-wins merge, approve / revoke, file form.
void testTrust()
{
	const Mac a = mac("02:00:00:00:00:01");
	const Mac b = mac("02:00:00:00:00:02");
	const ed25519::PublicKey ka = ed25519::keyPairFromSeed(unhex<32U>(
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")).pub;
	const ed25519::PublicKey kb = ed25519::keyPairFromSeed(unhex<32U>(
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")).pub;
	const ed25519::PublicKey kb2 = ed25519::keyPairFromSeed(unhex<32U>(
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).pub;
	trust::Table t;
	trust::Record self;
	self.used = true;
	self.apId = a;
	self.pub = ka;
	CHECK(trust::merge(t, self) && !trust::merge(t, self));         // added once
	CHECK(trust::trustedKey(t, a) != nullptr && trust::trustedKey(t, b) == nullptr);
	CHECK(trust::countTrustedOthers(t, a) == 0U);
	CHECK(trust::approve(t, b, kb));                                 // generation 1
	CHECK(trust::find(t, b)->gen == 1U && trust::countTrustedOthers(t, a) == 1U);
	trust::Table other = t;                                          // a peer's copy
	CHECK(trust::revoke(t, b));                                      // generation 2, revoked
	CHECK(trust::trustedKey(t, b) == nullptr && trust::find(t, b)->gen == 2U);
	// the stale copy cannot undo the revocation; the revocation reaches it
	CHECK(!trust::merge(t, *trust::find(other, b)));
	CHECK(trust::merge(other, *trust::find(t, b)) && trust::trustedKey(other, b) == nullptr);
	// a re-flashed AP: approving its new key wins over the revocation
	CHECK(trust::approve(t, b, kb2) && trust::find(t, b)->gen == 3U);
	CHECK(trust::trustedKey(t, b) != nullptr && *trust::trustedKey(t, b) == kb2);
	CHECK(trust::merge(other, *trust::find(t, b)) && *trust::trustedKey(other, b) == kb2);
	// same generation: revoked wins, then the larger key (deterministic)
	trust::Record r1 = *trust::find(t, b);
	r1.revoked = true;
	CHECK(trust::merge(t, r1) && trust::trustedKey(t, b) == nullptr);
	trust::Record r2 = r1;
	r2.revoked = false;
	CHECK(!trust::merge(t, r2));
	CHECK(!trust::revoke(t, mac("02:00:00:00:00:09")));              // unknown
	// file form round trip
	t.enrolled = true;
	trust::Text text;
	trust::saveText(t, text);
	trust::Table back;
	CHECK(trust::loadText(back, text.view()) && back.enrolled);
	CHECK(trust::find(back, b) != nullptr && trust::find(back, b)->revoked && trust::find(back, b)->gen == 3U);
	CHECK(trust::trustedKey(back, a) != nullptr && *trust::trustedKey(back, a) == ka);
	trust::Table bad;
	CHECK(!trust::loadText(bad, "trusted 02:00:00:00:00:01 abcd 1\n"));
	CHECK(!trust::loadText(bad, "bogus line\n"));
	CHECK(trust::loadText(bad, "# comment only\n\n"));
	// fingerprint: 4 groups of 4 hex digits, differs between keys
	const trust::Fingerprint fa = trust::fingerprint(ka);
	CHECK(fa.view().size() == 19U && fa.view()[4] == '-' && fa.view() != trust::fingerprint(kb).view());
	// TRUST_REC / ENROLL_KEY TLVs
	arcp::TrustRecord w;
	w.apId = b;
	w.pub = kb;
	w.revoked = true;
	w.gen = 0x01020304U;
	arcp::Message m;
	m.begin(arcp::MsgType::TRUST, 0U, a, 1U, 1U);
	CHECK(m.add(w) && m.addEnrollKey(ka) && m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value());
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t tt = 0U;
	ByteView v;
	arcp::TrustRecord wo;
	CHECK(rd.next(tt, v) && tt == arcp::raw(arcp::Tlv::TRUST_REC) && arcp::decode(v, wo));
	CHECK(wo.apId == b && wo.pub == kb && wo.revoked && wo.gen == 0x01020304U);
	ed25519::PublicKey ko{};
	CHECK(rd.next(tt, v) && tt == arcp::raw(arcp::Tlv::ENROLL_KEY) && arcp::decodeEnrollKey(v, ko) && ko == ka);
	CHECK(arcp::msgName(arcp::raw(arcp::MsgType::ENROLL_REQ)) == "ENROLL_REQ");
}
