// SPDX-License-Identifier: MIT
// Unit tests: SHA-256 / HMAC / PBKDF2, SHA-512, Ed25519 (src/core/sha256, sha512, ed25519).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "unit.hpp"

#include "core/ed25519.hpp"
#include "core/sha256.hpp"
#include "core/sha512.hpp"

using namespace donghoa;

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

	// PBKDF2-HMAC-SHA256 (RFC 7914 §11 / widely published vectors)
	const auto pw = bytesOf("password");
	const auto salt = bytesOf("salt");
	CHECK(hexs(pbkdf2Sha256(viewOf(pw), viewOf(salt), 1U)).view() ==
	      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
	CHECK(hexs(pbkdf2Sha256(viewOf(pw), viewOf(salt), 2U)).view() ==
	      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
	CHECK(hexs(pbkdf2Sha256(viewOf(pw), viewOf(salt), 4096U)).view() ==
	      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
}

void testSha512()
{
	const auto abc = bytesOf("abc");
	CHECK(hexs(computeSha512(viewOf(abc))).view() ==
	      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
	      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	CHECK(hexs(computeSha512(ByteView())).view() ==
	      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
	      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
	// 112 bytes: the length no longer fits the first block
	const auto two = bytesOf("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
				 "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
	CHECK(hexs(computeSha512(viewOf(two))).view() ==
	      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
	      "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

// RFC 8032 §7.1 tests 1-3, then rejections. These also check the curve
// constants of ed25519.cpp: a wrong D, base point or sqrt(-1) breaks them.
void testEd25519()
{
	struct Vec {
		std::string_view seed;
		std::string_view msg;
		std::string_view pub;
		std::string_view sig;
	};
	const std::array<Vec, 3U> vecs{{
		{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
		 "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		 "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
		 "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
		 "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		 "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
		 "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
		{"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
		 "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		 "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
		 "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	}};
	for (const Vec &v : vecs) {
		const ed25519::KeyPair kp = ed25519::keyPairFromSeed(unhex<32U>(v.seed));
		std::array<std::uint8_t, 2U> msg{};
		const std::optional<std::size_t> n = hexDecode(v.msg, spanOf(msg));
		const ByteView m = viewOf(msg).first(n.has_value() ? *n : 0U);
		const ed25519::Signature sig = ed25519::sign(kp, m);
		CHECK(hexs(kp.pub).view() == v.pub);
		CHECK(hexs(sig).view() == v.sig);
		CHECK(ed25519::verify(kp.pub, m, sig));
	}
	const ed25519::KeyPair kp = ed25519::keyPairFromSeed(unhex<32U>(vecs[1U].seed));
	const ed25519::KeyPair other = ed25519::keyPairFromSeed(unhex<32U>(vecs[2U].seed));
	auto msg = bytesOf("ARCP HELLO");
	const ed25519::Signature sig = ed25519::sign(kp, viewOf(msg));
	CHECK(ed25519::verify(kp.pub, viewOf(msg), sig));
	CHECK(!ed25519::verify(other.pub, viewOf(msg), sig));     // another AP's key
	ed25519::Signature bad = sig;
	bad[3U] = static_cast<std::uint8_t>(bad[3U] ^ 0x10U);     // R changed
	CHECK(!ed25519::verify(kp.pub, viewOf(msg), bad));
	bad = sig;
	bad[40U] = static_cast<std::uint8_t>(bad[40U] ^ 0x01U);   // S changed
	CHECK(!ed25519::verify(kp.pub, viewOf(msg), bad));
	// S + L: same value mod L, but not canonical (malleability)
	constexpr std::array<std::uint8_t, 32U> L{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	};
	bad = sig;
	unsigned carry = 0U;
	for (std::size_t i = 0U; i < 32U; i++) {
		const unsigned v = static_cast<unsigned>(bad[32U + i]) + L[i] + carry;
		bad[32U + i] = static_cast<std::uint8_t>(v & 0xffU);
		carry = v >> 8U;
	}
	CHECK(carry == 0U && !ed25519::verify(kp.pub, viewOf(msg), bad));
	msg[0U] = static_cast<std::uint8_t>(msg[0U] ^ 1U);              // message changed
	CHECK(!ed25519::verify(kp.pub, viewOf(msg), sig));
	CHECK(ed25519::isValidPublicKey(kp.pub));
	ed25519::PublicKey notOnCurve{};
	notOnCurve[0U] = 2U; // y = 2 has no x on the curve
	CHECK(!ed25519::isValidPublicKey(notOnCurve));
	CHECK(!ed25519::verify(notOnCurve, viewOf(msg), sig));
}
