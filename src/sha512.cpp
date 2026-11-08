// SPDX-License-Identifier: MIT
#include "sha512.hpp"

namespace donghoa {

namespace {

constexpr std::array<std::uint64_t, 80U> K{
	0x428a2f98d728ae22U, 0x7137449123ef65cdU, 0xb5c0fbcfec4d3b2fU, 0xe9b5dba58189dbbcU,
	0x3956c25bf348b538U, 0x59f111f1b605d019U, 0x923f82a4af194f9bU, 0xab1c5ed5da6d8118U,
	0xd807aa98a3030242U, 0x12835b0145706fbeU, 0x243185be4ee4b28cU, 0x550c7dc3d5ffb4e2U,
	0x72be5d74f27b896fU, 0x80deb1fe3b1696b1U, 0x9bdc06a725c71235U, 0xc19bf174cf692694U,
	0xe49b69c19ef14ad2U, 0xefbe4786384f25e3U, 0x0fc19dc68b8cd5b5U, 0x240ca1cc77ac9c65U,
	0x2de92c6f592b0275U, 0x4a7484aa6ea6e483U, 0x5cb0a9dcbd41fbd4U, 0x76f988da831153b5U,
	0x983e5152ee66dfabU, 0xa831c66d2db43210U, 0xb00327c898fb213fU, 0xbf597fc7beef0ee4U,
	0xc6e00bf33da88fc2U, 0xd5a79147930aa725U, 0x06ca6351e003826fU, 0x142929670a0e6e70U,
	0x27b70a8546d22ffcU, 0x2e1b21385c26c926U, 0x4d2c6dfc5ac42aedU, 0x53380d139d95b3dfU,
	0x650a73548baf63deU, 0x766a0abb3c77b2a8U, 0x81c2c92e47edaee6U, 0x92722c851482353bU,
	0xa2bfe8a14cf10364U, 0xa81a664bbc423001U, 0xc24b8b70d0f89791U, 0xc76c51a30654be30U,
	0xd192e819d6ef5218U, 0xd69906245565a910U, 0xf40e35855771202aU, 0x106aa07032bbd1b8U,
	0x19a4c116b8d2d0c8U, 0x1e376c085141ab53U, 0x2748774cdf8eeb99U, 0x34b0bcb5e19b48a8U,
	0x391c0cb3c5c95a63U, 0x4ed8aa4ae3418acbU, 0x5b9cca4f7763e373U, 0x682e6ff3d6b2b8a3U,
	0x748f82ee5defb2fcU, 0x78a5636f43172f60U, 0x84c87814a1f0ab72U, 0x8cc702081a6439ecU,
	0x90befffa23631e28U, 0xa4506cebde82bde9U, 0xbef9a3f7b2c67915U, 0xc67178f2e372532bU,
	0xca273eceea26619cU, 0xd186b8c721c0c207U, 0xeada7dd6cde0eb1eU, 0xf57d4f7fee6ed178U,
	0x06f067aa72176fbaU, 0x0a637dc5a2c898a6U, 0x113f9804bef90daeU, 0x1b710b35131c471bU,
	0x28db77f523047d84U, 0x32caab7b40c72493U, 0x3c9ebe0a15c9bebcU, 0x431d67c49c100d4cU,
	0x4cc5d4becb3e42b6U, 0x597f299cfc657e2aU, 0x5fcb6fab3ad6faecU, 0x6c44198c4a475817U,
};

constexpr std::array<std::uint64_t, 8U> IV{
	0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU, 0xa54ff53a5f1d36f1U,
	0x510e527fade682d1U, 0x9b05688c2b3e6c1fU, 0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U,
};

constexpr std::uint64_t ror(std::uint64_t x, std::uint64_t n) noexcept
{
	return (x >> n) | (x << (64U - n));
}

std::uint64_t getBe64(const std::array<std::uint8_t, 128U> &b, std::size_t off) noexcept
{
	std::uint64_t v = 0U;
	for (std::size_t i = 0U; i < 8U; i++) {
		v = (v << 8U) | static_cast<std::uint64_t>(b[off + i]);
	}
	return v;
}

} // namespace

Sha512::Sha512() noexcept : mH(IV) {}

void Sha512::block() noexcept
{
	std::array<std::uint64_t, 80U> w{};

	for (std::size_t i = 0U; i < 16U; i++) {
		w[i] = getBe64(mBuf, 8U * i);
	}
	for (std::size_t i = 16U; i < 80U; i++) {
		const std::uint64_t s0 = ror(w[i - 15U], 1U) ^ ror(w[i - 15U], 8U) ^ (w[i - 15U] >> 7U);
		const std::uint64_t s1 = ror(w[i - 2U], 19U) ^ ror(w[i - 2U], 61U) ^ (w[i - 2U] >> 6U);
		w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
	}
	std::array<std::uint64_t, 8U> v = mH; // a..h
	for (std::size_t i = 0U; i < 80U; i++) {
		const std::uint64_t e = v[4U];
		const std::uint64_t a = v[0U];
		const std::uint64_t t1 = v[7U] + (ror(e, 14U) ^ ror(e, 18U) ^ ror(e, 41U)) +
					 ((e & v[5U]) ^ ((~e) & v[6U])) + K[i] + w[i];
		const std::uint64_t t2 = (ror(a, 28U) ^ ror(a, 34U) ^ ror(a, 39U)) +
					 ((a & v[1U]) ^ (a & v[2U]) ^ (v[1U] & v[2U]));
		v[7U] = v[6U];
		v[6U] = v[5U];
		v[5U] = e;
		v[4U] = v[3U] + t1;
		v[3U] = v[2U];
		v[2U] = v[1U];
		v[1U] = a;
		v[0U] = t1 + t2;
	}
	for (std::size_t i = 0U; i < 8U; i++) {
		mH[i] += v[i];
	}
}

void Sha512::update(ByteView data) noexcept
{
	mLen += data.size();
	for (std::size_t i = 0U; i < data.size(); i++) {
		mBuf[mFill] = data[i];
		mFill++;
		if (mFill == mBuf.size()) {
			block();
			mFill = 0U;
		}
	}
}

Digest512 Sha512::finish() noexcept
{
	const std::uint64_t bits = mLen * 8U;
	const std::array<std::uint8_t, 1U> pad{0x80U};
	const std::array<std::uint8_t, 1U> zero{0U};
	std::array<std::uint8_t, 16U> lenb{}; // 128-bit length, high half 0
	Digest512 out{};

	update(viewOf(pad));
	while (mFill != 112U) {
		update(viewOf(zero));
	}
	for (std::size_t i = 0U; i < 8U; i++) {
		lenb[8U + i] = static_cast<std::uint8_t>((bits >> (56U - (8U * i))) & 0xffU);
	}
	update(viewOf(lenb));
	for (std::size_t i = 0U; i < 8U; i++) {
		for (std::size_t j = 0U; j < 8U; j++) {
			out[(8U * i) + j] = static_cast<std::uint8_t>((mH[i] >> (56U - (8U * j))) & 0xffU);
		}
	}
	return out;
}

Digest512 computeSha512(ByteView data) noexcept
{
	Sha512 s;
	s.update(data);
	return s.finish();
}

} // namespace donghoa
