// SPDX-License-Identifier: MIT
#include "sha256.hpp"

namespace donghoa {

namespace {

constexpr std::array<std::uint32_t, 64U> K{
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
	0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
	0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
	0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
	0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
	0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
	0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
	0xc67178f2U,
};

constexpr std::array<std::uint32_t, 8U> IV{
	0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
	0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

constexpr std::uint32_t ror(std::uint32_t x, std::uint32_t n) noexcept
{
	return (x >> n) | (x << (32U - n));
}

} // namespace

Sha256::Sha256() noexcept : mH(IV) {}

void Sha256::block() noexcept
{
	std::array<std::uint32_t, 64U> w{};

	for (std::size_t i = 0U; i < 16U; i++) {
		w[i] = getBe32(viewOf(mBuf), 4U * i);
	}
	for (std::size_t i = 16U; i < 64U; i++) {
		const std::uint32_t s0 = ror(w[i - 15U], 7U) ^ ror(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
		const std::uint32_t s1 = ror(w[i - 2U], 17U) ^ ror(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
		w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
	}
	std::uint32_t a = mH[0U];
	std::uint32_t b = mH[1U];
	std::uint32_t c = mH[2U];
	std::uint32_t d = mH[3U];
	std::uint32_t e = mH[4U];
	std::uint32_t f = mH[5U];
	std::uint32_t g = mH[6U];
	std::uint32_t h = mH[7U];
	for (std::size_t i = 0U; i < 64U; i++) {
		const std::uint32_t t1 = h + (ror(e, 6U) ^ ror(e, 11U) ^ ror(e, 25U)) +
					 ((e & f) ^ ((~e) & g)) + K[i] + w[i];
		const std::uint32_t t2 = (ror(a, 2U) ^ ror(a, 13U) ^ ror(a, 22U)) +
					 ((a & b) ^ (a & c) ^ (b & c));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	mH[0U] += a;
	mH[1U] += b;
	mH[2U] += c;
	mH[3U] += d;
	mH[4U] += e;
	mH[5U] += f;
	mH[6U] += g;
	mH[7U] += h;
}

void Sha256::update(ByteView data) noexcept
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

Digest Sha256::finish() noexcept
{
	const std::uint64_t bits = mLen * 8U;
	const std::array<std::uint8_t, 1U> pad{0x80U};
	const std::array<std::uint8_t, 1U> zero{0U};
	std::array<std::uint8_t, 8U> lenb{};
	Digest out{};

	update(viewOf(pad));
	while (mFill != 56U) {
		update(viewOf(zero));
	}
	for (std::size_t i = 0U; i < 8U; i++) {
		lenb[i] = static_cast<std::uint8_t>((bits >> (56U - (8U * i))) & 0xffU);
	}
	update(viewOf(lenb));
	for (std::size_t i = 0U; i < 8U; i++) {
		putBe32(spanOf(out), 4U * i, mH[i]);
	}
	return out;
}

Digest computeSha256(ByteView data) noexcept
{
	Sha256 s;
	s.update(data);
	return s.finish();
}

Digest computeHmacSha256(ByteView key, ByteView msg) noexcept
{
	std::array<std::uint8_t, 64U> k{};
	std::array<std::uint8_t, 64U> pad{};

	if (key.size() > k.size()) {
		const Digest kd = computeSha256(key);
		(void)copyBytes(spanOf(k), viewOf(kd));
	} else {
		(void)copyBytes(spanOf(k), key);
	}
	for (std::size_t i = 0U; i < pad.size(); i++) {
		pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36U);
	}
	Sha256 inner;
	inner.update(viewOf(pad));
	inner.update(msg);
	const Digest ih = inner.finish();

	for (std::size_t i = 0U; i < pad.size(); i++) {
		pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5cU);
	}
	Sha256 outer;
	outer.update(viewOf(pad));
	outer.update(viewOf(ih));
	return outer.finish();
}

} // namespace donghoa
