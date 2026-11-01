// SPDX-License-Identifier: MIT
#include "sha256.hpp"

namespace donghoa {

namespace {

constexpr std::array<std::uint32_t, 64U> kK{
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

constexpr std::array<std::uint32_t, 8U> kIv{
	0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
	0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

constexpr std::uint32_t ror(std::uint32_t x, std::uint32_t n) noexcept
{
	return (x >> n) | (x << (32U - n));
}

} // namespace

Sha256::Sha256() noexcept : h_(kIv) {}

void Sha256::block() noexcept
{
	std::array<std::uint32_t, 64U> w{};

	for (std::size_t i = 0U; i < 16U; i++) {
		w[i] = get_be32(view_of(buf_), 4U * i);
	}
	for (std::size_t i = 16U; i < 64U; i++) {
		const std::uint32_t s0 = ror(w[i - 15U], 7U) ^ ror(w[i - 15U], 18U) ^ (w[i - 15U] >> 3U);
		const std::uint32_t s1 = ror(w[i - 2U], 17U) ^ ror(w[i - 2U], 19U) ^ (w[i - 2U] >> 10U);
		w[i] = w[i - 16U] + s0 + w[i - 7U] + s1;
	}
	std::uint32_t a = h_[0U];
	std::uint32_t b = h_[1U];
	std::uint32_t c = h_[2U];
	std::uint32_t d = h_[3U];
	std::uint32_t e = h_[4U];
	std::uint32_t f = h_[5U];
	std::uint32_t g = h_[6U];
	std::uint32_t h = h_[7U];
	for (std::size_t i = 0U; i < 64U; i++) {
		const std::uint32_t t1 = h + (ror(e, 6U) ^ ror(e, 11U) ^ ror(e, 25U)) +
					 ((e & f) ^ ((~e) & g)) + kK[i] + w[i];
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
	h_[0U] += a;
	h_[1U] += b;
	h_[2U] += c;
	h_[3U] += d;
	h_[4U] += e;
	h_[5U] += f;
	h_[6U] += g;
	h_[7U] += h;
}

void Sha256::update(ByteView data) noexcept
{
	len_ += data.size();
	for (std::size_t i = 0U; i < data.size(); i++) {
		buf_[fill_] = data[i];
		fill_++;
		if (fill_ == buf_.size()) {
			block();
			fill_ = 0U;
		}
	}
}

Digest Sha256::finish() noexcept
{
	const std::uint64_t bits = len_ * 8U;
	const std::array<std::uint8_t, 1U> pad{0x80U};
	const std::array<std::uint8_t, 1U> zero{0U};
	std::array<std::uint8_t, 8U> lenb{};
	Digest out{};

	update(view_of(pad));
	while (fill_ != 56U) {
		update(view_of(zero));
	}
	for (std::size_t i = 0U; i < 8U; i++) {
		lenb[i] = static_cast<std::uint8_t>((bits >> (56U - (8U * i))) & 0xffU);
	}
	update(view_of(lenb));
	for (std::size_t i = 0U; i < 8U; i++) {
		put_be32(span_of(out), 4U * i, h_[i]);
	}
	return out;
}

Digest sha256(ByteView data) noexcept
{
	Sha256 s;
	s.update(data);
	return s.finish();
}

Digest hmac_sha256(ByteView key, ByteView msg) noexcept
{
	std::array<std::uint8_t, 64U> k{};
	std::array<std::uint8_t, 64U> pad{};

	if (key.size() > k.size()) {
		const Digest kd = sha256(key);
		(void)copy_bytes(span_of(k), view_of(kd));
	} else {
		(void)copy_bytes(span_of(k), key);
	}
	for (std::size_t i = 0U; i < pad.size(); i++) {
		pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36U);
	}
	Sha256 inner;
	inner.update(view_of(pad));
	inner.update(msg);
	const Digest ih = inner.finish();

	for (std::size_t i = 0U; i < pad.size(); i++) {
		pad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5cU);
	}
	Sha256 outer;
	outer.update(view_of(pad));
	outer.update(view_of(ih));
	return outer.finish();
}

} // namespace donghoa
