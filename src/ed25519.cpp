// SPDX-License-Identifier: MIT
// Ed25519 (RFC 8032). Field elements mod p = 2^255 - 19 are 10 signed limbs
// in radix 2^25.5 (as in ref10); points use extended coordinates (X, Y, Z, T)
// with the unified addition law and a dedicated doubling. Signed arithmetic avoids shifts of negative
// values: floor division by powers of two is written out (floorDiv).
#include "ed25519.hpp"

#include "sha512.hpp"

namespace donghoa {
namespace ed25519 {

namespace {

using Fe = std::array<std::int64_t, 10U>;
using Ge = std::array<Fe, 4U>; // X, Y, Z, T

// Limb i holds bits [POS[i], POS[i + 1]) of the value: 26, 25, 26, ... bits
// (radix 2^25.5). Every Fe operation returns a carried element, |limb| about
// 2^25 at most, so a product sum (10 terms, x2 x19) stays below 2^59.
constexpr std::array<std::size_t, 11U> POS{0U, 26U, 51U, 77U, 102U, 128U, 153U, 179U, 204U, 230U, 255U};
constexpr std::array<std::uint32_t, 10U> SHIFT{26U, 25U, 26U, 25U, 26U, 25U, 26U, 25U, 26U, 25U};
constexpr std::array<std::int64_t, 10U> RADIX{1 << 26, 1 << 25, 1 << 26, 1 << 25, 1 << 26,
					      1 << 25, 1 << 26, 1 << 25, 1 << 26, 1 << 25};
// floor(v / 2^k) as an unsigned shift of v + 2^62 (|v| < 2^62 here): defined
// behaviour, no branch.
constexpr std::uint64_t BIAS = static_cast<std::uint64_t>(1) << 62U;

constexpr std::int64_t shiftDown(std::int64_t v, std::uint32_t k) noexcept
{
	return static_cast<std::int64_t>((static_cast<std::uint64_t>(v) + BIAS) >> k) -
	       static_cast<std::int64_t>(BIAS >> k);
}

// Curve constants, checked by the unit tests: D = -121665/121666, D2 = 2 D,
// SQRT_M1 = sqrt(-1), (BX, BY) the base point.
constexpr Fe FE_ZERO{};
constexpr Fe FE_ONE{1};
constexpr Fe D{56195235, 13857412, 51736253, 6949390, 114729,
	       24766616, 60832955, 30306712, 48412415, 21499315};
constexpr Fe D2{45281625, 27714825, 36363642, 13898781, 229458,
		15978800, 54557047, 27058993, 29715967, 9444199};
constexpr Fe BX{52811034, 25909283, 16144682, 17082669, 27570973,
		30858332, 40966398, 8378388, 20764389, 8758491};
constexpr Fe BY{40265304, 26843545, 13421772, 20132659, 26843545,
		6710886, 53687091, 13421772, 40265318, 26843545};
constexpr Fe SQRT_M1{34513072, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654, 31548777, 326685,
		     11406482};
// Group order L = 2^252 + 27742317777372353535851937790883648493, bytes LE.
constexpr std::array<std::int64_t, 32U> L{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

// floor(v / pow2) for a power of two, for negative v too (scalar code).
constexpr std::int64_t floorDiv(std::int64_t v, std::int64_t pow2) noexcept
{
	return (v >= 0) ? (v / pow2) : -(((-v) + (pow2 - 1)) / pow2);
}

std::uint8_t lowByte(std::int64_t v) noexcept
{
	return static_cast<std::uint8_t>(static_cast<std::uint64_t>(v) & 0xffU);
}

// Rounded carries: each limb ends within half its radix (2^255 = 19 mod p).
void carry(Fe &h) noexcept
{
	for (std::size_t i = 0U; i < 10U; i++) {
		const std::int64_t c = shiftDown(h[i] + (RADIX[i] / 2), SHIFT[i]);
		h[i] -= c * RADIX[i];
		if (i < 9U) {
			h[i + 1U] += c;
		} else {
			h[0U] += 19 * c;
		}
	}
	const std::int64_t c = shiftDown(h[0U] + (RADIX[0U] / 2), SHIFT[0U]);
	h[0U] -= c * RADIX[0U];
	h[1U] += c;
}

// Exact (floor) carries: limbs into [0, radix), wrapping the top with 19.
void carryFloor(Fe &h) noexcept
{
	for (std::size_t i = 0U; i < 10U; i++) {
		const std::int64_t c = shiftDown(h[i], SHIFT[i]);
		h[i] -= c * RADIX[i];
		if (i < 9U) {
			h[i + 1U] += c;
		} else {
			h[0U] += 19 * c;
		}
	}
}

// Constant-time: swap p and q when b == 1.
void cswap(Fe &p, Fe &q, std::uint32_t b) noexcept
{
	const std::uint64_t mask = 0U - static_cast<std::uint64_t>(b);
	for (std::size_t i = 0U; i < p.size(); i++) {
		const std::uint64_t pi = static_cast<std::uint64_t>(p[i]);
		const std::uint64_t qi = static_cast<std::uint64_t>(q[i]);
		const std::uint64_t t = mask & (pi ^ qi);
		p[i] = static_cast<std::int64_t>(pi ^ t);
		q[i] = static_cast<std::int64_t>(qi ^ t);
	}
}

// Canonical little-endian encoding (value mod p, top bit 0).
void pack(std::array<std::uint8_t, 32U> &o, const Fe &n) noexcept
{
	Fe h = n;
	carry(h);
	carryFloor(h);
	carryFloor(h);
	carryFloor(h);
	// h is now in [0, 2^255): subtract p once if h >= p, i.e. h + 19 >= 2^255
	std::int64_t q = h[0U] + 19;
	for (std::size_t i = 0U; i < 10U; i++) {
		q = shiftDown(q, SHIFT[i]);
		if (i < 9U) {
			q += h[i + 1U];
		}
	}
	h[0U] += 19 * q;
	for (std::size_t i = 0U; i < 9U; i++) {
		const std::int64_t c = shiftDown(h[i], SHIFT[i]);
		h[i] -= c * RADIX[i];
		h[i + 1U] += c;
	}
	h[9U] -= shiftDown(h[9U], SHIFT[9U]) * RADIX[9U]; // drop 2^255
	o.fill(0U);
	for (std::size_t i = 0U; i < 10U; i++) {
		const std::uint64_t v = static_cast<std::uint64_t>(h[i]);
		for (std::size_t b = 0U; b < (POS[i + 1U] - POS[i]); b++) {
			const std::size_t at = POS[i] + b;
			const std::uint64_t bit = (v >> b) & 1U;
			const std::uint8_t mask = static_cast<std::uint8_t>(bit << (at % 8U));
			o[at / 8U] = static_cast<std::uint8_t>(o[at / 8U] | mask);
		}
	}
}

// From 32 bytes; the top bit (x sign of a point) is ignored.
void unpack(Fe &o, const std::array<std::uint8_t, 32U> &n) noexcept
{
	for (std::size_t i = 0U; i < 10U; i++) {
		std::int64_t v = 0;
		for (std::size_t b = 0U; b < (POS[i + 1U] - POS[i]); b++) {
			const std::size_t at = POS[i] + b;
			const std::uint32_t byte = n[at / 8U];
			const std::int64_t bit = static_cast<std::int64_t>((byte >> (at % 8U)) & 1U);
			v += bit * (static_cast<std::int64_t>(1) << b);
		}
		o[i] = v;
	}
	carry(o);
}

bool isEqual(const Fe &a, const Fe &b) noexcept
{
	std::array<std::uint8_t, 32U> x{};
	std::array<std::uint8_t, 32U> y{};
	pack(x, a);
	pack(y, b);
	return x == y;
}

std::uint8_t parity(const Fe &a) noexcept
{
	std::array<std::uint8_t, 32U> d{};
	pack(d, a);
	return static_cast<std::uint8_t>(d[0U] & 1U);
}

Fe add(const Fe &a, const Fe &b) noexcept
{
	Fe o{};
	for (std::size_t i = 0U; i < 10U; i++) {
		o[i] = a[i] + b[i];
	}
	carry(o);
	return o;
}

Fe sub(const Fe &a, const Fe &b) noexcept
{
	Fe o{};
	for (std::size_t i = 0U; i < 10U; i++) {
		o[i] = a[i] - b[i];
	}
	carry(o);
	return o;
}

// Limb weights: limb i is 2^ceil(25.5 i), so when i and j are both odd the
// product lands one bit above limb i + j and is doubled; i + j >= 10 wraps
// with 2^255 = 19. The doubled / x19 operands are prepared once (all fit in
// 32 bits: |limb| < 2^26, 38 * 2^26 < 2^31).
Fe mul(const Fe &a, const Fe &b) noexcept
{
	std::array<std::int32_t, 10U> b1{};  // b
	std::array<std::int32_t, 10U> b2{};  // b, odd limbs doubled
	std::array<std::int32_t, 10U> b19{}; // 19 b
	std::array<std::int32_t, 10U> b38{}; // 19 b, odd limbs doubled
	for (std::size_t j = 0U; j < 10U; j++) {
		const std::int32_t v = static_cast<std::int32_t>(b[j]);
		const std::int32_t m = ((j % 2U) == 1U) ? 2 : 1;
		b1[j] = v;
		b2[j] = v * m;
		b19[j] = 19 * v;
		b38[j] = 19 * v * m;
	}
	Fe h{};
	for (std::size_t i = 0U; i < 10U; i++) {
		const std::int64_t ai = static_cast<std::int64_t>(static_cast<std::int32_t>(a[i]));
		const bool odd = (i % 2U) == 1U;
		const std::array<std::int32_t, 10U> &lo = odd ? b2 : b1;
		const std::array<std::int32_t, 10U> &hi = odd ? b38 : b19;
		for (std::size_t j = 0U; j < (10U - i); j++) {
			h[i + j] += ai * static_cast<std::int64_t>(lo[j]);
		}
		for (std::size_t j = 10U - i; j < 10U; j++) {
			h[i + j - 10U] += ai * static_cast<std::int64_t>(hi[j]);
		}
	}
	carry(h);
	return h;
}

Fe square(const Fe &a) noexcept
{
	return mul(a, a);
}

// a^(2^n)
Fe squareN(const Fe &a, std::size_t n) noexcept
{
	Fe c = a;
	for (std::size_t i = 0U; i < n; i++) {
		c = square(c);
	}
	return c;
}

// a^(2^250 - 1), and a^11 in a11 (shared start of both exponent chains)
Fe pow2250m1(const Fe &a, Fe &a11) noexcept
{
	const Fe a2 = square(a);
	const Fe a9 = mul(squareN(a2, 2U), a);
	a11 = mul(a2, a9);
	const Fe e5 = mul(square(a11), a9);    // 2^5 - 1
	const Fe e10 = mul(squareN(e5, 5U), e5);
	const Fe e20 = mul(squareN(e10, 10U), e10);
	const Fe e40 = mul(squareN(e20, 20U), e20);
	const Fe e50 = mul(squareN(e40, 10U), e10);
	const Fe e100 = mul(squareN(e50, 50U), e50);
	const Fe e200 = mul(squareN(e100, 100U), e100);
	return mul(squareN(e200, 50U), e50);  // 2^250 - 1
}

// a^(p - 2) = a^(2^255 - 21)
Fe invert(const Fe &a) noexcept
{
	Fe a11{};
	const Fe e250 = pow2250m1(a, a11);
	return mul(squareN(e250, 5U), a11);
}

// a^((p - 5) / 8) = a^(2^252 - 3)
Fe pow2523(const Fe &a) noexcept
{
	Fe a11{};
	const Fe e250 = pow2250m1(a, a11);
	return mul(squareN(e250, 2U), a);
}

// p += q (unified law: also p = 2p when q is p)
void addPoint(Ge &p, const Ge &q) noexcept
{
	const Fe a = mul(sub(p[1U], p[0U]), sub(q[1U], q[0U]));
	const Fe b = mul(add(p[0U], p[1U]), add(q[0U], q[1U]));
	const Fe c = mul(mul(p[3U], q[3U]), D2);
	const Fe d0 = mul(p[2U], q[2U]);
	const Fe d = add(d0, d0);
	const Fe e = sub(b, a);
	const Fe f = sub(d, c);
	const Fe g = add(d, c);
	const Fe h = add(b, a);
	p[0U] = mul(e, f);
	p[1U] = mul(h, g);
	p[2U] = mul(g, f);
	p[3U] = mul(e, h);
}

// p = 2p (dbl-2008-hwcd, a = -1): 4 squarings, 4 multiplications
void doublePoint(Ge &p) noexcept
{
	const Fe a = square(p[0U]);
	const Fe b = square(p[1U]);
	const Fe zz = square(p[2U]);
	const Fe c = add(zz, zz);
	const Fe e = sub(sub(square(add(p[0U], p[1U])), a), b);
	const Fe g = sub(b, a);
	const Fe f = sub(g, c);
	const Fe h = sub(sub(FE_ZERO, a), b);
	p[0U] = mul(e, f);
	p[1U] = mul(g, h);
	p[2U] = mul(f, g);
	p[3U] = mul(e, h);
}

// A fixed addend prepared once: Y + X, Y - X, 2 d T, 2 Z
using Cached = std::array<Fe, 4U>;

Cached toCached(const Ge &q) noexcept
{
	return Cached{add(q[1U], q[0U]), sub(q[1U], q[0U]), mul(q[3U], D2), add(q[2U], q[2U])};
}

// p += q, with q in cached form (8 multiplications)
void addCached(Ge &p, const Cached &q) noexcept
{
	const Fe a = mul(sub(p[1U], p[0U]), q[1U]);
	const Fe b = mul(add(p[1U], p[0U]), q[0U]);
	const Fe c = mul(p[3U], q[2U]);
	const Fe d = mul(p[2U], q[3U]);
	const Fe e = sub(b, a);
	const Fe f = sub(d, c);
	const Fe g = add(d, c);
	const Fe h = add(b, a);
	p[0U] = mul(e, f);
	p[1U] = mul(h, g);
	p[2U] = mul(g, f);
	p[3U] = mul(e, h);
}

void cswapPoint(Ge &p, Ge &q, std::uint32_t b) noexcept
{
	for (std::size_t i = 0U; i < 4U; i++) {
		cswap(p[i], q[i], b);
	}
}

Ge identity() noexcept
{
	return Ge{FE_ZERO, FE_ONE, FE_ONE, FE_ZERO};
}

Ge basePoint() noexcept
{
	return Ge{BX, BY, FE_ONE, mul(BX, BY)};
}

std::uint32_t bitOf(const std::array<std::uint8_t, 32U> &s, std::size_t i) noexcept
{
	const std::uint32_t byte = s[i / 8U];
	return (byte >> (i % 8U)) & 1U;
}

// [s]q, constant time (secret scalars)
Ge scalarMult(Ge q, const std::array<std::uint8_t, 32U> &s) noexcept
{
	Ge p = identity();
	for (std::size_t k = 0U; k < 256U; k++) {
		const std::uint32_t b = bitOf(s, 255U - k);
		cswapPoint(p, q, b);
		addPoint(q, p);
		doublePoint(p);
		cswapPoint(p, q, b);
	}
	return p;
}

void packPoint(std::array<std::uint8_t, 32U> &r, const Ge &p) noexcept
{
	const Fe zi = invert(p[2U]);
	const Fe tx = mul(p[0U], zi);
	const Fe ty = mul(p[1U], zi);
	pack(r, ty);
	r[31U] = static_cast<std::uint8_t>(r[31U] ^ static_cast<std::uint8_t>(parity(tx) << 7U));
}

// -A from its encoding; false if it is not a curve point.
bool unpackNeg(Ge &r, const std::array<std::uint8_t, 32U> &p) noexcept
{
	r[2U] = FE_ONE;
	unpack(r[1U], p);
	Fe num = square(r[1U]);
	Fe den = mul(num, D);
	num = sub(num, r[2U]);
	den = add(r[2U], den);
	const Fe den2 = square(den);
	const Fe den4 = square(den2);
	const Fe den6 = mul(den4, den2);
	Fe t = mul(mul(den6, num), den);
	t = pow2523(t);
	t = mul(mul(mul(t, num), den), den);
	r[0U] = mul(t, den);
	Fe chk = mul(square(r[0U]), den);
	if (!isEqual(chk, num)) {
		r[0U] = mul(r[0U], SQRT_M1);
	}
	chk = mul(square(r[0U]), den);
	bool ok = isEqual(chk, num);
	if (ok) {
		if (parity(r[0U]) == static_cast<std::uint8_t>(p[31U] >> 7U)) {
			r[0U] = sub(FE_ZERO, r[0U]);
		}
		r[3U] = mul(r[0U], r[1U]);
	}
	return ok;
}

// r = x mod L, x as 64 signed byte-sized limbs (destroyed)
void modL(std::array<std::uint8_t, 32U> &r, std::array<std::int64_t, 64U> &x) noexcept
{
	for (std::size_t k = 0U; k < 32U; k++) {
		const std::size_t i = 63U - k;
		std::int64_t c = 0;
		std::size_t j = i - 32U;
		while (j < (i - 12U)) {
			x[j] += c - (16 * x[i] * L[j - (i - 32U)]);
			c = floorDiv(x[j] + 128, 256);
			x[j] -= c * 256;
			j++;
		}
		x[j] += c;
		x[i] = 0;
	}
	std::int64_t c = 0;
	for (std::size_t j = 0U; j < 32U; j++) {
		x[j] += c - (floorDiv(x[31U], 16) * L[j]);
		c = floorDiv(x[j], 256);
		x[j] -= c * 256;
	}
	for (std::size_t j = 0U; j < 32U; j++) {
		x[j] -= c * L[j];
	}
	for (std::size_t i = 0U; i < 32U; i++) {
		const std::int64_t q = floorDiv(x[i], 256);
		x[i + 1U] += q;
		r[i] = lowByte(x[i] - (q * 256));
	}
}

// 64-byte hash -> scalar mod L
std::array<std::uint8_t, 32U> reduce(const Digest512 &h) noexcept
{
	std::array<std::int64_t, 64U> x{};
	for (std::size_t i = 0U; i < 64U; i++) {
		x[i] = static_cast<std::int64_t>(h[i]);
	}
	std::array<std::uint8_t, 32U> r{};
	modL(r, x);
	return r;
}

// S < L (canonical), compared from the most significant byte
bool isScalarCanonical(const Signature &sig) noexcept
{
	bool decided = false;
	bool less = false;
	for (std::size_t k = 0U; (k < 32U) && !decided; k++) {
		const std::size_t i = 31U - k;
		const std::int64_t s = static_cast<std::int64_t>(sig[32U + i]);
		if (s != L[i]) {
			less = s < L[i];
			decided = true;
		}
	}
	return less;
}

} // namespace

KeyPair keyPairFromSeed(const Seed &seed) noexcept
{
	const Digest512 d = computeSha512(viewOf(seed));
	KeyPair kp;
	for (std::size_t i = 0U; i < 32U; i++) {
		kp.scalar[i] = d[i];
		kp.prefix[i] = d[32U + i];
	}
	kp.scalar[0U] = static_cast<std::uint8_t>(kp.scalar[0U] & 248U);
	kp.scalar[31U] = static_cast<std::uint8_t>((kp.scalar[31U] & 127U) | 64U);
	packPoint(kp.pub, scalarMult(basePoint(), kp.scalar));
	return kp;
}

bool isValidPublicKey(const PublicKey &pub) noexcept
{
	Ge a{};
	return unpackNeg(a, pub);
}

Signature sign(const KeyPair &kp, ByteView msg) noexcept
{
	Sha512 hr;
	hr.update(viewOf(kp.prefix));
	hr.update(msg);
	const std::array<std::uint8_t, 32U> r = reduce(hr.finish());
	std::array<std::uint8_t, 32U> rEnc{};
	packPoint(rEnc, scalarMult(basePoint(), r));

	Sha512 hk;
	hk.update(viewOf(rEnc));
	hk.update(viewOf(kp.pub));
	hk.update(msg);
	const std::array<std::uint8_t, 32U> k = reduce(hk.finish());

	// S = r + k * a mod L
	std::array<std::int64_t, 64U> x{};
	for (std::size_t i = 0U; i < 32U; i++) {
		x[i] = static_cast<std::int64_t>(r[i]);
	}
	for (std::size_t i = 0U; i < 32U; i++) {
		for (std::size_t j = 0U; j < 32U; j++) {
			x[i + j] += static_cast<std::int64_t>(k[i]) * static_cast<std::int64_t>(kp.scalar[j]);
		}
	}
	std::array<std::uint8_t, 32U> s{};
	modL(s, x);
	Signature sig{};
	for (std::size_t i = 0U; i < 32U; i++) {
		sig[i] = rEnc[i];
		sig[32U + i] = s[i];
	}
	return sig;
}

bool verify(const PublicKey &pub, ByteView msg, const Signature &sig) noexcept
{
	Ge negA{};
	bool ok = isScalarCanonical(sig) && unpackNeg(negA, pub);
	if (ok) {
		std::array<std::uint8_t, 32U> rEnc{};
		std::array<std::uint8_t, 32U> s{};
		for (std::size_t i = 0U; i < 32U; i++) {
			rEnc[i] = sig[i];
			s[i] = sig[32U + i];
		}
		Sha512 hk;
		hk.update(viewOf(rEnc));
		hk.update(viewOf(pub));
		hk.update(msg);
		const std::array<std::uint8_t, 32U> k = reduce(hk.finish());

		// [s]B + [k](-A), one doubling chain (public data: not constant time)
		const Ge base = basePoint();
		Ge sum = negA;
		addPoint(sum, base);
		const Cached b = toCached(base);
		const Cached a = toCached(negA);
		const Cached both = toCached(sum);
		Ge p = identity();
		for (std::size_t n = 0U; n < 256U; n++) {
			const std::size_t i = 255U - n;
			doublePoint(p);
			const std::uint32_t bs = bitOf(s, i);
			const std::uint32_t bk = bitOf(k, i);
			if ((bs != 0U) && (bk != 0U)) {
				addCached(p, both);
			} else if (bs != 0U) {
				addCached(p, b);
			} else if (bk != 0U) {
				addCached(p, a);
			} else {
				// both bits clear: doubling only
			}
		}
		std::array<std::uint8_t, 32U> check{};
		packPoint(check, p);
		ok = check == rEnc;
	}
	return ok;
}

} // namespace ed25519
} // namespace donghoa
