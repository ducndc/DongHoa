// SPDX-License-Identifier: MIT
// Ed25519 signatures (RFC 8032, pure Ed25519): key pair from a 32-byte seed,
// sign, verify. Pure: no I/O, no heap. Field arithmetic in radix 2^25.5;
// signing uses a constant-time ladder, verification (public data only) a
// joint double-scalar walk.
#ifndef DONGHOA_ED25519_HPP
#define DONGHOA_ED25519_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "types.hpp"

namespace donghoa {
namespace ed25519 {

constexpr std::size_t SEED_LEN = 32U;
constexpr std::size_t PUB_LEN = 32U;
constexpr std::size_t SIG_LEN = 64U;

using Seed = std::array<std::uint8_t, SEED_LEN>;
using PublicKey = std::array<std::uint8_t, PUB_LEN>;
using Signature = std::array<std::uint8_t, SIG_LEN>;

// Expanded private key: clamped scalar and nonce prefix (SHA-512 of the
// seed), plus the public key derived from them.
struct KeyPair {
	std::array<std::uint8_t, 32U> scalar{};
	std::array<std::uint8_t, 32U> prefix{};
	PublicKey pub{};
};

KeyPair keyPairFromSeed(const Seed &seed) noexcept;
// True if pub decodes to a curve point (configuration check).
bool isValidPublicKey(const PublicKey &pub) noexcept;
Signature sign(const KeyPair &kp, ByteView msg) noexcept;
// False for a bad signature, a non-canonical S (>= L) or an invalid key.
bool verify(const PublicKey &pub, ByteView msg, const Signature &sig) noexcept;

} // namespace ed25519
} // namespace donghoa

#endif
