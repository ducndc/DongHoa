// SPDX-License-Identifier: MIT
// FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256 and RFC 8018 PBKDF2-HMAC-SHA256.
#ifndef DONGHOA_SHA256_HPP
#define DONGHOA_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "types.hpp"

namespace donghoa {

constexpr std::size_t SHA256_LEN = 32U;
using Digest = std::array<std::uint8_t, SHA256_LEN>;

class Sha256 {
public:
	Sha256() noexcept;
	void update(ByteView data) noexcept;
	Digest finish() noexcept;

private:
	void block() noexcept;

	std::array<std::uint32_t, 8U> mH{};
	std::array<std::uint8_t, 64U> mBuf{};
	std::uint64_t mLen{0U};
	std::size_t mFill{0U};
};

Digest computeSha256(ByteView data) noexcept;
Digest computeHmacSha256(ByteView key, ByteView msg) noexcept;
// RFC 8018 PBKDF2 with HMAC-SHA256: the first 32-byte block of the derived
// key (iterations >= 1).
Digest pbkdf2Sha256(ByteView password, ByteView salt, std::uint32_t iterations) noexcept;

} // namespace donghoa

#endif
