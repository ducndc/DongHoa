// SPDX-License-Identifier: MIT
// FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256.
#ifndef DONGHOA_SHA256_HPP
#define DONGHOA_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "types.hpp"

namespace donghoa {

constexpr std::size_t kSha256Len = 32U;
using Digest = std::array<std::uint8_t, kSha256Len>;

class Sha256 {
public:
	Sha256() noexcept;
	void update(ByteView data) noexcept;
	Digest finish() noexcept;

private:
	void block() noexcept;

	std::array<std::uint32_t, 8U> h_{};
	std::array<std::uint8_t, 64U> buf_{};
	std::uint64_t len_{0U};
	std::size_t fill_{0U};
};

Digest sha256(ByteView data) noexcept;
Digest hmac_sha256(ByteView key, ByteView msg) noexcept;

} // namespace donghoa

#endif
