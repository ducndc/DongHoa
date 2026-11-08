// SPDX-License-Identifier: MIT
// FIPS 180-4 SHA-512 (Ed25519 hashes with it).
#ifndef DONGHOA_SHA512_HPP
#define DONGHOA_SHA512_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "types.hpp"

namespace donghoa {

constexpr std::size_t SHA512_LEN = 64U;
using Digest512 = std::array<std::uint8_t, SHA512_LEN>;

class Sha512 {
public:
	Sha512() noexcept;
	void update(ByteView data) noexcept;
	Digest512 finish() noexcept;

private:
	void block() noexcept;

	std::array<std::uint64_t, 8U> mH{};
	std::array<std::uint8_t, 128U> mBuf{};
	std::uint64_t mLen{0U}; // bytes (messages here are far below 2^61)
	std::size_t mFill{0U};
};

Digest512 computeSha512(ByteView data) noexcept;

} // namespace donghoa

#endif
