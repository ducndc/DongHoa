// SPDX-License-Identifier: MIT
// Basic value types shared by every module: MAC addresses, byte views,
// fixed-capacity strings and endian helpers. No heap, no exceptions.
#ifndef DONGHOA_TYPES_HPP
#define DONGHOA_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace donghoa {

using Millis = std::uint64_t;

// IEEE 802 MAC address.
struct Mac {
	std::array<std::uint8_t, 6U> b{};

	bool isZero() const noexcept
	{
		bool zero = true;
		for (const std::uint8_t x : b) {
			zero = zero && (x == 0U);
		}
		return zero;
	}
};

inline bool operator==(const Mac &x, const Mac &y) noexcept
{
	return x.b == y.b;
}

inline bool operator!=(const Mac &x, const Mac &y) noexcept
{
	return !(x == y);
}

// Read-only view of bytes (std::span is C++20).
class ByteView {
public:
	constexpr ByteView() noexcept = default;
	constexpr ByteView(const std::uint8_t *data, std::size_t size) noexcept
		: mData(data), mSize(size)
	{
	}
	template <std::size_t N>
	constexpr explicit ByteView(const std::array<std::uint8_t, N> &a) noexcept
		: mData(a.data()), mSize(N)
	{
	}

	constexpr const std::uint8_t *data() const noexcept { return mData; }
	constexpr std::size_t size() const noexcept { return mSize; }
	constexpr bool empty() const noexcept { return mSize == 0U; }
	// Precondition: i < size().
	constexpr std::uint8_t operator[](std::size_t i) const noexcept { return mData[i]; }

	// Sub-view; empty if [off, off + len) is not inside the view.
	constexpr ByteView sub(std::size_t off, std::size_t len) const noexcept
	{
		return ((off <= mSize) && (len <= (mSize - off))) ? ByteView(&mData[off], len)
								    : ByteView();
	}
	constexpr ByteView first(std::size_t len) const noexcept { return sub(0U, len); }

private:
	const std::uint8_t *mData{nullptr};
	std::size_t mSize{0U};
};

// Writable view of bytes.
class ByteSpan {
public:
	constexpr ByteSpan() noexcept = default;
	constexpr ByteSpan(std::uint8_t *data, std::size_t size) noexcept : mData(data), mSize(size)
	{
	}
	template <std::size_t N>
	constexpr explicit ByteSpan(std::array<std::uint8_t, N> &a) noexcept
		: mData(a.data()), mSize(N)
	{
	}

	constexpr std::uint8_t *data() const noexcept { return mData; }
	constexpr std::size_t size() const noexcept { return mSize; }
	// Precondition: i < size().
	constexpr std::uint8_t &operator[](std::size_t i) const noexcept { return mData[i]; }
	constexpr ByteView view() const noexcept { return ByteView(mData, mSize); }

private:
	std::uint8_t *mData{nullptr};
	std::size_t mSize{0U};
};

template <std::size_t N>
constexpr ByteView viewOf(const std::array<std::uint8_t, N> &a) noexcept
{
	return ByteView(a);
}

template <std::size_t N>
constexpr ByteSpan spanOf(std::array<std::uint8_t, N> &a) noexcept
{
	return ByteSpan(a);
}

inline bool equal(ByteView a, ByteView b) noexcept
{
	bool eq = (a.size() == b.size());
	for (std::size_t i = 0U; eq && (i < a.size()); i++) {
		eq = (a[i] == b[i]);
	}
	return eq;
}

// Copy min(src.size(), dst.size()) bytes; returns the number copied.
inline std::size_t copyBytes(const ByteSpan &dst, ByteView src) noexcept
{
	const std::size_t n = (src.size() < dst.size()) ? src.size() : dst.size();
	for (std::size_t i = 0U; i < n; i++) {
		dst[i] = src[i];
	}
	return n;
}

// Big-endian (ARCP wire) and little-endian (802.11 fields) helpers.
// Preconditions: the view covers [off, off + width).
constexpr std::uint16_t getBe16(ByteView v, std::size_t off) noexcept
{
	return static_cast<std::uint16_t>((static_cast<std::uint32_t>(v[off]) << 8U) |
					  static_cast<std::uint32_t>(v[off + 1U]));
}

constexpr std::uint32_t getBe32(ByteView v, std::size_t off) noexcept
{
	return (static_cast<std::uint32_t>(v[off]) << 24U) |
	       (static_cast<std::uint32_t>(v[off + 1U]) << 16U) |
	       (static_cast<std::uint32_t>(v[off + 2U]) << 8U) | static_cast<std::uint32_t>(v[off + 3U]);
}

constexpr std::uint16_t getLe16(ByteView v, std::size_t off) noexcept
{
	return static_cast<std::uint16_t>(static_cast<std::uint32_t>(v[off]) |
					  (static_cast<std::uint32_t>(v[off + 1U]) << 8U));
}

constexpr void putBe16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v >> 8U);
	s[off + 1U] = static_cast<std::uint8_t>(v & 0xffU);
}

constexpr void putBe32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v >> 24U);
	s[off + 1U] = static_cast<std::uint8_t>((v >> 16U) & 0xffU);
	s[off + 2U] = static_cast<std::uint8_t>((v >> 8U) & 0xffU);
	s[off + 3U] = static_cast<std::uint8_t>(v & 0xffU);
}

constexpr void putLe16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v & 0xffU);
	s[off + 1U] = static_cast<std::uint8_t>(v >> 8U);
}

constexpr void putLe32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v & 0xffU);
	s[off + 1U] = static_cast<std::uint8_t>((v >> 8U) & 0xffU);
	s[off + 2U] = static_cast<std::uint8_t>((v >> 16U) & 0xffU);
	s[off + 3U] = static_cast<std::uint8_t>(v >> 24U);
}

// Fixed-capacity, always NUL-terminated string (no heap).
template <std::size_t N>
class FixedString {
public:
	constexpr FixedString() noexcept = default;
	explicit FixedString(std::string_view s) noexcept { (void)assign(s); }

	// Returns false if s was truncated.
	bool assign(std::string_view s) noexcept
	{
		clear();
		return append(s);
	}

	bool append(std::string_view s) noexcept
	{
		bool whole = true;
		for (const char c : s) {
			whole = pushBack(c) && whole;
		}
		return whole;
	}

	bool pushBack(char c) noexcept
	{
		bool ok = false;
		if (mLen < N) {
			mBuf[mLen] = c;
			mLen++;
			mBuf[mLen] = '\0';
			ok = true;
		}
		return ok;
	}

	void clear() noexcept
	{
		mLen = 0U;
		mBuf[0U] = '\0';
	}

	std::string_view view() const noexcept { return std::string_view(mBuf.data(), mLen); }
	const char *cStr() const noexcept { return mBuf.data(); }
	std::size_t size() const noexcept { return mLen; }
	bool empty() const noexcept { return mLen == 0U; }
	static constexpr std::size_t capacity() noexcept { return N; }

private:
	std::array<char, N + 1U> mBuf{};
	std::size_t mLen{0U};
};

} // namespace donghoa

#endif
