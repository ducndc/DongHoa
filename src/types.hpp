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

	bool is_zero() const noexcept
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
		: data_(data), size_(size)
	{
	}
	template <std::size_t N>
	constexpr explicit ByteView(const std::array<std::uint8_t, N> &a) noexcept
		: data_(a.data()), size_(N)
	{
	}

	constexpr const std::uint8_t *data() const noexcept { return data_; }
	constexpr std::size_t size() const noexcept { return size_; }
	constexpr bool empty() const noexcept { return size_ == 0U; }
	// Precondition: i < size().
	constexpr std::uint8_t operator[](std::size_t i) const noexcept { return data_[i]; }

	// Sub-view; empty if [off, off + len) is not inside the view.
	constexpr ByteView sub(std::size_t off, std::size_t len) const noexcept
	{
		return ((off <= size_) && (len <= (size_ - off))) ? ByteView(&data_[off], len)
								    : ByteView();
	}
	constexpr ByteView first(std::size_t len) const noexcept { return sub(0U, len); }

private:
	const std::uint8_t *data_{nullptr};
	std::size_t size_{0U};
};

// Writable view of bytes.
class ByteSpan {
public:
	constexpr ByteSpan() noexcept = default;
	constexpr ByteSpan(std::uint8_t *data, std::size_t size) noexcept : data_(data), size_(size)
	{
	}
	template <std::size_t N>
	constexpr explicit ByteSpan(std::array<std::uint8_t, N> &a) noexcept
		: data_(a.data()), size_(N)
	{
	}

	constexpr std::uint8_t *data() const noexcept { return data_; }
	constexpr std::size_t size() const noexcept { return size_; }
	// Precondition: i < size().
	constexpr std::uint8_t &operator[](std::size_t i) const noexcept { return data_[i]; }
	constexpr ByteView view() const noexcept { return ByteView(data_, size_); }

private:
	std::uint8_t *data_{nullptr};
	std::size_t size_{0U};
};

template <std::size_t N>
constexpr ByteView view_of(const std::array<std::uint8_t, N> &a) noexcept
{
	return ByteView(a);
}

template <std::size_t N>
constexpr ByteSpan span_of(std::array<std::uint8_t, N> &a) noexcept
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
inline std::size_t copy_bytes(const ByteSpan &dst, ByteView src) noexcept
{
	const std::size_t n = (src.size() < dst.size()) ? src.size() : dst.size();
	for (std::size_t i = 0U; i < n; i++) {
		dst[i] = src[i];
	}
	return n;
}

// Big-endian (ARCP wire) and little-endian (802.11 fields) helpers.
// Preconditions: the view covers [off, off + width).
constexpr std::uint16_t get_be16(ByteView v, std::size_t off) noexcept
{
	return static_cast<std::uint16_t>((static_cast<std::uint32_t>(v[off]) << 8U) |
					  static_cast<std::uint32_t>(v[off + 1U]));
}

constexpr std::uint32_t get_be32(ByteView v, std::size_t off) noexcept
{
	return (static_cast<std::uint32_t>(v[off]) << 24U) |
	       (static_cast<std::uint32_t>(v[off + 1U]) << 16U) |
	       (static_cast<std::uint32_t>(v[off + 2U]) << 8U) | static_cast<std::uint32_t>(v[off + 3U]);
}

constexpr std::uint16_t get_le16(ByteView v, std::size_t off) noexcept
{
	return static_cast<std::uint16_t>(static_cast<std::uint32_t>(v[off]) |
					  (static_cast<std::uint32_t>(v[off + 1U]) << 8U));
}

constexpr void put_be16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v >> 8U);
	s[off + 1U] = static_cast<std::uint8_t>(v & 0xffU);
}

constexpr void put_be32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v >> 24U);
	s[off + 1U] = static_cast<std::uint8_t>((v >> 16U) & 0xffU);
	s[off + 2U] = static_cast<std::uint8_t>((v >> 8U) & 0xffU);
	s[off + 3U] = static_cast<std::uint8_t>(v & 0xffU);
}

constexpr void put_le16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept
{
	s[off] = static_cast<std::uint8_t>(v & 0xffU);
	s[off + 1U] = static_cast<std::uint8_t>(v >> 8U);
}

constexpr void put_le32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept
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
			whole = push_back(c) && whole;
		}
		return whole;
	}

	bool push_back(char c) noexcept
	{
		bool ok = false;
		if (len_ < N) {
			buf_[len_] = c;
			len_++;
			buf_[len_] = '\0';
			ok = true;
		}
		return ok;
	}

	void clear() noexcept
	{
		len_ = 0U;
		buf_[0U] = '\0';
	}

	std::string_view view() const noexcept { return std::string_view(buf_.data(), len_); }
	const char *c_str() const noexcept { return buf_.data(); }
	std::size_t size() const noexcept { return len_; }
	bool empty() const noexcept { return len_ == 0U; }
	static constexpr std::size_t capacity() noexcept { return N; }

private:
	std::array<char, N + 1U> buf_{};
	std::size_t len_{0U};
};

} // namespace donghoa

#endif
