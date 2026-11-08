// SPDX-License-Identifier: MIT
// Type-safe text formatting and parsing (no <cstdio>, <cstdarg>, <cctype>,
// <cstring>, no heap). formatTo() replaces "{}" placeholders in order.
#ifndef DONGHOA_TEXT_HPP
#define DONGHOA_TEXT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <type_traits>

#include "types.hpp"

namespace donghoa {

constexpr std::size_t MAX_LINE = 512U;
using Line = FixedString<MAX_LINE>;

// Hexadecimal output of an unsigned value, zero-padded to width digits.
struct Hex {
	std::uint64_t value;
	std::uint8_t width;
};

constexpr Hex hex(std::uint64_t value, std::uint8_t width) noexcept
{
	return Hex{value, width};
}

// Bytes printed as characters (an SSID).
struct SsidText {
	ByteView bytes;
};

// Bytes printed as lowercase hex digits.
struct HexBytes {
	ByteView bytes;
};

enum class FmtKind : std::uint8_t { SINT, UINT, STR, MAC, HEXNUM, SSID, HEXBYTES };

// One formatting argument; plain struct (no union, MISRA C++ 12.3.1).
struct FmtArg {
	FmtKind kind{FmtKind::STR};
	std::int64_t s{0};
	std::uint64_t u{0U};
	std::uint8_t width{0U};
	std::string_view str{};
	Mac mac{};
	ByteView bytes{};
};

template <typename T>
std::enable_if_t<std::is_integral<T>::value && std::is_signed<T>::value, FmtArg> toArg(T v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::SINT;
	a.s = static_cast<std::int64_t>(v);
	return a;
}

template <typename T>
std::enable_if_t<std::is_integral<T>::value && std::is_unsigned<T>::value, FmtArg> toArg(T v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::UINT;
	a.u = static_cast<std::uint64_t>(v);
	return a;
}

FmtArg toArg(std::string_view v) noexcept;
FmtArg toArg(const char *v) noexcept;
FmtArg toArg(const Mac &v) noexcept;
FmtArg toArg(const Hex &v) noexcept;
FmtArg toArg(const SsidText &v) noexcept;
FmtArg toArg(const HexBytes &v) noexcept;

template <std::size_t N>
FmtArg toArg(const FixedString<N> &v) noexcept
{
	return toArg(v.view());
}

// Format fmt with args into out (appended); output is truncated to out's
// capacity. Each "{}" takes the next argument; surplus "{}" print as is.
void formatArgs(Line &out, std::string_view fmt, const FmtArg *args, std::size_t n) noexcept;

template <std::size_t N, typename... A>
void formatTo(FixedString<N> &out, std::string_view fmt, const A &...args) noexcept
{
	const std::array<FmtArg, sizeof...(A)> a{{toArg(args)...}};
	Line tmp;
	formatArgs(tmp, fmt, a.data(), a.size());
	(void)out.append(tmp.view());
}

// ---- character classes (no <cctype>, MISRA C++ 24.5.1) ----

constexpr bool isSpace(char c) noexcept
{
	return (c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') || (c == '\f') || (c == '\v');
}

constexpr bool isDigit(char c) noexcept
{
	return (c >= '0') && (c <= '9');
}

// 0..15, or -1 when c is not a hex digit.
constexpr int hexValue(char c) noexcept
{
	int v = -1;
	if ((c >= '0') && (c <= '9')) {
		v = static_cast<int>(c) - static_cast<int>('0');
	} else if ((c >= 'a') && (c <= 'f')) {
		v = (static_cast<int>(c) - static_cast<int>('a')) + 10;
	} else if ((c >= 'A') && (c <= 'F')) {
		v = (static_cast<int>(c) - static_cast<int>('A')) + 10;
	} else {
		// not a hex digit
	}
	return v;
}

// ---- parsing ----

std::string_view trim(std::string_view s) noexcept;
// Non-throwing std::string_view::substr: pos past the end gives an empty
// view (substr would throw std::out_of_range, pulling in libstdc++.so).
constexpr std::string_view subView(std::string_view s, std::size_t pos,
				    std::size_t n = std::string_view::npos) noexcept
{
	const std::size_t left = (pos > s.size()) ? 0U : (s.size() - pos);
	return (pos > s.size()) ? std::string_view()
				 : std::string_view(s.data() + pos, (left < n) ? left : n);
}
bool startsWith(std::string_view s, std::string_view prefix) noexcept;

// Whole string as an integer in [min, max] (base 10 or 16; "0x" allowed
// for 16). parseLongTok accepts a number followed by whitespace.
std::optional<long> parseLong(std::string_view s, int base, long min, long max) noexcept;
std::optional<long> parseLongTok(std::string_view s, int base, long min, long max) noexcept;
std::optional<std::uint64_t> parseU64(std::string_view s) noexcept;

// "aa:bb:cc:dd:ee:ff" (1 or 2 hex digits per byte), whole string.
std::optional<Mac> parseMac(std::string_view s) noexcept;
// A MAC address at the start of s, followed by anything.
std::optional<Mac> parseMacPrefix(std::string_view s) noexcept;

// "key=value" lines (hostapd style): value up to the end of its line.
std::optional<std::string_view> getKv(std::string_view buf, std::string_view key) noexcept;
std::optional<long> getKvInt(std::string_view buf, std::string_view key) noexcept;

// Hex string to bytes; number of bytes, or nothing on bad input or overflow.
std::optional<std::size_t> hexDecode(std::string_view hex, const ByteSpan &out) noexcept;

template <std::size_t N>
bool hexEncode(ByteView in, FixedString<N> &out) noexcept
{
	formatTo(out, "{}", HexBytes{in});
	return out.size() >= (2U * in.size());
}

// Splits a string at any of the separator characters (strtok replacement).
class Tokens {
public:
	Tokens(std::string_view s, std::string_view seps) noexcept : mRest(s), mSeps(seps) {}
	// Next non-empty token; false at the end.
	bool next(std::string_view &tok) noexcept;
	// What is left after the last token returned.
	std::string_view rest() const noexcept { return mRest; }

private:
	bool isSep(char c) const noexcept;
	std::string_view mRest;
	std::string_view mSeps;
};

} // namespace donghoa

#endif
