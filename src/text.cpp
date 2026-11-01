// SPDX-License-Identifier: MIT
#include "text.hpp"

#include <charconv>
#include <limits>

namespace donghoa {

namespace {

constexpr std::string_view DIGITS{"0123456789abcdef"};

void putUnsigned(Line &out, std::uint64_t v, unsigned int base, std::uint8_t width) noexcept
{
	std::array<char, 24U> tmp{};
	std::size_t n = 0U;
	std::uint64_t x = v;

	do {
		// base <= 16: the digit always fits; uint32 keeps 32-bit targets warning-free
		const std::uint32_t digit = static_cast<std::uint32_t>(x % base);
		tmp[n] = DIGITS[digit];
		n++;
		x /= base;
	} while ((x != 0U) && (n < tmp.size()));
	while ((n < static_cast<std::size_t>(width)) && (n < tmp.size())) {
		tmp[n] = '0';
		n++;
	}
	while (n > 0U) {
		n--;
		(void)out.pushBack(tmp[n]);
	}
}

void putArg(Line &out, const FmtArg &a) noexcept
{
	switch (a.kind) {
	case FmtKind::SINT:
		if (a.s < 0) {
			(void)out.pushBack('-');
			// -(INT64_MIN) does not fit: go through unsigned arithmetic.
			putUnsigned(out, 0U - static_cast<std::uint64_t>(a.s), 10U, 0U);
		} else {
			putUnsigned(out, static_cast<std::uint64_t>(a.s), 10U, 0U);
		}
		break;
	case FmtKind::UINT:
		putUnsigned(out, a.u, 10U, 0U);
		break;
	case FmtKind::STR:
		(void)out.append(a.str);
		break;
	case FmtKind::MAC:
		for (std::size_t i = 0U; i < a.mac.b.size(); i++) {
			if (i != 0U) {
				(void)out.pushBack(':');
			}
			putUnsigned(out, a.mac.b[i], 16U, 2U);
		}
		break;
	case FmtKind::HEXNUM:
		putUnsigned(out, a.u, 16U, a.width);
		break;
	case FmtKind::SSID:
		for (std::size_t i = 0U; i < a.bytes.size(); i++) {
			(void)out.pushBack(static_cast<char>(a.bytes[i]));
		}
		break;
	case FmtKind::HEXBYTES:
		for (std::size_t i = 0U; i < a.bytes.size(); i++) {
			putUnsigned(out, a.bytes[i], 16U, 2U);
		}
		break;
	default:
		break;
	}
}

std::optional<long> parseLongEnd(std::string_view s, int base, long min, long max,
				   bool whole) noexcept
{
	std::optional<long> r;
	std::string_view t = s;

	if ((base == 16) && (t.size() > 2U) && (t[0U] == '0') && ((t[1U] == 'x') || (t[1U] == 'X'))) {
		t.remove_prefix(2U);
	}
	if (!t.empty()) {
		long v = 0;
		const char *const end = t.data() + t.size();
		const std::from_chars_result res = std::from_chars(t.data(), end, v, base);

		if ((res.ec == std::errc()) && (res.ptr != t.data()) && (v >= min) && (v <= max) &&
		    ((res.ptr == end) || (!whole && isSpace(*res.ptr)))) {
			r = v;
		}
	}
	return r;
}

} // namespace

FmtArg toArg(std::string_view v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::STR;
	a.str = v;
	return a;
}

FmtArg toArg(const char *v) noexcept
{
	return toArg((v != nullptr) ? std::string_view(v) : std::string_view("(null)"));
}

FmtArg toArg(const Mac &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::MAC;
	a.mac = v;
	return a;
}

FmtArg toArg(const Hex &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::HEXNUM;
	a.u = v.value;
	a.width = v.width;
	return a;
}

FmtArg toArg(const SsidText &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::SSID;
	a.bytes = v.bytes;
	return a;
}

FmtArg toArg(const HexBytes &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::HEXBYTES;
	a.bytes = v.bytes;
	return a;
}

void formatArgs(Line &out, std::string_view fmt, const FmtArg *args, std::size_t n) noexcept
{
	std::size_t next = 0U;
	std::size_t i = 0U;

	while (i < fmt.size()) {
		if ((fmt[i] == '{') && ((i + 1U) < fmt.size()) && (fmt[i + 1U] == '}') && (next < n)) {
			putArg(out, args[next]);
			next++;
			i += 2U;
		} else {
			(void)out.pushBack(fmt[i]);
			i++;
		}
	}
}

std::string_view trim(std::string_view s) noexcept
{
	std::string_view t = s;
	while (!t.empty() && isSpace(t.front())) {
		t.remove_prefix(1U);
	}
	while (!t.empty() && isSpace(t.back())) {
		t.remove_suffix(1U);
	}
	return t;
}

bool startsWith(std::string_view s, std::string_view prefix) noexcept
{
	return (s.size() >= prefix.size()) && (subView(s, 0U, prefix.size()) == prefix);
}

std::optional<long> parseLong(std::string_view s, int base, long min, long max) noexcept
{
	return parseLongEnd(s, base, min, max, true);
}

std::optional<long> parseLongTok(std::string_view s, int base, long min, long max) noexcept
{
	return parseLongEnd(s, base, min, max, false);
}

std::optional<std::uint64_t> parseU64(std::string_view s) noexcept
{
	std::optional<std::uint64_t> r;

	// from_chars rejects signs for unsigned types; require a leading digit.
	if (!s.empty() && isDigit(s.front())) {
		std::uint64_t v = 0U;
		const char *const end = s.data() + s.size();
		const std::from_chars_result res = std::from_chars(s.data(), end, v, 10);

		if ((res.ec == std::errc()) && (res.ptr == end)) {
			r = v;
		}
	}
	return r;
}

std::optional<Mac> parseMac(std::string_view s) noexcept
{
	Mac m;
	std::size_t pos = 0U;
	bool ok = true;

	for (std::size_t i = 0U; ok && (i < m.b.size()); i++) {
		int v = 0;
		std::size_t digits = 0U;

		while ((pos < s.size()) && (digits < 2U) && (hexValue(s[pos]) >= 0)) {
			v = (v * 16) + hexValue(s[pos]);
			pos++;
			digits++;
		}
		ok = (digits > 0U);
		if (ok) {
			m.b[i] = static_cast<std::uint8_t>(v);
			if (i < (m.b.size() - 1U)) {
				ok = (pos < s.size()) && (s[pos] == ':');
				pos++;
			}
		}
	}
	std::optional<Mac> r;
	if (ok && (pos == s.size())) {
		r = m;
	}
	return r;
}

std::optional<Mac> parseMacPrefix(std::string_view s) noexcept
{
	std::optional<Mac> r;
	if (s.size() >= 17U) {
		r = parseMac(subView(s, 0U, 17U));
	}
	return r;
}

std::optional<std::string_view> getKv(std::string_view buf, std::string_view key) noexcept
{
	std::optional<std::string_view> r;
	std::string_view rest = buf;

	while (!rest.empty() && !r.has_value()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view line = (eol == std::string_view::npos) ? rest : subView(rest, 0U, eol);

		if ((line.size() > key.size()) && startsWith(line, key) && (line[key.size()] == '=')) {
			r = subView(line, key.size() + 1U);
		}
		rest = (eol == std::string_view::npos) ? std::string_view() : subView(rest, eol + 1U);
	}
	return r;
}

std::optional<long> getKvInt(std::string_view buf, std::string_view key) noexcept
{
	std::optional<long> r;
	const std::optional<std::string_view> v = getKv(buf, key);

	// hostapd values may continue after the number ("217 mcs 2")
	if (v.has_value()) {
		r = parseLongTok(*v, 10, std::numeric_limits<long>::min(),
				   std::numeric_limits<long>::max());
	}
	return r;
}

std::optional<std::size_t> hexDecode(std::string_view hex, const ByteSpan &out) noexcept
{
	std::optional<std::size_t> r;
	const std::size_t n = hex.size() / 2U;

	if (((hex.size() % 2U) == 0U) && (n <= out.size())) {
		bool ok = true;
		for (std::size_t i = 0U; ok && (i < n); i++) {
			const int hi = hexValue(hex[2U * i]);
			const int lo = hexValue(hex[(2U * i) + 1U]);

			ok = (hi >= 0) && (lo >= 0);
			if (ok) {
				out[i] = static_cast<std::uint8_t>((hi * 16) + lo);
			}
		}
		if (ok) {
			r = n;
		}
	}
	return r;
}

bool Tokens::isSep(char c) const noexcept
{
	return mSeps.find(c) != std::string_view::npos;
}

bool Tokens::next(std::string_view &tok) noexcept
{
	while (!mRest.empty() && isSep(mRest.front())) {
		mRest.remove_prefix(1U);
	}
	bool found = !mRest.empty();
	if (found) {
		std::size_t len = 0U;
		while ((len < mRest.size()) && !isSep(mRest[len])) {
			len++;
		}
		tok = subView(mRest, 0U, len);
		mRest.remove_prefix(len);
	}
	return found;
}

} // namespace donghoa
