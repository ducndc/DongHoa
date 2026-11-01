// SPDX-License-Identifier: MIT
#include "text.hpp"

#include <charconv>
#include <limits>

namespace donghoa {

namespace {

constexpr std::string_view kDigits{"0123456789abcdef"};

void put_unsigned(Line &out, std::uint64_t v, unsigned int base, std::uint8_t width) noexcept
{
	std::array<char, 24U> tmp{};
	std::size_t n = 0U;
	std::uint64_t x = v;

	do {
		// base <= 16: the digit always fits; uint32 keeps 32-bit targets warning-free
		const std::uint32_t digit = static_cast<std::uint32_t>(x % base);
		tmp[n] = kDigits[digit];
		n++;
		x /= base;
	} while ((x != 0U) && (n < tmp.size()));
	while ((n < static_cast<std::size_t>(width)) && (n < tmp.size())) {
		tmp[n] = '0';
		n++;
	}
	while (n > 0U) {
		n--;
		(void)out.push_back(tmp[n]);
	}
}

void put_arg(Line &out, const FmtArg &a) noexcept
{
	switch (a.kind) {
	case FmtKind::sint:
		if (a.s < 0) {
			(void)out.push_back('-');
			// -(INT64_MIN) does not fit: go through unsigned arithmetic.
			put_unsigned(out, 0U - static_cast<std::uint64_t>(a.s), 10U, 0U);
		} else {
			put_unsigned(out, static_cast<std::uint64_t>(a.s), 10U, 0U);
		}
		break;
	case FmtKind::uint:
		put_unsigned(out, a.u, 10U, 0U);
		break;
	case FmtKind::str:
		(void)out.append(a.str);
		break;
	case FmtKind::mac:
		for (std::size_t i = 0U; i < a.mac.b.size(); i++) {
			if (i != 0U) {
				(void)out.push_back(':');
			}
			put_unsigned(out, a.mac.b[i], 16U, 2U);
		}
		break;
	case FmtKind::hexnum:
		put_unsigned(out, a.u, 16U, a.width);
		break;
	case FmtKind::ssid:
		for (std::size_t i = 0U; i < a.bytes.size(); i++) {
			(void)out.push_back(static_cast<char>(a.bytes[i]));
		}
		break;
	case FmtKind::hexbytes:
		for (std::size_t i = 0U; i < a.bytes.size(); i++) {
			put_unsigned(out, a.bytes[i], 16U, 2U);
		}
		break;
	default:
		break;
	}
}

std::optional<long> parse_long_end(std::string_view s, int base, long min, long max,
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
		    ((res.ptr == end) || (!whole && is_space(*res.ptr)))) {
			r = v;
		}
	}
	return r;
}

} // namespace

FmtArg to_arg(std::string_view v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::str;
	a.str = v;
	return a;
}

FmtArg to_arg(const char *v) noexcept
{
	return to_arg((v != nullptr) ? std::string_view(v) : std::string_view("(null)"));
}

FmtArg to_arg(const Mac &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::mac;
	a.mac = v;
	return a;
}

FmtArg to_arg(const Hex &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::hexnum;
	a.u = v.value;
	a.width = v.width;
	return a;
}

FmtArg to_arg(const SsidText &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::ssid;
	a.bytes = v.bytes;
	return a;
}

FmtArg to_arg(const HexBytes &v) noexcept
{
	FmtArg a;
	a.kind = FmtKind::hexbytes;
	a.bytes = v.bytes;
	return a;
}

void format_args(Line &out, std::string_view fmt, const FmtArg *args, std::size_t n) noexcept
{
	std::size_t next = 0U;
	std::size_t i = 0U;

	while (i < fmt.size()) {
		if ((fmt[i] == '{') && ((i + 1U) < fmt.size()) && (fmt[i + 1U] == '}') && (next < n)) {
			put_arg(out, args[next]);
			next++;
			i += 2U;
		} else {
			(void)out.push_back(fmt[i]);
			i++;
		}
	}
}

std::string_view trim(std::string_view s) noexcept
{
	std::string_view t = s;
	while (!t.empty() && is_space(t.front())) {
		t.remove_prefix(1U);
	}
	while (!t.empty() && is_space(t.back())) {
		t.remove_suffix(1U);
	}
	return t;
}

bool starts_with(std::string_view s, std::string_view prefix) noexcept
{
	return (s.size() >= prefix.size()) && (sub_view(s, 0U, prefix.size()) == prefix);
}

std::optional<long> parse_long(std::string_view s, int base, long min, long max) noexcept
{
	return parse_long_end(s, base, min, max, true);
}

std::optional<long> parse_long_tok(std::string_view s, int base, long min, long max) noexcept
{
	return parse_long_end(s, base, min, max, false);
}

std::optional<std::uint64_t> parse_u64(std::string_view s) noexcept
{
	std::optional<std::uint64_t> r;

	// from_chars rejects signs for unsigned types; require a leading digit.
	if (!s.empty() && is_digit(s.front())) {
		std::uint64_t v = 0U;
		const char *const end = s.data() + s.size();
		const std::from_chars_result res = std::from_chars(s.data(), end, v, 10);

		if ((res.ec == std::errc()) && (res.ptr == end)) {
			r = v;
		}
	}
	return r;
}

std::optional<Mac> parse_mac(std::string_view s) noexcept
{
	Mac m;
	std::size_t pos = 0U;
	bool ok = true;

	for (std::size_t i = 0U; ok && (i < m.b.size()); i++) {
		int v = 0;
		std::size_t digits = 0U;

		while ((pos < s.size()) && (digits < 2U) && (hex_value(s[pos]) >= 0)) {
			v = (v * 16) + hex_value(s[pos]);
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

std::optional<Mac> parse_mac_prefix(std::string_view s) noexcept
{
	std::optional<Mac> r;
	if (s.size() >= 17U) {
		r = parse_mac(sub_view(s, 0U, 17U));
	}
	return r;
}

std::optional<std::string_view> kv_get(std::string_view buf, std::string_view key) noexcept
{
	std::optional<std::string_view> r;
	std::string_view rest = buf;

	while (!rest.empty() && !r.has_value()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view line = (eol == std::string_view::npos) ? rest : sub_view(rest, 0U, eol);

		if ((line.size() > key.size()) && starts_with(line, key) && (line[key.size()] == '=')) {
			r = sub_view(line, key.size() + 1U);
		}
		rest = (eol == std::string_view::npos) ? std::string_view() : sub_view(rest, eol + 1U);
	}
	return r;
}

std::optional<long> kv_get_int(std::string_view buf, std::string_view key) noexcept
{
	std::optional<long> r;
	const std::optional<std::string_view> v = kv_get(buf, key);

	// hostapd values may continue after the number ("217 mcs 2")
	if (v.has_value()) {
		r = parse_long_tok(*v, 10, std::numeric_limits<long>::min(),
				   std::numeric_limits<long>::max());
	}
	return r;
}

std::optional<std::size_t> hex_decode(std::string_view hex, const ByteSpan &out) noexcept
{
	std::optional<std::size_t> r;
	const std::size_t n = hex.size() / 2U;

	if (((hex.size() % 2U) == 0U) && (n <= out.size())) {
		bool ok = true;
		for (std::size_t i = 0U; ok && (i < n); i++) {
			const int hi = hex_value(hex[2U * i]);
			const int lo = hex_value(hex[(2U * i) + 1U]);

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

bool Tokens::is_sep(char c) const noexcept
{
	return seps_.find(c) != std::string_view::npos;
}

bool Tokens::next(std::string_view &tok) noexcept
{
	while (!rest_.empty() && is_sep(rest_.front())) {
		rest_.remove_prefix(1U);
	}
	bool found = !rest_.empty();
	if (found) {
		std::size_t len = 0U;
		while ((len < rest_.size()) && !is_sep(rest_[len])) {
			len++;
		}
		tok = sub_view(rest_, 0U, len);
		rest_.remove_prefix(len);
	}
	return found;
}

} // namespace donghoa
