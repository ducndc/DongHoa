// SPDX-License-Identifier: MIT
#include "trust.hpp"

#include "sha256.hpp"

namespace donghoa {
namespace trust {

namespace {

// a < b as unsigned big numbers (tie-break between equal generations)
bool isKeyLess(const ed25519::PublicKey &a, const ed25519::PublicKey &b) noexcept
{
	bool decided = false;
	bool less = false;
	for (std::size_t i = 0U; (i < a.size()) && !decided; i++) {
		if (a[i] != b[i]) {
			less = a[i] < b[i];
			decided = true;
		}
	}
	return less;
}

// True if incoming r beats the local record cur.
bool isNewer(const Record &r, const Record &cur) noexcept
{
	bool newer = false;
	if (r.gen != cur.gen) {
		newer = r.gen > cur.gen;
	} else if (r.revoked != cur.revoked) {
		newer = r.revoked;
	} else {
		newer = isKeyLess(cur.pub, r.pub);
	}
	return newer;
}

Record *findMut(Table &t, const Mac &apId) noexcept
{
	Record *r = nullptr;
	for (Record &x : t.rec) {
		if ((r == nullptr) && x.used && (x.apId == apId)) {
			r = &x;
		}
	}
	return r;
}

Record *freeSlot(Table &t) noexcept
{
	Record *r = nullptr;
	for (Record &x : t.rec) {
		if ((r == nullptr) && !x.used) {
			r = &x;
		}
	}
	return r;
}

} // namespace

Fingerprint fingerprint(const ed25519::PublicKey &pub) noexcept
{
	const Digest d = computeSha256(viewOf(pub));
	Fingerprint f;
	for (std::size_t i = 0U; i < 8U; i++) {
		if ((i > 0U) && ((i % 2U) == 0U)) {
			(void)f.pushBack('-');
		}
		formatTo(f, "{}", hex(d[i], 2U));
	}
	return f;
}

const Record *find(const Table &t, const Mac &apId) noexcept
{
	const Record *r = nullptr;
	for (const Record &x : t.rec) {
		if ((r == nullptr) && x.used && (x.apId == apId)) {
			r = &x;
		}
	}
	return r;
}

const ed25519::PublicKey *trustedKey(const Table &t, const Mac &apId) noexcept
{
	const Record *const r = find(t, apId);
	return ((r != nullptr) && !r->revoked) ? &r->pub : nullptr;
}

std::size_t countTrustedOthers(const Table &t, const Mac &self) noexcept
{
	std::size_t n = 0U;
	for (const Record &x : t.rec) {
		if (x.used && !x.revoked && (x.apId != self)) {
			n++;
		}
	}
	return n;
}

bool merge(Table &t, const Record &r) noexcept
{
	bool changed = false;
	Record *cur = findMut(t, r.apId);
	if (cur == nullptr) {
		cur = freeSlot(t);
		if (cur != nullptr) {
			*cur = r;
			cur->used = true;
			changed = true;
		}
	} else if (isNewer(r, *cur)) {
		*cur = r;
		cur->used = true;
		changed = true;
	} else {
		// local record is as new or newer
	}
	return changed;
}

bool approve(Table &t, const Mac &apId, const ed25519::PublicKey &pub) noexcept
{
	const Record *const cur = find(t, apId);
	Record r;
	r.used = true;
	r.apId = apId;
	r.pub = pub;
	r.revoked = false;
	r.gen = (cur != nullptr) ? (cur->gen + 1U) : 1U;
	return merge(t, r);
}

bool revoke(Table &t, const Mac &apId) noexcept
{
	const Record *const cur = find(t, apId);
	bool ok = cur != nullptr;
	if (ok) {
		Record r = *cur;
		r.revoked = true;
		r.gen = cur->gen + 1U;
		ok = merge(t, r);
	}
	return ok;
}

void saveText(const Table &t, Text &out) noexcept
{
	out.clear();
	formatTo(out, "# donghoa trust table (written by the daemon)\nenrolled {}\n", t.enrolled ? 1 : 0);
	for (const Record &x : t.rec) {
		if (x.used) {
			FixedString<64U> k;
			(void)hexEncode(viewOf(x.pub), k);
			formatTo(out, "{} {} {} {}\n", x.revoked ? "revoked" : "trusted", x.apId, k, x.gen);
		}
	}
}

bool loadText(Table &t, std::string_view text) noexcept
{
	bool ok = true;
	std::string_view rest = text;
	while (ok && !rest.empty()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view raw = (eol == std::string_view::npos) ? rest : subView(rest, 0U, eol);
		const std::string_view line = trim(raw);
		rest = (eol == std::string_view::npos) ? std::string_view() : subView(rest, eol + 1U);
		Tokens tok(line, " \t");
		std::string_view kind;
		if (line.empty() || startsWith(line, "#") || !tok.next(kind)) {
			continue;
		}
		std::string_view a;
		std::string_view b;
		std::string_view c;
		if (kind == "enrolled") {
			ok = tok.next(a) && ((a == "0") || (a == "1"));
			t.enrolled = ok && (a == "1");
		} else if ((kind == "trusted") || (kind == "revoked")) {
			Record r;
			ok = tok.next(a) && tok.next(b) && tok.next(c);
			const std::optional<Mac> m = ok ? parseMac(a) : std::nullopt;
			const std::optional<std::size_t> n = ok ? hexDecode(b, spanOf(r.pub)) : std::nullopt;
			const std::optional<std::uint64_t> g = ok ? parseU64(c) : std::nullopt;
			ok = m.has_value() && n.has_value() && (*n == r.pub.size()) && g.has_value() &&
			     (*g <= 0xffffffffU) && ed25519::isValidPublicKey(r.pub);
			if (ok) {
				r.used = true;
				r.apId = *m;
				r.revoked = kind == "revoked";
				r.gen = static_cast<std::uint32_t>(*g);
				(void)merge(t, r);
			}
		} else {
			ok = false;
		}
	}
	return ok;
}

} // namespace trust
} // namespace donghoa
