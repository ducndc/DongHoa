// SPDX-License-Identifier: MIT
// Trust table for automatic key enrollment: which AP (ap_id) may talk ARCP
// with which Ed25519 public key. Pure: no I/O, no heap.
//
// One record per ap_id: public key, state (trusted / revoked), generation.
// Tables merge as last-writer-wins registers: the higher generation wins, a
// tie goes to "revoked", then to the larger key. Approving or revoking takes
// the next generation, so a revocation is never undone by a stale copy and a
// later approval (new key after a re-flash) wins over an old revocation.
#ifndef DONGHOA_TRUST_HPP
#define DONGHOA_TRUST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ed25519.hpp"
#include "text.hpp"
#include "types.hpp"

namespace donghoa {
namespace trust {

constexpr std::size_t MAX_RECORDS = 64U;

struct Record {
	bool used{false};
	Mac apId{};
	ed25519::PublicKey pub{};
	bool revoked{false};
	std::uint32_t gen{0U};
};

struct Table {
	std::array<Record, MAX_RECORDS> rec{};
	// Enrolled: this AP joined a mesh (trusts another AP) or was marked as
	// the first AP. An enrolled AP never accepts a welcome again.
	bool enrolled{false};
};

using Fingerprint = FixedString<20U>; // "xxxx-xxxx-xxxx-xxxx"

// Short form of a key for humans: first 8 bytes of SHA-256, hex in groups.
Fingerprint fingerprint(const ed25519::PublicKey &pub) noexcept;

const Record *find(const Table &t, const Mac &apId) noexcept;
// Key of a trusted (not revoked) ap_id, or nullptr.
const ed25519::PublicKey *trustedKey(const Table &t, const Mac &apId) noexcept;
// Number of trusted records other than self.
std::size_t countTrustedOthers(const Table &t, const Mac &self) noexcept;

// Adds or updates by the merge rule; true if the table changed. False and
// unchanged also when the table is full.
bool merge(Table &t, const Record &r) noexcept;
// Local decision (approve: trusted with pub; revoke: keeps the key):
// next generation for that ap_id. False if full (approve) or unknown
// (revoke).
bool approve(Table &t, const Mac &apId, const ed25519::PublicKey &pub) noexcept;
bool revoke(Table &t, const Mac &apId) noexcept;

// File form, one record per line: "trusted|revoked <ap_id> <pub hex> <gen>",
// plus "enrolled 1". Lines that do not parse make loadText return false.
using Text = FixedString<8192U>;
void saveText(const Table &t, Text &out) noexcept;
bool loadText(Table &t, std::string_view text) noexcept;

} // namespace trust
} // namespace donghoa

#endif
