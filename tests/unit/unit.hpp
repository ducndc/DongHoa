// SPDX-License-Identifier: MIT
// Shared by the unit test files (tests/unit/test_*.cpp): the CHECK macro,
// byte helpers and the list of test functions that main.cpp runs. Test
// code is exempt from the no-macro rule (docs/CODING_CONVENTION.md §6.1):
// CHECK reports the expression, file and line.
#ifndef DONGHOA_UNIT_HPP
#define DONGHOA_UNIT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "base/text.hpp"
#include "base/types.hpp"

// Counts the check; a failed one is printed (main.cpp).
void check(bool ok, const char *expr, const char *file, int line);

#define CHECK(c) check(static_cast<bool>(c), #c, __FILE__, __LINE__)

// String literal as bytes (tests only).
template <std::size_t N>
std::array<std::uint8_t, N - 1U> bytesOf(const char (&s)[N])
{
	std::array<std::uint8_t, N - 1U> b{};
	for (std::size_t i = 0U; i + 1U < N; i++) {
		b[i] = static_cast<std::uint8_t>(s[i]);
	}
	return b;
}

inline donghoa::Mac mac(std::string_view s)
{
	const std::optional<donghoa::Mac> m = donghoa::parseMac(s);
	return m.has_value() ? *m : donghoa::Mac{};
}

template <std::size_t N>
donghoa::FixedString<2U * N> hexs(const std::array<std::uint8_t, N> &a)
{
	donghoa::FixedString<2U * N> h;
	(void)donghoa::hexEncode(donghoa::viewOf(a), h);
	return h;
}

template <std::size_t N>
std::array<std::uint8_t, N> unhex(std::string_view h)
{
	std::array<std::uint8_t, N> b{};
	(void)donghoa::hexDecode(h, donghoa::spanOf(b));
	return b;
}

// One function per area; a new one also goes into TESTS in main.cpp.
void testSha256();          // test_crypto.cpp
void testSha512();
void testEd25519();
void testTrust();           // test_trust.cpp
void testSignedMessage();   // test_proto.cpp
void testProtoRoundtrip();
void testProtoOverflow();
void testSteerTlvs();
void testChallengeTlvs();
void testReplayWindow();
void testRrm();             // test_rrm.cpp
void testAirMonitor();
void testHapdParsers();     // test_hapd_parse.cpp
void testMlo();
void testPolicy();          // test_policy.cpp
void testPolicyTput();
void testLowPower();        // test_low_power.cpp
void testRobustness();      // test_base.cpp
void testLog();
void testConfig();          // test_config.cpp
void testNlParse();         // test_nlparse.cpp
void testConsistency();     // test_consistency.cpp
void testMetrics();         // test_metrics.cpp

#endif
