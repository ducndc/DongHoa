// SPDX-License-Identifier: MIT
// Unit tests for the pure modules (src/base, src/core), one binary:
//   test_unit              every test
//   test_unit policy rrm   the tests whose name contains one of the words
//   test_unit -l           the names
#include <cstdio>

#include "unit.hpp"

namespace {

int sFails = 0;
int sChecks = 0;

struct Test {
	std::string_view name;
	void (*run)();
};

constexpr std::array<Test, 23U> TESTS{{
	{"sha256", testSha256},
	{"sha512", testSha512},
	{"ed25519", testEd25519},
	{"signed_message", testSignedMessage},
	{"trust", testTrust},
	{"proto_roundtrip", testProtoRoundtrip},
	{"proto_overflow", testProtoOverflow},
	{"steer_tlvs", testSteerTlvs},
	{"rrm", testRrm},
	{"hapd_parsers", testHapdParsers},
	{"policy", testPolicy},
	{"policy_tput", testPolicyTput},
	{"air_monitor", testAirMonitor},
	{"robustness", testRobustness},
	{"log", testLog},
	{"config", testConfig},
	{"mlo", testMlo},
	{"low_power", testLowPower},
	{"nlparse", testNlParse},
	{"replay_window", testReplayWindow},
	{"challenge_tlvs", testChallengeTlvs},
	{"consistency", testConsistency},
	{"metrics", testMetrics},
}};

// No word given: every test. Otherwise the name contains one of them.
bool isSelected(std::string_view name, int argc, char **argv)
{
	bool selected = (argc < 2);
	for (int i = 1; i < argc; i++) {
		if (name.find(argv[i]) != std::string_view::npos) {
			selected = true;
		}
	}
	return selected;
}

} // namespace

void check(bool ok, const char *expr, const char *file, int line)
{
	sChecks++;
	if (!ok) {
		sFails++;
		(void)std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", file, line, expr);
	}
}

int main(int argc, char **argv)
{
	if ((argc == 2) && (std::string_view(argv[1]) == "-l")) {
		for (const Test &t : TESTS) {
			(void)std::printf("%.*s\n", static_cast<int>(t.name.size()), t.name.data());
		}
		return 0;
	}
	std::size_t ran = 0U;
	for (const Test &t : TESTS) {
		if (isSelected(t.name, argc, argv)) {
			t.run();
			ran++;
		}
	}
	if (ran == 0U) {
		(void)std::fprintf(stderr, "no test matches; test_unit -l lists the names\n");
		return 2;
	}
	if (ran < TESTS.size()) {
		(void)std::printf("%zu of %zu tests: ", ran, TESTS.size());
	}
	(void)std::printf("%d/%d checks passed\n", sChecks - sFails, sChecks);
	return (sFails != 0) ? 1 : 0;
}
