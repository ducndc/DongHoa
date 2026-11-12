// SPDX-License-Identifier: MIT
// libFuzzer target: text the daemon parses. hostapd control replies and
// events (hapd_parse.cpp), hex 802.11 elements in them (rrm.cpp), the
// configuration file and the trust table file. The first byte selects the
// parser.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "config.hpp"
#include "hapd_parse.hpp"
#include "rrm.hpp"
#include "trust.hpp"

using namespace donghoa;

namespace {

Config sCfg;
trust::Table sTrust;

// One configuration line; "key" is skipped: its PBKDF2 (100000 rounds)
// would make every input that contains it take ~50 ms.
void parseConfigText(std::string_view text)
{
	sCfg = Config{};
	std::string_view rest = text;
	while (!rest.empty()) {
		const std::size_t eol = rest.find('\n');
		const std::string_view line = (eol == std::string_view::npos) ? rest : subView(rest, 0U, eol);
		rest = (eol == std::string_view::npos) ? std::string_view() : subView(rest, eol + 1U);
		if (!startsWith(trim(line), "key")) {
			(void)parseConfigLine(sCfg, line);
		}
	}
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	if (size < 1U) {
		return 0;
	}
	// NOLINTNEXTLINE: libFuzzer hands bytes; the parsers take text
	const std::string_view in(reinterpret_cast<const char *>(&data[1]), size - 1U);
	switch (data[0] % 6U) {
	case 0U:
		(void)hapd::parseStatus(in, "wlan0");
		break;
	case 1U:
		(void)hapd::parseSta(in);
		break;
	case 2U:
		(void)hapd::parseBtmResp(in);
		(void)hapd::netdevName(in);
		(void)hapd::ctrlLinkId(in);
		break;
	case 3U:
		(void)rrm::parseBcnRepHex(in);
		(void)rrm::parseBcnReqHex(in);
		(void)rrm::parseNrHex(in);
		(void)rrm::isFtAkm(in);
		(void)rrm::isAkmForbidden6g(in);
		break;
	case 4U:
		parseConfigText(in);
		break;
	default:
		sTrust = trust::Table{};
		(void)trust::loadText(sTrust, in);
		break;
	}
	return 0;
}
