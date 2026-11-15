// SPDX-License-Identifier: MIT
// Unit tests: checked parsing and comparison, log levels (src/base).
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

#include "unit.hpp"

#include "base/log.hpp"
#include "core/config.hpp"
#include "core/hapd_parse.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"

using namespace donghoa;

// Robustness: checked number parsing, field-wise struct comparison
void testRobustness()
{
	CHECK(parseLong("42", 10, 0, 100) == std::optional<long>(42));
	CHECK(parseLong("-75", 10, -128, 0) == std::optional<long>(-75));
	CHECK(parseLong("a1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(parseLong("0xa1b2", 16, 0, 0xffff) == std::optional<long>(0xa1b2));
	CHECK(!parseLong("", 10, 0, 100).has_value());          // empty
	CHECK(!parseLong("12x", 10, 0, 100).has_value());       // junk
	CHECK(!parseLong("12 34", 10, 0, 100).has_value());     // two values
	CHECK(!parseLong("101", 10, 0, 100).has_value());       // range
	CHECK(!parseLong("99999999999999999999", 10, std::numeric_limits<long>::min(),
			  std::numeric_limits<long>::max()).has_value());
	CHECK(parseLongTok("217 mcs 2 shortGI", 10, 0, 100000) == std::optional<long>(217));
	CHECK(parseLongTok("7", 10, 0, 255) == std::optional<long>(7));
	CHECK(!parseLongTok("7x bss", 10, 0, 255).has_value());
	CHECK(parseU64("18446744073709551615") ==
	      std::optional<std::uint64_t>(std::numeric_limits<std::uint64_t>::max()));
	CHECK(!parseU64("18446744073709551616").has_value()); // overflow
	CHECK(!parseU64("-1").has_value() && !parseU64("12a").has_value() && !parseU64("").has_value());
	CHECK(parseMac("a:b:c:d:e:f").has_value() && !parseMac("aa:bb:cc:dd:ee").has_value() &&
	      !parseMac("aa:bb:cc:dd:ee:ff:00").has_value() && !parseMac("aa:bb:cc:dd:ee:fg").has_value());

	// Config values that used to become 0 silently are rejected
	Config c;
	CHECK(!parseConfigLine(c, "sim_port abc") && !parseConfigLine(c, "sim_port 70000") &&
	      !parseConfigLine(c, "sim_port 0"));
	CHECK(!parseConfigLine(c, "bss wlan0 mdid=xyz") && !parseConfigLine(c, "bss wlan0 max_sta=12abc"));
	CHECK(!parseConfigLine(c, "rssi_low 99999999999"));
	CHECK(parseConfigLine(c, "air_monitor_sim 31000") && c.monitorSimPort == 31000U);
	CHECK(parseConfigLine(c, "bss wlan1 mdid=A1B2 max_sta=64") && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].maxSta == 64);

	// hostapd fields that do not parse are ignored or rejected
	CHECK(!hapd::parseBtmResp("BSS-TM-RESP aa:bb:cc:dd:ee:01 status_code=x7").has_value());
	const std::optional<hapd::Sta> st = hapd::parseSta("aa:bb:cc:dd:ee:01\nrx_bytes=-5\ntx_bytes=12\n");
	CHECK(st.has_value() && st->rxBytes == 0U && st->txBytes == 12U);
	CHECK(!rrm::isFtAkm("00-0f-ac-4x") && !rrm::isFtAkm("00-0f-ac-"));

	// BssInfo equality ignores SSID bytes beyond ssidLen
	arcp::BssInfo a;
	arcp::BssInfo b;
	a.freq = 5180U;
	b.freq = 5180U;
	a.channel = 36U;
	b.channel = 36U;
	a.ssidLen = 4U;
	b.ssidLen = 4U;
	for (std::size_t i = 0U; i < 4U; i++) {
		a.ssid[i] = static_cast<std::uint8_t>("home"[i]);
		b.ssid[i] = static_cast<std::uint8_t>("home"[i]);
	}
	b.ssid[10] = 0xa5U; // beyond ssidLen
	CHECK(a == b);
	b.channel = 40U;
	CHECK(a != b);
	b.channel = 36U;
	b.ssid[3] = 'x';
	CHECK(a != b);
}

// Per-module log levels and config keys
void testLog()
{
	Config c;

	// Every module, the last one included, starts at info. Checked before
	// anything here sets a level.
	for (std::size_t i = 0U; i < logging::MODULES; i++) {
		CHECK(logging::level(logging::moduleAt(i)) == LogLevel::INFO);
	}
	CHECK(logging::parseLevel("debug") == std::optional<LogLevel>(LogLevel::DEBUG));
	CHECK(logging::parseLevel("err") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(!logging::parseLevel("verbose").has_value());
	// RFC 5424 keywords, common aliases and numeric codes
	CHECK(logging::parseLevel("warning") == std::optional<LogLevel>(LogLevel::WARN));
	CHECK(logging::parseLevel("warn") == std::optional<LogLevel>(LogLevel::WARN));
	CHECK(logging::parseLevel("notice") == std::optional<LogLevel>(LogLevel::NOTICE));
	CHECK(logging::parseLevel("error") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("crit") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("emerg") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("0") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("2") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("3") == std::optional<LogLevel>(LogLevel::ERR));
	CHECK(logging::parseLevel("5") == std::optional<LogLevel>(LogLevel::NOTICE));
	CHECK(logging::parseLevel("7") == std::optional<LogLevel>(LogLevel::DEBUG));
	CHECK(!logging::parseLevel("8").has_value() && !logging::parseLevel("-1").has_value());
	CHECK(!logging::parseLevel("").has_value());
	// A number is one digit: no sign, no leading zeros
	CHECK(!logging::parseLevel("-0").has_value() && !logging::parseLevel("00").has_value());
	CHECK(!logging::parseLevel("007").has_value() && !logging::parseLevel("+5").has_value());
	CHECK(!logging::parseLevel("5 ").has_value() && !logging::parseLevel("-").has_value());
	CHECK(static_cast<int>(LogLevel::ERR) == 3 && static_cast<int>(LogLevel::NOTICE) == 5 &&
	      static_cast<int>(LogLevel::DEBUG) == 7);
	CHECK(logging::levelName(LogLevel::NOTICE) == "notice");
	logging::setAll(LogLevel::NOTICE);
	CHECK(logging::enabled(LogModule::PEER, LogLevel::NOTICE) && logging::enabled(LogModule::PEER, LogLevel::WARN) &&
	      !logging::enabled(LogModule::PEER, LogLevel::INFO));
	logging::setAll(static_cast<LogLevel>(1U)); // invalid: ignored
	CHECK(logging::level(LogModule::PEER) == LogLevel::NOTICE);
	logging::setAll(LogLevel::INFO);
	CHECK(logging::parseModule("steer") == std::optional<LogModule>(LogModule::STEER));
	CHECK(logging::parseModule("config") == std::optional<LogModule>(LogModule::CONFIG));
	CHECK(logging::parseModule("rrm") == std::optional<LogModule>(LogModule::RRM));
	CHECK(logging::levelName(static_cast<LogLevel>(1U)) == "?" &&
	      logging::levelName(static_cast<LogLevel>(8U)) == "?");
	CHECK(!logging::parseModule("nosuch").has_value());
	CHECK(logging::moduleName(LogModule::AMON) == "amon" && logging::levelName(LogLevel::WARN) == "warning");

	logging::setAll(LogLevel::INFO);
	logging::setLevel(LogModule::STEER, LogLevel::DEBUG);
	CHECK(logging::level(LogModule::STEER) == LogLevel::DEBUG && logging::level(LogModule::MSG) == LogLevel::INFO);
	CHECK(logging::enabled(LogModule::STEER, LogLevel::DEBUG) &&
	      !logging::enabled(LogModule::MSG, LogLevel::DEBUG) &&
	      logging::enabled(LogModule::MSG, LogLevel::INFO));
	logging::setAll(LogLevel::ERR);
	CHECK(!logging::enabled(LogModule::STEER, LogLevel::WARN) &&
	      logging::enabled(LogModule::CONFIG, LogLevel::ERR));
	logging::setAll(LogLevel::INFO);

	CHECK(c.logLevel == LogLevel::INFO && c.logDebugMask == 0U);
	CHECK(parseConfigLine(c, "log_level warn") && c.logLevel == LogLevel::WARN);
	CHECK(parseConfigLine(c, "log_level notice") && c.logLevel == LogLevel::NOTICE);
	CHECK(parseConfigLine(c, "log_level 6") && c.logLevel == LogLevel::INFO);
	CHECK(parseConfigLine(c, "log_debug steer,amon msg") &&
	      c.logDebugMask == ((1U << static_cast<std::uint32_t>(LogModule::STEER)) |
				   (1U << static_cast<std::uint32_t>(LogModule::AMON)) |
				   (1U << static_cast<std::uint32_t>(LogModule::MSG))));
	CHECK(!parseConfigLine(c, "log_level verbose") && !parseConfigLine(c, "log_debug nosuch"));

	// type-safe formatting
	Line l;
	formatTo(l, "a {} b {} c {} d {} e {}", -5, 7U, mac("02:00:00:00:00:01"), hex(0x1aU, 4U),
		  std::string_view("x"));
	CHECK(l.view() == "a -5 b 7 c 02:00:00:00:00:01 d 001a e x");
	l.clear();
	formatTo(l, "{} {}", std::numeric_limits<std::int64_t>::min(), "extra {}");
	CHECK(l.view() == "-9223372036854775808 extra {}");
}
