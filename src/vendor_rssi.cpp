// SPDX-License-Identifier: MIT
// Per-STA RSSI from the Wi-Fi driver (see vendor_rssi.hpp).
//
// VENDOR PLACEHOLDER. Fill in the four functions in "vendor implementation"
// once the chipset vendor's API documentation is reviewed. Typical shapes:
//   - an nl80211 vendor command (NL80211_CMD_VENDOR with the vendor OUI and
//     subcommand) carrying the STA MAC; the result comes back in the reply
//     or as a vendor event;
//   - a private ioctl / iwpriv on the radio's netdev;
//   - a vendor library or ubus/procfs interface.
// Rules for the implementation:
//   - no blocking: the daemon is one poll() loop. start must return at once
//     and read is called once, after durationMs (the watch end);
//   - system calls go into os.cpp (the only file allowed to touch POSIX), as
//     for survey.cpp's genetlink;
//   - map the driver's "no sample" to NOT_HEARD and errors to FAILED, so the
//     requesting AP gets the right STA_MONITOR_STATUS;
//   - report the average RSSI in dBm of the STA's own frames (uplink), the
//     same quantity a radiotap monitor gives.
//
// SIMULATED DRIVER (sta_rssi_sim <file>, tests). The file is re-read on
// each call, so a test can change it while the daemon runs:
//   unsupported              -> isStaRssiSupported() is false
//   fail                     -> startStaRssi() returns FAILED
//   <ifname> <sta> <dBm>     -> readStaRssi() returns that RSSI (10 samples)
// A STA without a line is NOT_HEARD; a missing file means unsupported.
#include "vendor_rssi.hpp"

#include <array>
#include <optional>

#include "config.hpp"
#include "os.hpp"
#include "text.hpp"

namespace donghoa {
namespace vendor {

namespace {

Path sSimPath{};
bool sSim = false;
FixedString<16384U> sSimText{};

// Lines of the simulation file; false if it cannot be read.
bool readSim() noexcept
{
	return os::readTextFile(sSimPath.cStr(), sSimText);
}

std::string_view nextToken(std::string_view &s) noexcept
{
	std::size_t i = 0U;
	while ((i < s.size()) && isSpace(s[i])) {
		i++;
	}
	std::size_t j = i;
	while ((j < s.size()) && !isSpace(s[j])) {
		j++;
	}
	const std::string_view t = subView(s, i, j - i);
	s = subView(s, j, s.size() - j);
	return t;
}

// True if the file holds the single-word line w.
bool hasSimWord(std::string_view w) noexcept
{
	std::string_view rest = sSimText.view();
	bool found = false;
	while (!rest.empty() && !found) {
		const std::size_t nl = rest.find('\n');
		const std::size_t len = (nl == std::string_view::npos) ? rest.size() : nl;
		found = trim(subView(rest, 0U, len)) == w;
		rest = subView(rest, (nl == std::string_view::npos) ? rest.size() : (nl + 1U), rest.size());
	}
	return found;
}

std::optional<int> findSimRssi(std::string_view ifname, const Mac &sta) noexcept
{
	std::string_view rest = sSimText.view();
	std::optional<int> r;
	while (!rest.empty() && !r.has_value()) {
		const std::size_t nl = rest.find('\n');
		const std::size_t len = (nl == std::string_view::npos) ? rest.size() : nl;
		std::string_view line = subView(rest, 0U, len);
		rest = subView(rest, (nl == std::string_view::npos) ? rest.size() : (nl + 1U), rest.size());
		const std::string_view ifn = nextToken(line);
		const std::optional<Mac> mac = parseMac(nextToken(line));
		const std::optional<long> dbm = parseLong(nextToken(line), 10, -127, 0);
		if ((ifn == ifname) && mac.has_value() && (*mac == sta) && dbm.has_value()) {
			r = static_cast<int>(*dbm);
		}
	}
	return r;
}

// ---- vendor implementation (placeholder) ----

bool vendorSupported(std::string_view ifname) noexcept
{
	// TODO(vendor): ask the driver whether the radio behind ifname has the
	// per-STA RSSI API (capability query, or try the command once).
	(void)ifname;
	return false;
}

RssiStatus vendorStart(std::string_view ifname, const Mac &sta, std::uint8_t opClass, std::uint8_t channel,
		       std::uint16_t durationMs) noexcept
{
	// TODO(vendor): pass sta to the driver of ifname and start the
	// measurement for durationMs (opClass/channel: the STA's channel).
	(void)ifname;
	(void)sta;
	(void)opClass;
	(void)channel;
	(void)durationMs;
	return RssiStatus::UNSUPPORTED;
}

RssiStatus vendorRead(std::string_view ifname, const Mac &sta, RssiSample &out) noexcept
{
	// TODO(vendor): fetch the measured RSSI (dBm), frame count and age.
	(void)ifname;
	(void)sta;
	out = RssiSample{};
	return RssiStatus::UNSUPPORTED;
}

void vendorStop(std::string_view ifname, const Mac &sta) noexcept
{
	// TODO(vendor): release the driver's per-STA measurement entry.
	(void)ifname;
	(void)sta;
}

} // namespace

void useSimFile(std::string_view path) noexcept
{
	sSim = !path.empty();
	(void)sSimPath.assign(path);
}

bool isStaRssiSupported(std::string_view ifname) noexcept
{
	bool r = false;
	if (!sSim) {
		r = vendorSupported(ifname);
	} else {
		r = readSim() && !hasSimWord("unsupported");
	}
	return r;
}

RssiStatus startStaRssi(std::string_view ifname, const Mac &sta, std::uint8_t opClass, std::uint8_t channel,
			std::uint16_t durationMs) noexcept
{
	RssiStatus r = RssiStatus::OK;
	if (!sSim) {
		r = vendorStart(ifname, sta, opClass, channel, durationMs);
	} else if (!readSim() || hasSimWord("unsupported")) {
		r = RssiStatus::UNSUPPORTED;
	} else if (hasSimWord("fail")) {
		r = RssiStatus::FAILED;
	} else {
		// measuring
	}
	return r;
}

RssiStatus readStaRssi(std::string_view ifname, const Mac &sta, RssiSample &out) noexcept
{
	RssiStatus r = RssiStatus::NOT_HEARD;
	out = RssiSample{};
	if (!sSim) {
		r = vendorRead(ifname, sta, out);
	} else if (!readSim()) {
		r = RssiStatus::FAILED;
	} else {
		const std::optional<int> dbm = findSimRssi(ifname, sta);
		if (dbm.has_value()) {
			out.rssi = static_cast<std::int8_t>(*dbm);
			out.samples = 10U;
			out.ageMs = 50U;
			r = RssiStatus::OK;
		}
	}
	return r;
}

void stopStaRssi(std::string_view ifname, const Mac &sta) noexcept
{
	if (!sSim) {
		vendorStop(ifname, sta);
	}
}

} // namespace vendor
} // namespace donghoa
