// SPDX-License-Identifier: MIT
#include "rrm_log.hpp"

#include <array>
#include <cstdint>
#include <optional>

#include "hapd_parse.hpp"
#include "log.hpp"
#include "rrm.hpp"
#include "text.hpp"

namespace donghoa {
namespace rrmlog {

namespace {

constexpr LogModule LOG_MODULE{LogModule::RRM};

constexpr std::string_view REQ_BEACON = "REQ_BEACON ";
constexpr std::string_view BSS_TM_REQ = "BSS_TM_REQ ";
constexpr std::string_view SET_NEIGHBOR = "SET_NEIGHBOR ";
constexpr std::string_view REMOVE_NEIGHBOR = "REMOVE_NEIGHBOR ";
constexpr std::string_view BEACON_RESP_RX = "BEACON-RESP-RX ";
constexpr std::string_view BEACON_REQ_TX_STATUS = "BEACON-REQ-TX-STATUS ";
constexpr std::string_view BSS_TM_RESP = "BSS-TM-RESP ";
constexpr std::string_view BSS_TM_QUERY = "BSS-TM-QUERY ";

// The text without trailing newlines.
std::string_view trimEol(std::string_view s) noexcept
{
	std::size_t n = s.size();
	while ((n > 0U) && ((s[n - 1U] == '\n') || (s[n - 1U] == '\r'))) {
		n--;
	}
	return subView(s, 0U, n);
}

// Value of key=<value> among the space-separated tokens of s.
std::optional<std::string_view> findOption(std::string_view s, std::string_view key) noexcept
{
	Tokens t(s, " ");
	std::string_view tok;
	std::optional<std::string_view> r;
	while (!r.has_value() && t.next(tok)) {
		if ((tok.size() > key.size()) && startsWith(tok, key) && (tok[key.size()] == '=')) {
			r = subView(tok, key.size() + 1U);
		}
	}
	return r;
}

std::string_view modeName(std::uint8_t mode) noexcept
{
	constexpr std::array<std::string_view, 3U> NAMES{"passive", "active", "table"};
	return (mode < NAMES.size()) ? NAMES[mode] : std::string_view("?");
}

// "REQ_BEACON <sta> [req_mode=<hex>] <hex>": the request is the last token.
void decodeBeaconReq(std::string_view ifname, std::string_view args, std::string_view reply) noexcept
{
	Tokens t(args, " ");
	std::string_view sta;
	std::string_view tok;
	std::string_view hex;
	if (!t.next(sta)) {
		return;
	}
	while (t.next(tok)) {
		hex = tok;
	}
	const std::optional<rrm::BeaconRequest> q = rrm::parseBcnReqHex(hex);
	if (!q.has_value()) {
		logging::dbg(LOG_MODULE, "{}   11k beacon request: undecodable", ifname);
		return;
	}
	Line l;
	formatTo(l, "{}   11k beacon request -> {}: ", ifname, sta);
	if (startsWith(reply, "FAIL")) {
		formatTo(l, "refused by hostapd (mode not advertised by the STA?),");
	} else {
		formatTo(l, "token {}", reply);
	}
	formatTo(l, " op_class {} ch {} mode {} dur {} TU rand {} TU bssid {}", q->opClass, q->channel,
		 modeName(q->mode), q->duration, q->randInt, q->bssid);
	if (q->hasSsid) {
		formatTo(l, " ssid \"{}\"", SsidText{viewOf(q->ssid).first(q->ssidLen)});
	}
	if (q->detail >= 0) {
		formatTo(l, " detail {}", q->detail);
	}
	if (q->nChans > 0U) {
		formatTo(l, " chans");
		for (std::size_t i = 0U; i < q->nChans; i++) {
			formatTo(l, " {}/{}", q->chans[i].opClass, q->chans[i].channel);
		}
	}
	logging::dbg(LOG_MODULE, "{}", l.view());
}

// neighbor=<BSSID>,<BSSID Info>,<Op Class>,<Channel>,<PHY type>[,<subelems>]
void decodeBtmReq(std::string_view ifname, std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view sta;
	if (!t.next(sta)) {
		return;
	}
	Line l;
	formatTo(l, "{}   11v BTM request -> {}:", ifname, sta);
	const std::optional<std::string_view> nb = findOption(args, "neighbor");
	if (nb.has_value()) {
		Tokens f(*nb, ",");
		std::array<std::string_view, 6U> v{};
		std::size_t n = 0U;
		while ((n < v.size()) && f.next(v[n])) {
			n++;
		}
		const std::optional<long> bi = (n > 1U) && startsWith(v[1U], "0x")
						       ? parseLong(subView(v[1U], 2U), 16, 0, 0xffffffffL)
						       : std::optional<long>();
		formatTo(l, " candidate {} op_class {} ch {} phy {}", v[0U], v[2U], v[3U], v[4U]);
		if (bi.has_value()) {
			FixedString<96U> info;
			rrm::describeBssidInfo(static_cast<std::uint32_t>(*bi), info);
			formatTo(l, " info [{}]", info.view());
		}
		// Subelement 3 (BSS Transition Candidate Preference): "03 01 <pref>"
		if ((n > 5U) && (v[5U].size() >= 6U) && startsWith(v[5U], "0301")) {
			const std::optional<long> pref = parseLong(subView(v[5U], 4U, 2U), 16, 0, 255);
			if (pref.has_value()) {
				formatTo(l, " cand_pref {}", *pref);
			}
		}
	}
	// Request Mode bits and timers; "pref" = Preferred Candidate List Included
	struct Key {
		std::string_view key;
		std::string_view name;
	};
	constexpr std::array<Key, 5U> KEYS{{
		{"pref", "pref_list"},
		{"abridged", "abridged"},
		{"valid_int", "valid_int"},
		{"disassoc_imminent", "disassoc_imminent"},
		{"disassoc_timer", "disassoc_timer"},
	}};
	formatTo(l, ";");
	for (const Key &k : KEYS) {
		const std::optional<std::string_view> o = findOption(args, k.key);
		if (o.has_value()) {
			formatTo(l, " {}={}", k.name, *o);
		}
	}
	logging::dbg(LOG_MODULE, "{}", l.view());
}

// "SET_NEIGHBOR <bssid> ssid=<hex> nr=<hex>"
void decodeSetNeighbor(std::string_view ifname, std::string_view args) noexcept
{
	const std::optional<std::string_view> nrHex = findOption(args, "nr");
	const std::optional<rrm::NeighborReport> nr =
		nrHex.has_value() ? rrm::parseNrHex(*nrHex) : std::optional<rrm::NeighborReport>();
	if (!nr.has_value()) {
		return;
	}
	Line l;
	FixedString<96U> info;
	rrm::describeBssidInfo(nr->bssidInfo, info);
	formatTo(l, "{}   11k neighbor report entry {}", ifname, nr->bssid);
	const std::optional<std::string_view> ssidHex = findOption(args, "ssid");
	std::array<std::uint8_t, 32U> ssid{};
	const std::optional<std::size_t> sl =
		ssidHex.has_value() ? hexDecode(*ssidHex, spanOf(ssid)) : std::optional<std::size_t>();
	if (sl.has_value()) {
		formatTo(l, " ssid \"{}\"", SsidText{viewOf(ssid).first(*sl)});
	}
	formatTo(l, " op_class {} ch {} phy {} info [{}]", nr->opClass, nr->channel, nr->phyType, info.view());
	logging::dbg(LOG_MODULE, "{}", l.view());
}

// "BEACON-RESP-RX <sta> <token> <report mode hex> [<report hex>]"
void decodeBeaconResp(std::string_view ifname, std::string_view args) noexcept
{
	Tokens t(args, " ");
	std::string_view sta;
	std::string_view token;
	std::string_view mode;
	std::string_view hex;
	if (!(t.next(sta) && t.next(token) && t.next(mode))) {
		return;
	}
	const bool haveHex = t.next(hex);
	const std::optional<long> m = parseLong(mode, 16, 0, 255);
	Line l;
	formatTo(l, "{}   11k beacon report <- {}: token {} mode {}", ifname, sta, token,
		 m.has_value() ? rrm::reportModeName(static_cast<std::uint8_t>(*m)) : std::string_view("?"));
	const std::optional<rrm::BeaconReport> r =
		haveHex ? rrm::parseBcnRepHex(hex) : std::optional<rrm::BeaconReport>();
	if (r.has_value()) {
		formatTo(l, ", bssid {} op_class {} ch {} rcpi {} ({} dBm) rsni {} dur {} TU phy {} frame {}", r->bssid,
			 r->opClass, r->channel, r->rcpi, rrm::rcpiToDbm(r->rcpi), r->rsni, r->duration,
			 r->frameInfo & 0x7fU, ((r->frameInfo & 0x80U) != 0U) ? "pilot" : "beacon/probe-resp");
	}
	logging::dbg(LOG_MODULE, "{}", l.view());
}

void decodeBtmResp(std::string_view ifname, std::string_view ev) noexcept
{
	const std::optional<hapd::BtmResp> r = hapd::parseBtmResp(ev);
	if (!r.has_value()) {
		return;
	}
	Line l;
	formatTo(l, "{}   11v BTM response <- {}: status {} ({})", ifname, r->addr, r->status,
		 rrm::btmStatusName(r->status));
	if (r->hasTarget) {
		formatTo(l, " target {}", r->target);
	}
	logging::dbg(LOG_MODULE, "{}", l.view());
}

} // namespace

void logCommand(std::string_view ifname, std::string_view command, std::string_view reply) noexcept
{
	const bool beacon = startsWith(command, REQ_BEACON);
	const bool btm = startsWith(command, BSS_TM_REQ);
	const bool setNb = startsWith(command, SET_NEIGHBOR);
	const bool dot11 = beacon || btm || setNb || startsWith(command, REMOVE_NEIGHBOR);

	if (!dot11 || !logging::enabled(LOG_MODULE, LogLevel::DEBUG)) {
		return;
	}
	const std::string_view rep = trimEol(reply);
	logging::dbg(LOG_MODULE, "{} TX {} -> {}", ifname, command, rep);
	if (beacon) {
		decodeBeaconReq(ifname, subView(command, REQ_BEACON.size()), rep);
	} else if (btm) {
		decodeBtmReq(ifname, subView(command, BSS_TM_REQ.size()));
	} else if (setNb) {
		decodeSetNeighbor(ifname, subView(command, SET_NEIGHBOR.size()));
	} else {
		// REMOVE_NEIGHBOR: the raw line says it all
	}
}

void logEvent(std::string_view ifname, std::string_view ev) noexcept
{
	const bool bcn = startsWith(ev, BEACON_RESP_RX);
	const bool btm = startsWith(ev, BSS_TM_RESP);
	const bool dot11 = bcn || btm || startsWith(ev, BEACON_REQ_TX_STATUS) || startsWith(ev, BSS_TM_QUERY);

	if (!dot11 || !logging::enabled(LOG_MODULE, LogLevel::DEBUG)) {
		return;
	}
	logging::dbg(LOG_MODULE, "{} RX {}", ifname, trimEol(ev));
	if (bcn) {
		decodeBeaconResp(ifname, subView(ev, BEACON_RESP_RX.size()));
	} else if (btm) {
		decodeBtmResp(ifname, ev);
	} else {
		// BEACON-REQ-TX-STATUS (ack=0/1) and BSS-TM-QUERY: raw only
	}
}

} // namespace rrmlog
} // namespace donghoa
