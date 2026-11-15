// SPDX-License-Identifier: MIT
// Unit tests: configuration consistency check (src/core/consistency).
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "unit.hpp"

#include "core/config.hpp"
#include "core/consistency.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"

using namespace donghoa;

namespace {

arcp::BssInfo essBss(std::uint8_t last, std::string_view ssid, std::uint16_t caps, std::uint16_t mdid,
		     bool secured)
{
	arcp::BssInfo b;
	b.bssid = Mac{{2U, 0U, 0U, 0U, 1U, last}};
	b.ssidLen = static_cast<std::uint8_t>(ssid.size());
	for (std::size_t i = 0U; i < ssid.size(); i++) {
		b.ssid[i] = static_cast<std::uint8_t>(ssid[i]);
	}
	b.caps = caps;
	b.mdid = mdid;
	b.bssidInfo = secured ? rrm::BI_SECURITY : 0U;
	return b;
}

} // namespace

void testConsistency()
{
	using namespace consistency;
	const std::uint16_t ft = arcp::CAP_FT | arcp::CAP_BTM;
	const arcp::BssInfo a = essBss(1U, "Home", ft, 0x1234U, true);
	CHECK(checkPair(a, essBss(2U, "Home", ft, 0x1234U, true)) == 0U);
	CHECK(checkPair(a, essBss(2U, "Home", ft, 0x4321U, true)) == MDID_DIFFERS);
	CHECK(checkPair(a, essBss(2U, "Home", arcp::CAP_BTM, 0U, true)) == FT_ONE_SIDED);
	CHECK(checkPair(a, essBss(2U, "Home", ft | arcp::CAP_FT_OVER_DS, 0x1234U, true)) == FT_DS_DIFFERS);
	CHECK(checkPair(a, essBss(2U, "Home", ft, 0x1234U, false)) == SECURITY_DIFFERS);
	CHECK(checkPair(a, essBss(2U, "Home", arcp::CAP_BTM, 0U, false)) == (FT_ONE_SIDED | SECURITY_DIFFERS));
	// other ESS, the same BSS, links of one AP MLD: nothing to compare
	CHECK(checkPair(a, essBss(2U, "Guest", 0U, 0U, false)) == 0U);
	CHECK(checkPair(a, a) == 0U);
	arcp::BssInfo l1 = essBss(3U, "Home", ft, 0x1111U, true);
	arcp::BssInfo l2 = essBss(4U, "Home", ft, 0x2222U, true);
	l1.mldAddr = Mac{{2U, 9U, 9U, 9U, 9U, 9U}};
	l2.mldAddr = l1.mldAddr;
	CHECK(checkPair(l1, l2) == 0U);
	CHECK(pairIssueName(MDID_DIFFERS) == "mdid_differs");
	CHECK(!pairIssueHint(SECURITY_DIFFERS).empty());
	CHECK(pairIssueName(0x100U) == "?");

	PolicyConfig p;
	const arcp::PolicySum s0 = summarize(p);
	CHECK(s0.rssiLow == -75 && s0.utilHigh == 70 && s0.steerCooldownS == 30U);
	CHECK((s0.flags & arcp::POL_RSSI_STEERING) != 0U && (s0.flags & arcp::POL_LOAD_BALANCING) != 0U);
	CHECK(diffPolicy(s0, s0) == 0U);
	PolicyConfig q;
	q.rssiLow = -70;
	q.utilHigh = 80;
	q.loadBalancing = false;
	const arcp::PolicySum s1 = summarize(q);
	const std::uint32_t d = diffPolicy(s0, s1);
	CHECK(d == (POL_RSSI_LOW | POL_UTIL_HIGH | POL_FEATURES));
	DiffText t;
	describePolicyDiff(t, s0, s1, d);
	CHECK(t.view() == "load_balancing 1/0 rssi_low -75/-70 util_high 70/80");
	// out-of-range values saturate instead of wrapping
	q.rssiLow = -300;
	q.steerCooldownMs = 100000000;
	CHECK(summarize(q).rssiLow == -128 && summarize(q).steerCooldownS == 65535U);

	// POLICY TLV round trip, and a longer TLV from a newer peer
	arcp::Message m;
	m.begin(arcp::MsgType::HELLO, 0U, Mac{{2U}}, 1U, 1U);
	CHECK(m.add(s1));
	CHECK(m.finish(ByteView()));
	const std::optional<arcp::Header> h = arcp::parseHeader(m.bytes());
	CHECK(h.has_value());
	if (!h.has_value()) {
		return;
	}
	arcp::TlvReader rd(m.bytes(), *h);
	std::uint8_t ty = 0U;
	ByteView v;
	arcp::PolicySum o;
	CHECK(rd.next(ty, v) && ty == arcp::raw(arcp::Tlv::POLICY) && v.size() == arcp::POLICY_LEN);
	CHECK(arcp::decode(v, o) && diffPolicy(o, s1) == 0U);
	CHECK(!arcp::decode(v.first(arcp::POLICY_LEN - 1U), o));
	std::array<std::uint8_t, arcp::POLICY_LEN + 4U> longer{};
	for (std::size_t i = 0U; i < v.size(); i++) {
		longer[i] = v[i];
	}
	arcp::PolicySum o2;
	CHECK(arcp::decode(viewOf(longer), o2) && diffPolicy(o2, s1) == 0U);
	CHECK(arcp::tlvName(arcp::raw(arcp::Tlv::POLICY)) == "POLICY");
}
