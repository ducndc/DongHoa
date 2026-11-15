// SPDX-License-Identifier: MIT
// Unit tests: configuration file (src/core/config).
#include <array>
#include <string_view>

#include "unit.hpp"

#include "core/config.hpp"
#include "core/proto.hpp"
#include "core/rrm.hpp"
#include "core/sha256.hpp"

using namespace donghoa;

void testConfig()
{
	Config c;

	CHECK(parseConfigLine(c, "iface br-lan") && c.nIfaces == 1U && c.ifaces[0].view() == "br-lan");
	CHECK(parseConfigLine(c, "bss wlan0 mdid=a1b2 max_sta=32") && c.nBss == 1U && c.bss[0].mdid == 0xa1b2U &&
	      c.bss[0].maxSta == 32);
	CHECK(parseConfigLine(c, "rssi_low -72  # comment") && c.pol.rssiLow == -72);
	CHECK(parseConfigLine(c, "lb_only_idle 0") && !c.pol.lbOnlyIdle);
	CHECK(parseConfigLine(c, "key hex:00112233445566778899aabbccddeeff") && c.keyLen == 16U);
	CHECK(!parseConfigLine(c, "bogus 1"));
	CHECK(!parseConfigLine(c, "key short"));
	{
		// the public example key is refused, whatever its length
		Config pc;
		CHECK(!parseConfigLine(pc, "key change-me-to-a-long-random-secret") && pc.keyPlaceholder &&
		      pc.keyLen == 0U);
		// passphrase: PBKDF2-HMAC-SHA256 with the fixed salt
		CHECK(parseConfigLine(pc, "key a-long-passphrase") && pc.keyLen == 32U);
		const auto pw = bytesOf("a-long-passphrase");
		const auto salt = bytesOf("donghoa-arcp-key");
		const Digest d = pbkdf2Sha256(viewOf(pw), viewOf(salt), KEY_KDF_ITERATIONS);
		CHECK(arcp::ctEqual(pc.keyView(), viewOf(d)));
		// security is off by default
		Config dc;
		CHECK(dc.keyLen == 0U && !dc.livenessCheck && !dc.signing && !dc.enroll);
		CHECK(parseConfigLine(dc, "liveness_check 1") && dc.livenessCheck);
		CHECK(!parseConfigLine(dc, "liveness_check 2"));
		CHECK(parseConfigLine(dc, "enroll 1") && dc.enroll && !parseConfigLine(dc, "enroll 3"));
		// Ed25519: own seed, trusted peers (once each, valid points only)
		Config sc;
		CHECK(parseConfigLine(sc, "sign_seed hex:4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
		CHECK(sc.signing && hexs(sc.signKey.pub).view() ==
				    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
		CHECK(!parseConfigLine(sc, "sign_seed 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
		CHECK(!parseConfigLine(sc, "sign_seed hex:4ccd089b"));
		CHECK(parseConfigLine(sc, "peer_key 02:00:00:00:00:01 "
					  "hex:3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"));
		CHECK(sc.nTrusted == 1U && sc.findTrusted(mac("02:00:00:00:00:01")) != nullptr);
		CHECK(sc.findTrusted(mac("02:00:00:00:00:02")) == nullptr);
		CHECK(!parseConfigLine(sc, "peer_key 02:00:00:00:00:01 "        // listed twice
					   "hex:fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"));
		CHECK(!parseConfigLine(sc, "peer_key 02:00:00:00:00:03 "        // not a curve point
					   "hex:0200000000000000000000000000000000000000000000000000000000000000"));
		CHECK(!parseConfigLine(sc, "peer_key 02:00:00:00:00:03"));
		CHECK(!parseConfigLine(sc, "peer_key 02:00:00:00:00:03 "
					   "hex:fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025 x"));
		CHECK(sc.nTrusted == 1U);
		Config lc;
		std::array<char, 129U> longKey{};
		longKey.fill('x');
		FixedString<160U> line{"key "};
		CHECK(line.append(std::string_view(longKey.data(), longKey.size())));
		CHECK(!parseConfigLine(lc, line.view())); // over KEY_PASSPHRASE_MAX
	}
	CHECK(parseConfigLine(c, "ap_id 02:00:00:00:00:01") && c.apIdSet && c.apId.b[5] == 1U);
	CHECK(c.pol.scoreModel == ScoreModel::LINEAR && c.pol.staNss == 2);
	CHECK(parseConfigLine(c, "score_model 1") && c.pol.scoreModel == ScoreModel::TPUT);
	CHECK(parseConfigLine(c, "tput_gain_pct 200") && c.pol.tputGainPct == 200);
	CHECK(parseConfigLine(c, "beacon_mode 0") && c.pol.beaconMode == rrm::BeaconMode::PASSIVE);
	CHECK(!parseConfigLine(c, "beacon_mode 3"));
	CHECK(parseConfigLine(c, "key a-long-passphrase") && c.keyLen == 32U);
}
