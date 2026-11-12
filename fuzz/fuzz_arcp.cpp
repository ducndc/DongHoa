// SPDX-License-Identifier: MIT
// libFuzzer target: a received ARCP frame, as msg.cpp handles it (header,
// HMAC, Ed25519 signature, every TLV through its decoder). See fuzz/README.md.
#include <cstddef>
#include <cstdint>

#include "ed25519.hpp"
#include "proto.hpp"

using namespace donghoa;

namespace {

const std::array<std::uint8_t, 32U> KEY{{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 16U,
					   17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U, 27U, 28U, 29U, 30U,
					   31U, 32U}};

// A valid public key, so verifySig gets past the key decoding.
const ed25519::KeyPair sSigner = ed25519::keyPairFromSeed(KEY);

template <typename T> void decodeAs(ByteView v)
{
	T o{};
	(void)arcp::decode(v, o);
}

void decodeTlv(std::uint8_t type, ByteView v)
{
	switch (static_cast<arcp::Tlv>(type)) {
	case arcp::Tlv::AP_INFO: decodeAs<arcp::ApInfo>(v); break;
	case arcp::Tlv::BSS_INFO: decodeAs<arcp::BssInfo>(v); break;
	case arcp::Tlv::BSS_LOAD: decodeAs<arcp::BssLoad>(v); break;
	case arcp::Tlv::STA_ENTRY: decodeAs<arcp::StaEntry>(v); break;
	case arcp::Tlv::RF_INFO: decodeAs<arcp::RfInfo>(v); break;
	case arcp::Tlv::STA_EVENT: decodeAs<arcp::StaEvent>(v); break;
	case arcp::Tlv::STA_CLASS: decodeAs<arcp::StaClass>(v); break;
	case arcp::Tlv::STEER_REQ: decodeAs<arcp::SteerReq>(v); break;
	case arcp::Tlv::STEER_RESP: decodeAs<arcp::SteerResp>(v); break;
	case arcp::Tlv::STEER_RESULT: decodeAs<arcp::SteerResult>(v); break;
	case arcp::Tlv::STA_MONITOR_REQ: decodeAs<arcp::StaMonitorReq>(v); break;
	case arcp::Tlv::STA_MONITOR_RESULT: decodeAs<arcp::StaMonitorResult>(v); break;
	case arcp::Tlv::STA_MONITOR_STATUS: decodeAs<arcp::StaMonitorStatus>(v); break;
	case arcp::Tlv::STA_ROAM: decodeAs<arcp::StaRoam>(v); break;
	case arcp::Tlv::TRUST_REC: decodeAs<arcp::TrustRecord>(v); break;
	case arcp::Tlv::POLICY: decodeAs<arcp::PolicySum>(v); break;
	case arcp::Tlv::CHALLENGE:
	case arcp::Tlv::RESPONSE: {
		arcp::Nonce n{};
		(void)arcp::decodeNonce(v, n);
		break;
	}
	case arcp::Tlv::ENROLL_KEY: {
		ed25519::PublicKey pub{};
		if (arcp::decodeEnrollKey(v, pub)) {
			(void)ed25519::isValidPublicKey(pub);
		}
		break;
	}
	case arcp::Tlv::ACK: {
		std::uint32_t id = 0U;
		(void)arcp::decodeAck(v, id);
		break;
	}
	default:
		break;
	}
	(void)arcp::tlvName(type);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const ByteView frame(data, size);
	const std::optional<arcp::Header> h = arcp::parseHeader(frame);
	if (h.has_value()) {
		(void)arcp::msgName(h->type);
		(void)arcp::verify(frame, *h, ByteView());
		(void)arcp::verify(frame, *h, viewOf(KEY));
		(void)arcp::verifySig(frame, *h, sSigner.pub);
		arcp::TlvReader rd(frame, *h);
		std::uint8_t type = 0U;
		ByteView v;
		while (rd.next(type, v)) {
			decodeTlv(type, v);
		}
		arcp::ReplayWindow w{};
		arcp::resetSeq(w, h->bootId, h->msgId);
		(void)arcp::acceptSeq(w, h->bootId, h->msgId + 1U);
	}
	// Not a frame: the bytes as a raw (public key, signature, message)
	// triple, for point decoding and the S < L check on arbitrary input.
	if (!h.has_value() && (size >= 96U)) {
		ed25519::PublicKey pub{};
		ed25519::Signature sig{};
		for (std::size_t i = 0U; i < pub.size(); i++) {
			pub[i] = data[i];
		}
		for (std::size_t i = 0U; i < sig.size(); i++) {
			sig[i] = data[32U + i];
		}
		(void)ed25519::verify(pub, frame.sub(96U, size - 96U), sig);
	}
	return 0;
}
