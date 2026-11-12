// SPDX-License-Identifier: MIT
// Automatic key enrollment (PROTOCOL.md §10): own key created on first
// start, enrollment requests from APs not enrolled yet, approval by
// fingerprint on any trusted AP, trust table spread to every AP and kept on
// disk.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::ENROLL};
constexpr Millis ENROLL_REQ_INTERVAL_MS = 3000U;  // while not enrolled
constexpr Millis TRUST_SYNC_INTERVAL_MS = 60000U; // full table, multicast
constexpr Millis TRUST_SYNC_SOON_MS = 300U;       // after a change (batches several)
constexpr Millis PENDING_TTL_MS = 60000U;         // request quiet that long: forgotten

arcp::TrustRecord toWire(const trust::Record &r) noexcept
{
	arcp::TrustRecord w;
	w.apId = r.apId;
	w.pub = r.pub;
	w.revoked = r.revoked;
	w.gen = r.gen;
	return w;
}

trust::Record fromWire(const arcp::TrustRecord &w) noexcept
{
	trust::Record r;
	r.used = true;
	r.apId = w.apId;
	r.pub = w.pub;
	r.revoked = w.revoked;
	r.gen = w.gen;
	return r;
}

// Own seed: from the file, or a new random one written there (0600).
bool loadOrCreateSeed(const Path &file, ed25519::Seed &seed) noexcept
{
	FixedString<16384U> text;
	bool ok = false;
	if (os::readTextFile(file.cStr(), text)) {
		const std::optional<std::size_t> n = hexDecode(trim(text.view()), spanOf(seed));
		ok = n.has_value() && (*n == seed.size());
		if (!ok) {
			logging::err(LOG_MODULE, "{}: not a 64-digit hex seed", file);
		}
	} else if (os::randomBytes(spanOf(seed))) {
		FixedString<80U> out;
		(void)hexEncode(viewOf(seed), out);
		(void)out.pushBack('\n');
		ok = os::writeTextFile(file.cStr(), out.view());
		if (ok) {
			logging::notice(LOG_MODULE, "new signing key created in {}", file);
		} else {
			logging::err(LOG_MODULE, "cannot write {}: {}", file, os::lastError());
		}
	} else {
		logging::err(LOG_MODULE, "no randomness for a new signing key");
	}
	return ok;
}

} // namespace

const ed25519::PublicKey *Daemon::trustedKeyFor(const Mac &origin) const noexcept
{
	return mCfg.enroll ? trust::trustedKey(mTrust, origin) : mCfg.findTrusted(origin);
}

bool Daemon::initEnroll() noexcept
{
	if (!mCfg.enroll) {
		return true;
	}
	bool ok = true;
	if (!mCfg.signing) {
		ed25519::Seed seed{};
		ok = loadOrCreateSeed(mCfg.seedFile, seed);
		if (ok) {
			mCfg.signKey = ed25519::keyPairFromSeed(seed);
			mCfg.signing = true;
		}
	}
	FixedString<16384U> text;
	if (ok && os::readTextFile(mCfg.trustFile.cStr(), text)) {
		ok = trust::loadText(mTrust, text.view());
		if (!ok) {
			logging::err(LOG_MODULE, "{}: invalid trust table (fix or delete it)",
				     mCfg.trustFile);
		}
	}
	if (ok) {
		// peer_key lines are fixed anchors at generation 0: any approval or
		// revocation in the mesh supersedes them.
		for (std::size_t i = 0U; i < mCfg.nTrusted; i++) {
			trust::Record r;
			r.used = true;
			r.apId = mCfg.trusted[i].apId;
			r.pub = mCfg.trusted[i].pub;
			(void)trust::merge(mTrust, r);
		}
		const trust::Record *const self = trust::find(mTrust, mApId);
		if (self == nullptr) {
			trust::Record r;
			r.used = true;
			r.apId = mApId;
			r.pub = mCfg.signKey.pub;
			(void)trust::merge(mTrust, r);
		} else if ((self->pub != mCfg.signKey.pub) || self->revoked) {
			logging::warn(LOG_MODULE,
				      "the trust table has {} for this AP: a trusted AP must approve "
						  "this key again", self->revoked ? "a revocation" :
						  "another key");
		} else {
			// our own record, current
		}
		mTrust.enrolled = mTrust.enrolled || (trust::countTrustedOthers(mTrust, mApId) > 0U);
		saveTrust();
		logging::notice(LOG_MODULE, "key fingerprint {} ({}), {}",
				trust::fingerprint(mCfg.signKey.pub), mApId,
				mTrust.enrolled ? "enrolled" : "not enrolled: asking to be approved");
	}
	return ok;
}

void Daemon::saveTrust() noexcept
{
	trust::Text text;
	trust::saveText(mTrust, text);
	if (!os::writeTextFile(mCfg.trustFile.cStr(), text.view())) {
		logging::warn(LOG_MODULE, "cannot write {}: {}", mCfg.trustFile, os::lastError());
	}
}

void Daemon::tickEnroll(Millis now) noexcept
{
	if (!mCfg.enroll) {
		return;
	}
	if (!mTrust.enrolled && (now >= mNextEnrollReq)) {
		arcp::Message m;
		beginMsg(m, arcp::MsgType::ENROLL_REQ, 0U);
		(void)m.addEnrollKey(mCfg.signKey.pub);
		multicast(m);
		mNextEnrollReq = now + ENROLL_REQ_INTERVAL_MS;
	}
	if (mTrust.enrolled && (now >= mNextTrustSync)) {
		sendTrust();
		mNextTrustSync = now + TRUST_SYNC_INTERVAL_MS;
	}
	for (EnrollPending &e : mEnrollPend) {
		if (e.used && ((now - e.last) > PENDING_TTL_MS)) {
			e.used = false;
		}
	}
}

// The whole table, multicast in as many TRUST messages as needed; our own
// record leads each message.
void Daemon::sendTrust() noexcept
{
	const trust::Record *const self = trust::find(mTrust, mApId);
	arcp::Message m;
	std::size_t n = 0U;
	for (const trust::Record &r : mTrust.rec) {
		if (!r.used || (&r == self)) {
			continue;
		}
		if ((n > 0U) && (m.room() < (arcp::TLV_HDR_LEN + arcp::TRUST_REC_LEN))) {
			multicast(m);
			n = 0U;
		}
		if (n == 0U) {
			beginMsg(m, arcp::MsgType::TRUST, 0U);
			if (self != nullptr) {
				(void)m.add(toWire(*self));
			}
		}
		(void)m.add(toWire(r));
		n++;
	}
	if (n > 0U) {
		multicast(m);
	}
}

// Welcome for an approved AP: our record and its record in one message, the
// form a not-yet-enrolled AP accepts (onUntrusted).
void Daemon::sendWelcome(const Mac &apId) noexcept
{
	const trust::Record *const self = trust::find(mTrust, mApId);
	const trust::Record *const it = trust::find(mTrust, apId);
	if ((self != nullptr) && (it != nullptr) && !it->revoked) {
		arcp::Message m;
		beginMsg(m, arcp::MsgType::TRUST, 0U);
		(void)m.add(toWire(*self));
		(void)m.add(toWire(*it));
		multicast(m);
	}
}

// A message from an origin we do not trust (signature not checked yet).
void Daemon::onUntrusted(ByteView frame, const arcp::Header &h) noexcept
{
	arcp::TlvReader rd(frame, h);
	std::uint8_t t = 0U;
	ByteView v;

	if (h.type == arcp::raw(arcp::MsgType::ENROLL_REQ)) {
		ed25519::PublicKey pub{};
		bool have = false;
		while (!have && rd.next(t, v)) {
			have = (t == arcp::raw(arcp::Tlv::ENROLL_KEY)) && arcp::decodeEnrollKey(v, pub);
		}
		// Self-signed: proves the sender holds the key it announces.
		if (!have || !arcp::verifySig(frame, h, pub)) {
			return;
		}
		const trust::Record *const rec = trust::find(mTrust, h.origin);
		if ((rec != nullptr) && rec->revoked && (rec->pub == pub)) {
			return; // a revoked key stays out until approved again
		}
		EnrollPending *e = nullptr;
		EnrollPending *freeSlot = nullptr;
		for (EnrollPending &x : mEnrollPend) {
			if (x.used && (x.apId == h.origin)) {
				e = &x;
			} else if (!x.used && (freeSlot == nullptr)) {
				freeSlot = &x;
			} else {
				// keep looking
			}
		}
		const Millis now = os::nowMs();
		const bool isNew = (e == nullptr) || (e->pub != pub);
		if ((e == nullptr) && (freeSlot != nullptr)) {
			e = freeSlot;
			e->first = now;
		}
		if (e != nullptr) {
			e->used = true;
			e->apId = h.origin;
			e->pub = pub;
			e->keyChange = (rec != nullptr) && (rec->pub != pub);
			e->last = now;
			if (isNew) {
				logging::notice(LOG_MODULE,
						"enrollment request from {}, fingerprint {}{}: approve with "
						"'ENROLL approve {}'",
						h.origin, trust::fingerprint(pub),
						e->keyChange ? " (KEY CHANGE)" : "", h.origin);
			}
		}
		return;
	}
	if ((h.type != arcp::raw(arcp::MsgType::TRUST)) || mTrust.enrolled) {
		logging::dbg(LOG_MODULE, "rx: {} from untrusted {}, dropped", arcp::msgName(h.type),
			     h.origin);
		return;
	}
	// Not enrolled: accept one welcome, a TRUST message holding our own key
	// as trusted and the sender's own trusted record, signed by the sender.
	std::array<arcp::TrustRecord, 32U> recs{};
	std::size_t n = 0U;
	bool forUs = false;
	const ed25519::PublicKey *senderPub = nullptr;
	while (rd.next(t, v)) {
		arcp::TrustRecord r;
		if ((t == arcp::raw(arcp::Tlv::TRUST_REC)) && arcp::decode(v, r) && (n < recs.size())) {
			recs[n] = r;
			if ((r.apId == mApId) && (r.pub == mCfg.signKey.pub) && !r.revoked) {
				forUs = true;
			}
			if ((r.apId == h.origin) && !r.revoked) {
				senderPub = &recs[n].pub;
			}
			n++;
		}
	}
	if (!forUs || (senderPub == nullptr) || !arcp::verifySig(frame, h, *senderPub)) {
		return;
	}
	for (std::size_t i = 0U; i < n; i++) {
		(void)trust::merge(mTrust, fromWire(recs[i]));
	}
	mTrust.enrolled = true;
	saveTrust();
	logging::notice(LOG_MODULE, "enrolled: welcomed by {} (fingerprint {}); check it is a trusted AP",
		        h.origin, trust::fingerprint(*senderPub));
	mNextHello = 0U;
	mNextTrustSync = os::nowMs() + TRUST_SYNC_SOON_MS;
}

// TRUST message from a trusted AP (signature checked).
void Daemon::onTrust(ByteView frame, const arcp::Header &h) noexcept
{
	arcp::TlvReader rd(frame, h);
	std::uint8_t t = 0U;
	ByteView v;
	bool changed = false;
	while (rd.next(t, v)) {
		arcp::TrustRecord r;
		if ((t == arcp::raw(arcp::Tlv::TRUST_REC)) && arcp::decode(v, r)) {
			onTrustRecord(r, changed);
		}
	}
	if (changed) {
		afterTrustChange();
	}
}

// One record of a TRUST message from a trusted AP.
void Daemon::onTrustRecord(const arcp::TrustRecord &r, bool &changed) noexcept
{
	if (!mCfg.enroll) {
		return;
	}
	if (trust::merge(mTrust, fromWire(r))) {
		changed = true;
		if (r.apId == mApId) {
			logging::warn(LOG_MODULE, "the mesh {} this AP's key", r.revoked ? "revoked" :
				      "replaced");
		} else {
			logging::notice(LOG_MODULE, "{} {} (fingerprint {}, generation {})",
					r.revoked ? "revoked" : "trusted", r.apId, trust::fingerprint(r.pub),
					r.gen);
		}
	}
}

// After the table changed: keep it, spread it soon, drop peers that are
// no longer trusted, forget requests that were approved.
void Daemon::afterTrustChange() noexcept
{
	mTrust.enrolled = mTrust.enrolled || (trust::countTrustedOthers(mTrust, mApId) > 0U);
	saveTrust();
	mNextTrustSync = os::nowMs() + TRUST_SYNC_SOON_MS;
	for (Peer &p : mPeers) {
		if (p.used && (trustedKeyFor(p.id) == nullptr)) {
			removePeer(p);
		}
	}
	for (EnrollPending &e : mEnrollPend) {
		const ed25519::PublicKey *const k = e.used ? trust::trustedKey(mTrust, e.apId) : nullptr;
		if ((k != nullptr) && (*k == e.pub)) {
			e.used = false;
		}
	}
}

void Daemon::cmdEnroll(FixedString<8192U> &o, std::string_view args) noexcept
{
	if (!mCfg.enroll) {
		formatTo(o, "FAIL enrollment is off (enroll 1)\n");
		return;
	}
	Tokens tok(args, " \t");
	std::string_view verb;
	std::string_view arg;
	const bool hasVerb = tok.next(verb);
	const bool hasArg = tok.next(arg);
	const std::optional<Mac> id = hasArg ? parseMac(arg) : std::nullopt;

	if (hasVerb && (verb == "approve") && id.has_value()) {
		const EnrollPending *e = nullptr;
		for (const EnrollPending &x : mEnrollPend) {
			if (x.used && (x.apId == *id)) {
				e = &x;
			}
		}
		if (e == nullptr) {
			formatTo(o, "FAIL no pending request from {}\n", *id);
			return;
		}
		const ed25519::PublicKey pub = e->pub;
		if (!trust::approve(mTrust, *id, pub)) {
			formatTo(o, "FAIL trust table full\n");
			return;
		}
		mTrust.enrolled = true;
		logging::notice(LOG_MODULE, "approved {} (fingerprint {})", *id, trust::fingerprint(pub));
		afterTrustChange();
		sendWelcome(*id);
		formatTo(o, "OK approved {} fingerprint {}\n", *id, trust::fingerprint(pub));
	} else if (hasVerb && (verb == "revoke") && id.has_value()) {
		if (*id == mApId) {
			formatTo(o, "FAIL cannot revoke this AP from itself\n");
		} else if (!trust::revoke(mTrust, *id)) {
			formatTo(o, "FAIL {} is not in the trust table\n", *id);
		} else {
			logging::notice(LOG_MODULE, "revoked {}", *id);
			afterTrustChange();
			formatTo(o, "OK revoked {}\n", *id);
		}
	} else if (hasVerb && (verb == "init") && !hasArg) {
		mTrust.enrolled = true;
		saveTrust();
		formatTo(o, "OK this AP is enrolled (first AP of the mesh)\n");
	} else if (!hasVerb) {
		const Millis now = os::nowMs();
		formatTo(o, "enroll ap_id={} fingerprint={} enrolled={}\n", mApId,
			 trust::fingerprint(mCfg.signKey.pub), mTrust.enrolled ? "yes" : "no");
		for (const EnrollPending &e : mEnrollPend) {
			if (e.used) {
				formatTo(o, "pending {} fingerprint={} seen={}s ago{}\n", e.apId,
					 trust::fingerprint(e.pub),
					 (now - e.last) / 1000U, e.keyChange ? " KEY-CHANGE" : "");
			}
		}
		for (const trust::Record &r : mTrust.rec) {
			if (r.used) {
				formatTo(o, "{} {} fingerprint={} gen={}{}\n", r.revoked ? "revoked" :
					 "trusted", r.apId,
					 trust::fingerprint(r.pub), r.gen, (r.apId == mApId) ? " (this AP)" :
					 "");
			}
		}
	} else {
		formatTo(o, "FAIL usage: ENROLL [approve <ap_id> | revoke <ap_id> | init]\n");
	}
}

} // namespace donghoa
