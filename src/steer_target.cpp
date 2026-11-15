// SPDX-License-Identifier: MIT
// Target side of a steering transaction: admission of a STEER_REQ, the
// reservation it creates and its release by STEER_RESULT. Reservations
// also end in steer.cpp: when the STA arrives (onStaEvent), when the source
// AP is lost (onPeerLost) and when they expire (tickSteer).
#include "daemon.hpp"
#include "log.hpp"
#include "policy.hpp"
#include "steer_util.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::STEER};

} // namespace

int Daemon::countReservations(std::size_t bss, Millis now) const noexcept
{
	int n = 0;
	for (const Reservation &r : mResv) {
		if (r.used && (r.bss == bss) && (r.expiry > now)) {
			n++;
		}
	}
	return n;
}

void Daemon::onSteerReq(const Peer &from, const arcp::SteerReq &r) noexcept
{
	const PolicyConfig &p = mCfg.pol;
	const Millis now = os::nowMs();
	const std::optional<std::size_t> b = findLocalBss(r.tgtBssid);
	arcp::SteerStatus status = arcp::SteerStatus::ACCEPT;
	arcp::SteerResp resp;
	arcp::Message m;

	resp.txn = r.txn;
	if (!b.has_value()) {
		status = arcp::SteerStatus::UNKNOWN_BSS;
	} else if (findTxnBySta(r.sta) != nullptr) {
		status = arcp::SteerStatus::BUSY;
	} else {
		status = policy::admit(p, policy::utilToPct(mBss[*b].load.util), mBss[*b].load.staCount,
				       countReservations(*b, now), mBss[*b].cfg->maxSta);
	}
	if (status == arcp::SteerStatus::ACCEPT) {
		Reservation *rv = nullptr;
		for (Reservation &x : mResv) {
			if ((rv == nullptr) && (!x.used || (x.expiry <= now))) {
				rv = &x;
			}
		}
		if (rv == nullptr) {
			status = arcp::SteerStatus::BUSY;
		} else {
			rv->used = true;
			rv->sta = r.sta;
			rv->srcAp = from.id;
			rv->bss = *b;
			rv->txn = r.txn;
			rv->expiry = now + static_cast<Millis>(p.reserveHoldMs);
			resp.holdMs = static_cast<std::uint16_t>(p.reserveHoldMs);
		}
	}
	resp.status = static_cast<std::uint8_t>(status);
	const std::size_t si = static_cast<std::size_t>(status);
	if (b.has_value() && (si < mMetrics[*b].in.status.size())) {
		mMetrics[*b].in.status[si]++;
	} else {
		mArcpMetrics.steerInUnknownBss++;
	}
	logging::info(LOG_MODULE, "steer-in request #{} from {}: sta {} -> {} ({}, rcpi {}): {}", r.txn,
		      from.id, r.sta, r.tgtBssid, steer::reasonNameRaw(r.reason), r.rcpi,
		      (status == arcp::SteerStatus::ACCEPT) ? "accept" : "reject");
	beginMsg(m, arcp::MsgType::STEER_RESP, arcp::FLAG_ACK_REQ);
	(void)m.add(resp);
	(void)unicast(from.id, m);
}

void Daemon::onSteerResult(const Peer &from, const arcp::SteerResult &r) noexcept
{
	for (Reservation &rv : mResv) {
		if (rv.used && (rv.txn == r.txn) && (rv.srcAp == from.id)) {
			rv.used = false;
			if (rv.bss < mMetrics.size()) {
				if (r.outcome == steer::raw(arcp::SteerOutcome::SUCCESS)) {
					mMetrics[rv.bss].in.success++;
				} else {
					mMetrics[rv.bss].in.failed++;
				}
			}
		}
	}
	logging::info(LOG_MODULE, "steer #{} from {} sta {}: {}", r.txn, from.id, r.sta,
		      steer::outcomeName(r.outcome));
}

} // namespace donghoa
