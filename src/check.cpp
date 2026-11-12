// SPDX-License-Identifier: MIT
// Configuration consistency across the mesh (feature 18): BSS pairs of one
// ESS whose 802.11r or security settings differ, and peers whose steering
// settings differ from this AP's. Findings are logged when they appear and
// when they clear, and listed by the CHECK command.
#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::CHECK};

std::string_view bssName(const LocalBss &b) noexcept
{
	return b.cfg->ifname.view();
}

} // namespace

void Daemon::checkConsistency() noexcept
{
	const arcp::PolicySum own = consistency::summarize(mCfg.pol);

	// This AP's own BSSes of one ESS (e.g. its 2.4 and 5 GHz BSS).
	std::uint32_t ownIssues = 0U;
	for (std::size_t i = 0U; i < mNBss; i++) {
		for (std::size_t j = i + 1U; j < mNBss; j++) {
			if (!mBss[i].up || !mBss[j].up) {
				continue;
			}
			const std::uint32_t f = consistency::checkPair(mBss[i].info, mBss[j].info);
			for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
				const std::uint32_t bit = consistency::pairBit(k);
				if (((f & bit) != 0U) && ((mOwnIssues & bit) == 0U)) {
					logging::warn(LOG_MODULE, "bss {} and bss {}: {}", bssName(mBss[i]),
						      bssName(mBss[j]), consistency::pairIssueHint(bit));
				}
			}
			ownIssues |= f;
		}
	}
	if ((ownIssues == 0U) && (mOwnIssues != 0U)) {
		logging::notice(LOG_MODULE, "own BSSes consistent again");
	}
	mOwnIssues = ownIssues;

	for (Peer &p : mPeers) {
		if (!p.used) {
			continue;
		}
		std::uint32_t issues = 0U;
		for (std::size_t i = 0U; i < mNBss; i++) {
			if (!mBss[i].up) {
				continue;
			}
			for (const RemoteBss &rb : p.bss) {
				if (!rb.used) {
					continue;
				}
				const std::uint32_t f = consistency::checkPair(mBss[i].info, rb.info);
				for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
					const std::uint32_t bit = consistency::pairBit(k);
					if (((f & bit) != 0U) && ((p.pairIssues & bit) == 0U)) {
						logging::warn(LOG_MODULE, "bss {} and {} of peer {}: {}",
							      bssName(mBss[i]), rb.info.bssid, p.id,
							      consistency::pairIssueHint(bit));
					}
				}
				issues |= f;
			}
		}
		if ((issues == 0U) && (p.pairIssues != 0U)) {
			logging::notice(LOG_MODULE, "peer {}: BSS settings consistent again", p.id);
		}
		p.pairIssues = issues;

		const std::uint32_t diff = p.hasPolicy ? consistency::diffPolicy(own, p.policy) : 0U;
		if ((diff != 0U) && (diff != p.policyDiff)) {
			consistency::DiffText d;
			consistency::describePolicyDiff(d, own, p.policy, diff);
			logging::warn(LOG_MODULE, "peer {} steers with other settings (here/there): {}", p.id,
				      d);
		} else if ((diff == 0U) && (p.policyDiff != 0U)) {
			logging::notice(LOG_MODULE, "peer {}: steering settings match again", p.id);
		} else {
			// unchanged
		}
		p.policyDiff = diff;
	}
}

std::size_t Daemon::countIssues() const noexcept
{
	std::size_t n = 0U;
	for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
		const std::uint32_t bit = consistency::pairBit(k);
		n += ((mOwnIssues & bit) != 0U) ? 1U : 0U;
	}
	for (const Peer &p : mPeers) {
		if (p.used) {
			for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
				const std::uint32_t bit = consistency::pairBit(k);
				n += ((p.pairIssues & bit) != 0U) ? 1U : 0U;
			}
			n += (p.policyDiff != 0U) ? 1U : 0U;
		}
	}
	return n;
}

void Daemon::cmdCheck(FixedString<8192U> &o) const noexcept
{
	const arcp::PolicySum own = consistency::summarize(mCfg.pol);
	std::size_t n = 0U;

	for (std::size_t i = 0U; i < mNBss; i++) {
		for (std::size_t j = i + 1U; j < mNBss; j++) {
			const std::uint32_t f = (mBss[i].up && mBss[j].up)
							? consistency::checkPair(mBss[i].info, mBss[j].info)
							: 0U;
			for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
				const std::uint32_t bit = consistency::pairBit(k);
				if ((f & bit) != 0U) {
					formatTo(o, "{} bss {} {} bss {} {}: {}\n",
						 consistency::pairIssueName(bit), bssName(mBss[i]),
						 mBss[i].info.bssid, bssName(mBss[j]), mBss[j].info.bssid,
						 consistency::pairIssueHint(bit));
					n++;
				}
			}
		}
	}
	for (const Peer &p : mPeers) {
		if (!p.used) {
			continue;
		}
		for (std::size_t i = 0U; i < mNBss; i++) {
			for (const RemoteBss &rb : p.bss) {
				const bool both = mBss[i].up && rb.used;
				const std::uint32_t f =
					both ? consistency::checkPair(mBss[i].info, rb.info) : 0U;
				for (std::size_t k = 0U; k < consistency::PAIR_BITS; k++) {
					const std::uint32_t bit = consistency::pairBit(k);
					if ((f & bit) != 0U) {
						formatTo(o,
							 "{} bss {} {} peer {} bss {} (mdid {} / {}): {}\n",
							 consistency::pairIssueName(bit), bssName(mBss[i]),
							 mBss[i].info.bssid, p.id, rb.info.bssid,
							 hex(mBss[i].info.mdid, 4U), hex(rb.info.mdid, 4U),
							 consistency::pairIssueHint(bit));
						n++;
					}
				}
			}
		}
		if (!p.hasPolicy) {
			formatTo(o, "policy_unknown peer {}: sends no POLICY (older version?)\n", p.id);
		} else {
			const std::uint32_t diff = consistency::diffPolicy(own, p.policy);
			if (diff != 0U) {
				consistency::DiffText d;
				consistency::describePolicyDiff(d, own, p.policy, diff);
				formatTo(o, "policy_differs peer {} (here/there): {}\n", p.id, d);
				n++;
			}
		}
	}
	formatTo(o, "issues={}\n", n);
}

} // namespace donghoa
