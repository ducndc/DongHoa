// SPDX-License-Identifier: MIT
#include "consistency.hpp"

#include <array>

#include "rrm.hpp"

namespace donghoa {
namespace consistency {

namespace {

struct PairText {
	std::uint32_t bit;
	std::string_view name;
	std::string_view hint;
};

constexpr std::array<PairText, 4U> PAIR_TEXT{{
	{MDID_DIFFERS, "mdid_differs",
	 "different 802.11r mobility domains: roams between them need a full authentication"},
	{FT_ONE_SIDED, "ft_one_sided", "802.11r on one BSS only: no fast roaming between them"},
	{FT_DS_DIFFERS, "ft_over_ds_differs",
	 "FT over DS on one BSS only: STAs may fall back to FT over air"},
	{SECURITY_DIFFERS, "security_differs",
	 "open and secured BSS under one SSID: a STA cannot roam between them"},
}};

std::int8_t toI8(int v) noexcept
{
	const int c = (v < -128) ? -128 : ((v > 127) ? 127 : v);
	return static_cast<std::int8_t>(c);
}

std::uint8_t toU8(int v) noexcept
{
	const int c = (v < 0) ? 0 : ((v > 255) ? 255 : v);
	return static_cast<std::uint8_t>(c);
}

bool hasFt(const arcp::BssInfo &b) noexcept
{
	return (b.caps & arcp::CAP_FT) != 0U;
}

bool hasFtDs(const arcp::BssInfo &b) noexcept
{
	return (b.caps & arcp::CAP_FT_OVER_DS) != 0U;
}

bool isSecured(const arcp::BssInfo &b) noexcept
{
	return (b.bssidInfo & rrm::BI_SECURITY) != 0U;
}

void putFlag(DiffText &out, std::string_view name, std::uint16_t mask, const arcp::PolicySum &own,
	     const arcp::PolicySum &peer) noexcept
{
	const bool a = (own.flags & mask) != 0U;
	const bool b = (peer.flags & mask) != 0U;
	if (a != b) {
		formatTo(out, "{}{} {}/{}", out.empty() ? "" : " ", name, a ? 1 : 0, b ? 1 : 0);
	}
}

void putInt(DiffText &out, std::string_view name, int own, int peer) noexcept
{
	formatTo(out, "{}{} {}/{}", out.empty() ? "" : " ", name, own, peer);
}

} // namespace

std::uint32_t checkPair(const arcp::BssInfo &a, const arcp::BssInfo &b) noexcept
{
	std::uint32_t r = 0U;

	if (arcp::isSameEss(a, b) && !arcp::isSameMld(a, b) && (a.bssid != b.bssid)) {
		if (hasFt(a) != hasFt(b)) {
			r |= FT_ONE_SIDED;
		} else if (hasFt(a) && (a.mdid != b.mdid)) {
			r |= MDID_DIFFERS;
		} else if (hasFt(a) && (hasFtDs(a) != hasFtDs(b))) {
			r |= FT_DS_DIFFERS;
		} else {
			// FT consistent
		}
		if (isSecured(a) != isSecured(b)) {
			r |= SECURITY_DIFFERS;
		}
	}
	return r;
}

std::string_view pairIssueName(std::uint32_t bit) noexcept
{
	std::string_view n = "?";
	for (const PairText &t : PAIR_TEXT) {
		if (t.bit == bit) {
			n = t.name;
		}
	}
	return n;
}

std::string_view pairIssueHint(std::uint32_t bit) noexcept
{
	std::string_view n = "";
	for (const PairText &t : PAIR_TEXT) {
		if (t.bit == bit) {
			n = t.hint;
		}
	}
	return n;
}

arcp::PolicySum summarize(const PolicyConfig &p) noexcept
{
	arcp::PolicySum s;
	std::uint16_t f = 0U;

	f = static_cast<std::uint16_t>(f | (p.rssiSteering ? arcp::POL_RSSI_STEERING : 0U));
	f = static_cast<std::uint16_t>(f | (p.loadBalancing ? arcp::POL_LOAD_BALANCING : 0U));
	f = static_cast<std::uint16_t>(f | (p.bandSteering ? arcp::POL_BAND_STEERING : 0U));
	f = static_cast<std::uint16_t>(f | (p.bandSteer6g ? arcp::POL_BAND_STEER_6G : 0U));
	f = static_cast<std::uint16_t>(f | (p.lpNoSteer ? arcp::POL_LP_NO_STEER : 0U));
	f = static_cast<std::uint16_t>(f | (p.roamThrLearn ? arcp::POL_ROAM_THR_LEARN : 0U));
	f = static_cast<std::uint16_t>(f | (p.lbOnlyIdle ? arcp::POL_LB_ONLY_IDLE : 0U));
	s.flags = f;
	s.rssiLow = toI8(p.rssiLow);
	s.rssiHysteresis = toU8(p.rssiHysteresis);
	s.rssiMinTarget = toI8(p.rssiMinTarget);
	s.bandSteerRssi = toI8(p.bandSteerRssi);
	s.bandSteer6gRssi = toI8(p.bandSteer6gRssi);
	s.utilHigh = toU8(p.utilHigh);
	s.utilAdmitMax = toU8(p.utilAdmitMax);
	s.lbMargin = toU8(p.lbMargin);
	s.scoreModel = static_cast<std::uint8_t>(p.scoreModel);
	const int cooldownS = p.steerCooldownMs / 1000;
	const int cooldownMax = 65535;
	int c = cooldownS;
	if (c < 0) {
		c = 0;
	} else if (c > cooldownMax) {
		c = cooldownMax;
	} else {
		// in range
	}
	s.steerCooldownS = static_cast<std::uint16_t>(c);
	return s;
}

std::uint32_t diffPolicy(const arcp::PolicySum &a, const arcp::PolicySum &b) noexcept
{
	std::uint32_t d = 0U;

	d |= (a.flags != b.flags) ? POL_FEATURES : 0U;
	d |= (a.rssiLow != b.rssiLow) ? POL_RSSI_LOW : 0U;
	d |= (a.rssiHysteresis != b.rssiHysteresis) ? POL_RSSI_HYSTERESIS : 0U;
	d |= (a.rssiMinTarget != b.rssiMinTarget) ? POL_RSSI_MIN_TARGET : 0U;
	d |= (a.bandSteerRssi != b.bandSteerRssi) ? POL_BAND_STEER_RSSI : 0U;
	d |= (a.bandSteer6gRssi != b.bandSteer6gRssi) ? POL_BAND_STEER_6G_RSSI : 0U;
	d |= (a.utilHigh != b.utilHigh) ? POL_UTIL_HIGH : 0U;
	d |= (a.utilAdmitMax != b.utilAdmitMax) ? POL_UTIL_ADMIT_MAX : 0U;
	d |= (a.lbMargin != b.lbMargin) ? POL_LB_MARGIN : 0U;
	d |= (a.scoreModel != b.scoreModel) ? POL_SCORE_MODEL : 0U;
	d |= (a.steerCooldownS != b.steerCooldownS) ? POL_STEER_COOLDOWN : 0U;
	return d;
}

void describePolicyDiff(DiffText &out, const arcp::PolicySum &own, const arcp::PolicySum &peer,
			std::uint32_t diff) noexcept
{
	out.clear();
	if ((diff & POL_FEATURES) != 0U) {
		putFlag(out, "rssi_steering", arcp::POL_RSSI_STEERING, own, peer);
		putFlag(out, "load_balancing", arcp::POL_LOAD_BALANCING, own, peer);
		putFlag(out, "band_steering", arcp::POL_BAND_STEERING, own, peer);
		putFlag(out, "band_steer_6g", arcp::POL_BAND_STEER_6G, own, peer);
		putFlag(out, "lp_no_steer", arcp::POL_LP_NO_STEER, own, peer);
		putFlag(out, "roam_thr_learn", arcp::POL_ROAM_THR_LEARN, own, peer);
		putFlag(out, "lb_only_idle", arcp::POL_LB_ONLY_IDLE, own, peer);
	}
	if ((diff & POL_RSSI_LOW) != 0U) {
		putInt(out, "rssi_low", own.rssiLow, peer.rssiLow);
	}
	if ((diff & POL_RSSI_HYSTERESIS) != 0U) {
		putInt(out, "rssi_hysteresis", own.rssiHysteresis, peer.rssiHysteresis);
	}
	if ((diff & POL_RSSI_MIN_TARGET) != 0U) {
		putInt(out, "rssi_min_target", own.rssiMinTarget, peer.rssiMinTarget);
	}
	if ((diff & POL_BAND_STEER_RSSI) != 0U) {
		putInt(out, "band_steer_rssi", own.bandSteerRssi, peer.bandSteerRssi);
	}
	if ((diff & POL_BAND_STEER_6G_RSSI) != 0U) {
		putInt(out, "band_steer_6g_rssi", own.bandSteer6gRssi, peer.bandSteer6gRssi);
	}
	if ((diff & POL_UTIL_HIGH) != 0U) {
		putInt(out, "util_high", own.utilHigh, peer.utilHigh);
	}
	if ((diff & POL_UTIL_ADMIT_MAX) != 0U) {
		putInt(out, "util_admit_max", own.utilAdmitMax, peer.utilAdmitMax);
	}
	if ((diff & POL_LB_MARGIN) != 0U) {
		putInt(out, "lb_margin", own.lbMargin, peer.lbMargin);
	}
	if ((diff & POL_SCORE_MODEL) != 0U) {
		putInt(out, "score_model", own.scoreModel, peer.scoreModel);
	}
	if ((diff & POL_STEER_COOLDOWN) != 0U) {
		putInt(out, "steer_cooldown_s", own.steerCooldownS, peer.steerCooldownS);
	}
}

} // namespace consistency
} // namespace donghoa
