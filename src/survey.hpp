// SPDX-License-Identifier: MIT
// Minimal nl80211 channel survey over generic netlink (no libnl).
#ifndef DONGHOA_SURVEY_HPP
#define DONGHOA_SURVEY_HPP

#include <cstdint>

#include "os.hpp"

namespace donghoa {

struct SurveySample {
	bool valid{false};
	int freq{0};
	std::int8_t noise{0};
	std::uint64_t activeMs{0U};
	std::uint64_t busyMs{0U};
};

class Survey {
public:
	bool open() noexcept;
	// In-use channel survey of ifindex.
	bool get(int ifindex, SurveySample &out) noexcept;
	// Channel utilisation 0..255 from two samples, -1 if not computable.
	static int util(const SurveySample &prev, const SurveySample &cur) noexcept;

private:
	os::Fd mFd{};
	std::uint16_t mFamily{0U};
	std::uint32_t mSeq{0U};
};

} // namespace donghoa

#endif
