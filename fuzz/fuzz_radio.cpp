// SPDX-License-Identifier: MIT
// libFuzzer target: bytes from the air and the kernel. Radiotap frames from
// a monitor interface (amon.cpp) and nl80211 station-dump messages
// (survey.cpp). The first byte selects the parser.
#include <cstddef>
#include <cstdint>

#include "nlparse.hpp"
#include "rrm.hpp"

using namespace donghoa;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	if (size < 1U) {
		return 0;
	}
	const ByteView in(&data[1], size - 1U);
	switch (data[0] % 3U) {
	case 0U:
		(void)rrm::parseRadiotap(in);
		break;
	case 1U:
		(void)nl::parseStation(in);
		(void)nl::findAttr(nl::genlAttrs(in), 1U);
		break;
	default:
		(void)rrm::bandsFromOpClasses(in);
		(void)rrm::hasBtmCapab(in);
		break;
	}
	return 0;
}
