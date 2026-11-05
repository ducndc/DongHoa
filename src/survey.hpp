// SPDX-License-Identifier: MIT
// Minimal nl80211 channel survey over generic netlink (no libnl).
//
// request() sends a dump and returns; the main poll() loop calls
// onReadable() when the reply is there, and the caller uses the result on
// its next poll, so the daemon never waits for a reply. The kernel runs the
// driver's get_survey (once per channel of the radio) inside the sendto()
// and recv() calls themselves, though: a slow driver (firmware round trip,
// USB/SDIO register reads) holds the loop for that long, which no socket
// trick avoids in a single thread. That time is measured (blocked_us) and
// kept low by doing one dump per radio (wiphy) per round, however many
// BSSes the radio carries.
#ifndef DONGHOA_SURVEY_HPP
#define DONGHOA_SURVEY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "os.hpp"
#include "types.hpp"

namespace donghoa {

struct SurveySample {
	bool valid{false};
	int freq{0};
	std::int8_t noise{0};
	std::uint64_t activeMs{0U};
	std::uint64_t busyMs{0U};
	Millis ts{0U}; // when the dump that produced it completed
};

struct SurveyStats {
	std::uint32_t dumps{0U};    // completed dumps
	std::uint32_t timeouts{0U}; // dumps abandoned after DUMP_TIMEOUT_MS
	std::uint32_t errors{0U};   // dumps the kernel refused
	std::uint32_t lastUs{0U};   // time spent in the kernel/driver (send + recv) for the last dump
	std::uint32_t maxUs{0U};    // the same, worst dump so far
	std::size_t radios{0U};     // wiphys surveyed
};

class Survey {
public:
	static constexpr std::size_t MAX_WIPHY = 8U;
	// In-use entries kept per wiphy: one per channel, several for a
	// multi-link (MLO) wiphy whose links are active at once.
	static constexpr std::size_t MAX_IN_USE = 4U;
	static constexpr Millis DUMP_TIMEOUT_MS = 1000U;
	// A dump that blocks longer than this is reported once (warn).
	static constexpr std::uint32_t SLOW_US = 20000U;

	bool open() noexcept;
	bool isOpen() const noexcept { return mFd.valid() && (mFamily != 0U); }
	// Wiphy index of a network interface (NL80211_CMD_GET_INTERFACE, on a
	// one-shot socket so it never mixes with a dump in flight). Empty if
	// nl80211 is unavailable or the interface is not wireless.
	std::optional<std::uint32_t> findWiphy(int ifindex) noexcept;
	// Queues one survey dump of wiphy through its interface ifindex. A
	// wiphy already queued or in flight is not queued again.
	void request(std::uint32_t wiphy, int ifindex) noexcept;
	// Descriptor to poll while a dump is in flight, -1 otherwise.
	int pollFd() const noexcept { return mInFlight.has_value() ? mFd.get() : -1; }
	// The socket is readable: consume the dump, then send the next queued one.
	void onReadable() noexcept;
	// Abandons a dump the driver has not finished in DUMP_TIMEOUT_MS.
	void tick(Millis now) noexcept;
	// Latest in-use sample of wiphy on freq, or nullptr.
	const SurveySample *find(std::uint32_t wiphy, int freq) const noexcept;
	const SurveyStats &stats() const noexcept { return mStats; }
	// Channel utilisation 0..255 from two samples, -1 if not computable.
	static int util(const SurveySample &prev, const SurveySample &cur) noexcept;

private:
	struct Radio {
		bool used{false};
		std::uint32_t wiphy{0U};
		int ifindex{0};
		bool queued{false};
		std::array<SurveySample, MAX_IN_USE> cur{}; // last completed dump
		std::size_t nCur{0U};
		std::array<SurveySample, MAX_IN_USE> next{}; // dump in progress
		std::size_t nNext{0U};
	};

	bool resolveFamily() noexcept;
	void sendNext() noexcept;
	void finish(bool ok) noexcept;

	os::Fd mFd{};
	std::uint16_t mFamily{0U};
	std::uint32_t mSeq{0U};
	std::array<Radio, MAX_WIPHY> mRadio{};
	std::optional<std::size_t> mInFlight{};
	std::uint64_t mBlockedUs{0U}; // time inside send/recv for the dump in flight
	Millis mDeadline{0U};
	bool mWarnedSlow{false};
	SurveyStats mStats{};
};

} // namespace donghoa

#endif
