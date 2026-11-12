// SPDX-License-Identifier: MIT
// Operating-system layer: every POSIX/Linux call, and every cast those
// interfaces need (sockaddr, netlink, BPF), lives in os.cpp. This confines
// the MISRA C++ deviations for system interfaces (DEV-01..DEV-04 in
// docs/CODING_CONVENTION.md) to one file.
#ifndef DONGHOA_OS_HPP
#define DONGHOA_OS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "types.hpp"

namespace donghoa {
namespace os {

// ---- time, process, randomness ----

// Monotonic clock in milliseconds.
Millis nowMs() noexcept;
// Monotonic clock in microseconds (timing of driver calls).
std::uint64_t nowUs() noexcept;
std::int32_t processId() noexcept;
std::optional<std::uint32_t> randomU32() noexcept;
// Fills out from the kernel CSPRNG; false if it is not available.
bool randomBytes(const ByteSpan &out) noexcept;

// ---- logging sinks ----

void writeStderr(std::string_view line) noexcept;
void writeStdout(std::string_view text) noexcept;
void openSyslog() noexcept;
void closeSyslog() noexcept;
// prio: RFC 5424 severity 0..7 (3 err, 4 warning, 5 notice, 6 info, 7 debug)
void writeSyslog(std::uint8_t prio, std::string_view line) noexcept;

// ---- signals ----

// SIGINT/SIGTERM set the stop flag; SIGPIPE is ignored.
void installSignalHandlers() noexcept;
bool stopRequested() noexcept;

// ---- files ----

// Reads a whole text file (at most out.capacity() bytes); false on error.
bool readTextFile(const char *path, FixedString<16384U> &out) noexcept;
void removeFile(const char *path) noexcept;
// Replaces a small file atomically (path.tmp, fsync, rename), mode 0600.
bool writeTextFile(const char *path, std::string_view text) noexcept;

// ---- file descriptors ----

// Owning file descriptor (closed on destruction; move-only).
class Fd {
public:
	Fd() noexcept = default;
	explicit Fd(int fd) noexcept : mFd(fd) {}
	~Fd() noexcept { reset(); }
	Fd(const Fd &) = delete;
	Fd &operator=(const Fd &) = delete;
	Fd(Fd &&o) noexcept : mFd(o.mFd) { o.mFd = -1; }
	Fd &operator=(Fd &&o) noexcept;

	int get() const noexcept { return mFd; }
	bool valid() const noexcept { return mFd >= 0; }
	void reset() noexcept;

private:
	int mFd{-1};
};

// Waits up to timeoutMs for any of fds to become readable. ready[i] is set
// for each readable (or failed) descriptor. Returns false on poll error.
constexpr std::size_t MAX_POLL = 32U;
bool pollReadable(const std::array<int, MAX_POLL> &fds, std::size_t n, int timeoutMs,
		   std::array<bool, MAX_POLL> &ready) noexcept;
// Waits for one descriptor; true if readable within timeoutMs.
bool waitReadable(int fd, int timeoutMs) noexcept;

// Results of a non-blocking receive.
enum class Rx : std::uint8_t { DATA, EMPTY, ERROR };

// ---- UNIX datagram sockets ----

// Opaque UNIX socket address, used to reply to a control client.
struct UnixAddr {
	std::array<std::uint8_t, 112U> raw{};
	std::uint32_t len{0U};
};

// Bound (non-blocking if nonblock) datagram socket at path (replaced).
Fd bindUnix(const char *path, bool nonblock) noexcept;
// Gives path the owner of otherPath when they differ (hostapd running as
// another user must be able to reply). Harmless when not root.
void shareOwner(const char *path, const char *otherPath) noexcept;
bool connectUnix(const Fd &fd, const char *path) noexcept;
bool sendText(const Fd &fd, std::string_view text, bool dontwait) noexcept;
// Blocking receive into buf; byte count, or nothing on error.
std::optional<std::size_t> recvBytes(const Fd &fd, const ByteSpan &buf) noexcept;
// Non-blocking receive.
Rx recvNowait(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept;
Rx recvFrom(const Fd &fd, const ByteSpan &buf, std::size_t &n, UnixAddr &from) noexcept;
void sendTo(const Fd &fd, ByteView data, const UnixAddr &to) noexcept;
// One request/reply exchange for a command-line client.
bool sendUnixRequest(const char *server, const char *local, std::string_view request,
		  const ByteSpan &reply, std::size_t &n, int timeoutMs) noexcept;

// ---- raw Ethernet (AF_PACKET) ----

struct LinkInfo {
	int ifindex{0};
	Mac mac{};
};

int ifnameToIndex(const char *ifname) noexcept;
// Socket for one EtherType on ifname, joined to the multicast group.
Fd openPacket(const char *ifname, std::uint16_t ethertype, const Mac &group, LinkInfo &info) noexcept;
bool sendPacket(const Fd &fd, int ifindex, const Mac &dst, ByteView frame) noexcept;
// Receives one frame; outgoing frames (our own) are reported as empty.
Rx recvPacket(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept;

// Air monitor: radiotap frames of every type on a monitor interface, with
// a kernel filter passing only probe requests and ToDS data frames.
Fd openMonitor(const char *ifname) noexcept;

// ---- UDP on loopback (simulation transport, test inputs) ----

Fd bindUdpLoopback(std::uint16_t port) noexcept;
void sendUdpLoopback(const Fd &fd, std::uint16_t port, ByteView data) noexcept;

// ---- generic netlink ----

Fd openNetlink() noexcept;
bool sendNetlink(const Fd &fd, ByteView msg) noexcept;
// Byte count received within timeoutMs, or nothing.
std::optional<std::size_t> recvNetlink(const Fd &fd, const ByteSpan &buf, int timeoutMs) noexcept;
// Host-order integers inside netlink messages (native endianness).
std::uint16_t loadNe16(ByteView v, std::size_t off) noexcept;
std::uint32_t loadNe32(ByteView v, std::size_t off) noexcept;
std::uint64_t loadNe64(ByteView v, std::size_t off) noexcept;
void storeNe16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept;
void storeNe32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept;

// Text of the last system error (strerror of errno).
std::string_view lastError() noexcept;

} // namespace os
} // namespace donghoa

#endif
