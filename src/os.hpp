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
Millis now_ms() noexcept;
std::int32_t process_id() noexcept;
std::optional<std::uint32_t> random_u32() noexcept;

// ---- logging sinks ----

void write_stderr(std::string_view line) noexcept;
void write_stdout(std::string_view text) noexcept;
void syslog_open() noexcept;
void syslog_close() noexcept;
// prio: 0 err, 1 warning, 2 info, 3 debug
void syslog_write(std::uint8_t prio, std::string_view line) noexcept;

// ---- signals ----

// SIGINT/SIGTERM set the stop flag; SIGPIPE is ignored.
void install_signal_handlers() noexcept;
bool stop_requested() noexcept;

// ---- files ----

// Reads a whole text file (at most out.capacity() bytes); false on error.
bool read_text_file(const char *path, FixedString<16384U> &out) noexcept;
void remove_file(const char *path) noexcept;

// ---- file descriptors ----

// Owning file descriptor (closed on destruction; move-only).
class Fd {
public:
	Fd() noexcept = default;
	explicit Fd(int fd) noexcept : fd_(fd) {}
	~Fd() noexcept { reset(); }
	Fd(const Fd &) = delete;
	Fd &operator=(const Fd &) = delete;
	Fd(Fd &&o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
	Fd &operator=(Fd &&o) noexcept;

	int get() const noexcept { return fd_; }
	bool valid() const noexcept { return fd_ >= 0; }
	void reset() noexcept;

private:
	int fd_{-1};
};

// Waits up to timeout_ms for any of fds to become readable. ready[i] is set
// for each readable (or failed) descriptor. Returns false on poll error.
constexpr std::size_t kMaxPoll = 32U;
bool poll_readable(const std::array<int, kMaxPoll> &fds, std::size_t n, int timeout_ms,
		   std::array<bool, kMaxPoll> &ready) noexcept;
// Waits for one descriptor; true if readable within timeout_ms.
bool wait_readable(int fd, int timeout_ms) noexcept;

// Results of a non-blocking receive.
enum class Rx : std::uint8_t { data, empty, error };

// ---- UNIX datagram sockets ----

// Opaque UNIX socket address, used to reply to a control client.
struct UnixAddr {
	std::array<std::uint8_t, 112U> raw{};
	std::uint32_t len{0U};
};

// Bound (non-blocking if nonblock) datagram socket at path (replaced).
Fd unix_bind(const char *path, bool nonblock) noexcept;
// Gives path the owner of other_path when they differ (hostapd running as
// another user must be able to reply). Harmless when not root.
void share_owner(const char *path, const char *other_path) noexcept;
bool unix_connect(const Fd &fd, const char *path) noexcept;
bool send_text(const Fd &fd, std::string_view text, bool dontwait) noexcept;
// Blocking receive into buf; byte count, or nothing on error.
std::optional<std::size_t> recv_bytes(const Fd &fd, const ByteSpan &buf) noexcept;
// Non-blocking receive.
Rx recv_nowait(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept;
Rx recv_from(const Fd &fd, const ByteSpan &buf, std::size_t &n, UnixAddr &from) noexcept;
void send_to(const Fd &fd, ByteView data, const UnixAddr &to) noexcept;
// One request/reply exchange for a command-line client.
bool unix_request(const char *server, const char *local, std::string_view request,
		  const ByteSpan &reply, std::size_t &n, int timeout_ms) noexcept;

// ---- raw Ethernet (AF_PACKET) ----

struct LinkInfo {
	int ifindex{0};
	Mac mac{};
};

int ifname_to_index(const char *ifname) noexcept;
// Socket for one EtherType on ifname, joined to the multicast group.
Fd packet_open(const char *ifname, std::uint16_t ethertype, const Mac &group, LinkInfo &info) noexcept;
bool packet_send(const Fd &fd, int ifindex, const Mac &dst, ByteView frame) noexcept;
// Receives one frame; outgoing frames (our own) are reported as empty.
Rx packet_recv(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept;

// Air monitor: radiotap frames of every type on a monitor interface, with
// a kernel filter passing only probe requests and ToDS data frames.
Fd monitor_open(const char *ifname) noexcept;

// ---- UDP on loopback (simulation transport, test inputs) ----

Fd udp_bind_loopback(std::uint16_t port) noexcept;
void udp_send_loopback(const Fd &fd, std::uint16_t port, ByteView data) noexcept;

// ---- generic netlink ----

Fd netlink_open() noexcept;
bool netlink_send(const Fd &fd, ByteView msg) noexcept;
// Byte count received within timeout_ms, or nothing.
std::optional<std::size_t> netlink_recv(const Fd &fd, const ByteSpan &buf, int timeout_ms) noexcept;
// Host-order integers inside netlink messages (native endianness).
std::uint16_t load_ne16(ByteView v, std::size_t off) noexcept;
std::uint32_t load_ne32(ByteView v, std::size_t off) noexcept;
std::uint64_t load_ne64(ByteView v, std::size_t off) noexcept;
void store_ne16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept;
void store_ne32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept;

// Text of the last system error (strerror of errno).
std::string_view last_error() noexcept;

} // namespace os
} // namespace donghoa

#endif
