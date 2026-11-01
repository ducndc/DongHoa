// SPDX-License-Identifier: MIT
// System interface layer. MISRA C++ deviations confined to this file
// (docs/CODING_CONVENTION.md): DEV-01 POSIX/Linux system calls and their
// structures, DEV-02 reinterpret_cast to sockaddr/netlink/BPF types required
// by those calls, DEV-03 <csignal>-equivalent sigaction for SIGINT/SIGTERM,
// DEV-04 std::memcpy for opaque socket addresses and native-endian netlink
// fields.
#include "os.hpp"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

namespace donghoa {
namespace os {

namespace {

volatile sig_atomic_t g_stop = 0;

extern "C" void on_stop_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

// Fills a sockaddr_un with path; false if it does not fit.
bool make_unix_addr(const char *path, sockaddr_un &a) noexcept
{
	const std::size_t len = std::strlen(path);
	bool ok = len < sizeof(a.sun_path);

	a = sockaddr_un{};
	a.sun_family = AF_UNIX;
	if (ok) {
		(void)std::memcpy(&a.sun_path[0], path, len + 1U);
	}
	return ok;
}

const sockaddr *as_sockaddr(const sockaddr_un &a) noexcept
{
	return reinterpret_cast<const sockaddr *>(&a); // DEV-02
}

const sockaddr *as_sockaddr(const sockaddr_ll &a) noexcept
{
	return reinterpret_cast<const sockaddr *>(&a); // DEV-02
}

const sockaddr *as_sockaddr(const sockaddr_in &a) noexcept
{
	return reinterpret_cast<const sockaddr *>(&a); // DEV-02
}

const sockaddr *as_sockaddr(const sockaddr_nl &a) noexcept
{
	return reinterpret_cast<const sockaddr *>(&a); // DEV-02
}

Rx classify(ssize_t r) noexcept
{
	Rx x = Rx::error;
	if (r >= 0) {
		x = Rx::data;
	} else if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
		x = Rx::empty;
	} else {
		// real error
	}
	return x;
}

// Kernel filter for air monitors: pass probe requests and data frames with
// ToDS and not FromDS (what a STA sends to its AP, incl. power-save nulls).
// The 802.11 header follows the radiotap header, whose length is LE16 at 2.
sock_filter g_monitor_bpf[] = {
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 3),           // 0: A = it_len high byte
	BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 8),          // 1
	BPF_STMT(BPF_MISC | BPF_TAX, 0),                 // 2: X = A
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),           // 3: A = it_len low byte
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),          // 4: A = it_len
	BPF_STMT(BPF_MISC | BPF_TAX, 0),                 // 5: X = it_len
	BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),           // 6: A = frame control 0
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 5, 0), // 7: probe req -> 13
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0c),       // 8: type
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x08, 0, 4), // 9: not data -> 14
	BPF_STMT(BPF_LD | BPF_B | BPF_IND, 1),           // 10: A = frame control 1
	BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x03),       // 11: ToDS | FromDS
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 0, 1), // 12: ToDS only
	BPF_STMT(BPF_RET | BPF_K, 256),                  // 13: accept, 256 bytes
	BPF_STMT(BPF_RET | BPF_K, 0),                    // 14: drop
};

} // namespace

// ---- time, process, randomness ----

Millis now_ms() noexcept
{
	timespec ts{};
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (static_cast<Millis>(ts.tv_sec) * 1000U) + (static_cast<Millis>(ts.tv_nsec) / 1000000U);
}

std::int32_t process_id() noexcept
{
	return getpid(); // pid_t is int on Linux
}

std::optional<std::uint32_t> random_u32() noexcept
{
	std::uint32_t v = 0U;
	std::optional<std::uint32_t> r;
	if (getrandom(&v, sizeof(v), 0U) == static_cast<ssize_t>(sizeof(v))) {
		r = v;
	}
	return r;
}

// ---- logging sinks ----

void write_stderr(std::string_view line) noexcept
{
	// Nothing useful can be done if stderr is gone.
	const ssize_t w = ::write(STDERR_FILENO, line.data(), line.size());
	(void)w;
}

void write_stdout(std::string_view text) noexcept
{
	const ssize_t w = ::write(STDOUT_FILENO, text.data(), text.size());
	(void)w;
}

void syslog_open() noexcept
{
	openlog("donghoa", LOG_PID, LOG_DAEMON);
}

void syslog_close() noexcept
{
	closelog();
}

void syslog_write(std::uint8_t prio, std::string_view line) noexcept
{
	static constexpr int kPrio[4] = {LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG};
	const int p = (prio < 4U) ? kPrio[prio] : LOG_INFO;
	syslog(p, "%.*s", static_cast<int>(line.size()), line.data());
}

// ---- signals ----

void install_signal_handlers() noexcept
{
	struct sigaction sa {};
	sa.sa_handler = &on_stop_signal;
	(void)sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGINT, &sa, nullptr);
	(void)sigaction(SIGTERM, &sa, nullptr);
	struct sigaction ign {};
	ign.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &ign, nullptr);
}

bool stop_requested() noexcept
{
	return g_stop != 0;
}

// ---- files ----

bool read_text_file(const char *path, FixedString<16384U> &out) noexcept
{
	Fd fd(::open(path, O_RDONLY | O_CLOEXEC));
	bool ok = fd.valid();
	std::array<char, 1024U> buf{};

	out.clear();
	while (ok) {
		const ssize_t n = ::read(fd.get(), buf.data(), buf.size());
		if (n < 0) {
			ok = false;
		} else if (n == 0) {
			break;
		} else {
			ok = out.append(std::string_view(buf.data(), static_cast<std::size_t>(n)));
		}
	}
	return ok;
}

void remove_file(const char *path) noexcept
{
	(void)::unlink(path);
}

// ---- file descriptors ----

Fd &Fd::operator=(Fd &&o) noexcept
{
	if (this != &o) {
		reset();
		fd_ = o.fd_;
		o.fd_ = -1;
	}
	return *this;
}

void Fd::reset() noexcept
{
	if (fd_ >= 0) {
		(void)::close(fd_);
		fd_ = -1;
	}
}

bool poll_readable(const std::array<int, kMaxPoll> &fds, std::size_t n, int timeout_ms,
		   std::array<bool, kMaxPoll> &ready) noexcept
{
	std::array<pollfd, kMaxPoll> p{};
	const std::size_t cnt = (n > kMaxPoll) ? kMaxPoll : n;

	for (std::size_t i = 0U; i < cnt; i++) {
		p[i].fd = fds[i];
		p[i].events = POLLIN;
		ready[i] = false;
	}
	const int r = ::poll(p.data(), static_cast<nfds_t>(cnt), timeout_ms);
	for (std::size_t i = 0U; (r > 0) && (i < cnt); i++) {
		ready[i] = (p[i].revents & (POLLIN | POLLERR | POLLHUP)) != 0;
	}
	return (r >= 0) || (errno == EINTR);
}

bool wait_readable(int fd, int timeout_ms) noexcept
{
	pollfd p{};
	p.fd = fd;
	p.events = POLLIN;
	return (timeout_ms > 0) && (::poll(&p, 1U, timeout_ms) > 0);
}

// ---- UNIX datagram sockets ----

Fd unix_bind(const char *path, bool nonblock) noexcept
{
	const int flags = SOCK_DGRAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0);
	Fd fd(::socket(AF_UNIX, flags, 0));
	sockaddr_un a{};

	if (fd.valid() && make_unix_addr(path, a)) {
		(void)::unlink(path);
		if (::bind(fd.get(), as_sockaddr(a), sizeof(a)) < 0) {
			fd.reset();
		}
	} else {
		fd.reset();
	}
	return fd;
}

void share_owner(const char *path, const char *other_path) noexcept
{
	struct stat st {};
	if ((::stat(other_path, &st) == 0) && (st.st_uid != ::geteuid())) {
		// Fails harmlessly when not root: hostapd then runs as us anyway.
		const int r = ::chown(path, st.st_uid, st.st_gid);
		(void)r;
		(void)::chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	}
}

bool unix_connect(const Fd &fd, const char *path) noexcept
{
	sockaddr_un a{};
	return make_unix_addr(path, a) && (::connect(fd.get(), as_sockaddr(a), sizeof(a)) == 0);
}

bool send_text(const Fd &fd, std::string_view text, bool dontwait) noexcept
{
	return ::send(fd.get(), text.data(), text.size(), dontwait ? MSG_DONTWAIT : 0) >= 0;
}

std::optional<std::size_t> recv_bytes(const Fd &fd, const ByteSpan &buf) noexcept
{
	std::optional<std::size_t> r;
	const ssize_t n = ::recv(fd.get(), buf.data(), buf.size(), 0);
	if (n >= 0) {
		r = static_cast<std::size_t>(n);
	}
	return r;
}

Rx recv_nowait(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept
{
	const ssize_t r = ::recv(fd.get(), buf.data(), buf.size(), MSG_DONTWAIT);
	n = (r > 0) ? static_cast<std::size_t>(r) : 0U;
	return classify(r);
}

Rx recv_from(const Fd &fd, const ByteSpan &buf, std::size_t &n, UnixAddr &from) noexcept
{
	sockaddr_un a{};
	socklen_t len = sizeof(a);
	const ssize_t r = ::recvfrom(fd.get(), buf.data(), buf.size(), 0,
				     reinterpret_cast<sockaddr *>(&a), &len); // DEV-02
	n = (r > 0) ? static_cast<std::size_t>(r) : 0U;
	if ((r >= 0) && (len <= sizeof(from.raw))) {
		(void)std::memcpy(from.raw.data(), &a, len); // DEV-04
		from.len = static_cast<std::uint32_t>(len);
	}
	return classify(r);
}

void send_to(const Fd &fd, ByteView data, const UnixAddr &to) noexcept
{
	sockaddr_un a{};
	if (to.len <= sizeof(a)) {
		(void)std::memcpy(&a, to.raw.data(), to.len); // DEV-04
		(void)::sendto(fd.get(), data.data(), data.size(), 0, as_sockaddr(a),
			       static_cast<socklen_t>(to.len));
	}
}

bool unix_request(const char *server, const char *local, std::string_view request,
		  const ByteSpan &reply, std::size_t &n, int timeout_ms) noexcept
{
	Fd fd = unix_bind(local, false);
	sockaddr_un a{};
	bool ok = fd.valid() && make_unix_addr(server, a) &&
		  (::sendto(fd.get(), request.data(), request.size(), 0, as_sockaddr(a), sizeof(a)) >= 0);

	n = 0U;
	if (ok) {
		ok = wait_readable(fd.get(), timeout_ms);
	}
	if (ok) {
		const std::optional<std::size_t> r = recv_bytes(fd, reply);
		ok = r.has_value();
		n = ok ? *r : 0U;
	}
	(void)::unlink(local);
	return ok;
}

// ---- raw Ethernet ----

int ifname_to_index(const char *ifname) noexcept
{
	return static_cast<int>(if_nametoindex(ifname));
}

Fd packet_open(const char *ifname, std::uint16_t ethertype, const Mac &group, LinkInfo &info) noexcept
{
	Fd fd(::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, static_cast<int>(htons(ethertype))));
	ifreq ifr{};
	bool ok = fd.valid() && (std::strlen(ifname) < sizeof(ifr.ifr_name));

	if (ok) {
		(void)std::memcpy(&ifr.ifr_name[0], ifname, std::strlen(ifname) + 1U);
		ok = ::ioctl(fd.get(), SIOCGIFINDEX, &ifr) >= 0;
	}
	if (ok) {
		info.ifindex = ifr.ifr_ifindex;
		sockaddr_ll sll{};
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ethertype);
		sll.sll_ifindex = info.ifindex;
		ok = ::bind(fd.get(), as_sockaddr(sll), sizeof(sll)) >= 0;
	}
	if (ok) {
		packet_mreq mr{};
		mr.mr_ifindex = info.ifindex;
		mr.mr_type = PACKET_MR_MULTICAST;
		mr.mr_alen = 6U;
		(void)std::memcpy(&mr.mr_address[0], group.b.data(), group.b.size());
		ok = ::setsockopt(fd.get(), SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) >= 0;
	}
	if (ok) {
		ok = ::ioctl(fd.get(), SIOCGIFHWADDR, &ifr) >= 0;
	}
	if (ok) {
		for (std::size_t i = 0U; i < info.mac.b.size(); i++) {
			info.mac.b[i] = static_cast<std::uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
		}
	} else {
		fd.reset();
	}
	return fd;
}

bool packet_send(const Fd &fd, int ifindex, const Mac &dst, ByteView frame) noexcept
{
	sockaddr_ll sll{};
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_halen = 6U;
	(void)std::memcpy(&sll.sll_addr[0], dst.b.data(), dst.b.size());
	return ::sendto(fd.get(), frame.data(), frame.size(), 0, as_sockaddr(sll), sizeof(sll)) >= 0;
}

Rx packet_recv(const Fd &fd, const ByteSpan &buf, std::size_t &n) noexcept
{
	sockaddr_ll sll{};
	socklen_t sl = sizeof(sll);
	const ssize_t r = ::recvfrom(fd.get(), buf.data(), buf.size(), 0,
				     reinterpret_cast<sockaddr *>(&sll), &sl); // DEV-02
	Rx x = classify(r);

	n = (r > 0) ? static_cast<std::size_t>(r) : 0U;
	if ((x == Rx::data) && (sll.sll_pkttype == PACKET_OUTGOING)) {
		x = Rx::empty;
		n = 0U;
	}
	return x;
}

Fd monitor_open(const char *ifname) noexcept
{
	Fd fd(::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, static_cast<int>(htons(ETH_P_ALL))));
	sock_fprog prog{};
	sockaddr_ll sll{};

	prog.len = static_cast<unsigned short>(sizeof(g_monitor_bpf) / sizeof(g_monitor_bpf[0]));
	prog.filter = &g_monitor_bpf[0];
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifname_to_index(ifname);
	if (!fd.valid() || (sll.sll_ifindex == 0) ||
	    (::setsockopt(fd.get(), SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) ||
	    (::bind(fd.get(), as_sockaddr(sll), sizeof(sll)) < 0)) {
		fd.reset();
	}
	return fd;
}

// ---- UDP on loopback ----

Fd udp_bind_loopback(std::uint16_t port) noexcept
{
	Fd fd(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
	sockaddr_in sin{};

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd.valid() && (::bind(fd.get(), as_sockaddr(sin), sizeof(sin)) < 0)) {
		fd.reset();
	}
	return fd;
}

void udp_send_loopback(const Fd &fd, std::uint16_t port, ByteView data) noexcept
{
	sockaddr_in sin{};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)::sendto(fd.get(), data.data(), data.size(), 0, as_sockaddr(sin), sizeof(sin));
}

// ---- generic netlink ----

Fd netlink_open() noexcept
{
	Fd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC));
	sockaddr_nl sa{};
	sa.nl_family = AF_NETLINK;
	if (fd.valid() && (::bind(fd.get(), as_sockaddr(sa), sizeof(sa)) < 0)) {
		fd.reset();
	}
	return fd;
}

bool netlink_send(const Fd &fd, ByteView msg) noexcept
{
	sockaddr_nl sa{};
	sa.nl_family = AF_NETLINK;
	return ::sendto(fd.get(), msg.data(), msg.size(), 0, as_sockaddr(sa), sizeof(sa)) >= 0;
}

std::optional<std::size_t> netlink_recv(const Fd &fd, const ByteSpan &buf, int timeout_ms) noexcept
{
	std::optional<std::size_t> r;
	if (wait_readable(fd.get(), timeout_ms)) {
		r = recv_bytes(fd, buf);
	}
	return r;
}

std::uint16_t load_ne16(ByteView v, std::size_t off) noexcept
{
	std::uint16_t x = 0U;
	if ((off + sizeof(x)) <= v.size()) {
		(void)std::memcpy(&x, &v.data()[off], sizeof(x)); // DEV-04
	}
	return x;
}

std::uint32_t load_ne32(ByteView v, std::size_t off) noexcept
{
	std::uint32_t x = 0U;
	if ((off + sizeof(x)) <= v.size()) {
		(void)std::memcpy(&x, &v.data()[off], sizeof(x)); // DEV-04
	}
	return x;
}

std::uint64_t load_ne64(ByteView v, std::size_t off) noexcept
{
	std::uint64_t x = 0U;
	if ((off + sizeof(x)) <= v.size()) {
		(void)std::memcpy(&x, &v.data()[off], sizeof(x)); // DEV-04
	}
	return x;
}

void store_ne16(const ByteSpan &s, std::size_t off, std::uint16_t v) noexcept
{
	if ((off + sizeof(v)) <= s.size()) {
		(void)std::memcpy(&s.data()[off], &v, sizeof(v)); // DEV-04
	}
}

void store_ne32(const ByteSpan &s, std::size_t off, std::uint32_t v) noexcept
{
	if ((off + sizeof(v)) <= s.size()) {
		(void)std::memcpy(&s.data()[off], &v, sizeof(v)); // DEV-04
	}
}

std::string_view last_error() noexcept
{
	return std::string_view(std::strerror(errno));
}

} // namespace os
} // namespace donghoa
