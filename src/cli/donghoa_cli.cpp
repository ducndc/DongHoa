// SPDX-License-Identifier: MIT
// donghoa_cli - query a running donghoa over its control socket: one command
// from the command line, or a shell reading commands from stdin. ATTACH
// shows the daemon's events (its log lines) as they happen.
#include <array>
#include <cstdint>
#include <string_view>

#include "base/os.hpp"
#include "base/text.hpp"

namespace {

using donghoa::Millis;
namespace os = donghoa::os;

constexpr int REPLY_TIMEOUT_MS = 2000;
constexpr int POLL_MS = 1000;
// ATTACH is repeated this often: the reply shows the daemon is alive, and a
// restarted daemon learns about this client again.
constexpr Millis KEEPALIVE_MS = 5000U;
constexpr Millis LOST_AFTER_MS = 12000U;
constexpr std::string_view PROMPT{"donghoa> "};
constexpr std::string_view COMMANDS{
	"commands:\n"
	"  STATUS PEERS STAS STEERS DEVCLASS CALIB METRICS CHECK PING\n"
	"  STEER <sta> [<bssid>]\n"
	"  MONITOR <sta> [<ms>]\n"
	"  RL [mode <0|1|2> | reset]\n"
	"  BANDIT [mode <0|1|2> | reset]\n"
	"  ENROLL [approve <ap_id> | revoke <ap_id> | init]\n"
	"  DROPRX [<MESSAGE> <n>]\n"
	"  LOG [err|warning|notice|info|debug|0..7 [<module>...]]\n"
	"  ATTACH [err|warning|notice|info|debug|0..7]   show events: log lines up to that level\n"
	"  DETACH\n"};

using Text = donghoa::FixedString<8192U>;

void usage(std::string_view prog) noexcept
{
	donghoa::Line u;
	donghoa::formatTo(u,
			   "usage: {} <ctrl_socket> [<command>]\n"
			   "without a command: reads commands from stdin (interactive: help, quit)\n"
			   "ATTACH as the command: prints events until interrupted\n", prog);
	os::writeStderr(u.view());
	os::writeStderr(COMMANDS);
}

bool isAttachCommand(std::string_view cmd) noexcept
{
	return (cmd == "ATTACH") || donghoa::startsWith(cmd, "ATTACH ");
}

// The event subscription. It has a socket of its own, so an event is never
// taken for the reply to a command; on that socket an event starts with '<'
// and anything else answers our own ATTACH or DETACH. The socket is not
// connected: the daemon sends events from another socket than its control
// socket.
class Events {
public:
	explicit Events(const char *server) noexcept : mServer(server) {}

	bool isOn() const noexcept { return mFd.valid(); }
	int fd() const noexcept { return mFd.get(); }
	bool hasPrinted() const noexcept { return mPrinted; }
	bool isStdoutOk() const noexcept { return mStdoutOk; }

	// Sends cmd ("ATTACH [<level>]") and waits for the reply, which is left
	// in reply. True if the daemon accepted. A refused change of level
	// leaves the subscription as it was.
	bool attach(std::string_view cmd, Text &reply) noexcept
	{
		const bool wasOn = mFd.valid();
		if (wasOn) {
			// An answer to an earlier keep-alive must not pass for this one's.
			drain(false);
		} else {
			mPath.clear();
			donghoa::formatTo(mPath, "/tmp/donghoa_cli-{}-ev", os::processId());
			mFd = os::bindUnix(mPath.cStr(), true);
		}
		const bool ok = mFd.valid() && request(cmd, reply) && donghoa::startsWith(reply.view(), "OK");
		if (ok) {
			(void)mAttachCmd.assign(cmd);
			mLastSent = os::nowMs();
			mLastOk = mLastSent;
			mLost = false;
		} else if (!wasOn) {
			close();
		} else {
			// still attached with the earlier command
		}
		return ok;
	}

	void detach() noexcept
	{
		if (mFd.valid()) {
			Text reply;
			(void)request("DETACH", reply);
			close();
		}
	}

	// Prints the events that have arrived. atPrompt: a prompt is on the
	// current line, start over it.
	void drain(bool atPrompt) noexcept
	{
		Text msg;
		mPrinted = false;
		while (mFd.valid() && receive(msg)) {
			if (isEvent(msg.view())) {
				print(msg.view(), atPrompt && !mPrinted);
			} else if (donghoa::startsWith(msg.view(), "OK")) {
				mLastOk = os::nowMs();
				if (mLost) {
					os::writeStderr("donghoa_cli: the daemon answers again\n");
					mLost = false;
				}
			} else {
				os::writeStderr("donghoa_cli: no events: ");
				os::writeStderr(msg.view());
			}
		}
	}

	// Repeats ATTACH when it is due and reports a daemon that went silent.
	void keepAlive() noexcept
	{
		const Millis now = os::nowMs();
		if (mFd.valid() && ((now - mLastSent) >= KEEPALIVE_MS)) {
			mLastSent = now;
			// Fails while the daemon is down; the next one finds it again.
			(void)os::sendTextTo(mFd, mServer, mAttachCmd.view());
			if (!mLost && ((now - mLastOk) > LOST_AFTER_MS)) {
				os::writeStderr("donghoa_cli: the daemon does not answer, waiting for it\n");
				mLost = true;
			}
		}
	}

private:
	static bool isEvent(std::string_view msg) noexcept
	{
		return !msg.empty() && (msg.front() == '<');
	}

	void print(std::string_view event, bool overPrompt) noexcept
	{
		if (overPrompt) {
			mStdoutOk = os::writeStdout("\r") && mStdoutOk;
		}
		mStdoutOk = os::writeStdout(event) && mStdoutOk;
		if (event.back() != '\n') {
			mStdoutOk = os::writeStdout("\n") && mStdoutOk;
		}
		mPrinted = true;
	}

	bool receive(Text &msg) noexcept
	{
		std::array<std::uint8_t, 8192U> buf{};
		std::size_t n = 0U;
		const bool got = os::recvNowait(mFd, donghoa::spanOf(buf), n) == os::Rx::DATA;

		msg.clear();
		for (std::size_t i = 0U; got && (i < n); i++) {
			(void)msg.pushBack(static_cast<char>(buf[i]));
		}
		return got;
	}

	// One exchange on the event socket. Events that arrive before the reply
	// are printed.
	bool request(std::string_view cmd, Text &reply) noexcept
	{
		const Millis end = os::nowMs() + static_cast<Millis>(REPLY_TIMEOUT_MS);
		bool waiting = os::sendTextTo(mFd, mServer, cmd);
		bool got = false;

		reply.clear();
		while (waiting && !got) {
			const Millis now = os::nowMs();
			waiting = (now < end) && os::waitReadable(mFd.get(), static_cast<int>(end - now));
			if (waiting && receive(reply)) {
				if (isEvent(reply.view())) {
					print(reply.view(), false);
				} else {
					got = true;
				}
			}
		}
		if (!got) {
			(void)reply.assign("no reply\n");
		}
		return got;
	}

	void close() noexcept
	{
		if (mFd.valid()) {
			mFd.reset();
			os::removeFile(mPath.cStr());
		}
	}

	const char *mServer;
	os::Fd mFd{};
	donghoa::FixedString<108U> mPath{};
	donghoa::FixedString<32U> mAttachCmd{};
	Millis mLastSent{0U};
	Millis mLastOk{0U};
	bool mLost{false};
	bool mPrinted{false};
	bool mStdoutOk{true};
};

// Sends one command and prints the reply. False if the daemon did not answer
// or answered FAIL. endLine: finish a reply that lacks a newline, so the next
// prompt starts on its own line.
bool runCommand(const char *server, std::string_view cmd, bool endLine) noexcept
{
	donghoa::FixedString<108U> local;
	donghoa::formatTo(local, "/tmp/donghoa_cli-{}", os::processId());

	std::array<std::uint8_t, 8192U> reply{};
	std::size_t n = 0U;
	bool ok = false;
	if (os::sendUnixRequest(server, local.cStr(), cmd, donghoa::spanOf(reply), n, REPLY_TIMEOUT_MS)) {
		Text text;
		for (std::size_t i = 0U; i < n; i++) {
			(void)text.pushBack(static_cast<char>(reply[i]));
		}
		(void)os::writeStdout(text.view());
		if (endLine && !text.empty() && (text.view().back() != '\n')) {
			(void)os::writeStdout("\n");
		}
		ok = !donghoa::startsWith(text.view(), "FAIL");
	} else {
		os::writeStderr("donghoa_cli: no reply\n");
	}
	return ok;
}

// What one line of input asks for. False if it failed.
bool runLine(const char *server, Events &events, std::string_view cmd, bool &more) noexcept
{
	bool ok = true;

	if (cmd.empty() || (cmd.front() == '#')) {
		// blank line or comment: nothing to send
	} else if ((cmd == "quit") || (cmd == "exit")) {
		more = false;
	} else if (cmd == "help") {
		(void)os::writeStdout(COMMANDS);
		(void)os::writeStdout("  help, quit (or exit, Ctrl-D)\n");
	} else if (isAttachCommand(cmd)) {
		// From the event socket: a command's own socket is gone after its reply.
		Text reply;
		ok = events.attach(cmd, reply);
		(void)os::writeStdout(reply.view());
	} else if (cmd == "DETACH") {
		ok = events.isOn();
		events.detach();
		(void)os::writeStdout(ok ? "OK\n" : "FAIL not attached\n");
	} else {
		ok = runCommand(server, cmd, true);
	}
	return ok;
}

// The shell: one command per line of stdin until "quit" or end of input,
// events in between. The prompt is shown only to a terminal, so piped
// commands give the replies alone. attachCmd: an ATTACH to start with.
// readInput false: events only, until a signal or stdout closes.
// Returns the exit status: 1 if any command failed.
int runShell(const char *server, std::string_view attachCmd, bool readInput) noexcept
{
	const bool isTerminal = readInput && os::isStdinTerminal();
	Events events(server);
	bool allOk = true;
	bool more = true;
	bool promptShown = false; // a prompt is on the current line

	// SIGINT and SIGTERM end the loop, so the daemon is told (DETACH) and the
	// event socket's file is removed.
	os::installSignalHandlers();
	if (!attachCmd.empty()) {
		Text reply;
		if (!events.attach(attachCmd, reply)) {
			os::writeStderr("donghoa_cli: no events: ");
			os::writeStderr(reply.view());
			// The shell works without events; alone they were the whole job.
			allOk = readInput;
			more = readInput;
		}
	}
	if (isTerminal) {
		(void)os::writeStdout("type a command, 'help' or 'quit'\n");
	}
	while (more) {
		if (isTerminal && !promptShown) {
			(void)os::writeStdout(PROMPT);
			promptShown = true;
		}
		std::array<int, os::MAX_POLL> fds{};
		std::array<bool, os::MAX_POLL> ready{};
		std::size_t n = 0U;
		std::size_t eventsAt = os::MAX_POLL;
		if (readInput) {
			fds[n] = os::STDIN_FD;
			n++;
		}
		if (events.isOn()) {
			eventsAt = n;
			fds[n] = events.fd();
			n++;
		}
		if ((n == 0U) || !os::pollReadable(fds, n, POLL_MS, ready) || os::stopRequested()) {
			more = false;
			continue;
		}
		if ((eventsAt < n) && ready[eventsAt]) {
			events.drain(promptShown);
			promptShown = promptShown && !events.hasPrinted();
			more = events.isStdoutOk();
		}
		if (more && readInput && ready[0U]) {
			donghoa::FixedString<255U> line;
			const os::LineRead got = os::readStdinLine(line);

			if (got == os::LineRead::END) {
				more = false;
			} else if (got == os::LineRead::TOO_LONG) {
				os::writeStderr("donghoa_cli: line too long (255 characters at most)\n");
				allOk = false;
				promptShown = false;
			} else {
				allOk = runLine(server, events, donghoa::trim(line.view()), more) && allOk;
				promptShown = false;
			}
		}
		events.keepAlive();
	}
	if (promptShown) {
		(void)os::writeStdout("\n");
	}
	events.detach();
	return allOk ? 0 : 1;
}

} // namespace

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc < 2) {
		usage((argc > 0) ? std::string_view(argv[0]) : std::string_view("donghoa_cli"));
	} else if (argc == 2) {
		// A person at a terminal sees events; a script asks with ATTACH.
		const bool isTerminal = os::isStdinTerminal();
		rc = runShell(argv[1], isTerminal ? std::string_view("ATTACH") : std::string_view(), true);
	} else {
		donghoa::FixedString<255U> cmd;
		for (int i = 2; i < argc; i++) {
			if (i > 2) {
				(void)cmd.pushBack(' ');
			}
			(void)cmd.append(std::string_view(argv[i]));
		}
		if (isAttachCommand(cmd.view())) {
			rc = runShell(argv[1], cmd.view(), false);
		} else {
			rc = runCommand(argv[1], cmd.view(), false) ? 0 : 1;
		}
	}
	return rc;
}
