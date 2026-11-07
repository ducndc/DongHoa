// SPDX-License-Identifier: MIT
// donghoa_cli - query a running donghoa over its control socket.
#include <array>
#include <cstdint>
#include <string_view>

#include "os.hpp"
#include "text.hpp"

namespace {

constexpr int REPLY_TIMEOUT_MS = 2000;

void usage(std::string_view prog) noexcept
{
	donghoa::Line u;
	donghoa::formatTo(u,
			   "usage: {} <ctrl_socket> STATUS|PEERS|STAS|STEERS|DEVCLASS|CALIB|RL|PING|"
			   "STEER <sta> [<bssid>]|MONITOR <sta> [<ms>]|\n"
			   "LOG [err|warn|info|debug [<module>...]]\n",
			   prog);
	donghoa::os::writeStderr(u.view());
}

} // namespace

int main(int argc, char **argv)
{
	if (argc < 3) {
		usage((argc > 0) ? std::string_view(argv[0]) : std::string_view("donghoa_cli"));
		return 1;
	}

	donghoa::FixedString<255U> cmd;
	for (int i = 2; i < argc; i++) {
		if (i > 2) {
			(void)cmd.pushBack(' ');
		}
		(void)cmd.append(std::string_view(argv[i]));
	}

	donghoa::FixedString<108U> local;
	donghoa::formatTo(local, "/tmp/donghoa_cli-{}", donghoa::os::processId());

	std::array<std::uint8_t, 8192U> reply{};
	std::size_t n = 0U;
	int rc = 1;
	if (donghoa::os::sendUnixRequest(argv[1], local.cStr(), cmd.view(), donghoa::spanOf(reply), n,
				      REPLY_TIMEOUT_MS)) {
		donghoa::FixedString<8192U> text;
		for (std::size_t i = 0U; i < n; i++) {
			(void)text.pushBack(static_cast<char>(reply[i]));
		}
		donghoa::os::writeStdout(text.view());
		rc = donghoa::startsWith(text.view(), "FAIL") ? 1 : 0;
	} else {
		donghoa::os::writeStderr("donghoa_cli: no reply\n");
	}
	return rc;
}
