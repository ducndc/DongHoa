// SPDX-License-Identifier: MIT
// donghoa_cli - query a running donghoa over its control socket.
#include <array>
#include <cstdint>
#include <string_view>

#include "os.hpp"
#include "text.hpp"

namespace {

constexpr int kReplyTimeoutMs = 2000;

void usage(std::string_view prog) noexcept
{
	donghoa::Line u;
	donghoa::format_to(u,
			   "usage: {} <ctrl_socket> STATUS|PEERS|STAS|STEERS|PING|"
			   "STEER <sta> [<bssid>]|MONITOR <sta> [<ms>]|\n"
			   "LOG [err|warn|info|debug [<module>...]]\n",
			   prog);
	donghoa::os::write_stderr(u.view());
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
			(void)cmd.push_back(' ');
		}
		(void)cmd.append(std::string_view(argv[i]));
	}

	donghoa::FixedString<108U> local;
	donghoa::format_to(local, "/tmp/donghoa_cli-{}", donghoa::os::process_id());

	std::array<std::uint8_t, 8192U> reply{};
	std::size_t n = 0U;
	int rc = 1;
	if (donghoa::os::unix_request(argv[1], local.c_str(), cmd.view(), donghoa::span_of(reply), n,
				      kReplyTimeoutMs)) {
		donghoa::FixedString<8192U> text;
		for (std::size_t i = 0U; i < n; i++) {
			(void)text.push_back(static_cast<char>(reply[i]));
		}
		donghoa::os::write_stdout(text.view());
		rc = donghoa::starts_with(text.view(), "FAIL") ? 1 : 0;
	} else {
		donghoa::os::write_stderr("donghoa_cli: no reply\n");
	}
	return rc;
}
