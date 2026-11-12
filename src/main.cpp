// SPDX-License-Identifier: MIT
// DongHoa entry point: start-up, the poll() event loop, timers, shutdown.
#include <string_view>

#include "daemon.hpp"
#include "log.hpp"

namespace donghoa {

namespace {

constexpr LogModule LOG_MODULE{LogModule::MAIN};

constexpr int LOOP_TICK_MS = 100;
constexpr Millis CHECK_INTERVAL_MS = 10000U; // configuration consistency check

// Owner of each polled descriptor.
enum class Src : std::uint8_t { L2, HAPD, CTRL, AMON, SURVEY };

} // namespace

bool Daemon::setupTransport() noexcept
{
	bool ok = true;

	for (std::size_t i = 0U; ok && (i < mCfg.nIfaces); i++) {
		ok = mL2.addIface(mCfg.ifaces[i]);
	}
	if (ok) {
		if (mCfg.apIdSet) {
			mApId = mCfg.apId;
		} else if (mL2.size() > 0U) {
			mApId = mL2.port(0U).mac;
		} else {
			logging::err(LOG_MODULE, "ap_id must be configured when only sim ports are used");
			ok = false;
		}
	}
	if (ok && (mCfg.simPort != 0U)) {
		ok = mL2.addSim(mCfg.simPort, mCfg.simPeers, mCfg.nSimPeers, mApId);
	}
	if (ok) {
		ok = initEnroll();
	}
	if (ok && mCfg.signing && !mCfg.enroll) {
		// Peers list our public key under our ap_id: a mismatch here means
		// they would drop everything we send.
		FixedString<64U> pub;
		(void)hexEncode(viewOf(mCfg.signKey.pub), pub);
		const ed25519::PublicKey *const own = mCfg.findTrusted(mApId);
		if ((own != nullptr) && (*own != mCfg.signKey.pub)) {
			logging::err(LOG_MODULE, "peer_key for this AP ({}) does not match sign_seed "
				     "(public key {})", mApId, pub);
			ok = false;
		} else {
			logging::info(LOG_MODULE, "signing as {}: peer_key {} hex:{}", mApId, mApId, pub);
		}
	}
	return ok;
}

bool Daemon::init(const char *cfgPath, bool debugAll) noexcept
{
	bool ok = loadConfig(mCfg, cfgPath);

	mStartMs = os::nowMs();

	if (ok) {
		logging::setAll(mCfg.logLevel);
		for (std::size_t i = 0U; i < logging::MODULES; i++) {
			if ((mCfg.logDebugMask & (1U << static_cast<std::uint32_t>(i))) != 0U) {
				logging::setLevel(logging::moduleAt(i), LogLevel::DEBUG);
			}
		}
		if (debugAll) {
			logging::setAll(LogLevel::DEBUG);
		}
		ok = setupTransport();
	}
	if (ok) {
		std::optional<std::uint32_t> r = os::randomU32();
		while (!r.has_value() || (*r == 0U)) {
			const std::uint64_t seed = os::nowMs() ^
				(static_cast<std::uint64_t>(static_cast<std::uint32_t>(os::processId())) <<
				 16U);
			r = static_cast<std::uint32_t>((seed & 0xffffffffU) | 1U);
		}
		mBootId = *r;
		initLocal();
		ok = openCtrl();
	}
	if (ok) {
		initAmon();
		os::installSignalHandlers();
		std::string_view auth = mCfg.keyView().empty() ? " (NO authentication)" : " (authenticated)";
		if (mCfg.signing) {
			auth = mCfg.keyView().empty() ? " (Ed25519 signed)" : " (Ed25519 signed + HMAC)";
		}
		logging::info(LOG_MODULE, "DongHoa '{}' ap_id {} boot {}{}", mCfg.name, mApId,
			      hex(mBootId, 8U), auth);
	}
	return ok;
}

void Daemon::runTimers() noexcept
{
	const Millis now = os::nowMs();

	if (now >= mNextStaPoll) {
		pollBss();
		pollStas();
		mNextStaPoll = now + static_cast<Millis>(mCfg.staPollMs);
	}
	if (now >= mNextHello) {
		sendHello();
		mNextHello = now + static_cast<Millis>(mCfg.helloMs);
	}
	if (now >= mNextBssStatus) {
		sendBssStatus();
		mNextBssStatus = now + static_cast<Millis>(mCfg.bssStatusMs);
	}
	if (now >= mNextStaStatus) {
		sendStaStatus();
		mNextStaStatus = now + static_cast<Millis>(mCfg.staStatusMs);
	}
	if (now >= mNextRfStatus) {
		sendRfStatus();
		mNextRfStatus = now + static_cast<Millis>(mCfg.rfStatusMs);
	}
	if (now >= mNextLb) {
		runLbRound();
		mNextLb = now + static_cast<Millis>(mCfg.pol.lbIntervalMs);
	}
	if (now >= mNextCheck) {
		checkConsistency();
		mNextCheck = now + CHECK_INTERVAL_MS;
	}
	tickSteer(now);
	tickAmon(now);
	tickEnroll(now);
	mSurvey.tick(now);
	retransmit(now);
	expirePeers(now);
}

void Daemon::run() noexcept
{
	while (!os::stopRequested()) {
		std::array<int, os::MAX_POLL> fds{};
		std::array<Src, os::MAX_POLL> src{};
		std::array<std::size_t, os::MAX_POLL> idx{};
		std::array<bool, os::MAX_POLL> ready{};
		std::size_t n = 0U;
		const auto add = [&](int fd, Src s, std::size_t i) {
			if ((fd >= 0) && (n < os::MAX_POLL)) {
				fds[n] = fd;
				src[n] = s;
				idx[n] = i;
				n++;
			}
		};

		for (std::size_t i = 0U; i < mL2.size(); i++) {
			add(mL2.port(i).fd.get(), Src::L2, i);
		}
		for (std::size_t i = 0U; i < mNBss; i++) {
			add(mBss[i].hapd.eventFd(), Src::HAPD, i);
		}
		add(mCtrlFd.get(), Src::CTRL, 0U);
		for (std::size_t i = 0U; i < mNAmon; i++) {
			add(mAmon[i].fd.get(), Src::AMON, i);
		}
		add(mSurvey.pollFd(), Src::SURVEY, 0U);
		if (!os::pollReadable(fds, n, LOOP_TICK_MS, ready)) {
			logging::err(LOG_MODULE, "poll: {}", os::lastError());
			break;
		}
		for (std::size_t k = 0U; k < n; k++) {
			if (!ready[k]) {
				continue;
			}
			switch (src[k]) {
			case Src::L2:
				receiveMsg(idx[k]);
				break;
			case Src::HAPD: {
				LocalBss &b = mBss[idx[k]];
				hapd::Reply ev;
				os::Rx r = os::Rx::DATA;
				while (b.hapd.isOpen() && (r == os::Rx::DATA)) {
					r = b.hapd.recvEvent(ev);
					if (r == os::Rx::DATA) {
						handleEvent(idx[k], ev.view());
					} else if (r == os::Rx::ERROR) {
						b.hapd.close();
					} else {
						// drained
					}
				}
				break;
			}
			case Src::CTRL:
				handleCtrl();
				break;
			case Src::AMON:
				receiveAmon(idx[k]);
				break;
			case Src::SURVEY:
				mSurvey.onReadable();
				processStationDumps();
				break;
			default:
				break;
			}
		}
		runTimers();
	}
}

void Daemon::shutdown() noexcept
{
	sendBye();
	for (std::size_t i = 0U; i < mNBss; i++) {
		mBss[i].hapd.close();
	}
	closeCtrl();
	logging::info(LOG_MODULE, "DongHoa stopped");
}

} // namespace donghoa

namespace {

donghoa::Daemon sDaemon;

// -g: new random seed; prints the configuration lines for it.
int generateKey() noexcept
{
	donghoa::ed25519::Seed seed{};
	if (!donghoa::os::randomBytes(donghoa::spanOf(seed))) {
		donghoa::os::writeStderr("no randomness available\n");
		return 1;
	}
	const donghoa::ed25519::KeyPair kp = donghoa::ed25519::keyPairFromSeed(seed);
	donghoa::FixedString<64U> s;
	donghoa::FixedString<64U> p;
	(void)donghoa::hexEncode(donghoa::viewOf(seed), s);
	(void)donghoa::hexEncode(donghoa::viewOf(kp.pub), p);
	donghoa::FixedString<400U> out;
	donghoa::formatTo(out,
			   "# this AP only (keep secret, like the config file):\n"
			   "sign_seed hex:{}\n"
			   "# on every AP, with this AP's ap_id:\n"
			   "peer_key <ap_id> hex:{}\n", s, p);
	donghoa::os::writeStdout(out.view());
	return 0;
}

void usage(std::string_view prog) noexcept
{
	donghoa::Line u;
	donghoa::formatTo(u,
			   "usage: {} -c <config> [-d] [-s]\n"
			   "       {} -g\n"
			   "  -c  configuration file\n"
			   "  -d  debug logging for every module (overrides log_level/log_debug)\n"
			   "  -s  log to syslog (daemon facility) instead of stderr\n"
			   "  -g  generate an Ed25519 key pair: a sign_seed line for this AP and the\n"
			   "      peer_key line to add on every AP\n"
			   "Log levels can also be changed at run time: donghoa_cli <socket> LOG\n",
			   prog, prog);
	donghoa::os::writeStderr(u.view());
}

} // namespace

int main(int argc, char **argv)
{
	const char *cfgPath = nullptr;
	bool debugAll = false;
	bool syslog = false;
	int rc = 0;
	const std::string_view prog = (argc > 0) ? std::string_view(argv[0]) : std::string_view("donghoa");

	for (int i = 1; (i < argc) && (rc == 0); i++) {
		const std::string_view a(argv[i]);
		if ((a == "-c") && ((i + 1) < argc)) {
			i++;
			cfgPath = argv[i];
		} else if (a == "-d") {
			debugAll = true;
		} else if (a == "-s") {
			syslog = true;
		} else if (a == "-h") {
			usage(prog);
			return 0;
		} else if (a == "-g") {
			return generateKey();
		} else {
			rc = 1;
		}
	}
	if ((rc != 0) || (cfgPath == nullptr)) {
		usage(prog);
		return 1;
	}
	donghoa::logging::useSyslog(syslog);
	if (!sDaemon.init(cfgPath, debugAll)) {
		return 1;
	}
	sDaemon.run();
	sDaemon.shutdown();
	return 0;
}
