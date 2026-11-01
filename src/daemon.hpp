// SPDX-License-Identifier: MIT
// DongHoa daemon state and behaviour. All state lives in fixed-size tables
// inside one Daemon object (no heap). The member functions are implemented
// per area: msg.cpp, peer.cpp, local.cpp, steer.cpp, amon.cpp, ctrl.cpp,
// main.cpp.
#ifndef DONGHOA_DAEMON_HPP
#define DONGHOA_DAEMON_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "config.hpp"
#include "hapd.hpp"
#include "hapd_parse.hpp"
#include "l2.hpp"
#include "os.hpp"
#include "proto.hpp"
#include "rrm.hpp"
#include "survey.hpp"

namespace donghoa {

constexpr std::size_t MAX_STA = 256U;
constexpr std::size_t MAX_PEERS = 32U;
constexpr std::size_t MAX_REMOTE_STA = 512U;
constexpr std::size_t MAX_MEAS = 16U;
constexpr std::size_t MAX_TXN = 16U;
constexpr std::size_t MAX_RESV = 32U;
constexpr std::size_t MAX_PENDING = 32U;
constexpr std::size_t MAX_RADIO = 4U;
constexpr std::size_t MAX_CAND = 16U;
constexpr std::size_t MAX_WATCH = 16U;
constexpr std::size_t WATCH_FREQS = 4U;

// ---- local side ----

struct LocalBss {
	const BssCfg *cfg{nullptr};
	hapd::Conn hapd{};
	bool up{false};
	bool secured{false};
	int ifindex{0};
	arcp::BssInfo info{};
	arcp::BssLoad load{};
	int hapdUtil{-1}; // chan_util_avg from hostapd STATUS, -1 if absent
	SurveySample surveyPrev{};
	Millis nextReconnectMs{0U};
};

// Where a STA's level towards one BSS comes from.
enum class MeasSrc : std::uint8_t { STA_11K, AIR_MONITOR };

struct Measurement {
	Mac bssid{};
	std::uint8_t rcpi{255U};
	std::uint8_t opClass{0U};
	std::uint8_t channel{0U};
	MeasSrc src{MeasSrc::STA_11K};
	Millis ts{0U};
};

struct Sta {
	bool used{false};
	Mac addr{};
	std::size_t bss{0U};        // index into Daemon::mBss
	int rssi{0};                // smoothed dBm, 0 = unknown
	int lowCount{0};
	std::uint64_t rxBytes{0U};
	std::uint64_t txBytes{0U};
	Millis bytesTs{0U};
	std::uint32_t tputKbps{0U};
	std::uint32_t inactiveMs{0U};
	std::uint32_t connectedS{0U};
	std::uint16_t txRate{0U};
	std::uint16_t rxRate{0U};
	std::uint8_t flags{0U};     // arcp::STA_F*
	bool bcnUnsupported{false};
	std::optional<rrm::BeaconMode> bcnMode{}; // mode hostapd accepted
	bool away{false};           // a peer reported it associated elsewhere
	Millis lastPollMs{0U};
	Millis nextSteerMs{0U};
	int steerFailures{0};
	std::array<Measurement, MAX_MEAS> meas{};
	std::size_t nMeas{0U};
};

// ---- remote side ----

struct RemoteBss {
	bool used{false};
	arcp::BssInfo info{};
	arcp::BssLoad load{};
	bool hasLoad{false};
	bool nrInstalled{false}; // pushed to the local hostapd neighbor DB
	Millis ts{0U};
};

struct Peer {
	bool used{false};
	Mac id{};
	FixedString<32U> name{};
	std::uint16_t flags{0U};   // arcp::AP_FLAG_*
	std::uint32_t bootId{0U};
	std::uint32_t seqHi{0U};  // highest msgId accepted
	std::uint64_t seqWin{0U}; // bit i = (seqHi - i) seen
	std::optional<std::size_t> port{}; // L2 port where reachable
	Mac l2addr{};              // Ethernet source address on that port
	Millis lastSeen{0U};
	std::array<RemoteBss, MAX_BSS> bss{};
	std::array<arcp::RfInfo, MAX_RADIO> rf{};
	std::size_t nRf{0U};
};

struct RemoteSta {
	bool used{false};
	Mac sta{};
	Mac ap{};
	Mac bssid{};
	std::int8_t rssi{0};
	std::uint8_t flags{0U};
	Millis ts{0U};
};

// ---- steering ----

enum class SteerState : std::uint8_t {
	IDLE,
	MEASURE,   // waiting for 11k beacon reports / air monitor reports
	NEGOTIATE, // waiting for STEER_RESP from the target AP
	BTM,       // waiting for the 11v BSS-TM-RESP
	ROAM,      // waiting for the STA to show up at the target
};

struct Candidate {
	Mac bssid{};
	Mac ap{};       // owner AP id (own ap_id for a local BSS)
	bool local{false};
	int score{0};
	std::uint8_t rcpi{255U};
	arcp::BssInfo info{};
};

struct SteerTxn {
	bool used{false};
	std::uint32_t id{0U};
	SteerState state{SteerState::IDLE};
	Mac sta{};
	std::size_t bss{0U}; // local source BSS index
	arcp::SteerReason reason{arcp::SteerReason::MANUAL};
	Millis deadline{0U};
	Millis started{0U};
	std::array<Candidate, MAX_CAND> cand{};
	std::size_t nCand{0U};
	std::size_t cur{MAX_CAND}; // candidate in negotiation / BTM; MAX_CAND = none
	bool bcnOutstanding{false}; // 11k request sent, no report or refusal yet
	bool amonPending{false};    // air monitor reports requested
	Mac forcedTarget{};         // manual steer target, zero = any
};

struct Reservation {
	bool used{false};
	Mac sta{};
	std::size_t bss{0U};
	std::uint32_t txn{0U};
	Mac srcAp{};
	Millis expiry{0U};
};

// Reliable unicast (ACK_REQ) bookkeeping
struct PendingTx {
	bool used{false};
	std::uint32_t msgId{0U};
	Mac peer{};
	int tries{0};
	Millis nextTry{0U};
	arcp::Message msg{};
};

// ---- air monitor ----

struct AmonPort {
	os::Fd fd{};
	bool sim{false};
	IfName name{};
};

// Samples of one watched STA on one frequency
struct AmonAcc {
	int freq{0};
	int sum{0};
	int n{0};
	Millis last{0U};
};

// A STA this AP's monitors listen for, on behalf of requester
struct AmonWatch {
	bool used{false};
	Mac sta{};
	Mac requester{}; // AP id; own id for local requests
	std::uint32_t txn{0U};
	Millis until{0U};
	std::array<AmonAcc, WATCH_FREQS> acc{};
};

std::string_view steerStateName(SteerState s) noexcept;

// Replay window: true if (bootId, msgId) is new for p, and records it.
bool acceptPeerSeq(Peer &p, std::uint32_t bootId, std::uint32_t msgId) noexcept;

class Daemon {
public:
	// Loads the configuration and opens every socket. False on fatal error.
	bool init(const char *cfgPath, bool debugAll) noexcept;
	void run() noexcept;
	void shutdown() noexcept;

	// ---- msg.cpp ----
	void beginMsg(arcp::Message &m, arcp::MsgType type, std::uint8_t flags) noexcept;
	void multicast(arcp::Message &m) noexcept;
	bool unicast(const Mac &peer, arcp::Message &m) noexcept;
	void sendHello() noexcept;
	void sendBssStatus() noexcept;
	void sendStaStatus() noexcept;
	void sendRfStatus() noexcept;
	void sendStaEvent(const Mac &sta, std::size_t bss, arcp::StaEventType ev,
			    std::uint16_t reason) noexcept;
	void sendBye() noexcept;
	void receiveMsg(std::size_t port) noexcept;
	void retransmit(Millis now) noexcept;

	// ---- peer.cpp ----
	Peer *findPeer(const Mac &id) noexcept;
	Peer *getPeer(const Mac &id) noexcept;
	RemoteBss *updatePeerBss(Peer &p, const arcp::BssInfo &bi) noexcept;
	static RemoteBss *findPeerBss(Peer &p, const Mac &bssid) noexcept;
	RemoteBss *lookupRemoteBss(const Mac &bssid, Peer **owner) noexcept;
	void expirePeers(Millis now) noexcept;
	void removePeer(Peer &p) noexcept;
	void updateRemoteSta(const Mac &ap, const arcp::StaEntry &e) noexcept;
	void forgetRemoteSta(const Mac &sta) noexcept;

	// ---- local.cpp ----
	void initLocal() noexcept;
	std::optional<std::size_t> findLocalBss(const Mac &bssid) const noexcept;
	Sta *findSta(const Mac &addr) noexcept;
	Sta *getSta(const Mac &addr, std::size_t bss) noexcept;
	void pollBss() noexcept;
	void pollStas() noexcept;
	void handleEvent(std::size_t bss, std::string_view ev) noexcept;
	void syncNeighbors() noexcept;
	void removeNeighbor(const arcp::BssInfo &bi) noexcept;
	arcp::StaEntry fillEntry(const Sta &s) const noexcept;

	// ---- steer.cpp ----
	void tickSteer(Millis now) noexcept;
	void runLbRound() noexcept;
	void onStaPoll(Sta &s) noexcept;
	bool startSteer(Sta &s, arcp::SteerReason reason, const Mac *target) noexcept;
	void onBeaconReport(Sta &s, const std::optional<rrm::BeaconReport> &r) noexcept;
	void onBtmResp(const hapd::BtmResp &r) noexcept;
	void onStaEvent(const Mac &ap, const arcp::StaEvent &e) noexcept;
	void onSteerReq(const Peer &from, const arcp::SteerReq &r) noexcept;
	void onSteerResp(const Peer &from, const arcp::SteerResp &r) noexcept;
	void onSteerResult(const Peer &from, const arcp::SteerResult &r) noexcept;
	void onPeerLost(const Peer &p) noexcept;
	void onLocalDisassoc(const Mac &sta) noexcept;
	void onMonitorResult(Sta &s) noexcept;
	int countReservations(std::size_t bss, Millis now) const noexcept;
	SteerTxn *findTxnBySta(const Mac &sta) noexcept;
	static void storeMeasurement(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
			       std::uint8_t opClass, std::uint8_t channel, Millis ts) noexcept;

	// ---- amon.cpp ----
	void initAmon() noexcept;
	void receiveAmon(std::size_t port) noexcept;
	void tickAmon(Millis now) noexcept;
	bool startAmonWatch(const Mac &sta, const Mac &requester, std::uint32_t txn,
			      int durationMs) noexcept;
	void onAmonReq(const Peer &from, const arcp::StaMonitorReq &r) noexcept;
	void onAmonResult(const Mac &from, const arcp::StaMonitorResult &r) noexcept;

	// ---- ctrl.cpp ----
	bool openCtrl() noexcept;
	void handleCtrl() noexcept;
	void closeCtrl() noexcept;

private:
	// msg.cpp helpers
	bool finish(arcp::Message &m) noexcept;
	void sendAck(const Mac &peer, std::uint32_t id) noexcept;
	void onAckReceived(const Mac &peer, std::uint32_t id) noexcept;
	void handleTlvs(Peer &p, ByteView frame, const arcp::Header &h) noexcept;
	void trace(std::string_view dir, ByteView frame, const Mac *peer, std::string_view port,
		   int tries) const noexcept;
	// local.cpp helpers
	void applyStaSample(Sta &s, const hapd::Sta &h) noexcept;
	void markBssDown(std::size_t i) noexcept;
	void refreshBss(std::size_t i) noexcept;
	void onHapdConnected(std::size_t bss, const Mac &addr) noexcept;
	void onHapdDisconnected(std::size_t bss, const Mac &addr) noexcept;
	void onHapdBeaconResp(std::string_view args) noexcept;
	void setNeighbor(LocalBss &lb, const arcp::BssInfo &bi) noexcept;
	// steer.cpp helpers
	void sendResult(const SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus) noexcept;
	void endTxn(SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btmStatus,
		     bool countFailure) noexcept;
	void failTxnNoCandidate(SteerTxn &t) noexcept;
	void sendBtm(SteerTxn &t) noexcept;
	void advance(SteerTxn &t) noexcept;
	void evaluate(SteerTxn &t) noexcept;
	void buildPool(SteerTxn &t) noexcept;
	bool requestBeacons(SteerTxn &t, Sta &s) noexcept;
	std::size_t requestMonitors(const SteerTxn &t, const Sta &s) noexcept;
	bool isMeasureComplete(const SteerTxn &t, const Sta &s) const noexcept;
	SteerTxn *findTxnById(std::uint32_t id) noexcept;
	// amon.cpp helpers
	void addAmonSample(const rrm::AirFrame &f) noexcept;
	void finishAmonWatch(AmonWatch &w, Millis now) noexcept;
	// ctrl.cpp helpers
	void runCtrlCommand(std::string_view req, FixedString<8192U> &out) noexcept;
	// main.cpp helpers
	bool setupTransport() noexcept;
	void runTimers() noexcept;

	Config mCfg{};
	L2 mL2{};
	Mac mApId{};
	std::uint32_t mBootId{0U};
	std::uint32_t mNextMsgId{0U};
	std::uint32_t mNextTxn{0U};

	std::array<LocalBss, MAX_BSS> mBss{};
	std::size_t mNBss{0U};
	Survey mSurvey{};

	std::array<Sta, MAX_STA> mSta{};
	std::array<Peer, MAX_PEERS> mPeers{};
	std::array<RemoteSta, MAX_REMOTE_STA> mRsta{};
	std::array<SteerTxn, MAX_TXN> mTxn{};
	std::array<Reservation, MAX_RESV> mResv{};
	std::array<PendingTx, MAX_PENDING> mPending{};

	std::array<AmonPort, MAX_MONITORS + 1U> mAmon{};
	std::size_t mNAmon{0U};
	std::array<AmonWatch, MAX_WATCH> mWatch{};

	os::Fd mCtrlFd{};

	Millis mNextHello{0U};
	Millis mNextBssStatus{0U};
	Millis mNextStaStatus{0U};
	Millis mNextRfStatus{0U};
	Millis mNextStaPoll{0U};
	Millis mNextLb{0U};
};

} // namespace donghoa

#endif
