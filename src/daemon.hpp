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
#include "policy.hpp"
#include "proto.hpp"
#include "rrm.hpp"
#include "survey.hpp"
#include "trust.hpp"

namespace donghoa {

constexpr std::size_t MAX_STA = 256U;
constexpr std::size_t MAX_PEERS = 32U;
constexpr std::size_t MAX_CHALLENGES = 8U; // outstanding liveness challenges
constexpr std::size_t MAX_ENROLL_PENDING = 8U; // enrollment requests awaiting approval
constexpr std::size_t MAX_REMOTE_STA = 512U;
constexpr std::size_t MAX_MEAS = 16U;
constexpr std::size_t MAX_TXN = 16U;
constexpr std::size_t MAX_RESV = 32U;
constexpr std::size_t MAX_PENDING = 32U;
constexpr std::size_t MAX_RADIO = 4U;
constexpr std::size_t MAX_CAND = 16U;
constexpr std::size_t MAX_WATCH = 16U;
constexpr std::size_t WATCH_FREQS = 4U;
constexpr std::size_t MAX_DEV_CLASS = 512U;
constexpr std::size_t MAX_CAL = 64U; // BSSes with a learned uplink/downlink offset

// ---- local side ----

struct LocalBss {
	const BssCfg *cfg{nullptr};
	hapd::Conn hapd{};
	bool up{false};
	bool secured{false};
	int ifindex{0};
	std::optional<std::uint32_t> wiphy{}; // nl80211 radio, for the survey
	arcp::BssInfo info{};
	arcp::BssLoad load{};
	int hapdUtil{-1}; // chan_util_avg from hostapd STATUS, -1 if absent
	// Source of the last utilisation sample (STATUS util_src): the nl80211
	// survey can be open and healthy yet give no in-use channel (e.g.
	// mac80211_hwsim), and then hostapd's value is used.
	enum class UtilSrc : std::uint8_t { NONE, SURVEY, HOSTAPD };
	UtilSrc utilSrc{UtilSrc::NONE};
	// Per-STA metrics from nl80211 station dumps (asynchronous) instead of
	// a blocking hostapd STA-FIRST/NEXT round per poll. hostapd is still
	// listed in full every STA_RESYNC_MS (capabilities, missed events).
	Millis nextHapdListMs{0U};
	std::uint32_t nlGenSeen{0U};  // station dump generation processed
	std::uint32_t nlGenAsked{0U}; // generation when the last dump was asked
	bool nlAsked{false};
	int nlMissed{0};              // polls whose dump did not complete
	bool nlActive{false};         // last poll used the station dump
	// Load-balancing feedback (runLbRound): the last offload from here.
	bool lbCheck{false};      // a move to judge
	Mac lbSta{};
	Millis lbStartMs{0U};
	int lbUtilBefore{-1};     // % when it started
	bool lbByUtil{false};     // triggered by utilisation (not by STA count)
	int lbFutile{0};          // moves in a row that did not lower utilisation
	Millis lbHoldUntil{0U};   // offloading paused until then
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
	std::int8_t ulDbm{0}; // AIR_MONITOR: the uplink level as measured (before the offset)
	bool paired{false};   // already used as an uplink/downlink calibration sample
};

// One link of an MLD STA: the local BSS (an AP MLD link) it is on.
struct StaLink {
	bool used{false};
	std::size_t bss{0U};   // index into Daemon::mBss
	int rssi{0};           // smoothed dBm on this link, 0 = unknown
	int lowCount{0};       // consecutive samples below rssi_low on this link
	Millis lastPollMs{0U};
};

constexpr std::size_t MAX_STA_LINKS = 3U;

struct Sta {
	bool used{false};
	Mac addr{};
	std::size_t bss{0U};        // index into Daemon::mBss (MLD STA: its strongest link)
	int rssi{0};                // smoothed dBm, 0 = unknown (MLD STA: best link)
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
	std::uint8_t bandsAdv{0U};  // rrm::BANDS_* from supp_op_classes, 0 = unknown
	std::uint8_t bandsSeen{0U}; // rrm::BANDS_* it was associated or measured on
	std::uint8_t bandsBlocked{0U}; // rrm::BANDS_* it cannot join (6 GHz: WPA2-PSK AKM)
	int bandEmpty{0};           // band steers in a row with no candidate measured
	Millis nextBandMs{0U};      // band steering backoff
	// First peer slot buildPool visits. When more BSSes qualify than fit
	// the pool, it moves past the peers that made it in, so the next steer
	// of this STA measures the others (their levels then rank them).
	std::size_t poolStart{0U};
	std::array<Measurement, MAX_MEAS> meas{};
	std::size_t nMeas{0U};
	// Wi-Fi 7 MLO: an MLD STA is one entry (addr = MLD address) with one
	// StaLink per AP MLD link it is seen on. Non-MLD STAs leave these unused.
	bool mld{false};
	int maxSimulLinks{-1};
	std::array<StaLink, MAX_STA_LINKS> links{};
	// Low-power (IoT) classification (devclass.cpp)
	policy::TrafficStats traffic{};
	int lpScore{0};             // theta
	int lpS100{policy::LP_NO_EVIDENCE}; // last behaviour score S x 100
	std::uint32_t lpSamples{0U}; // evidence behind lpScore (carried across APs)
	bool lowPower{false};
	std::uint8_t phyCaps{0U}; // arcp::CAP_VHT/CAP_HE/CAP_EHT it negotiated
	bool capsKnown{false}; // capabilities read from hostapd at least once
	// Learned roaming threshold (dBm, 0 = none: rssi_low applies), the
	// outcomes behind it (its version when shared) and the last change.
	int roamThr{0};
	std::uint32_t roamEvents{0U};
	Millis roamThrTs{0U};
	// Q-learning (when to roam): trend input and the pending WAIT decision.
	int rssiPrev{0};          // smoothed RSSI before the last fresh sample
	bool sampleFresh{false};  // a fresh sample since the last decision
	bool rlWaiting{false};    // last decision was WAIT in rlState, reward pending
	std::size_t rlState{0U};
};

// Device class of a STA, kept by every AP so that it follows the STA
// between APs and survives an AP restart (peers resend it).
struct DevClassRec {
	bool used{false};
	Mac sta{};
	bool lowPower{false};
	int score{0};
	std::uint32_t samples{0U};
	Mac source{}; // AP that classified it
	Millis ts{0U};
	// Normal now, low-power before: a peer may still hold the old flag, so
	// syncDevClass sends this record too (other normal records it skips).
	bool corrected{false};
	// The STA's learned roaming threshold, shared the same way (STA_ROAM).
	int roamThr{0};
	std::uint32_t roamEvents{0U};
	// Left this AP by itself (no steer of ours) at this RSSI, at leftTs:
	// a peer's association report soon after is an own roam.
	int leftRssi{0};
	Millis leftTs{0U};
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
	int poolRank{0};           // policy::candidatePoolRank
	std::size_t banditCtx{0U}; // policy::banditCtx of this candidate
	int banditPrior{0};        // policy::banditPriorDb (dB)
	std::size_t poolPos{0U};   // peer visit order in buildPool (rotation)
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
	// The STA sends its reports in a burst once it has measured: when none
	// came for bcnQuietMs after the last one, the 11k measurement is over
	// (it never reports a BSS it does not hear, so waiting for every
	// candidate would always run to beacon_req_timeout_ms).
	Millis bcnQuietMs{0U};
	Millis bcnQuietUntil{0U}; // 0: no report yet
	bool amonPending{false};    // air monitor reports requested
	// APs whose STA_MONITOR_STATUS MEASURE still waits for (this AP's own
	// id for its local watch); MEASURE may end when the list is empty.
	std::array<Mac, MAX_PEERS + 1U> monWait{};
	std::size_t nMonWait{0U};
	bool anyMeasured{false};    // some candidate had a level at evaluate()
	bool staMld{false};         // MLD STA (kept: its entry may go before the outcome)
	Mac forcedTarget{};         // manual steer target, zero = any
	int startRssi{0};           // the STA's RSSI when the steer started
	bool rlArmed{false};        // started by a recorded RL decision (STEER in rlState)
	std::size_t rlState{0U};
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
	std::uint32_t vendorBss{0U}; // local BSSes measuring with the driver API (bit = index)
	bool vendorFailed{false};    // the driver API returned an error
};

std::string_view steerStateName(SteerState s) noexcept;
// Behaviour score S x 100 as "1.25", "inf" or "-" (no evidence).
void formatScore(FixedString<16U> &out, int s100) noexcept;
// Offset x 16 as "+8.0" / "-3.5" (dB).
void formatOffset16(FixedString<16U> &out, int offset16) noexcept;

// Learned uplink -> downlink offset of one BSS (amon.cpp).
struct UlDlCal {
	bool used{false};
	Mac bssid{};
	policy::UlDlOffset off{};
	Millis ts{0U}; // last sample
};

// Liveness CHALLENGE sent to an origin whose current boot is not verified
// (an unknown origin, or a known one with another boot_id).
struct Challenge {
	bool used{false};
	Mac origin{};
	arcp::Nonce nonce{};
	Millis sent{0U};
};

// An AP asking to be enrolled (ENROLL_REQ), until approved or quiet.
struct EnrollPending {
	bool used{false};
	Mac apId{};
	ed25519::PublicKey pub{};
	bool keyChange{false}; // the trust table has another key for this ap_id
	Millis first{0U};
	Millis last{0U};
};

// Replay window: true if (bootId, msgId) is new for p's verified boot, and
// records it.
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
	const RemoteSta *findRemoteSta(const Mac &sta) const noexcept;
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
	// New nl80211 station dumps: apply them (main loop, after the survey
	// socket was read).
	void processStationDumps() noexcept;
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
	static Measurement &storeMeasurement(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
					     std::uint8_t opClass, std::uint8_t channel, Millis ts) noexcept;
	// Uplink/downlink calibration: a STA has both an 11k and an AP-side level
	// of bssid, close in time and not used yet -> one sample (amon.cpp).
	void pairUlDl(Sta &s, const Mac &bssid) noexcept;
	const UlDlCal *findCal(const Mac &bssid) const noexcept;

	// ---- amon.cpp ----
	void initAmon() noexcept;
	void receiveAmon(std::size_t port) noexcept;
	void tickAmon(Millis now) noexcept;
	// MEASURED: the watch started; otherwise why this AP cannot measure.
	arcp::MonitorStatus startAmonWatch(const Mac &sta, const Mac &requester, std::uint32_t txn,
					   int durationMs,
					   std::uint8_t opClass, std::uint8_t channel) noexcept;
	// Monitor interface or driver RSSI API present (AP_FLAG_AIR_MONITOR).
	bool canMeasureStas() const noexcept;
	void onAmonReq(const Peer &from, const arcp::StaMonitorReq &r) noexcept;
	void onAmonResult(const Mac &from, const arcp::StaMonitorResult &r) noexcept;
	void onAmonStatus(const Mac &from, const arcp::StaMonitorStatus &r) noexcept;

	// ---- devclass.cpp ----
	// One poll's traffic of a local STA: up/down bytes over dtMs.
	void sampleTraffic(Sta &s, std::uint64_t upBytes, std::uint64_t downBytes, Millis dtMs) noexcept;
	// Local STA entry created / about to be dropped.
	void restoreDevClass(Sta &s) noexcept;
	void saveDevClass(const Sta &s) noexcept;
	const DevClassRec *findDevClass(const Mac &sta) const noexcept;
	void onStaClass(const Peer &from, const arcp::StaClass &c) noexcept;
	void onStaRoam(const Peer &from, const arcp::StaRoam &r) noexcept;
	// A roaming-threshold event of a local STA: store, share on change.
	void noteRoamThr(Sta &s, int thresholdDbm, std::string_view why) noexcept;
	// Q-learning of when to roam (steer.cpp).
	policy::RlMode rlMode() const noexcept;
	void rlLearn(const Mac &sta, std::size_t s, policy::RlAction a, int rewardDb, bool terminal,
		     std::size_t next) noexcept;
	void rlEndWait(Sta &s, int rewardDb, std::string_view why) noexcept; // terminal end of a pending WAIT
	std::uint32_t nextRandom() noexcept;
	policy::RlMode banditMode() const noexcept;
	void banditCredit(const Candidate &c, int rewardDb, std::string_view why) noexcept;
	void banditWatchPingPong(const SteerTxn &t) noexcept;
	void banditCheckPingPong(std::size_t bss, const Mac &sta) noexcept;
	// Own roam of a STA that already left: from its record (leftRssi).
	void noteOwnRoamFromRecord(const Mac &sta) noexcept;
	void shareRoamThr(const Mac &sta, int oldDbm, int newDbm, std::uint32_t events,
			  std::string_view why) noexcept;
	// A peer reports sta associated to it: hand it what we know.
	void onPeerStaAssoc(const Mac &ap, const Mac &sta) noexcept;
	// A peer appeared or restarted: send it every low-power record.
	void syncDevClass(const Mac &peer) noexcept;

	// ---- ctrl.cpp ----
	bool openCtrl() noexcept;
	void handleCtrl() noexcept;
	void closeCtrl() noexcept;

private:
	// msg.cpp helpers
	bool finish(arcp::Message &m) noexcept;
	void sendAck(const Mac &peer, std::uint32_t id) noexcept;
	// With peer_key configured: the origin is trusted and signed the message.
	bool isSignatureOk(ByteView frame, const arcp::Header &h) noexcept;
	// Key the origin must sign with: enrollment trust table, else peer_key.
	const ed25519::PublicKey *trustedKeyFor(const Mac &origin) const noexcept;
	// Automatic enrollment (enroll.cpp)
	bool initEnroll() noexcept;
	void tickEnroll(Millis now) noexcept;
	void saveTrust() noexcept;
	void sendTrust() noexcept;
	void sendWelcome(const Mac &apId) noexcept;
	void onUntrusted(ByteView frame, const arcp::Header &h) noexcept;
	void onTrust(ByteView frame, const arcp::Header &h) noexcept;
	void onTrustRecord(const arcp::TrustRecord &r, bool &changed) noexcept;
	void afterTrustChange() noexcept;
	void cmdEnroll(FixedString<8192U> &o, std::string_view args) noexcept;
	// Liveness check (msg.cpp): a message of an unverified (origin, boot_id)
	// is answered with a CHALLENGE; only a RESPONSE carrying its nonce, from
	// the boot it names, adopts that boot. Replayed frames cannot answer.
	void sendDirect(std::size_t port, const Mac &dst, arcp::Message &m) noexcept;
	void sendChallenge(std::size_t port, const Mac &dst, const Mac &origin) noexcept;
	void answerChallenge(std::size_t port, const Mac &dst, ByteView frame,
			     const arcp::Header &h) noexcept;
	bool isResponseValid(ByteView frame, const arcp::Header &h) noexcept;
	void onAckReceived(const Mac &peer, std::uint32_t id) noexcept;
	void handleTlvs(Peer &p, ByteView frame, const arcp::Header &h) noexcept;
	void trace(std::string_view dir, ByteView frame, const Mac *peer, std::string_view port,
		   int tries) const noexcept;
	// local.cpp helpers
	void applyStaSample(Sta &s, const hapd::Sta &h, std::size_t bss) noexcept;
	// One poll's signal / traffic of a non-MLD STA (hostapd or nl80211).
	void applyStaSignal(Sta &s, int signal, std::uint32_t inactiveMs) noexcept;
	void applyStaTraffic(Sta &s, std::uint64_t rxBytes, std::uint64_t txBytes, std::uint32_t inactiveMs,
			     std::uint32_t connectedS, std::uint16_t rxRate, std::uint16_t txRate,
			     Millis now) noexcept;
	void listStasFromHapd(std::size_t bss, Millis start) noexcept;
	void pruneUnlisted(std::size_t bss, Millis start) noexcept;
	void updateStaLink(Sta &s, const hapd::Sta &h, std::size_t bss, Millis now) noexcept;
	// Drops the links of s on bss not polled since start; false when the
	// STA has no link left.
	bool pruneStaLinks(Sta &s, std::size_t bss, Millis start) noexcept;
	bool isSameApMld(std::size_t a, std::size_t b) const noexcept;
	// BSS info of a local or remote BSSID, nullptr if unknown.
	const arcp::BssInfo *findBssInfo(const Mac &bssid) noexcept;
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
	std::size_t requestMonitors(SteerTxn &t, const Sta &s) noexcept;
	bool isMeasureComplete(const SteerTxn &t, const Sta &s) const noexcept;
	SteerTxn *findTxnById(std::uint32_t id) noexcept;
	// amon.cpp helpers
	void addAmonSample(const rrm::AirFrame &f) noexcept;
	void finishAmonWatch(AmonWatch &w, Millis now) noexcept;
	// devclass.cpp helpers
	DevClassRec &storeDevClass(const Mac &sta, bool lowPower, int score, std::uint32_t samples,
				   const Mac &source) noexcept;
	void sendStaClass(const Mac &peer, const DevClassRec &r) noexcept;
	void sendStaRoam(const Mac &peer, const DevClassRec &r) noexcept;
	DevClassRec &devClassSlot(const Mac &sta) noexcept;
	void storeRoamRec(const Mac &sta, int thresholdDbm, std::uint32_t events, const Mac &source) noexcept;
	// ctrl.cpp helpers
	void runCtrlCommand(std::string_view req, FixedString<8192U> &out) noexcept;
	void cmdRl(FixedString<8192U> &o, std::string_view args) noexcept;
	void cmdDropRx(FixedString<8192U> &o, std::string_view args) noexcept;
	void cmdBandit(FixedString<8192U> &o, std::string_view args) noexcept;
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
	std::array<DevClassRec, MAX_DEV_CLASS> mDevClass{};
	std::array<UlDlCal, MAX_CAL> mCal{};
	policy::RlTable mRl{};
	struct RlStats {
		std::uint32_t decisions{0U};
		std::uint32_t steers{0U};
		std::uint32_t explored{0U};
		std::uint32_t updates{0U};
	};
	RlStats mRlStats{};
	int mRlModeOverride{-1};       // RL mode <n> at run time; -1: config
	bool mRlNextArmed{false};      // handed to the transaction startSteer creates
	std::size_t mRlNextState{0U};
	std::uint32_t mRng{0x9e3779b9U};
	// Fault injection (DROPRX): drop the next mDropCount received messages
	// of type mDropType, before ACK and processing, as if lost.
	// Contextual bandit for the target choice (steer.cpp).
	policy::BanditTable mBandit{};
	struct BanditStats {
		std::uint32_t reordered{0U};
		std::uint32_t explored{0U};
		std::uint32_t updates{0U};
	};
	BanditStats mBanditStats{};
	int mBanditModeOverride{-1};
	struct PingPongWatch {
		bool used{false};
		Mac sta{};
		std::size_t srcBss{0U};   // local BSS the STA was steered away from
		std::size_t ctx{0U};      // context of the successful target
		Millis ts{0U};
	};
	std::array<PingPongWatch, 32U> mPingPong{};
	std::uint8_t mDropType{0U};
	std::uint32_t mDropCount{0U};
	bool mRlInit{false};

	os::Fd mCtrlFd{};

	std::array<Challenge, MAX_CHALLENGES> mChal{};
	trust::Table mTrust{};
	std::array<EnrollPending, MAX_ENROLL_PENDING> mEnrollPend{};
	Millis mNextEnrollReq{0U};
	Millis mNextTrustSync{0U};
	Millis mLastResync{0U}; // last HELLO/BSS_STATUS sent early for a CHALLENGE

	Millis mNextHello{0U};
	Millis mNextBssStatus{0U};
	Millis mNextStaStatus{0U};
	Millis mNextRfStatus{0U};
	Millis mNextStaPoll{0U};
	Millis mNextLb{0U};
};

} // namespace donghoa

#endif
