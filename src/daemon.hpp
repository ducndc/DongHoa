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

constexpr std::size_t kMaxSta = 256U;
constexpr std::size_t kMaxPeers = 32U;
constexpr std::size_t kMaxRemoteSta = 512U;
constexpr std::size_t kMaxMeas = 16U;
constexpr std::size_t kMaxTxn = 16U;
constexpr std::size_t kMaxResv = 32U;
constexpr std::size_t kMaxPending = 32U;
constexpr std::size_t kMaxRadio = 4U;
constexpr std::size_t kMaxCand = 16U;
constexpr std::size_t kMaxWatch = 16U;
constexpr std::size_t kWatchFreqs = 4U;

// ---- local side ----

struct LocalBss {
	const BssCfg *cfg{nullptr};
	hapd::Conn hapd{};
	bool up{false};
	bool secured{false};
	int ifindex{0};
	arcp::BssInfo info{};
	arcp::BssLoad load{};
	int hapd_util{-1}; // chan_util_avg from hostapd STATUS, -1 if absent
	SurveySample survey_prev{};
	Millis next_reconnect_ms{0U};
};

// Where a STA's level towards one BSS comes from.
enum class MeasSrc : std::uint8_t { sta_11k, air_monitor };

struct Measurement {
	Mac bssid{};
	std::uint8_t rcpi{255U};
	std::uint8_t op_class{0U};
	std::uint8_t channel{0U};
	MeasSrc src{MeasSrc::sta_11k};
	Millis ts{0U};
};

struct Sta {
	bool used{false};
	Mac addr{};
	std::size_t bss{0U};        // index into Daemon::bss_
	int rssi{0};                // smoothed dBm, 0 = unknown
	int low_count{0};
	std::uint64_t rx_bytes{0U};
	std::uint64_t tx_bytes{0U};
	Millis bytes_ts{0U};
	std::uint32_t tput_kbps{0U};
	std::uint32_t inactive_ms{0U};
	std::uint32_t connected_s{0U};
	std::uint16_t tx_rate{0U};
	std::uint16_t rx_rate{0U};
	std::uint8_t flags{0U};     // arcp::kStaF*
	bool bcn_unsupported{false};
	std::optional<rrm::BeaconMode> bcn_mode{}; // mode hostapd accepted
	bool away{false};           // a peer reported it associated elsewhere
	Millis last_poll_ms{0U};
	Millis next_steer_ms{0U};
	int steer_failures{0};
	std::array<Measurement, kMaxMeas> meas{};
	std::size_t n_meas{0U};
};

// ---- remote side ----

struct RemoteBss {
	bool used{false};
	arcp::BssInfo info{};
	arcp::BssLoad load{};
	bool has_load{false};
	bool nr_installed{false}; // pushed to the local hostapd neighbor DB
	Millis ts{0U};
};

struct Peer {
	bool used{false};
	Mac id{};
	FixedString<32U> name{};
	std::uint16_t flags{0U};   // arcp::kApFlag*
	std::uint32_t boot_id{0U};
	std::uint32_t seq_hi{0U};  // highest msg_id accepted
	std::uint64_t seq_win{0U}; // bit i = (seq_hi - i) seen
	std::optional<std::size_t> port{}; // L2 port where reachable
	Mac l2addr{};              // Ethernet source address on that port
	Millis last_seen{0U};
	std::array<RemoteBss, kMaxBss> bss{};
	std::array<arcp::RfInfo, kMaxRadio> rf{};
	std::size_t n_rf{0U};
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
	idle,
	measure,   // waiting for 11k beacon reports / air monitor reports
	negotiate, // waiting for STEER_RESP from the target AP
	btm,       // waiting for the 11v BSS-TM-RESP
	roam,      // waiting for the STA to show up at the target
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
	SteerState state{SteerState::idle};
	Mac sta{};
	std::size_t bss{0U}; // local source BSS index
	arcp::SteerReason reason{arcp::SteerReason::manual};
	Millis deadline{0U};
	Millis started{0U};
	std::array<Candidate, kMaxCand> cand{};
	std::size_t n_cand{0U};
	std::size_t cur{kMaxCand}; // candidate in negotiation / BTM; kMaxCand = none
	bool bcn_outstanding{false}; // 11k request sent, no report or refusal yet
	bool amon_pending{false};    // air monitor reports requested
	Mac forced_target{};         // manual steer target, zero = any
};

struct Reservation {
	bool used{false};
	Mac sta{};
	std::size_t bss{0U};
	std::uint32_t txn{0U};
	Mac src_ap{};
	Millis expiry{0U};
};

// Reliable unicast (ACK_REQ) bookkeeping
struct PendingTx {
	bool used{false};
	std::uint32_t msg_id{0U};
	Mac peer{};
	int tries{0};
	Millis next_try{0U};
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
	std::array<AmonAcc, kWatchFreqs> acc{};
};

std::string_view steer_state_name(SteerState s) noexcept;

// Replay window: true if (boot_id, msg_id) is new for p, and records it.
bool peer_accept_seq(Peer &p, std::uint32_t boot_id, std::uint32_t msg_id) noexcept;

class Daemon {
public:
	// Loads the configuration and opens every socket. False on fatal error.
	bool init(const char *cfg_path, bool debug_all) noexcept;
	void run() noexcept;
	void shutdown() noexcept;

	// ---- msg.cpp ----
	void msg_begin(arcp::Message &m, arcp::MsgType type, std::uint8_t flags) noexcept;
	void multicast(arcp::Message &m) noexcept;
	bool unicast(const Mac &peer, arcp::Message &m) noexcept;
	void send_hello() noexcept;
	void send_bss_status() noexcept;
	void send_sta_status() noexcept;
	void send_rf_status() noexcept;
	void send_sta_event(const Mac &sta, std::size_t bss, arcp::StaEventType ev,
			    std::uint16_t reason) noexcept;
	void send_bye() noexcept;
	void msg_rx(std::size_t port) noexcept;
	void retransmit(Millis now) noexcept;

	// ---- peer.cpp ----
	Peer *peer_find(const Mac &id) noexcept;
	Peer *peer_get(const Mac &id) noexcept;
	RemoteBss *peer_bss_update(Peer &p, const arcp::BssInfo &bi) noexcept;
	static RemoteBss *peer_bss_find(Peer &p, const Mac &bssid) noexcept;
	RemoteBss *remote_bss_lookup(const Mac &bssid, Peer **owner) noexcept;
	void peer_expire(Millis now) noexcept;
	void peer_remove(Peer &p) noexcept;
	void remote_sta_update(const Mac &ap, const arcp::StaEntry &e) noexcept;
	void remote_sta_forget(const Mac &sta) noexcept;

	// ---- local.cpp ----
	void local_init() noexcept;
	std::optional<std::size_t> local_bss_by_bssid(const Mac &bssid) const noexcept;
	Sta *sta_find(const Mac &addr) noexcept;
	Sta *sta_get(const Mac &addr, std::size_t bss) noexcept;
	void poll_bss() noexcept;
	void poll_stas() noexcept;
	void handle_event(std::size_t bss, std::string_view ev) noexcept;
	void nr_sync() noexcept;
	void nr_remove(const arcp::BssInfo &bi) noexcept;
	arcp::StaEntry fill_entry(const Sta &s) const noexcept;

	// ---- steer.cpp ----
	void steer_tick(Millis now) noexcept;
	void steer_lb_round() noexcept;
	void steer_on_sta_poll(Sta &s) noexcept;
	bool steer_start(Sta &s, arcp::SteerReason reason, const Mac *target) noexcept;
	void steer_on_beacon_report(Sta &s, const std::optional<rrm::BeaconReport> &r) noexcept;
	void steer_on_btm_resp(const hapd::BtmResp &r) noexcept;
	void steer_on_sta_event(const Mac &ap, const arcp::StaEvent &e) noexcept;
	void steer_on_req(const Peer &from, const arcp::SteerReq &r) noexcept;
	void steer_on_resp(const Peer &from, const arcp::SteerResp &r) noexcept;
	void steer_on_result(const Peer &from, const arcp::SteerResult &r) noexcept;
	void steer_on_peer_lost(const Peer &p) noexcept;
	void steer_on_local_disassoc(const Mac &sta) noexcept;
	void steer_on_monitor_result(Sta &s) noexcept;
	int resv_count(std::size_t bss, Millis now) const noexcept;
	SteerTxn *txn_find_sta(const Mac &sta) noexcept;
	static void meas_store(Sta &s, const Mac &bssid, MeasSrc src, std::uint8_t rcpi,
			       std::uint8_t op_class, std::uint8_t channel, Millis ts) noexcept;

	// ---- amon.cpp ----
	void amon_init() noexcept;
	void amon_rx(std::size_t port) noexcept;
	void amon_tick(Millis now) noexcept;
	bool amon_watch_start(const Mac &sta, const Mac &requester, std::uint32_t txn,
			      int duration_ms) noexcept;
	void amon_on_req(const Peer &from, const arcp::StaMonitorReq &r) noexcept;
	void amon_on_result(const Mac &from, const arcp::StaMonitorResult &r) noexcept;

	// ---- ctrl.cpp ----
	bool ctrl_open() noexcept;
	void ctrl_handle() noexcept;
	void ctrl_close() noexcept;

private:
	// msg.cpp helpers
	bool finish(arcp::Message &m) noexcept;
	void send_ack(const Mac &peer, std::uint32_t id) noexcept;
	void ack_received(const Mac &peer, std::uint32_t id) noexcept;
	void rx_tlvs(Peer &p, ByteView frame, const arcp::Header &h) noexcept;
	void trace(std::string_view dir, ByteView frame, const Mac *peer, std::string_view port,
		   int tries) const noexcept;
	// local.cpp helpers
	void sta_apply_sample(Sta &s, const hapd::Sta &h) noexcept;
	void bss_mark_down(std::size_t i) noexcept;
	void bss_refresh(std::size_t i) noexcept;
	void ev_connected(std::size_t bss, const Mac &addr) noexcept;
	void ev_disconnected(std::size_t bss, const Mac &addr) noexcept;
	void ev_beacon_resp(std::string_view args) noexcept;
	void nr_set(LocalBss &lb, const arcp::BssInfo &bi) noexcept;
	// steer.cpp helpers
	void send_result(const SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btm_status) noexcept;
	void txn_end(SteerTxn &t, arcp::SteerOutcome outcome, std::uint8_t btm_status,
		     bool count_failure) noexcept;
	void txn_no_candidate(SteerTxn &t) noexcept;
	void send_btm(SteerTxn &t) noexcept;
	void advance(SteerTxn &t) noexcept;
	void evaluate(SteerTxn &t) noexcept;
	void build_pool(SteerTxn &t) noexcept;
	bool request_beacons(SteerTxn &t, Sta &s) noexcept;
	std::size_t request_monitors(const SteerTxn &t, const Sta &s) noexcept;
	bool measure_complete(const SteerTxn &t, const Sta &s) const noexcept;
	SteerTxn *txn_find_id(std::uint32_t id) noexcept;
	// amon.cpp helpers
	void amon_sample(const rrm::AirFrame &f) noexcept;
	void amon_finish(AmonWatch &w, Millis now) noexcept;
	// ctrl.cpp helpers
	void ctrl_command(std::string_view req, FixedString<8192U> &out) noexcept;
	// main.cpp helpers
	bool setup_transport() noexcept;
	void run_timers() noexcept;

	Config cfg_{};
	L2 l2_{};
	Mac ap_id_{};
	std::uint32_t boot_id_{0U};
	std::uint32_t next_msg_id_{0U};
	std::uint32_t next_txn_{0U};

	std::array<LocalBss, kMaxBss> bss_{};
	std::size_t n_bss_{0U};
	Survey survey_{};

	std::array<Sta, kMaxSta> sta_{};
	std::array<Peer, kMaxPeers> peers_{};
	std::array<RemoteSta, kMaxRemoteSta> rsta_{};
	std::array<SteerTxn, kMaxTxn> txn_{};
	std::array<Reservation, kMaxResv> resv_{};
	std::array<PendingTx, kMaxPending> pending_{};

	std::array<AmonPort, kMaxMonitors + 1U> amon_{};
	std::size_t n_amon_{0U};
	std::array<AmonWatch, kMaxWatch> watch_{};

	os::Fd ctrl_fd_{};

	Millis next_hello_{0U};
	Millis next_bss_status_{0U};
	Millis next_sta_status_{0U};
	Millis next_rf_status_{0U};
	Millis next_sta_poll_{0U};
	Millis next_lb_{0U};
};

} // namespace donghoa

#endif
