# DongHoa — Software Requirements Specification

| | |
|---|---|
| Product | DongHoa: daemon `donghoa` and CLI `donghoa_cli` |
| Version covered | 1.0 (OpenWrt package `donghoa-1.0-r9`, C++17 implementation) |
| Document version | 1.4, 2026-11-01 (history in Appendix B) |
| Companion documents | `docs/SDD.md` (design), `docs/PROTOCOL.md` (wire format), `docs/ARCHITECTURE.md` (overview), `openwrt/README.md` (deployment) |

## 1. Introduction

### 1.1 Purpose

This document states what `donghoa` must do and under which constraints. It is
the reference for design (`docs/SDD.md`), for testing, and for deciding
whether a change is in scope. Every requirement has an identifier, so tests
and design sections can be traced back to it (§7).

### 1.2 Scope

`donghoa` runs on every access point (AP) of one Wi-Fi ESS, beside hostapd. The
APs coordinate over a custom Layer-2 protocol, ARCP, to provide:

- assisted roaming of weak-signal stations (STAs),
- band steering from 2.4 GHz to 5/6 GHz,
- load balancing between BSSes,
- automatic population of the 802.11k neighbor database.

STAs are moved only with standard mechanisms: an 802.11k Beacon Request to
measure, an 802.11v BSS Transition Management (BTM) Request to move, and
802.11r Fast BSS Transition to (re)associate. IEEE 1905.1 / EasyMesh is out
of scope by requirement.

### 1.3 Definitions and acronyms

| Term | Meaning |
|---|---|
| AP | Access point: one host running hostapd and `donghoa`. It may serve several BSSes. |
| ARCP | AP Roaming Coordination Protocol: the Layer-2 protocol in `docs/PROTOCOL.md`. |
| BSS / BSSID | One hostapd interface (SSID on one radio) and its MAC address. |
| ESS | All BSSes with the same SSID. Steering never leaves the ESS. |
| Peer | Another AP running `donghoa` and reachable over ARCP. |
| Source AP / target AP | The AP the STA is leaving, and the AP that owns the candidate BSS. |
| Steering transaction | One attempt to move one STA (§4.6). |
| Reservation | A capacity slot the target AP holds for an expected STA. |
| BTM | 802.11v BSS Transition Management. |
| FT | 802.11r Fast BSS Transition. MDID: its Mobility Domain identifier. |
| RCPI | Received Channel Power Indicator; dBm = RCPI / 2 − 110. |
| Utilisation | Share of time the channel is busy, 0–254 on the wire (255 = unknown). |
| hwsim | The Linux `mac80211_hwsim` virtual radio driver, used for testing. |

### 1.4 Requirement conventions

- **shall** marks a mandatory requirement, **should** a recommended one.
- Identifiers: `FR-<area>-<n>` for functional requirements, `NFR-<area>-<n>`
  for non-functional ones, `IR-<n>` for interfaces and `C-<n>` for
  constraints.
- Verification methods: **T-U** unit test (`make test`), **T-I** integration
  test scenario *n* (`make itest`, "PASS n"), **T-O** OpenWrt QEMU procedure
  (`openwrt/README.md`), **I** inspection, **A** analysis.
- Parameter names in `code font` are configuration keys (Appendix A), and
  their defaults are given where it matters.

## 2. Overall description

### 2.1 Product perspective

```
             ARCP over Ethernet (EtherType 0x88B5), wired or Wi-Fi backhaul
   +-----------------------------+                    +-----------------------------+
   | AP 1                        |<------------------>| AP 2                        |
   |  donghoa <-ctrl-> hostapd   |                    |  donghoa <-ctrl-> hostapd   |
   |  |  |                |      |                    |                             |
   |  |  +--> nl80211 <---+      |                    |                             |
   |  donghoa_cli (operator)     |                    |                             |
   +-------------|---------------+                    +-----------------------------+
                 | 802.11k/v/r (frames sent by hostapd on donghoa's request)
               STA
```

`donghoa` is a user-space daemon with no kernel component. It never sends
802.11 frames itself. It asks hostapd to send them through hostapd's control
interface, and it learns about STAs from hostapd's output and events.

### 2.2 Product functions (summary)

1. Discover the other APs and exchange BSS, load, STA and RF state with them.
2. Keep each local hostapd's 802.11k neighbor database in step with the ESS.
3. Monitor local BSSes and associated STAs.
4. Decide when a STA should move (RSSI, band, load, or an operator command)
   and run a steering transaction that ends in a measured, admitted, standard
   transition.
5. Admit or refuse incoming STAs on the target side, holding a reservation.
6. Report status to the operator and accept manual steering commands.

### 2.3 User classes

| User | Needs |
|---|---|
| Network operator / installer | Configures the daemon, checks status with `donghoa_cli`, reads the logs. |
| Firmware integrator | Packages the daemon for an AP image (OpenWrt or other Linux) and configures hostapd. |
| Developer / tester | Runs unit and integration tests without root, and the QEMU OpenWrt testbed. |
| STA (indirect) | Must see only standard 802.11k/v/r behaviour. |

### 2.4 Operating environment

- Linux AP with hostapd that has the control interface plus 802.11k (RRM),
  802.11v (WNM) and 802.11r support. Verified with OpenWrt 25.12.6,
  `wpad-mbedtls` 2025.08.26.
- Any netdev that carries Ethernet frames between APs: Ethernet, a bridge,
  4-address/WDS or 802.11s Wi-Fi backhaul.
- C library: glibc or musl. Architectures: any that the toolchain supports.
- Privileges: `CAP_NET_RAW` for raw sockets. Root is needed when hostapd runs
  as another user (§3.3, IR-2).

### 2.5 Constraints

| ID | Constraint |
|---|---|
| C-1 | IEEE 1905.1 / EasyMesh shall not be used. |
| C-2 | ARCP shall not carry 802.11r key material. Key distribution is hostapd's job (RRB or local FT-PSK keys). |
| C-3 | Implementation language C++17 without exceptions or RTTI (`-fno-exceptions -fno-rtti`), following `docs/CODING_CONVENTION.md` (MISRA C++:2023 based). It shall build warning-free with the strict flags of the Makefile (`-Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast -Wuseless-cast -Wcast-qual -Wpedantic`). |
| C-4 | No runtime dependency beyond libc and kernel headers (in particular no libnl, and no libstdc++.so: checked by `make check-deps`). |
| C-5 | No dynamic memory allocation after start-up. All state lives in fixed-size tables. |
| C-6 | Single-threaded, event-driven design. |
| C-7 | EtherType 0x88B5 (IEEE 802 Local Experimental) for development. A product shall replace it with an assigned EtherType. |

### 2.6 Assumptions and dependencies

| ID | Assumption |
|---|---|
| AS-1 | Target STAs support 802.11k beacon reports, 802.11v BTM and 802.11r. Without k, automatic steering needs air monitors on the candidate APs (§4.11); otherwise it only works manually (FR-STR-6). Without v, no automatic steering is attempted. |
| AS-2 | All APs of an ESS share the same SSID, FT mobility domain and ARCP key. |
| AS-3 | hostapd's control-interface output formats are those listed in `docs/ARCHITECTURE.md`, "Assumptions to verify". They were verified on OpenWrt 25.12.6. |
| AS-4 | The backhaul forwards Ethernet multicast to every AP of the ESS. |
| AS-5 | AP clocks need not be synchronised. Only local monotonic time is used. |

## 3. External interface requirements

### 3.1 Operator interfaces

| ID | Requirement | Verif. |
|---|---|---|
| IR-1 | **Configuration file.** The daemon shall read one text file given with `-c`, one `key value` per line, with `#` comments. An unknown key or an invalid value shall stop start-up with an error that gives the line number. At least one `bss` line and one transport (`iface` or `sim_port`) shall be required. | T-U `test_config`, I |
| IR-3 | **Control socket.** When `ctrl_socket` is set, the daemon shall answer UNIX-datagram requests: `PING`, `STATUS`, `PEERS`, `STAS`, `STEERS`, `STEER <sta> [<bssid>]`, `MONITOR <sta> [<ms>]` (measure a STA with this AP's air monitors; result in the log) and `LOG [<level> [<module>...]]` (show or set log levels). Each reply shall be a single datagram of at most 8 KiB. Unknown commands shall get `UNKNOWN COMMAND`. | T-I 1,5, T-O |
| IR-4 | **CLI.** `donghoa_cli <socket> <command…>` shall send one request, print the reply, and fail if no reply arrives within 2 s. | T-I, T-O |
| IR-5 | **Logging.** Each log line shall carry the monotonic time, a level tag (`ERR`, `WRN`, `INF`, `DBG`) and the module (`main`, `l2`, `msg`, `peer`, `hapd`, `local`, `steer`, `policy`, `amon`, `survey`, `ctrl`, `config`, `rrm`). Each module shall have its own level: info by default, set by `log_level` and `log_debug <modules>` in the configuration, by `-d` (all modules at debug), and at run time by the control command `LOG [<level> [<module>...]]` without a restart. Output shall go to stderr, or with `-s` to syslog (facility daemon) with priorities matching the levels. At debug level, module `msg` shall trace every ARCP frame sent, retransmitted and received (type, id, peer, port, flags, TLV list), and module `rrm` shall dump every 802.11k/v command sent to hostapd (`REQ_BEACON`, `BSS_TM_REQ`, `SET_NEIGHBOR`, `REMOVE_NEIGHBOR`) with its reply, and every 11k/v event (`BEACON-RESP-RX`, `BEACON-REQ-TX-STATUS`, `BSS-TM-RESP`, `BSS-TM-QUERY`), raw and decoded. | T-U `test_log`, `test_rrm`, T-I 1, 3, T-O |

### 3.2 Software interfaces

| ID | Requirement | Verif. |
|---|---|---|
| IR-2 | **hostapd control interface.** For each configured BSS, the daemon shall open the control socket `<hostapd_ctrl_dir>/<ifname>` and subscribe to events (`ATTACH`). It shall use only the commands and events listed in `docs/ARCHITECTURE.md`. When hostapd runs as a different user, the daemon's reply sockets shall be made writable by that user. | T-I, T-O |
| IR-6 | **nl80211.** The daemon shall read channel busy time and noise with `NL80211_CMD_GET_SURVEY` over raw generic netlink. When nl80211 is unavailable, it shall fall back to hostapd's `chan_util_avg`. | I, T-O |
| IR-7 | **Service manager.** On OpenWrt, a procd init script shall start the daemon after wireless start-up, respawn it on crash, and forward stderr to the system log. `/etc/donghoa.conf` shall be a conffile. | T-O |
| IR-13 | **Monitor interfaces.** For each `air_monitor <ifname>`, the daemon shall read radiotap frames from that monitor interface with an `AF_PACKET` socket and a kernel filter that passes only probe requests and data frames with ToDS and not FromDS. A missing or unusable interface shall be logged and shall not stop the daemon. For tests, `air_monitor_sim <port>` shall accept the same frames over UDP on loopback. | T-U `test_air_monitor`, T-I 5, T-O |
| IR-12 | **BSSes from UCI (OpenWrt).** When `/etc/donghoa.conf` has no `bss` line, the init script shall add one for every AP interface of `/etc/config/wireless` that is up. Each line takes the runtime name reported by netifd, and the `mobility_domain`, `max_num_sta` (`maxassoc`) and `ft_over_ds` of the hostapd configuration generated from UCI. It shall wait (≤ 15 s) until every such interface has a hostapd control socket, and it shall regenerate the lines and restart the daemon when the wireless configuration changes through uci/LuCI. Explicit `bss` lines shall be used unchanged. | T-O |

### 3.3 Communication interfaces

| ID | Requirement | Verif. |
|---|---|---|
| IR-8 | ARCP shall be carried directly in Ethernet II frames: EtherType 0x88B5, multicast group `03:41:52:43:50:00`, payload ≤ 1400 bytes, no IP. The wire format is normative in `docs/PROTOCOL.md`, with `src/proto.hpp` as the source of the numbers. | T-U `test_proto_*`, T-I 1 |
| IR-9 | All ARCP fields shall be big-endian. 802.11 structures handed to hostapd (Neighbor Report BSSID Information, Beacon Request duration) shall be little-endian as 802.11 requires. | T-U `test_rrm` |
| IR-10 | Decoders shall ignore unknown TLV types and accept TLVs longer than the version they understand (forward compatibility). | I |
| IR-11 | For root-free testing, a "sim" transport shall carry the identical Ethernet frames over UDP on loopback (`sim_port`, `sim_peer`). | T-I 1–5 |

## 4. Functional requirements

### 4.1 Discovery and peer management (DSC)

| ID | Requirement | Verif. |
|---|---|---|
| FR-DSC-1 | The daemon shall multicast HELLO (AP name plus the BSS_INFO of every BSS that is up) on every configured port every `hello_interval_ms` (2000). | T-I 1 |
| FR-DSC-2 | Every AP shall be identified by `ap_id` (default: the MAC of the first `iface`), independent of the egress port. Messages carrying its own `ap_id` as origin shall be ignored. | I |
| FR-DSC-3 | On the first message from an unknown AP, the daemon shall create a peer entry and send its own HELLO and BSS_STATUS at once. | I, T-I 1 |
| FR-DSC-4 | A peer shall be removed when nothing valid has arrived from it for `peer_timeout_ms` (7000), or when it sends BYE. | T-I 5 (BYE) |
| FR-DSC-5 | On graceful shutdown (SIGINT/SIGTERM), the daemon shall multicast BYE. | T-I 5 |
| FR-DSC-6 | A change of a peer's `boot_id` shall be treated as a restart: its sequence state is reset and the event is logged. | I |
| FR-DSC-7 | When a peer is removed, the daemon shall drop the peer's BSSes, remote STA entries and reservations, and move on from steering transactions negotiating with it. | T-I 5 |

### 4.2 State exchange (STE)

| ID | Requirement | Verif. |
|---|---|---|
| FR-STE-1 | The daemon shall multicast BSS_STATUS (BSS_INFO + BSS_LOAD for every BSS that is up) every `bss_status_interval_ms` (5000). BSS_LOAD shall carry the STA count, `max_sta`, utilisation, noise, TX power and an "accepting steer-in" flag computed by the admission policy. | T-I 1 |
| FR-STE-2 | The daemon shall multicast STA_STATUS with one STA_ENTRY per locally associated STA every `sta_status_interval_ms` (10000), split over several messages when needed. A STA known to have moved to another AP shall not be reported. | T-U `test_proto_overflow`, I |
| FR-STE-3 | The daemon shall multicast RF_STATUS with one RF_INFO per distinct operating frequency every `rf_status_interval_ms` (10000). | T-O |
| FR-STE-4 | On every local association and disassociation, the daemon shall multicast STA_EVENT at once. | T-I 3 |
| FR-STE-5 | A remote BSS not re-advertised for 3 × `bss_status_interval_ms` + `hello_interval_ms` shall be removed. A remote STA entry not refreshed for 3 × `sta_status_interval_ms` shall be removed. | I |

### 4.3 802.11k neighbor database (NBR)

| ID | Requirement | Verif. |
|---|---|---|
| FR-NBR-1 | Each local BSS shall get, in hostapd's neighbor database, every other BSS of the same ESS: local siblings and peers' BSSes (`SET_NEIGHBOR`). | T-I 1, T-O |
| FR-NBR-2 | The Neighbor Report's Mobility Domain bit shall be set only when the neighbor's MDID equals the receiving BSS's MDID. | T-U `test_rrm`, T-I 1, T-O |
| FR-NBR-3 | An entry shall be reinstalled when the neighbor's advertised information changes. It shall be removed (`REMOVE_NEIGHBOR`) when the BSS or its peer disappears. | T-I 5 |

### 4.4 Local monitoring (MON)

| ID | Requirement | Verif. |
|---|---|---|
| FR-MON-1 | Every `sta_poll_interval_ms` (1000), the daemon shall refresh each BSS (`STATUS`) and its authorised STAs (`STA-FIRST`/`STA-NEXT`). | T-I, T-O |
| FR-MON-2 | Per STA it shall keep: smoothed RSSI (EWMA, ¾ old value), the number of consecutive samples below `rssi_low`, throughput from byte counters, rates, inactivity time, and 11k/11v/11r capability flags. | T-U `test_hapd_parsers`, T-O |
| FR-MON-3 | Capability flags: 11v from the Extended Capabilities BSS Transition bit; 11r from an FT AKM suite; 11k assumed when `assume_kvr` is set, until hostapd refuses `REQ_BEACON` in every mode tried (FR-STR-3). When the evidence is missing, `assume_kvr` (1) decides. | T-U, T-O |
| FR-MON-4 | Channel utilisation shall come from the nl80211 survey (busy/active time of the in-use channel), scaled to 0–254 and smoothed. Without a survey it shall come from hostapd's `chan_util_avg`, and otherwise be reported as unknown (255). | I, T-O |
| FR-MON-5 | When a STA disappears from hostapd's list without a disassociation event, the daemon shall remove it as if it had disassociated. | I |
| FR-MON-6 | When hostapd is unreachable or stops answering, the BSS shall be marked down, its STAs removed, and a reconnection attempted every 5 s. | T-O |
| FR-MON-7 | When a peer reports the association of a locally known STA, that STA shall be marked "away": no longer reported or steered, until it associates locally again. | I |

### 4.5 Steering triggers (TRG)

| ID | Requirement | Verif. |
|---|---|---|
| FR-TRG-1 | **RSSI.** With `rssi_steering` on, a STA whose smoothed RSSI is below `rssi_low` (−75 dBm), after `rssi_low_count` (3) consecutive low samples, shall trigger a steer with reason RSSI. | T-U `test_policy`, T-I 3 |
| FR-TRG-2 | **Band.** With `band_steering` on, a STA on 2.4 GHz whose RSSI is at least `band_steer_rssi` (−55 dBm) shall trigger a steer with reason BAND, towards higher bands only, when it can use a higher band (FR-TRG-6). With `band_steer_6g` also on, a STA on 5 GHz whose RSSI is at least `band_steer_6g_rssi` (−55 dBm) shall trigger a BAND steer towards 6 GHz, only when 6 GHz is advertised or seen for it and not blocked. After a band steer in which no candidate was measured, the next band steer of that STA shall wait `steer_cooldown_ms` × 2^n (n = such steers in a row, capped at `steer_backoff_max_ms`); a 5/6 GHz level of the STA resets n. | T-U, T-I 7, 8, T-O |
| FR-TRG-3 | **Load.** Every `lb_interval_ms` (10000), with `load_balancing` on, each BSS whose utilisation is at least `util_high` (70 %) or whose STA count has reached `max_sta` shall offload one STA: the weakest STA that is eligible. With `lb_only_idle`, only STAs below `idle_kbps` qualify. | T-U, T-I 4 |
| FR-TRG-4 | **Manual.** `STEER <sta> [<bssid>]` shall start a steer with reason MANUAL. It ignores the STA's cooldown and, when a BSSID is given, considers only that BSS. | T-O |
| FR-TRG-6 | **STA bands.** The daemon shall take the bands a STA advertises from hostapd's `supp_op_classes` (Supported Operating Classes: 81–84 = 2.4 GHz, 115–129 = 5 GHz, 131–137 = 6 GHz, up to the 130 or 0 delimiter), and add every band the STA was associated or measured on. A STA whose association AKM is PSK, FT-PSK or PSK-SHA256 (not allowed on 6 GHz) shall have 6 GHz blocked. Automatic steers shall consider only candidates on usable bands. A STA that advertises no classes counts as able to use every band that is not blocked. | T-U `test_rrm`, `test_policy`, `test_hapd_parsers`, T-I 7, 8 |
| FR-TRG-5 | Automatic triggers shall skip a STA that lacks 11v, is "away", is in cooldown or backoff, or already has a transaction. | I |

### 4.6 Steering transaction, source side (STR)

| ID | Requirement | Verif. |
|---|---|---|
| FR-STR-1 | At most one transaction per STA, and at most 16 at a time. | I |
| FR-STR-2 | Candidates shall be every BSS of the same ESS other than the current one, local or remote (at most 16). Band steering keeps only higher bands. | I |
| FR-STR-3 | **Measure.** For an 11k STA, the daemon shall send a Beacon Request (mode `beacon_mode`, default active; duration `beacon_duration`, 50 TU; SSID of the ESS) covering every distinct candidate channel (up to 8) in **one** request: Channel 255 with AP Channel Report subelements when there are several, because a STA refuses a second beacon measurement while one is running. With `score_model 1` the serving channel is included. It shall wait until every candidate has been reported or `beacon_req_timeout_ms` (1500) expires. When hostapd refuses the configured mode (the STA did not advertise it in its RM Enabled Capabilities), the daemon shall try active, then passive mode (passive lasting at least 120 TU), remember the first mode accepted for that STA, and mark the STA as lacking 11k only when all fail. | T-I 3, T-O |
| FR-STR-4 | **Score.** Each candidate shall be scored by the policy (§4.8) from its STA-measured level (reports ≤ 10 s old) or, when there is none, its air-monitor level (FR-AMN-4), and its load. Ineligible candidates shall be dropped and the rest tried best first. | T-U `test_policy`, T-I 3 |
| FR-STR-5 | **Negotiate.** For a remote candidate, the daemon shall send STEER_REQ to the owning peer and wait for STEER_RESP (`steer_resp_timeout_ms` + 1.5 s). A rejection, a timeout or an unreachable peer shall move on to the next candidate. A local candidate shall be admitted locally, without negotiation. | T-I 3, T-O |
| FR-STR-6 | **Transition.** After admission, the daemon shall have hostapd send a BTM Request with a preferred candidate list, the abridged bit and validity `btm_valid_int`. It shall carry the single chosen candidate with preference 255, and the Mobility Domain bit when the MDIDs match; it carries Disassociation Imminent only when `disassoc_imminent` is set. Without a measurement, only a manual steer may pick a candidate (its level is then taken as `rssi_min_target`). | T-I 3, T-O |
| FR-STR-7 | **Outcome.** The transaction shall end as: SUCCESS when the STA associates to the chosen BSS; WRONG_TARGET when it associates to another BSS of the ESS; BTM_REJECT on a non-zero BTM status; BTM_TIMEOUT after `btm_timeout_ms` (2000) without a response; ROAM_TIMEOUT after `roam_timeout_ms` (5000) without an association; ABORTED when the STA leaves before the BTM, hostapd refuses the request, or no candidate remains after negotiation. | T-I 3,4, T-O |
| FR-STR-8 | After a remote candidate has reached the BTM stage, the outcome shall be sent to the target in STEER_RESULT. | T-O |
| FR-STR-9 | **Backoff.** SUCCESS and WRONG_TARGET shall reset the STA's failure count and apply `steer_cooldown_ms` (30000). A failure shall increase it and apply `steer_cooldown_ms` × 2^failures, capped at `steer_backoff_max_ms` (600000). "No suitable candidate" applies the plain cooldown and is not a failure. A newly associated STA shall not be steered before one cooldown has passed. | T-U `test_policy`, I |
| FR-STR-10 | Every transaction shall end within `beacon_req_timeout_ms` + N × (`steer_resp_timeout_ms` + 1500) + `btm_timeout_ms` + `roam_timeout_ms`, where N ≤ 16 is the number of remote candidates tried. | A |

### 4.7 Admission and reservations, target side (ADM)

| ID | Requirement | Verif. |
|---|---|---|
| FR-ADM-1 | On STEER_REQ, the target shall answer STEER_RESP: UNKNOWN_BSS when the BSS is not local and up; BUSY when it is itself steering that STA or has no free reservation; CAPACITY when `sta_count` + reservations would reach `max_sta`; LOAD when utilisation ≥ `util_admit_max` (80 %); otherwise ACCEPT with `hold_ms`. | T-U `test_policy`, T-I 3 |
| FR-ADM-2 | An accepted request shall reserve a slot for `reserve_hold_ms` (8000). It shall count against `max_sta` in later admission decisions and in the advertised "accepting" flag. | I |
| FR-ADM-3 | A reservation shall be released by the STA's local association, by a matching STEER_RESULT, by expiry, or by loss of the source peer. | I, T-O |

### 4.8 Decision policy (POL)

| ID | Requirement | Verif. |
|---|---|---|
| FR-POL-1 | A candidate shall be ineligible when it is not accepting, is full, has utilisation ≥ `util_admit_max`, has no measurement (except manual), or its measured level is below `rssi_min_target` (−70 dBm). | T-U |
| FR-POL-2 | Additional per-reason floors. RSSI: level ≥ current RSSI + `rssi_hysteresis` (8 dB). LOAD: target utilisation ≤ `util_high` − `lb_margin` and level ≥ current − `lb_rssi_tolerance` (5 dB). BAND: a strictly higher band. | T-U |
| FR-POL-3 | Score = measured level + band bonus (`band_bonus_5g` 5, `band_bonus_6g` 8) − `util_weight` × utilisation % / 10. The highest score is tried first. | T-U |
| FR-POL-4 | **Throughput model (`score_model 1`, experimental).** Score = expected throughput (kbps) = q(level) × peak PHY rate × (100 − utilisation) %. q is a logistic curve (500‰ at `tput_rssi_mid`, −72 dBm; slope 0.3 per dB) from an integer table. The peak rate comes from the BSS's HT/VHT/HE capability and width, times `sta_nss` (2). FR-POL-1 still applies; FR-POL-2/3 are replaced: RSSI and band steering need ≥ `tput_gain_pct` (150 %) of the STA's current expected throughput, load balancing needs ≥ 100 % and the FR-POL-2 utilisation limit. The current link shall be valued with the STA's own beacon measurement of the serving BSS when available. | T-U `test_policy_tput`, T-I 1–5 (`DONGHOA_ITEST_EXTRA="score_model 1"`), T-O |

### 4.9 Messaging reliability (REL)

| ID | Requirement | Verif. |
|---|---|---|
| FR-REL-1 | STEER_REQ, STEER_RESP and STEER_RESULT shall be sent unicast with ACK_REQ. They shall be retransmitted every 300 ms with the same `msg_id` until acknowledged, for at most 4 transmissions in total. | I |
| FR-REL-2 | The receiver shall acknowledge every copy of an ACK_REQ message, duplicates included, and process each message once. Duplicates shall be detected with a 64-entry sliding window over `msg_id` per peer and boot. | I (no automated test, see §7) |
| FR-REL-3 | A node with several ports shall send multicast on all of them. Unicast to a peer shall use the port and source address that delivered that peer's most recent new (non-duplicate) message. Unicast thereby fails over between wired and Wi-Fi backhaul. | I |

### 4.10 Security (SEC)

| ID | Requirement | Verif. |
|---|---|---|
| FR-SEC-1 | With `key` set, every message shall carry an HMAC-SHA256 (truncated to 16 bytes) over the header and the preceding TLVs, and messages without a valid MAC shall be dropped. | T-U `test_proto_roundtrip`, T-I 2 |
| FR-SEC-2 | Without `key`, messages that carry the AUTH flag shall be dropped, so a key mismatch fails closed in both directions. | T-U |
| FR-SEC-3 | A key shall be either `hex:` with at least 16 bytes, or a passphrase of at least 8 characters, turned into a key as SHA256("arcp-key:" ‖ passphrase). Shorter keys shall be refused. | T-U `test_config` |
| FR-SEC-4 | MAC comparison shall take constant time. | I |
| FR-SEC-5 | The daemon shall log at start-up whether authentication is enabled. | I |

### 4.11 Air monitor (AMN)

| ID | Requirement | Verif. |
|---|---|---|
| FR-AMN-1 | An AP with at least one usable monitor interface shall advertise the AIR_MONITOR flag in AP_INFO. | T-I 5 |
| FR-AMN-2 | During MEASURE, when `amon_request` is on (default), the source AP shall send STA_MONITOR_REQ (reliable unicast) to each peer that owns a candidate and advertises AIR_MONITOR, and start a local watch when it has a monitor and a local candidate. This shall happen in parallel with the 802.11k Beacon Request, for STAs with and without 11k. | T-I 5 |
| FR-AMN-3 | An AP receiving STA_MONITOR_REQ shall watch the STA for the requested duration (`amon_duration_ms`, 1000 ms by default, at most 5 s), averaging the dBm signal of its frames per frequency. It shall then send STA_MONITOR_REPORT with one STA_MONITOR_RESULT per local BSS (up) on a frequency the STA was heard on, and send nothing if it was not heard. At most 16 watches shall run at a time. | T-U, T-I 5, T-O |
| FR-AMN-4 | The source AP shall use a monitor result (≤ 10 s old, plus `amon_rssi_offset`) as a candidate's level only when the STA gave no 802.11k report for that candidate. | T-I 5 |
| FR-AMN-5 | A refused or unanswered Beacon Request shall not end MEASURE while monitor reports are pending. MEASURE shall end early when every candidate has an 11k report, or, once no 11k report is pending, when every candidate has any measurement; otherwise at max(`beacon_req_timeout_ms`, `amon_duration_ms` + 500 ms). | T-I 5 |
| FR-AMN-6 | Without monitors on any candidate AP, steering behaviour shall be unchanged. | T-I 1–4, 6 |

## 5. Non-functional requirements

### 5.1 Performance

| ID | Requirement | Verif. |
|---|---|---|
| NFR-PRF-1 | The event loop shall wake at least every 100 ms, so that timer resolution is ≤ 100 ms plus processing time. | I |
| NFR-PRF-2 | A beacon report covering every candidate shall lead to the BTM Request without waiting for the measurement timeout. | T-O (BTM 0.4 ms after the report) |
| NFR-PRF-3 | A new peer shall be learned within one `hello_interval_ms` of being reachable, and a lost peer forgotten within `peer_timeout_ms`. | T-I 1, I |
| NFR-PRF-4 | Every blocking call shall be bounded: hostapd command ≤ 1 s, nl80211 survey ≤ 0.5 s per receive. | I |

Measured, not required (hwsim on QEMU): a local band steer, from trigger to
association, took 397–407 ms. A cross-AP STEER_REQ → STEER_RESP round trip
took about 1 ms. A manual steer with the single multi-channel Beacon Request
(serving + target channel in one measurement) took 720 ms. A band steer under
the throughput model took 1.8 s, of which 1.5 s was the measurement timeout
because one candidate (a remote AP) could not be heard by the STA (SDD R11).

### 5.2 Capacity and resources

| ID | Requirement | Verif. |
|---|---|---|
| NFR-CAP-1 | Fixed limits: 8 local BSSes, 256 local STAs, 32 peers with 8 BSSes and 4 radios each, 512 remote STAs, 16 transactions, 32 reservations, 32 pending reliable messages, 8 L2 ports, 4 air monitors, 16 monitor watches. Running out of space in a table shall be logged and handled without crashing. | I |
| NFR-CAP-2 | No heap allocation (C-5). The fixed daemon state is 247,720 bytes on x86-64 (the static `Daemon` object, measured with `nm -S`), in `.bss`. | A |
| NFR-CAP-3 | The OpenWrt package file should stay below 64 KiB (measured: `donghoa-1.0-r5.apk`, 40.8 KB, x86-64). | T-O |

### 5.3 Reliability and availability

| ID | Requirement | Verif. |
|---|---|---|
| NFR-REL-1 | Loss of hostapd, of a peer or of a backhaul path shall not stop the daemon. It shall recover on its own when the resource returns (FR-MON-6, FR-DSC-4, FR-REL-3). | T-O (hostapd restart) |
| NFR-REL-2 | A steering failure shall never leave a STA without a reachable BSS. The daemon only suggests a transition (BTM without Disassociation Imminent by default), and the STA decides. | I |
| NFR-REL-3 | On OpenWrt the service shall be respawned after a crash (procd respawn). | I |

### 5.4 Security

| ID | Requirement | Verif. |
|---|---|---|
| NFR-SEC-1 | Authentication should be enabled in every deployment. The example configuration enables it. | I |
| NFR-SEC-2 | Known limitation, accepted for 1.0: a new `boot_id` resets the replay window, so messages from a peer's earlier boot can be replayed (PROTOCOL.md §5). | — |
| NFR-SEC-3 | ARCP shall not carry confidential data: no key material (C-2), only MAC addresses and radio metrics. Messages are authenticated, not encrypted. | I |

### 5.5 Portability and maintainability

| ID | Requirement | Verif. |
|---|---|---|
| NFR-POR-1 | The daemon shall build and run on glibc and musl, and cross-compile with the OpenWrt SDK (24.x `.ipk`, 25.x `.apk`). | T-O |
| NFR-MNT-1 | Decision logic and byte layouts shall live in pure modules (`proto`, `rrm`, `policy`, `config`, `sha256`, hostapd parsers) that the unit tests can link without I/O. | I |
| NFR-MNT-2 | Wire numbers shall be defined only in `src/proto.hpp`. A change to the protocol shall update `proto.{hpp,cpp}`, `docs/PROTOCOL.md` and the round-trip tests together. | I |
| NFR-MNT-3 | A change to daemon behaviour shall keep `make itest` passing (PASS 1–5). | T-I |

## 6. Out of scope (version 1.0)

- IEEE 1905.1 / EasyMesh controller–agent operation (C-1).
- Carrying or deriving 802.11r keys (C-2).
- Steering legacy STAs without 802.11v: no deauthentication or
  association-rejection based steering.
- Off-channel listening for unassociated STAs (air monitors hear only their
  own channel), and channel or TX-power planning.
- Multi-Link Operation (802.11be MLO) awareness, and wide-channel operating
  classes in neighbor reports (20 MHz only).
- A central controller. All decisions are made per AP, by the source AP.

## 7. Verification matrix

| Area | Automated coverage | Gaps (manual or not yet covered) |
|---|---|---|
| Wire format, HMAC (IR-8/9, FR-SEC-1..3) | `test_sha256`, `test_proto_roundtrip`, `test_proto_overflow`, `test_steer_tlvs`, `test_config`; itest PASS 2 | Forward-compatibility of longer TLVs (IR-10): inspection only |
| 802.11k/v byte layouts (FR-NBR-2, FR-STR-3/6) | `test_rrm` (incl. multi-channel Beacon Request: Channel 255 + AP Channel Reports); itest PASS 1, 3 (mock parses both forms) | Real STA behaviour only in the OpenWrt procedure: single- and multi-channel requests verified with wpa_supplicant, both channels returned in one report |
| hostapd parsers (IR-2, FR-MON-2/3) | `test_hapd_parsers` (mock format); itest | Real hostapd output: OpenWrt procedure (T-O) |
| Discovery, neighbor DB (FR-DSC, FR-NBR) | itest PASS 1, 5 | Peer **timeout** expiry and `boot_id` restart: no test |
| Policy (FR-POL, FR-TRG-1..3, FR-ADM-1, FR-STR-9) | `test_policy`, `test_policy_tput` (sigmoid table, peak rates, the five SDD §6.5 scenarios, hard gates in both models); itest PASS 3, 4 in both models (`DONGHOA_ITEST_EXTRA="score_model 1"`) | Calibration of the throughput model against real STAs (SDD R12) |
| Steering flow (FR-STR) | itest PASS 3 (remote RSSI roam), PASS 4 (load), PASS 7 (local band steer, band check, band backoff), PASS 8 (2.4 → 6 GHz, WPA2-PSK kept off 6 GHz, 5 → 6 GHz) | BTM reject, timeouts, WRONG_TARGET, manual steer, band steer: OpenWrt procedure only (manual and band steer verified, BTM reject with status 7 verified; throughput model verified refusing band steering at equal width and steering to a VHT80 BSS) |
| Reservations (FR-ADM-2/3) | itest PASS 3 (accept) | Expiry and peer-loss release: no test |
| Reliability (FR-REL) | — | Retransmission, duplicate re-ACK, replay window, path failover: **no automated test** (`peer.cpp` and `msg.cpp` are not linked into the unit tests) |
| Resilience (FR-MON-6, NFR-REL-1) | — | hostapd restart verified manually on OpenWrt |
| Air monitor (FR-AMN, IR-13) | `test_air_monitor` (radiotap alignment, extended bitmaps, frame filter, TLV round trip, config); itest PASS 5 (STA without 11k, injected frames, monitor report, steer) in both scoring models | Real monitor path verified on OpenWrt/hwsim (BPF + `AF_PACKET` + parser: −27 dBm, matching the station table); cross-AP over the air not possible with hwsim; BPF program has no unit test |
| OpenWrt service and BSSes from UCI (IR-7, IR-12) | — | OpenWrt procedure only: generated `bss` lines (names, `mdid`, `max_sta` from `maxassoc`) verified, and an interface rename via `reload_config` followed within 6 s; no automated test of the init script |

Recommended additions: a unit test for `acceptPeerSeq` (move it into a pure
module); itest scenarios for peer timeout, packet loss with retransmission,
and BTM rejection; a shell test of the init script's `bss` generation against
fixture `ubus` output and hostapd configs; and, once SDD R11 is fixed, an
itest check that a steer with an unmeasurable candidate does not wait for the
measurement timeout.

## Appendix A. Configuration parameters and defaults

| Key | Default | Unit / meaning |
|---|---|---|
| `name` | `arcp-ap` | AP name, ≤ 32 characters |
| `ap_id` | MAC of first `iface` | AP identifier; required when only sim ports are used |
| `iface` | — | L2 port, repeatable (≤ 8) |
| `sim_port`, `sim_peer` | — | UDP test transport |
| `key` | none | `hex:<≥32 hex digits>` or passphrase ≥ 8 characters |
| `bss <ifname> [mdid=<hex>] [max_sta=<n>] [ft_over_ds=1]` | — | Managed BSS, repeatable (≤ 8) |
| `hostapd_ctrl_dir` | `/var/run/hostapd` | |
| `ctrl_socket` | none | Control socket path |
| `hello_interval_ms` / `bss_status_interval_ms` / `sta_status_interval_ms` / `rf_status_interval_ms` | 2000 / 5000 / 10000 / 10000 | ms |
| `sta_poll_interval_ms` / `peer_timeout_ms` | 1000 / 7000 | ms |
| `rssi_steering` / `band_steering` / `load_balancing` | 1 / 1 / 1 | on/off |
| `rssi_low` / `rssi_low_count` / `rssi_hysteresis` / `rssi_min_target` | −75 / 3 / 8 / −70 | dBm / samples / dB / dBm |
| `band_steer_rssi` | −55 | dBm |
| `band_steer_6g` | 1 | on/off: 5 → 6 GHz band steering |
| `band_steer_6g_rssi` | −55 | dBm |
| `util_high` / `util_admit_max` / `lb_margin` | 70 / 80 / 15 | % |
| `lb_rssi_tolerance` / `lb_only_idle` / `idle_kbps` / `lb_interval_ms` | 5 / 1 / 50 / 10000 | dB / bool / kbit/s / ms |
| `util_weight` / `band_bonus_5g` / `band_bonus_6g` | 2 / 5 / 8 | score points |
| `steer_cooldown_ms` / `steer_backoff_max_ms` | 30000 / 600000 | ms |
| `beacon_req_timeout_ms` / `steer_resp_timeout_ms` / `btm_timeout_ms` / `roam_timeout_ms` / `reserve_hold_ms` | 1500 / 1000 / 2000 / 5000 / 8000 | ms |
| `btm_valid_int` / `disassoc_imminent` / `disassoc_timer` | 100 / 0 / 0 | TBTT / bool / TBTT |
| `beacon_mode` / `beacon_duration` | 1 (active) / 50 | 0 passive, 1 active, 2 table / TU |
| `assume_kvr` | 1 | treat STAs as 11k/v/r capable unless shown otherwise |
| `air_monitor` / `air_monitor_sim` | — | Monitor interface, repeatable (≤ 4) / UDP test input |
| `amon_request` / `amon_duration_ms` / `amon_rssi_offset` | 1 / 1000 / 0 | bool / ms / dB |
| `score_model` / `tput_rssi_mid` / `tput_gain_pct` / `sta_nss` | 0 (linear) / −72 / 150 / 2 | 0 linear, 1 expected throughput / dBm / % / streams |

## Appendix B. Revision history

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-30 | First issue |
| 1.1 | 2026-10-31 | Product renamed DongHoa (`donghoa`, `donghoa_cli`, `/etc/donghoa.conf`; protocol still ARCP). New FR-POL-4 (expected-throughput scoring, opt-in) and its configuration keys. FR-STR-3: one Beacon Request covering all candidate channels. New IR-12 (OpenWrt `bss` lines from UCI). Updated measurements (NFR-CAP-2/3, §5.1) and the verification matrix |
| 1.2 | 2026-10-31 | Air monitor: new §4.11 (FR-AMN-1..6) and IR-13; FR-STR-4 and AS-1 use monitor levels when the STA gives no 802.11k report; `MONITOR` control command; out-of-scope narrowed to off-channel listening; updated capacity figures, verification matrix and configuration appendix |
| 1.3 | 2026-10-31 | IR-5: per-module log levels, `log_level`/`log_debug` keys, run-time `LOG` command, syslog output (`-s`) with real priorities, ARCP frame trace; IR-3: `LOG` command; FR-STR-3 / FR-MON-3: beacon-report mode fallback (active → passive) |
| 1.4 | 2026-11-01 | C-3: implementation language C++17 without exceptions, RTTI or heap, MISRA C++:2023 based convention; C-4: no libstdc++.so at run time; NFR-CAP-2 re-measured (247,720 bytes). No functional requirement changed |
