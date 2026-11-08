# DongHoa — Software Requirements Specification

| | |
|---|---|
| Product | DongHoa: daemon `donghoa` and CLI `donghoa_cli` |
| Version covered | 1.0 (OpenWrt package `donghoa-1.0-r9`, C++17 implementation) |
| Document version | 2.9, 2026-11-08 (history in Appendix B) |
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
5. Admit or refuse incoming STAs on the target side, holding a reservation,
   and stop offloading from a BSS when moving STAs does not lower its load.
6. Measure STAs that give no 802.11k report from the APs' side (monitor
   interfaces or the driver per-STA RSSI API), every AP always answering,
   and learn the uplink → downlink offset per BSS.
7. Recognise low-power (IoT) devices from their traffic and keep them out of
   automatic steering; share the class between APs.
8. Learn a roaming threshold per STA from the outcomes of its steers and its
   own roams, shared between APs; optionally (off by default) learn when to
   roam with a Q-table.
9. Handle Wi-Fi 7 AP MLDs and MLD STAs as one device each.
10. Report status to the operator and accept manual steering commands.

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
| IR-3 | **Control socket.** When `ctrl_socket` is set, the daemon shall answer UNIX-datagram requests: `PING`, `STATUS`, `PEERS`, `STAS`, `STEERS`, `DEVCLASS` (device class records), `CALIB` (learned uplink/downlink offsets), `RL [mode <n> | reset]` (Q-learning state and control), `BANDIT [mode <n> | reset]` (target bandit state and control), `ENROLL [approve <ap_id> | revoke <ap_id> | init]` (key enrollment), `DROPRX [<MESSAGE> <n>]` (fault injection: drop received messages of a type), `STEER <sta> [<bssid>]`, `MONITOR <sta> [<ms>]` (measure a STA with this AP's air monitors; result in the log) and `LOG [<level> [<module>...]]` (show or set log levels). Each reply shall be a single datagram of at most 8 KiB. Unknown commands shall get `UNKNOWN COMMAND`. | T-I 1,5, T-O |
| IR-4 | **CLI.** `donghoa_cli <socket> <command…>` shall send one request, print the reply, and fail if no reply arrives within 2 s. | T-I, T-O |
| IR-5 | **Logging.** Each log line shall carry the monotonic time, a level tag (`ERR`, `WRN`, `INF`, `DBG`) and the module (`main`, `l2`, `msg`, `peer`, `hapd`, `local`, `steer`, `policy`, `amon`, `survey`, `ctrl`, `config`, `rrm`, `class`). Each module shall have its own level: info by default, set by `log_level` and `log_debug <modules>` in the configuration, by `-d` (all modules at debug), and at run time by the control command `LOG [<level> [<module>...]]` without a restart. Output shall go to stderr, or with `-s` to syslog (facility daemon) with priorities matching the levels. At debug level, module `msg` shall trace every ARCP frame sent, retransmitted and received (type, id, peer, port, flags, TLV list), and module `rrm` shall dump every 802.11k/v command sent to hostapd (`REQ_BEACON`, `BSS_TM_REQ`, `SET_NEIGHBOR`, `REMOVE_NEIGHBOR`) with its reply, and every 11k/v event (`BEACON-RESP-RX`, `BEACON-REQ-TX-STATUS`, `BSS-TM-RESP`, `BSS-TM-QUERY`), raw and decoded. | T-U `test_log`, `test_rrm`, T-I 1, 3, T-O |

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
| IR-8 | ARCP shall be carried directly in Ethernet II frames: EtherType 0x88B5, multicast group `03:41:52:43:50:00`, payload ≤ 1450 bytes, no IP. The wire format is normative in `docs/PROTOCOL.md`, with `src/proto.hpp` as the source of the numbers. | T-U `test_proto_*`, T-I 1 |
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
| FR-DSC-6 | With `liveness_check 1` (default 0), a peer's `boot_id` (new origin, or a known origin with another `boot_id`) shall be adopted only after the peer answered a CHALLENGE with a fresh 16-byte nonce from that boot. A verified new `boot_id` of a known peer shall be treated as a restart: its sequence state is reset and the event is logged. | T-U `test_replay_window`, T-I 22 |
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
| FR-TRG-1 | **RSSI.** With `rssi_steering` on, a STA whose smoothed RSSI is below its roaming threshold (FR-TRG-7; `rssi_low`, −75 dBm, until learned), after `rssi_low_count` (3) consecutive low samples, shall trigger a steer with reason RSSI. A sample counts (for the low count and the smoothed RSSI) only when the STA sent a frame within the last poll interval (hostapd `inactive_msec`); an idle STA's signal is its last frame's and shall not count again on every poll. | T-U `test_policy`, T-I 3 |
| FR-TRG-2 | **Band.** With `band_steering` on, a STA on 2.4 GHz whose RSSI is at least `band_steer_rssi` (−55 dBm) shall trigger a steer with reason BAND, towards higher bands only, when it can use a higher band (FR-TRG-6). With `band_steer_6g` also on, a STA on 5 GHz whose RSSI is at least `band_steer_6g_rssi` (−55 dBm) shall trigger a BAND steer towards 6 GHz, only when 6 GHz is advertised or seen for it and not blocked. After a band steer in which no candidate was measured, the next band steer of that STA shall wait `steer_cooldown_ms` × 2^n (n = such steers in a row, capped at `steer_backoff_max_ms`); a 5/6 GHz level of the STA resets n. | T-U, T-I 7, 8, T-O |
| FR-TRG-3 | **Load.** Every `lb_interval_ms` (10000), with `load_balancing` on, each BSS whose utilisation is at least `util_high` (70 %) or whose STA count has reached `max_sta` shall offload one STA: the weakest STA that is eligible. With `lb_only_idle`, only STAs below `idle_kbps` qualify. After a utilisation-triggered offload has moved its STA, the next offload from that BSS shall wait until the move can be judged (5 polls + 2 s); a move that did not lower the BSS's utilisation by `lb_min_drop_pct` (3) points counts as futile, and after `lb_max_futile` (2) futile moves in a row the BSS shall stop offloading for `lb_hold_ms` (300 s), with a warning naming the likely cause (airtime of other networks or interference).  An offload whose STA disconnects instead of associating elsewhere shall give no verdict. | T-U, T-I 4, 14, 20 |
| FR-TRG-4 | **Manual.** `STEER <sta> [<bssid>]` shall start a steer with reason MANUAL. It ignores the STA's cooldown and, when a BSSID is given, considers only that BSS. | T-O |
| FR-TRG-6 | **STA bands.** The daemon shall take the bands a STA advertises from hostapd's `supp_op_classes` (Supported Operating Classes: 81–84 = 2.4 GHz, 115–129 = 5 GHz, 131–137 = 6 GHz, up to the 130 or 0 delimiter), and add every band the STA was associated or measured on. A STA whose association AKM is PSK, FT-PSK or PSK-SHA256 (not allowed on 6 GHz) shall have 6 GHz blocked. Automatic steers shall consider only candidates on usable bands. A STA that advertises no classes counts as able to use every band that is not blocked. | T-U `test_rrm`, `test_policy`, `test_hapd_parsers`, T-I 7, 8 |
| FR-TRG-7 | **Per-STA roaming threshold.** With `roam_thr_learn` on, each STA's roaming threshold shall start at `rssi_low` and stay within `roam_thr_min`..`roam_thr_max` (−82..−65 dBm). After an RSSI steer of the STA: BTM rejected or not answered −2 dB; roam timeout −1 dB; success with a target ≥ 15 dB better than the STA's level at the start +1 dB; other outcomes unchanged. When the STA roams to another AP without a steer of this AP (also after a local disassociation followed within 5 s by the peer's report), the threshold shall move a quarter of the way (at least 1 dB) towards the STA's last level here. Without events for 10 min it shall drift 1 dB back towards `rssi_low`. The low-sample count and the trigger shall use the STA's threshold. The threshold shall be shared as in FR-LPC-3/4 (STA_ROAM, versioned by event count) and shown in `STAS` and `DEVCLASS`. | T-U, T-I 17 |
| FR-TRG-8 | **Q-learning of when to roam.** Q-learning shall be off by default (`rl_roam` 0) and enabled by `rl_roam` 1 (shadow) or 2 (active) in the configuration, or at run time by `RL mode <n>`. When enabled, each fresh sample of a non-MLD STA below −60 dBm shall be a decision WAIT/STEER in one of 432 states (RSSI bin, trend, best known neighbour gap, refusals, low streak), with Q values updated as Q ← Q + α(r + γ·max Q(s′) − Q), α = 1/(n+1) then 1/8, γ = 0.8, integer ×256. Rewards: steer success +8 + gain (≤ 24), wrong target +4, refused −10, roam timeout −6, no candidate −2; waiting −(−70 − RSSI + 2)/4 per sample below −70 dBm, −20 if the link drops below `rssi_low`, 0 on an own roam. The table shall start from a prior equal to the rule-based trigger. Shadow mode shall not change behaviour; active mode shall decide with the table, exploring `rl_epsilon_pct` (1 %) only in safe states. `RL`, `RL mode <n>`, `RL reset` shall show and control it. | T-U, T-I 18 |
| FR-TRG-5 | Automatic triggers shall skip a STA that lacks 11v, is "away", is in cooldown or backoff, or already has a transaction. | I |

### 4.6 Steering transaction, source side (STR)

| ID | Requirement | Verif. |
|---|---|---|
| FR-STR-1 | At most one transaction per STA, and at most 16 at a time. | I |
| FR-STR-2 | Candidates shall be every BSS of the same ESS other than the current one, local or remote (at most 16). Band steering keeps only higher bands. When more BSSes qualify than the 16 a steer holds (e.g. more than about 8 dual-band APs), the pool keeps the most promising: BSSes the STA was measured at in the last 2 minutes (802.11k or AP-side, best level first), then this AP's own BSSes, then the others in peer order. That peer order starts, for each STA, after the peers the previous pool held, so successive steers cover every AP. | I, T-I 12 |
| FR-STR-3 | **Measure.** For an 11k STA, the daemon shall send a Beacon Request (mode `beacon_mode`, default active; duration `beacon_duration`, 50 TU; SSID of the ESS) covering every distinct candidate channel (up to 8) in **one** request: Channel 255 with AP Channel Report subelements when there are several, because a STA refuses a second beacon measurement while one is running. With `score_model 1` the serving channel is included. It shall wait until every candidate has been reported, until no further report has come for 200 ms + twice the measurement duration after the last one (a STA does not report BSSes it does not hear), or until `beacon_req_timeout_ms` (1500) expires. When hostapd refuses the configured mode (the STA did not advertise it in its RM Enabled Capabilities), the daemon shall try active, then passive mode (passive lasting at least 120 TU), remember the first mode accepted for that STA, and mark the STA as lacking 11k only when all fail. | T-I 3, T-O |
| FR-STR-4 | **Score.** Each candidate shall be scored by the policy (§4.8) from its STA-measured level (reports ≤ 10 s old) or, when there is none, its air-monitor level (FR-AMN-4), and its load. Ineligible candidates shall be dropped and the rest tried best first. | T-U `test_policy`, T-I 3 |
| FR-STR-5 | **Negotiate.** For a remote candidate, the daemon shall send STEER_REQ to the owning peer and wait for STEER_RESP (`steer_resp_timeout_ms` + 1.5 s). A rejection, a timeout or an unreachable peer shall move on to the next candidate. A local candidate shall be admitted locally, without negotiation. | T-I 3, T-O |
| FR-STR-6 | **Transition.** After admission, the daemon shall have hostapd send a BTM Request with a preferred candidate list, the abridged bit and validity `btm_valid_int`. It shall carry the single chosen candidate with preference 255, and the Mobility Domain bit when the MDIDs match; it carries Disassociation Imminent only when `disassoc_imminent` is set. Without a measurement, only a manual steer may pick a candidate (its level is then taken as `rssi_min_target`). | T-I 3, T-O |
| FR-STR-7 | **Outcome.** The transaction shall end as: SUCCESS when the STA associates to the chosen BSS; WRONG_TARGET when it associates to another BSS of the ESS; BTM_REJECT on a non-zero BTM status; BTM_TIMEOUT after `btm_timeout_ms` (2000) without a response; ROAM_TIMEOUT after `roam_timeout_ms` (5000) without an association; ABORTED when the STA leaves before the BTM, hostapd refuses the request, or no candidate remains after negotiation. | T-I 3,4, T-O |
| FR-STR-8 | Once a STEER_REQ has been sent to a remote candidate, the outcome shall be sent to that target in STEER_RESULT, aborted included: when the STA disassociates during NEGOTIATE, and when no STEER_RESP arrives (the target may have accepted). A local disassociation shall abort the transaction in MEASURE and NEGOTIATE, and shall not end it in BTM and ROAM, where the outcome follows from where the STA associates or from the timeout. | T-I 19, T-O |
| FR-STR-9 | **Backoff.** SUCCESS and WRONG_TARGET shall reset the STA's failure count and apply `steer_cooldown_ms` (30000). A failure shall increase it and apply `steer_cooldown_ms` × 2^failures, capped at `steer_backoff_max_ms` (600000). "No suitable candidate" applies the plain cooldown and is not a failure. A newly associated STA shall not be steered before one cooldown has passed. | T-U `test_policy`, I |
| FR-STR-10 | Every transaction shall end within `beacon_req_timeout_ms` + N × (`steer_resp_timeout_ms` + 1500) + `btm_timeout_ms` + `roam_timeout_ms`, where N ≤ 16 is the number of remote candidates tried. | A |
| FR-STR-11 | **Contextual bandit for the target.** Off by default (`bandit_target` 0); enabled by `bandit_target` 1 (shadow) or 2 (active) or at run time by `BANDIT mode <n>`. Each eligible candidate shall get one of 216 contexts (level bin, band change, local/remote, utilisation bin, level source) and a value (mean reward × n + prior × 3)/(n + 3), prior = 8 + clamp(gain, 0, 24) dB. The outcome of each tried candidate shall update its context's mean (success +8 + gain, elsewhere +4, BTM refused −10, roam timeout −6, target refused −2, aborted none), and a STA returning to the BSS it was steered away from within 60 s of a success shall add −10. Active mode shall order the eligible candidates by value and swap the top two in `bandit_epsilon_pct` (5 %) of steers; no gate of FR-STR/FR-POL shall be relaxed. | T-U, T-I 21 |

### 4.7 Admission and reservations, target side (ADM)

| ID | Requirement | Verif. |
|---|---|---|
| FR-ADM-1 | On STEER_REQ, the target shall answer STEER_RESP: UNKNOWN_BSS when the BSS is not local and up; BUSY when it is itself steering that STA or has no free reservation; CAPACITY when `sta_count` + reservations would reach `max_sta`; LOAD when utilisation ≥ `util_admit_max` (80 %); otherwise ACCEPT with `hold_ms`. | T-U `test_policy`, T-I 3 |
| FR-ADM-2 | An accepted request shall reserve a slot for `reserve_hold_ms` (8000). It shall count against `max_sta` in later admission decisions and in the advertised "accepting" flag. | I |
| FR-ADM-3 | A reservation shall be released by the STA's local association, by a matching STEER_RESULT, by expiry, or by loss of the source peer. | T-I 19, T-O S6 |

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
| FR-REL-2 | The receiver shall acknowledge every copy of an ACK_REQ message, duplicates included, and process each message once. Duplicates shall be detected with a 64-entry sliding window over `msg_id` per peer and boot. | T-U `test_replay_window` |
| FR-REL-3 | A node with several ports shall send multicast on all of them. Unicast to a peer shall use the port and source address that delivered that peer's most recent new (non-duplicate) message. Unicast thereby fails over between wired and Wi-Fi backhaul. | I |

### 4.10 Security (SEC)

| ID | Requirement | Verif. |
|---|---|---|
| FR-SEC-1 | With `key` set, every message shall carry an HMAC-SHA256 (truncated to 16 bytes) over the header and the preceding TLVs, and messages without a valid MAC shall be dropped. | T-U `test_proto_roundtrip`, T-I 2 |
| FR-SEC-2 | Without `key`, messages that carry the AUTH flag shall be dropped, so a key mismatch fails closed in both directions. | T-U |
| FR-SEC-3 | A key shall be either `hex:` with at least 16 bytes, or a passphrase of 8 to 128 characters, turned into a key with PBKDF2-HMAC-SHA256 (salt `donghoa-arcp-key`, 100 000 iterations). Other keys, and the public example key, shall be refused. | T-U `test_config`, `test_sha256` |
| FR-SEC-4 | MAC comparison shall take constant time. | I |
| FR-SEC-5 | The daemon shall log at start-up whether authentication is enabled, and which kind (HMAC, Ed25519, both). | I |
| FR-SEC-6 | With `sign_seed` and `peer_key` configured, every message shall carry an Ed25519 signature (RFC 8032) of the header and preceding TLVs, made with the AP's own key; a receiver shall drop every message whose origin is not listed in `peer_key` or whose signature does not verify under that origin's key. Non-canonical signatures (S ≥ L) shall be rejected. | T-U `test_ed25519`, `test_signed_message`, T-I 23 |
| FR-SEC-7 | `sign_seed` without `peer_key` (or the reverse), a `peer_key` that is not a valid curve point or is listed twice, and a `peer_key` for the AP's own `ap_id` that does not match its seed shall be refused at start-up. `donghoa -g` shall generate a key pair. | T-U `test_config`, T-I 23 |
| FR-SEC-8 | With `enroll 1`, the daemon shall use the key in `seed_file`, creating it (random, mode 0600) on first start, and log its fingerprint (first 8 bytes of SHA-256 of the public key). | T-I 24 |
| FR-SEC-9 | An AP not enrolled shall multicast a self-signed ENROLL_REQ every 3 s; a trusted AP shall list valid requests (self-signature checked, revoked keys ignored) as pending with their fingerprint, and `ENROLL approve <ap_id>` shall add the key to the trust table and welcome the AP. Nothing shall be added to the trust table without an approval or a trusted AP's TRUST message. | T-U `test_trust`, T-I 24 |
| FR-SEC-10 | The trust table shall merge as last-writer-wins registers by generation (revoked wins ties), be sent to all peers after a change, every 60 s and to new peers, be kept in `trust_file` across restarts, and a peer whose record is revoked shall be removed at once. | T-U `test_trust`, T-I 24 |
| FR-SEC-11 | An AP not enrolled shall accept one welcome: a TRUST message with its own key as trusted and the sender's own trusted record, signed by the sender; afterwards (or after `ENROLL init`) it shall accept no welcome. | T-I 24 |

### 4.11 Air monitor (AMN)

| ID | Requirement | Verif. |
|---|---|---|
| FR-AMN-1 | An AP with at least one usable monitor interface, or with `sta_rssi_api` on, shall advertise the AIR_MONITOR flag in AP_INFO. | T-I 5 |
| FR-AMN-2 | During MEASURE, when `amon_request` is on (default), the source AP shall multicast STA_MONITOR_REQ to every peer, and start a local watch when it can measure and has a local candidate. This shall happen in parallel with the 802.11k Beacon Request, for STAs with and without 11k. | T-I 5, 11 |
| FR-AMN-3 | An AP receiving STA_MONITOR_REQ shall watch the STA for the requested duration (`amon_duration_ms`, 1000 ms by default, at most 5 s), averaging the dBm signal of its frames per frequency on its monitors and starting the driver per-STA RSSI measurement on each BSS that supports it (`sta_rssi_api`). It shall then send STA_MONITOR_REPORT with one STA_MONITOR_RESULT per local BSS (up) that heard the STA (the driver's value for a BSS, else the monitor's on the BSS's frequency) and a STA_MONITOR_STATUS (measured / not heard / failed). An AP that cannot measure (no monitor and no supported driver API: unsupported; 16 watches running: busy; driver error: failed) shall send the report with only the status at once. | T-U, T-I 5, 11, T-O |
| FR-AMN-7 | The source AP shall end MEASURE as soon as every peer owning a candidate (and its own watch) has sent its STA_MONITOR_STATUS and no 802.11k report is pending; at the MEASURE timeout it shall log each AP that has not answered and treat it as unable to measure. | T-I 11 |
| FR-AMN-8 | The driver per-STA RSSI API shall sit behind `src/vendor_rssi.hpp` (supported?, start, read, stop; non-blocking). Until the chipset vendor's API is documented, the implementation shall report unsupported; a file-backed simulation (`sta_rssi_sim`) shall stand in for tests. | T-I 11 |
| FR-AMN-4 | The source AP shall use a monitor result (≤ 10 s old, converted to a downlink level per FR-AMN-9) as a candidate's level only when the STA gave no 802.11k report for that candidate. | T-I 5, 16 |
| FR-AMN-9 | With `amon_offset_learn` on, the source AP shall learn, per BSS, the offset between a STA's 802.11k level of the BSS (downlink) and the BSS's AP-side level of that STA (uplink) from pairs measured within 5 s of each other, each measurement used once: cumulative mean of the first 8 samples, then EWMA 1/8; a pair whose difference exceeds 30 dB, or (once calibrated) lies more than 12 dB from the mean, shall be rejected. A BSS with at least `amon_offset_min_samples` samples shall convert AP-side levels with its learned offset, otherwise with `amon_rssi_offset`. `CALIB` shall list the learned offsets. | T-U, T-I 16 |
| FR-AMN-5 | A refused or unanswered Beacon Request shall not end MEASURE while monitor reports are pending. MEASURE shall end early when every candidate has an 11k report, or, once no 11k report is pending, when every candidate has any measurement; otherwise at max(`beacon_req_timeout_ms`, `amon_duration_ms` + 500 ms). | T-I 5 |
| FR-AMN-6 | Without monitors on any candidate AP, steering behaviour shall be unchanged. | T-I 1–4, 6 |

### 4.12 Wi-Fi 7 multi-link operation (MLO)

| ID | Requirement | Verif. |
|---|---|---|
| FR-MLO-1 | A `bss` line naming an AP MLD link's control socket (`<netdev>_link<id>`) shall take that link's entry from hostapd `STATUS` (`bss[i]` = netdev and `mld_link_id[i]` = id), its AP MLD address from `mld_addr[i]`, and use the netdev for nl80211. | T-U `test_mlo`, T-I 9 |
| FR-MLO-2 | BSS_INFO shall carry the AP MLD address and link ID of an AP MLD link as an optional trailer, ignored by older receivers; without it a BSS is not an MLD link. | T-U `test_mlo` |
| FR-MLO-3 | A STA listed with `peer_addr[]` (MLD STA) shall be one entry per MLD address across the links of its AP MLD, with RSSI per link. Its RSSI and BSS shall be its best link's; it shall be RSSI-triggered only when every measured link has been below `rssi_low` for `rssi_low_count` samples. Being listed on another link of the same AP MLD shall not count as a move. | T-U, T-I 9 |
| FR-MLO-4 | An MLD STA shall not be band-steered, and no steer shall send it to another link of its own AP MLD. | T-I 9 |
| FR-MLO-5 | For an MLD STA, association on any link of the target AP MLD shall count as success, and association on a link of the source AP MLD shall not end the transaction. A legacy STA shall be handled as before, also between the affiliated BSSes of one AP MLD. | T-I 9 (local target), I |

### 4.13 Low-power device classification (LPC)

The method is defined in `docs/PROTOCOL.md` §8.

| ID | Requirement | Verif. |
|---|---|---|
| FR-LPC-1 | With `lp_classify` on, each STA poll shall add the STA's uplink and downlink rates (bytes/s, from hostapd `rx_bytes`/`tx_bytes`) to running standard deviations σ_u, σ_d and compute S = α(band) × σ_u / σ_d (α = `lp_alpha_2g/5g/6g` / 100). S shall not count before `lp_min_samples` samples, while neither rate varies, on a poll in which the STA moved no data, or while the recent uplink rate (moving average, weight 1/8) exceeds `lp_max_mean_bps` (0 disables). | T-U `test_low_power` |
| FR-LPC-2 | The STA's score θ shall rise by one when S > 1 and fall by one otherwise, within 0..`lp_score_max`. The STA shall become low-power when θ > `lp_threshold` and normal again when θ < `lp_threshold` − `lp_hysteresis`. | T-U, T-I 10 |
| FR-LPC-3 | A change of class of a local STA shall be sent (STA_CLASS, reliable) to every peer, which shall keep the record (at most 512, the oldest replaced). A record shall replace another only when it carries more samples. | T-I 10 |
| FR-LPC-4 | When a peer reports a STA associated to it, an AP holding a record for that STA shall send it to that peer; a STA that (re)associates shall start from the record this AP holds. An AP that sees a new or restarted peer shall send it all its low-power records and the records corrected from low-power to normal, and no other normal records. | T-I 10 |
| FR-LPC-5 | With `lp_no_steer` on, a low-power STA shall not be steered automatically (RSSI, band, load); manual steering shall still work. STA_ENTRY shall carry the class as flag 0x20. | T-I 10 |
| FR-LPC-6 | A STA whose hostapd `flags` show a PHY ruled out by `lp_exclude_vht` / `lp_exclude_he` / `lp_exclude_eht` shall never be low-power; a low-power one shall be set to normal at once and the change sent to every peer with its sample count raised by one. | T-U, T-I 10 |

## 5. Non-functional requirements

### 5.1 Performance

| ID | Requirement | Verif. |
|---|---|---|
| NFR-PRF-1 | The event loop shall wake at least every 100 ms, so that timer resolution is ≤ 100 ms plus processing time. | I |
| NFR-PRF-2 | A beacon report covering every candidate shall lead to the BTM Request without waiting for the measurement timeout. | T-O (BTM 0.4 ms after the report) |
| NFR-PRF-3 | A new peer shall be learned within one `hello_interval_ms` of being reachable, and a lost peer forgotten within `peer_timeout_ms`. | T-I 1, I |
| NFR-PRF-4 | Every blocking call shall be bounded: hostapd command ≤ 1 s. Per-STA metrics (signal, signal average, inactivity, byte counters, rates) shall come from an nl80211 station dump per BSS, read from the main loop without waiting, with a full hostapd `STA-FIRST`/`STA-NEXT` listing only every 10 s (capabilities, missed events), for a STA seen for the first time (`STA <addr>`), for AP MLD links, and as fallback when nl80211 is unavailable or two dumps in a row do not complete; `STATUS` shall show the source per BSS (`sta_src`). The nl80211 survey shall not wait for its reply (it is read from the main loop) and shall be abandoned after 1 s; it shall run once per radio per poll, whatever the number of BSSes on the radio, and the time spent in the driver per dump shall be measured and reported in `STATUS`. | I, T-O |

Measured, not required (hwsim on QEMU): a local band steer, from trigger to
association, took 377–410 ms. A cross-AP STEER_REQ → STEER_RESP round trip
took about 1 ms. A band steer with a remote candidate the STA cannot hear
took 0.76–0.85 s: MEASURE ends 302 ms after the last beacon report (quiet
period, FR-STR-3) instead of at the 1.5 s timeout (1.78 s before). Per-STA
metrics: one nl80211 station dump per BSS per poll, at most 110 µs in the
kernel; 6 hostapd STA round trips per 20 s instead of one per STA per BSS
per second.

### 5.2 Capacity and resources

| ID | Requirement | Verif. |
|---|---|---|
| NFR-CAP-1 | Fixed limits: 16 local BSSes (valid `bss` lines beyond 16 are ignored with a warning, the daemon still starts), 256 local STAs, 32 peers with 16 BSSes and 4 radios each, 512 remote STAs, 16 transactions, 32 reservations, 32 pending reliable messages, 8 L2 ports, 4 air monitors, 16 monitor watches, 512 device class / roaming records, 64 uplink/downlink calibration entries, 16 candidates per steer, 256 stations per nl80211 station dump, a 432 × 2 Q-table, a 216-context bandit table, 32 ping-pong watches. Running out of space in a table shall be logged and handled without crashing. | I |
| NFR-CAP-2 | No heap allocation (C-5). The fixed daemon state is 449,352 bytes on x86-64 (the static `Daemon` object, measured with `nm -S`), in `.bss`. | A |
| NFR-CAP-3 | The OpenWrt package file should stay below 64 KiB. **Not met:** `donghoa-1.0-r21.apk` is 99.2 KB on x86-64 (40.8 KB at `r5`); the growth comes from the features added since (AP-side measurement, low-power classification, station dumps, learning). Build with `-Os` or split rarely used parts if the limit matters on a target | T-O |

### 5.3 Reliability and availability

| ID | Requirement | Verif. |
|---|---|---|
| NFR-REL-1 | Loss of hostapd, of a peer or of a backhaul path shall not stop the daemon. It shall recover on its own when the resource returns (FR-MON-6, FR-DSC-4, FR-REL-3). | T-O (hostapd restart) |
| NFR-REL-2 | A steering failure shall never leave a STA without a reachable BSS. The daemon only suggests a transition (BTM without Disassociation Imminent by default), and the STA decides. | I |
| NFR-REL-3 | On OpenWrt the service shall be respawned after a crash (procd respawn). | I |

### 5.4 Security

| ID | Requirement | Verif. |
|---|---|---|
| NFR-SEC-1 | Every security option shall be off by default (no `key`, `liveness_check 0`, no signatures, no enrollment) and enabled by configuration; the shipped configurations shall show each one commented out. Authentication is recommended in every deployment; the public example key shall be refused if used. | T-U `test_config` |
| NFR-SEC-2 | With `liveness_check 1`, recorded messages shall not be accepted when replayed across boots or after a peer's removal (FR-DSC-6); within a boot the replay window applies always. | T-U, T-I 22 |
| NFR-SEC-3 | ARCP shall not carry confidential data: no key material (C-2), only MAC addresses and radio metrics. Messages are authenticated, not encrypted. | I |

### 5.5 Portability and maintainability

| ID | Requirement | Verif. |
|---|---|---|
| NFR-POR-1 | The daemon shall build and run on glibc and musl, and cross-compile with the OpenWrt SDK (24.x `.ipk`, 25.x `.apk`). | T-O |
| NFR-MNT-1 | Decision logic and byte layouts shall live in pure modules (`proto`, `rrm`, `policy`, `config`, `sha256`, `sha512`, `ed25519`, `trust`, hostapd parsers) that the unit tests can link without I/O. | I |
| NFR-MNT-2 | Wire numbers shall be defined only in `src/proto.hpp`. A change to the protocol shall update `proto.{hpp,cpp}`, `docs/PROTOCOL.md` and the round-trip tests together. | I |
| NFR-MNT-3 | A change to daemon behaviour shall keep `make itest` passing (PASS 1–5). | T-I |

## 6. Out of scope (version 1.0)

- IEEE 1905.1 / EasyMesh controller–agent operation (C-1).
- Carrying or deriving 802.11r keys (C-2).
- Steering legacy STAs without 802.11v: no deauthentication or
  association-rejection based steering.
- Off-channel listening for unassociated STAs (air monitors hear only their
  own channel), and channel or TX-power planning.
- For MLO (§4.12): Multi-Link elements in neighbor reports and BTM
  candidates, link reconfiguration and TID-to-link mapping. Wide-channel
  operating classes in neighbor reports (20 MHz only).
- A central controller. All decisions are made per AP, by the source AP.

## 7. Verification matrix

Three automated levels: **T-U** unit tests (`make test`, pure modules),
**T-I** integration test (`make itest`: real daemons, mock hostapd, PASS
1–18), **T-O** the QEMU OpenWrt system test (`openwrt/qemu/systest.sh`: real
hostapd, `mac80211_hwsim`, `wpa_supplicant`, S1–S16). Details per scenario:
`docs/features/14-verification.md`.

| Area | Automated coverage | Gaps |
|---|---|---|
| Wire format, HMAC (IR-8/9/10, FR-SEC-1..3) | T-U TLV round trips incl. longer TLVs from newer peers, overflow, HMAC vectors, config; T-I 2; T-O S13 | — |
| Replay window, duplicates (FR-REL-2) | T-U `test_replay_window` (order, duplicates, late within the window, outside, big jump, restart) | — |
| Retransmission, path failover, peer timeout (FR-REL-1/3, FR-DSC) | T-I 19 (a lost STEER_REQ retransmitted, lost STEER_RESPs with `DROPRX`), 1, 6, 10 (peer restart); T-O S13 | Wired ↔ Wi-Fi path failover (two ports): no test |
| 802.11k/v byte layouts (FR-NBR-2, FR-STR-3/6) | T-U `test_rrm`; T-I 1, 3; T-O S2, S4 (real 11k/11v/11r frames) | — |
| hostapd and nl80211 parsers (IR-2, FR-MON-2/3, NFR-PRF-4) | T-U hostapd parsers, station-dump parser (synthetic kernel messages, truncation); T-O S3, S16 | Real driver field variants beyond `mac80211_hwsim` |
| Neighbor database (FR-NBR) | T-I 1, 6; T-O S2, S13 | — |
| Triggers and policy (FR-TRG, FR-POL, FR-ADM-1) | T-U `test_policy`, `test_policy_tput`, freshness, per-STA threshold, Q-learning; T-I 3, 4, 7, 8, 13, 17, 18 in both models; T-O S5, S7, S8 | Calibration of thresholds on real clients |
| Target bandit (FR-STR-11) | T-U context, prior, value, update; T-I 21 (shadow, active reordering, ping-pong; whole itest also with `bandit_target 1`) | Persisting/sharing the table |
| Steering flow (FR-STR) | T-I 3 (remote RSSI roam), 7, 8 (band, 6 GHz), 11, 12 (12 APs, ranked pool), 16, 17 (BTM reject); T-O S4 (manual), S5 (band), S6 (cross-AP, BTM reject, reservation released) | WRONG_TARGET outcome |
| Reservations, admission (FR-ADM) | T-I 3, 4, 19 (released at once by STEER_RESULT when the STA drops in NEGOTIATE or the answer is lost); T-O S6 (released on reject) | Expiry path (8 s) and peer-loss release |
| Load balancing (FR-TRG-3) | T-U overload, admission, feedback rule; T-I 4, 14 (pause when futile) | — |
| AP-side measurement (FR-AMN, IR-13) | T-U radiotap, filter, monitor TLVs, offset learning; T-I 5 (monitor), 11 (driver API, statuses, early end), 16 (offset learning); T-O S9 (real monitor), S14 (exchange) | Vendor driver API (placeholder) |
| Low-power classification (FR-LPC) | T-U `test_low_power`; T-I 10; T-O S15 | Calibration on real IoT devices (SDD R16) |
| MLO (FR-MLO) | T-U `test_mlo`; T-I 9 | Real AP MLD |
| Capacity (NFR-CAP-1) | T-I 12 (12 APs), 15 (17 BSSes: 16 managed); compile-time check that 16 BSSes fit HELLO/BSS_STATUS | 33 APs; message load at 10+ APs |
| Resilience (FR-MON-6, NFR-REL-1) | T-O S10 (hostapd restart) | — |
| OpenWrt service, UCI `bss` lines (IR-7, IR-12) | T-O S11 (interface rename), S12 (strict config); package upgrade with `apk add` | Init script against fixture `ubus` output |

Remaining recommended additions: an itest with two ports (path failover);
reservation expiry and peer-loss release;
real hardware runs (survey utilisation source, station dumps, client
11k/v/r behaviour).

## Appendix A. Configuration parameters and defaults

| Key | Default | Unit / meaning |
|---|---|---|
| `name` | `arcp-ap` | AP name, ≤ 32 characters |
| `ap_id` | MAC of first `iface` | AP identifier; required when only sim ports are used |
| `iface` | — | L2 port, repeatable (≤ 8) |
| `sim_port`, `sim_peer` | — | UDP test transport |
| `key` | none | `hex:<≥32 hex digits>` or passphrase ≥ 8 characters |
| `bss <ifname> [mdid=<hex>] [max_sta=<n>] [ft_over_ds=1]` | — | Managed BSS, repeatable (≤ 16; further valid lines are ignored with a warning). `<ifname>` is hostapd's control socket name: the netdev, or `<netdev>_link<id>` for an AP MLD link (≤ 22 characters) |
| `hostapd_ctrl_dir` | `/var/run/hostapd` | |
| `ctrl_socket` | none | Control socket path |
| `hello_interval_ms` / `bss_status_interval_ms` / `sta_status_interval_ms` / `rf_status_interval_ms` | 2000 / 5000 / 10000 / 10000 | ms |
| `sta_poll_interval_ms` / `peer_timeout_ms` | 1000 / 7000 | ms |
| `rssi_steering` / `band_steering` / `load_balancing` | 1 / 1 / 1 | on/off |
| `roam_thr_learn` / `roam_thr_min` / `roam_thr_max` | 1 / −82 / −65 | bool / dBm / dBm |
| `rl_roam` / `rl_epsilon_pct` | 0 / 1 | 0 off, 1 shadow, 2 active / % |
| `bandit_target` / `bandit_epsilon_pct` | 0 / 5 | 0 off, 1 shadow, 2 active / % |
| `rssi_low` / `rssi_low_count` / `rssi_hysteresis` / `rssi_min_target` | −75 / 3 / 8 / −70 | dBm / samples / dB / dBm |
| `band_steer_rssi` | −55 | dBm |
| `band_steer_6g` | 1 | on/off: 5 → 6 GHz band steering |
| `band_steer_6g_rssi` | −55 | dBm |
| `util_high` / `util_admit_max` / `lb_margin` | 70 / 80 / 15 | % |
| `lb_rssi_tolerance` / `lb_only_idle` / `idle_kbps` / `lb_interval_ms` | 5 / 1 / 50 / 10000 | dB / bool / kbit/s / ms |
| `lb_min_drop_pct` / `lb_max_futile` / `lb_hold_ms` | 3 / 2 / 300000 | % points / moves / ms |
| `util_weight` / `band_bonus_5g` / `band_bonus_6g` | 2 / 5 / 8 | score points |
| `steer_cooldown_ms` / `steer_backoff_max_ms` | 30000 / 600000 | ms |
| `beacon_req_timeout_ms` / `steer_resp_timeout_ms` / `btm_timeout_ms` / `roam_timeout_ms` / `reserve_hold_ms` | 1500 / 1000 / 2000 / 5000 / 8000 | ms |
| `btm_valid_int` / `disassoc_imminent` / `disassoc_timer` | 100 / 0 / 0 | TBTT / bool / TBTT |
| `beacon_mode` / `beacon_duration` | 1 (active) / 50 | 0 passive, 1 active, 2 table / TU |
| `assume_kvr` | 1 | treat STAs as 11k/v/r capable unless shown otherwise |
| `air_monitor` / `air_monitor_sim` | — | Monitor interface, repeatable (≤ 4) / UDP test input |
| `amon_request` / `amon_duration_ms` / `amon_rssi_offset` | 1 / 1000 / 0 | bool / ms / dB (used until a BSS's offset is learned) |
| `amon_offset_learn` / `amon_offset_min_samples` | 1 / 3 | bool / samples |
| `sta_rssi_api` / `sta_rssi_sim` | 0 / — | measure STAs with the driver's per-STA RSSI API / test: simulated driver file (implies `sta_rssi_api 1`) |
| `score_model` / `tput_rssi_mid` / `tput_gain_pct` / `sta_nss` | 0 (linear) / −72 / 150 / 2 | 0 linear, 1 expected throughput / dBm / % / streams |
| `lp_classify` / `lp_no_steer` | 1 / 1 | low-power classification / keep low-power STAs out of automatic steering |
| `lp_threshold` / `lp_hysteresis` / `lp_score_max` / `lp_min_samples` | 60 / 10 / 120 / 10 | θ (polls) / θ / θ / samples |
| `lp_alpha_2g` / `lp_alpha_5g` / `lp_alpha_6g` | 100 / 100 / 100 | α × 100 |
| `lp_max_mean_bps` | 20000 | bytes/s; recent uplink rate above which S is not evidence (0: off) |
| `lp_exclude_vht` / `lp_exclude_he` / `lp_exclude_eht` | 1 / 0 / 1 | a STA with this PHY is never low-power |

## Appendix B. Revision history

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-30 | First issue |
| 1.1 | 2026-10-31 | Product renamed DongHoa (`donghoa`, `donghoa_cli`, `/etc/donghoa.conf`; protocol still ARCP). New FR-POL-4 (expected-throughput scoring, opt-in) and its configuration keys. FR-STR-3: one Beacon Request covering all candidate channels. New IR-12 (OpenWrt `bss` lines from UCI). Updated measurements (NFR-CAP-2/3, §5.1) and the verification matrix |
| 1.2 | 2026-10-31 | Air monitor: new §4.11 (FR-AMN-1..6) and IR-13; FR-STR-4 and AS-1 use monitor levels when the STA gives no 802.11k report; `MONITOR` control command; out-of-scope narrowed to off-channel listening; updated capacity figures, verification matrix and configuration appendix |
| 1.3 | 2026-10-31 | IR-5: per-module log levels, `log_level`/`log_debug` keys, run-time `LOG` command, syslog output (`-s`) with real priorities, ARCP frame trace; IR-3: `LOG` command; FR-STR-3 / FR-MON-3: beacon-report mode fallback (active → passive) |
| 1.4 | 2026-11-01 | C-3: implementation language C++17 without exceptions, RTTI or heap, MISRA C++:2023 based convention; C-4: no libstdc++.so at run time; NFR-CAP-2 re-measured (247,720 bytes). No functional requirement changed |
| 1.5 | 2026-11-06 | New §4.13 (FR-LPC-1..5): low-power (IoT) device classification from traffic behaviour, shared between APs (STA_CLASS); `DEVCLASS` control command (IR-3); configuration keys `lp_*`; NFR-CAP-1/2 updated (315,808 bytes) |
| 1.6 | 2026-11-06 | FR-LPC-1: recent-uplink-rate gate (`lp_max_mean_bps`); FR-LPC-4: sync also carries corrections back to normal; new FR-LPC-6 (PHY exclusion, `lp_exclude_vht/he/eht`) |
| 1.7 | 2026-11-06 | AP-side measurement: STA_MONITOR_REQ multicast to every peer (FR-AMN-2), every AP answers with STA_MONITOR_STATUS (FR-AMN-3), MEASURE ends when all have answered (new FR-AMN-7), driver per-STA RSSI API placeholder (new FR-AMN-8); keys `sta_rssi_api`, `sta_rssi_sim` |
| 1.8 | 2026-11-06 | FR-LPC-1: an idle poll (no data either way) is no evidence (an idle STA was classified low-power on the QEMU testbed) |
| 1.9 | 2026-11-06 | FR-STR-2: ranked candidate pool when more than 16 BSSes qualify (measured first, then own, then rotating peer order); verified with 12 APs (itest PASS 12) |
| 2.0 | 2026-11-06 | FR-TRG-1: only fresh signal samples count (idle STA); FR-STR-3: MEASURE's 11k part ends after a quiet period following the last report; STATUS shows each BSS's utilisation source (`util_src`) |
| 2.1 | 2026-11-06 | FR-TRG-3: load-balancing feedback and pause (`lb_min_drop_pct`, `lb_max_futile`, `lb_hold_ms`); NFR-PRF-4: per-STA metrics from nl80211 station dumps, hostapd listing every 10 s |
| 2.2 | 2026-11-07 | NFR-CAP-1: 16 local BSSes and 16 per peer (was 8); `bss` lines beyond the limit ignored with a warning instead of a fatal error; NFR-CAP-2 re-measured (391,424 bytes) |
| 2.3 | 2026-11-07 | New FR-AMN-9 (uplink/downlink offset learned per BSS); FR-AMN-4 uses it; IR-3: `CALIB`; keys `amon_offset_learn`, `amon_offset_min_samples` |
| 2.4 | 2026-11-07 | New FR-TRG-7 (per-STA roaming threshold learned from outcomes and own roams, shared over ARCP); FR-TRG-1 uses it; keys `roam_thr_learn`, `roam_thr_min`, `roam_thr_max` |
| 2.5 | 2026-11-07 | New FR-TRG-8 (Q-learning of when to roam: shadow by default, active on request); IR-3: `RL`; keys `rl_roam`, `rl_epsilon_pct` |
| 2.6 | 2026-11-07 | FR-TRG-8: Q-learning off by default (`rl_roam` 0); enabled by configuration or `RL mode <n>` |
| 2.7 | 2026-11-07 | Documentation audit: §2.2 product functions brought up to date; IR-5 lists the `class` module; NFR-CAP-1 lists every table, NFR-CAP-2 re-measured (449,352 bytes); FR-REL-2 now unit-tested; §5.1 measurements updated; §7 verification matrix rewritten for the three test levels |
| 2.8 | 2026-11-08 | FR-STR-8: STEER_RESULT once a STEER_REQ went out (aborted included); FR-TRG-3: a disconnected offload gives no verdict; IR-3: `DROPRX`; verification matrix updated (T-I 19, 20) |
| 2.9 | 2026-11-08 | New FR-STR-11 (contextual bandit for the target, off by default); IR-3: `BANDIT`; keys `bandit_target`, `bandit_epsilon_pct`; NFR-CAP-1 tables |
| 2.10 | 2026-11-08 | Security review: FR-DSC-6 (liveness CHALLENGE / RESPONSE before adopting a boot), FR-SEC-3 (PBKDF2 passphrase keys), NFR-SEC-1 (example key refused), NFR-SEC-2 (replay closed) |
| 2.11 | 2026-11-08 | New FR-SEC-6, FR-SEC-7 (per-AP Ed25519 signatures, `sign_seed`, `peer_key`, `donghoa -g`); IR-8 payload 1450 bytes |
| 2.12 | 2026-11-08 | New FR-SEC-8..11 (automatic key enrollment: keys created, requests, approval by fingerprint, trust table sync and persistence, welcome); IR-3: `ENROLL` |
| 2.13 | 2026-11-08 | Security off by default: `liveness_check` (FR-DSC-6, NFR-SEC-2), shipped configurations without `key` (NFR-SEC-1) |
