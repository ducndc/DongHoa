# DongHoa — Software Design Description

| | |
|---|---|
| Product | DongHoa 1.0: daemon `donghoa` and CLI `donghoa_cli` |
| Document version | 2.9, 2026-11-08 (history in §13) |
| Requirements | `docs/SRS.md` (requirement IDs are cited in brackets) |
| Related | `docs/PROTOCOL.md` (normative wire format, not repeated here), `docs/ARCHITECTURE.md` (short overview), `openwrt/README.md` |

## 1. Introduction

This document describes how `donghoa` meets `docs/SRS.md`: its structure, data,
runtime behaviour, algorithms, error handling, deployment and the reasons
behind the main design choices. It describes the code as of version 1.0,
OpenWrt package `donghoa-1.0-r9`: about 8,000 lines of C++17 in `src/` and
`tools/`, built without exceptions, RTTI or heap. Function and file names are
given so each section can be checked against the source.

## 2. Design goals and constraints

| Goal | Derived from | How the design meets it |
|---|---|---|
| Run on small embedded APs | C-4, C-5, NFR-CAP-2 | C++17 linked against libc only (no libstdc++.so), no heap, about 242 KiB of fixed state in `.bss`, one process |
| Predictable behaviour | C-6, NFR-PRF-4 | One thread, one `poll()` loop, every blocking call bounded |
| Use only standard 802.11 mechanisms toward STAs | §1.2 | All 802.11 frames are sent by hostapd: 11k Beacon Request, 11v BTM, 11r left to hostapd and the STA |
| Work over any backhaul | IR-8, FR-REL-3 | Raw Ethernet on every port; per-peer path learning |
| Testable without hardware or root | NFR-MNT-1, IR-11 | Pure modules for unit tests; UDP "sim" transport and mock hostapd for the itest; QEMU/hwsim for OpenWrt |
| Fail safe | NFR-REL-2 | The daemon only suggests transitions; on any doubt it gives up and backs off |

## 3. Architectural design

### 3.1 Context and layering

```
                         +----------------------------------------------------+
 ARCP peers  <------->   | l2.cpp --> msg.cpp --> peer.cpp               ctrl.cpp     |<--> donghoa_cli
 (Ethernet 0x88B5)       |            |          |                            |
                         |            v          v                            |
                         |          steer.cpp <-- policy.cpp (pure)               |
                         |            |                                       |
                         |          local.cpp  (BSS/STA tables, events, NR)     |
                         |          /      \                                  |
                         |     hapd.cpp     survey.cpp     amon.cpp (air monitor)   |
                         +-------|------------|------------|------------------+
                              hostapd      nl80211     monitor interfaces (radiotap)
     pure, unit-tested: text  proto  rrm  policy  config  sha256  sha512  ed25519  trust  hapd_parse
                        (all I/O via os.cpp)
```

The modules fall into three layers:

1. **Pure layer:** encoding, decoding, 802.11 byte layouts, policy, config
   parsing and hashing. No I/O and no global state. These are the only
   modules `tests/test_unit.cpp` links (with `log.cpp` and `os.cpp`).
2. **I/O adapters:** `l2.cpp` (class `L2`: raw and sim sockets), `hapd.cpp`
   (class `hapd::Conn`: hostapd control socket), `survey.cpp` (class
   `Survey`: nl80211 generic netlink), `amon.cpp` (radiotap monitor sockets
   and STA watches) and `ctrl.cpp` (operator socket).
3. **Coordination:** `msg.cpp` (messaging), `peer.cpp` (remote view),
   `local.cpp` (local view) and `steer.cpp` (transactions). They are member
   functions of class `Daemon` (`src/daemon.hpp`), whose definition is split
   across these files. The only instance is a static object in `main.cpp`.

Below all of them, **`os.cpp`** is the single file that calls POSIX and
Linux interfaces (sockets, `poll`, `ioctl`, signals, clock, syslog) and
holds the casts and `memcpy` those interfaces need. The rest of the code
sees `os::Fd` (an owning descriptor, closed by its destructor),
`ByteView`/`ByteSpan` and `std::string_view`. This confines the MISRA C++
deviations DEV-01..04 (`docs/CODING_CONVENTION.md` §6.2) to one file.

### 3.2 Module catalogue

| Module | Layer | Responsibility | Key entry points | SRS |
|---|---|---|---|---|
| `main.cpp` | coord. | Start-up, event loop, timer dispatch, shutdown | `main`, `Daemon::init`, `Daemon::run`, `runTimers`, `shutdown` | C-6, NFR-PRF-1, FR-DSC-5 |
| `os.{hpp,cpp}` | system | Every POSIX/Linux call: clock, randomness, signals, files, UNIX/packet/UDP/netlink sockets, BPF, syslog; `Fd` RAII | `os::nowMs`, `os::Fd`, `os::pollReadable`, `os::openPacket`, `os::sendUnixRequest`, `os::recvNetlink`, `os::stopRequested` | C-4, C-6 |
| `types.hpp` | pure | `Mac`, `ByteView`/`ByteSpan`, big/little-endian get/put, `FixedString<N>` | `getBe16`, `putBe32`, `copyBytes`, `equal` | — |
| `text.{hpp,cpp}` | pure | Type-safe `{}` formatting, hex, checked number parsing (`std::from_chars`), MAC and key=value parsing, tokenizer | `formatTo`, `hex`, `parseLong`, `parseU64`, `parseMac`, `getKv`, `subView`, `Tokens` | IR-1 |
| `proto.{hpp,cpp}` | pure | ARCP header and TLV encode/decode, HMAC finish/verify, TLV iterator (namespace `arcp`) | `Message::begin/add/finish`, `parseHeader`, `verify`, `TlvReader`, `decode` | IR-8..10, FR-SEC-1..2,4 |
| `sha256.{hpp,cpp}` | pure | SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 | `Sha256`, `computeHmacSha256`, `pbkdf2Sha256` | FR-SEC-1,3 |
| `sha512.{hpp,cpp}` | pure | SHA-512 (for Ed25519) | `Sha512`, `computeSha512` | FR-SEC-6 |
| `ed25519.{hpp,cpp}` | pure | Ed25519 key pair, sign, verify (RFC 8032) | `keyPairFromSeed`, `sign`, `verify`, `isValidPublicKey` | FR-SEC-6,7 |
| `trust.{hpp,cpp}` | pure | Enrollment trust table: merge rule, approve / revoke, fingerprint, file form | `merge`, `approve`, `revoke`, `trustedKey`, `fingerprint`, `saveText`, `loadText` | FR-SEC-9,10 |
| `enroll.cpp` | coord. | Automatic key enrollment: seed file, ENROLL_REQ, pending list, welcome, TRUST sync, `ENROLL` | `initEnroll`, `tickEnroll`, `onUntrusted`, `onTrust`, `sendWelcome`, `cmdEnroll` | FR-SEC-8..11 |
| `rrm.{hpp,cpp}` | pure | Frequency/channel/op class mapping, BSSID Information, Neighbor Report and Beacon Request/Report layouts (single- and multi-channel requests), radiotap + 802.11 frame parser for air monitors, capability helpers | `rrm::buildNrHex`, `buildBcnReqHex`, `parseBcnRepHex`, `parseRadiotap`, `isFtAkm`, `hasBtmCapab` | IR-9, FR-NBR-2, FR-STR-3 |
| `policy.{hpp,cpp}` | pure | Triggers, scoring (linear and expected-throughput models), admission, backoff, low-power classification arithmetic | `policy::score`, `computeLinkQuality`, `computePeakMbps`, `computeExpectedKbps`, `triggers`, `admit`, `backoffMs`, `addTrafficSample`, `lpBehaviourScore`, `updateLpScore`, `isLowPower` | FR-POL, FR-TRG, FR-ADM-1, FR-STR-9, FR-LPC-1..2 |
| `consistency.{hpp,cpp}` | pure | Configuration consistency: BSS-pair findings (mobility domain, FT, security), steering settings summary (POLICY TLV) and their differences | `checkPair`, `summarize`, `diffPolicy`, `describePolicyDiff` | FR-OBS-2 |
| `metrics.{hpp,cpp}` | pure | Outcome counters, update rule, Prometheus text form | `addOutcome`, `formatBss`, `formatArcp` | FR-OBS-1 |
| `nlparse.{hpp,cpp}` | pure | nl80211 attribute lookup and station-dump entry parsing | `nl::findAttr`, `nl::parseStation` | NFR-PRF-4 |
| `config.{hpp,cpp}` | pure | Defaults (default member initializers) and line parser with pointer-to-member key tables | `parseConfigLine`, `loadConfig` | IR-1, FR-SEC-3 |
| `log.{hpp,cpp}` | pure | Logging with a level per module (`LogModule`); disabled levels skip formatting; stderr or syslog (`-s`) | `logging::info/dbg/…`, `setLevel`, `parseLevel`/`parseModule`, `useSyslog` | IR-5 |
| `hapd_parse.{hpp,cpp}` | pure | STATUS/STA/BTM-response parsers (namespace `hapd`) | `hapd::parseStatus`, `parseSta`, `parseBtmResp` | IR-2 |
| `l2.{hpp,cpp}` | I/O | `AF_PACKET` ports and UDP sim ports | `L2::addIface`, `addSim`, `send`, `recv` | IR-8, IR-11 |
| `hapd.{hpp,cpp}` | I/O | hostapd command and event sockets | `hapd::Conn::open`, `runCommand`, `recvEvent` | IR-2 |
| `survey.{hpp,cpp}` | I/O | Minimal genetlink client for `NL80211_CMD_GET_SURVEY`, asynchronous, one dump per radio | `Survey::open`, `findWiphy`, `request`, `onReadable`, `tick`, `find`, `util` | IR-6, FR-MON-4, NFR-PRF-4 |
| `amon.cpp` | I/O + coord. | AP-side STA measurement: BPF-filtered radiotap sockets and the driver per-STA RSSI API, STA watches on request, STA_MONITOR_REQ/REPORT/STATUS, results into the STA's measurements | `initAmon`, `receiveAmon`, `startAmonWatch`, `tickAmon`, `onAmonReq`, `onAmonResult` | FR-AMN, IR-13 |
| `vendor_rssi.cpp` | I/O | Driver per-STA RSSI API behind four calls; vendor placeholder (TODO) and a file-backed simulation for tests | `isStaRssiSupported`, `startStaRssi`, `readStaRssi`, `stopStaRssi`, `useSimFile` |
| `ctrl.cpp` | I/O | Operator command socket | `openCtrl`, `handleCtrl`, `runCtrlCommand` | IR-3 |
| `rrm_log.cpp` | I/O (log only) | Debug dump (log module `rrm`) of the 802.11k/v commands sent to hostapd, their replies and the 11k/v events, decoded | `rrmlog::logCommand`, `logEvent` | IR-5 |
| `msg.cpp` | coord. | Periodic messages, reliable unicast, RX dispatch, path learning | `send*`, `unicast`, `retransmit`, `receiveMsg` | FR-DSC-1,3, FR-STE-1..4, FR-REL |
| `peer.cpp` | coord. | Peer table, replay window, remote BSS/STA, expiry | `getPeer`, `acceptPeerSeq`, `updatePeerBss`, `expirePeers`, `removePeer` | FR-DSC-4,6,7, FR-STE-5 |
| `local.cpp` | coord. | BSS and STA polling, hostapd events, neighbor DB sync | `pollBss`, `pollStas`, `handleEvent`, `syncNeighbors` | FR-MON, FR-NBR, FR-STE-4 |
| `steer.cpp` | coord. | Source-side state machine, target-side admission and reservations | `startSteer`, `tickSteer`, `on*` handlers, `runLbRound` | FR-TRG, FR-STR, FR-ADM |
| `check.cpp` | coord. | Consistency check every 10 s against the peers, log on change, `CHECK` | `checkConsistency`, `cmdCheck`, `countIssues` | FR-OBS-2 |
| `devclass.cpp` | coord. | Low-power device classification per local STA, device class table, STA_CLASS exchange | `sampleTraffic`, `restoreDevClass`, `saveDevClass`, `onStaClass`, `onPeerStaAssoc`, `syncDevClass` | FR-LPC |
| `tools/donghoa_cli.cpp` | tool | One-shot control client (links `text.cpp` and `os.cpp` only) | `main` | IR-4 |

## 4. Runtime design

### 4.1 Start-up and shutdown

```
main: parse -c/-d/-s -> Daemon::init:
   -> config_load into a default-initialized Config (exit on error, IR-1)
   -> log levels (log_level, log_debug, -d)
   -> setup_transport: L2::add_iface per 'iface'; ap_id = cfg or first port MAC;
                       L2::add_sim when sim_port is set
   -> boot_id = os::randomU32() (non-zero; fallback: time ^ pid)
   -> local_init (BSS slots, ifindex, Survey::open) -> ctrl_open -> amon_init
   -> SIGINT/SIGTERM set the stop flag; SIGPIPE ignored
   -> Daemon::run()
   -> Daemon::shutdown: send_bye -> close hostapd and ctrl sockets
      (the remaining os::Fd members close when the process exits)
```

All `next_*` timers start at 0, so the first loop pass polls hostapd and sends
every periodic message at once.

### 4.2 Event loop

`Daemon::run()` rebuilds the descriptor list for `os::pollReadable` on each pass. The array holds every L2
port, the event socket of every connected hostapd, and the control socket.
It calls `poll()` with a 100 ms timeout [NFR-PRF-1], then:

1. L2 port readable: `receiveMsg(port)` drains every queued frame.
2. hostapd event socket readable: drain events into `handleEvent`. A
   receive error closes that hostapd connection.
3. Control socket readable: `handleCtrl`.
4. Monitor socket readable: `receiveAmon(port)` drains frames into the watches.
5. Always: `runTimers(now)`.

`runTimers` dispatches:

| Timer | Period (default) | Action |
|---|---|---|
| `mNextStaPoll` | `sta_poll_interval_ms` (1 s) | `pollBss` then `pollStas`, which runs the RSSI/band triggers |
| `mNextHello` | 2 s | `sendHello` |
| `mNextBssStatus` | 5 s | `sendBssStatus` |
| `mNextStaStatus` | 10 s | `sendStaStatus` |
| `mNextRfStatus` | 10 s | `sendRfStatus` |
| `mNextLb` | `lb_interval_ms` (10 s) | `runLbRound` |
| every pass | ≤ 100 ms | `tickSteer` (transaction deadlines, reservation expiry), `tickAmon` (finished watches → reports), `retransmit`, `expirePeers` |

### 4.3 Blocking calls and worst-case latency

The loop has one thread, so a blocking call delays everything else. The
blocking calls are:

| Call | Bound | Effect when the bound is hit |
|---|---|---|
| `hapd::Conn::runCommand` (send + wait for reply) | 1 s (`CMD_TIMEOUT_MS`) | Connection closed; BSS marked down at the next poll; reconnect after 5 s |
| `hapd::Conn::open` ATTACH reply | 1 s | Open fails; retried after 5 s |
| `Survey::findWiphy` reply (only when a BSS comes up) | 0.5 s | No wiphy: hostapd utilisation used for that BSS |
| Survey dump in flight (not waited for: read from the main `poll()`) | 1 s (`DUMP_TIMEOUT_MS`), checked by `Survey::tick` | Dump abandoned, socket reopened (ends the kernel's dump, drops late replies); hostapd utilisation used until a fresh sample |

A healthy hostapd answers in well under a millisecond, so one poll costs about
(1 + STAs) command round trips per BSS. If hostapd hangs, each BSS can stall
the loop for at most 1 s per poll cycle. The connection is then closed, which
stops further stalls until the reconnection 5 s later. Transaction deadlines
are checked against the monotonic clock, so a stall delays a timeout but never
loses it.

## 5. Data design

### 5.1 Global state

All state lives in one statically allocated `Daemon` object (`daemon.hpp`, `main.cpp`) [C-5],
as `std::array` members. Measured sizes on x86-64:

| Table | Capacity | Bytes | Notes |
|---|---|---|---|
| `sta[]` — local STAs | 256 | 124,928 | Includes a 16-entry beacon-report cache per STA |
| `pending[]` — reliable TX queue | 32 | ~47,900 | Each holds a full 1450-byte frame for retransmission |
| `peers[]` | 32 | — | Each holds 16 remote BSSes and 4 RF entries |
| `txn[]` — steering transactions | 16 | 22,656 | Each holds 16 candidates |
| `rsta[]` — remote STA locations | 512 | 16,384 | |
| `resv[]` — reservations | 32 | 1,280 | |
| `watch[]` — air monitor watches | 16 | 2,048 | Up to 4 frequencies each |
| `bss[]`, config, L2 ports, etc. | 16 BSS / 8 ports | remainder | |
| **Total** `sizeof(Daemon)` | | **470,760** | Re-measured in v2.14 (`nm -S`, x86-64; includes the 64-entry `peer_key` table and the outcome counters, ~5.5 KB per 16 BSSes); the per-table figures above date from v1.4 |

Lookups are linear scans. With these sizes a scan costs microseconds, and it
avoids hash tables and allocation. Each table entry has a `used` flag. Free
slots are found by scanning, and running out is logged [NFR-CAP-1].

### 5.2 Entity lifecycles

| Entity | Created | Updated | Removed |
|---|---|---|---|
| Peer | First valid message from a new origin (`getPeer`) | Each new message: `lastSeen`, path; `boot_id` change resets sequence state | Silence > `peer_timeout_ms`, or BYE → `removePeer` (NR entries, remote STAs, steering, reservations) |
| Remote BSS | BSS_INFO in HELLO/BSS_STATUS | Each BSS_INFO (`ts`); a content change clears `nrInstalled`; BSS_LOAD sets `load` | Not advertised for 3 × BSS-status period + hello period, or peer removed → `REMOVE_NEIGHBOR` |
| Remote STA | STA_ENTRY or STA_EVENT(assoc) from a peer | Same | STA_EVENT(disassoc), local association of the STA, 3 × STA-status period, peer removed |
| Local BSS | Config (`initLocal`) | Each poll: info, load, `up` | Never; marked down on hostapd loss and up again on reconnect |
| Local STA | Authorised in `STA-FIRST/NEXT`, or `AP-STA-CONNECTED` (`getSta`, with initial cooldown) | Each poll (`applyStaSample`); move between local BSSes resets RSSI and the beacon cache | `AP-STA-DISCONNECTED`, missing from a poll, BSS down |
| Transaction | `startSteer` | State machine (§6.6) | `endTxn` / `failTxnNoCandidate` |
| Reservation | Accepted STEER_REQ | — | Local association of the STA, STEER_RESULT, expiry, source peer lost |
| Pending TX | `unicast` with ACK_REQ | Each retransmission | ACK received, 4th transmission unacknowledged, or peer unreachable |
| Monitor watch | STA_MONITOR_REQ from a peer, a local steer (`requestMonitors`) or `MONITOR` | Each matching frame adds to the per-frequency sum | Watch time over (`tickAmon` → report) |

## 6. Component design

### 6.1 L2 transport (`l2.cpp`) [IR-8, IR-11]

- **Real port:** an `AF_PACKET`/`SOCK_RAW` socket bound to the interface and
  EtherType 0x88B5, joined to the ARCP multicast group with
  `PACKET_ADD_MEMBERSHIP`. The port MAC comes from `SIOCGIFHWADDR`.
- **Sim port:** a UDP socket on 127.0.0.1:`sim_port`. Each send goes to every
  `sim_peer`. The payload is the same 14-byte Ethernet header plus ARCP
  payload, so every layer above `l2.cpp` behaves exactly as with raw sockets.
- **Receive filter (`l2_recv`):** it drops a frame that is outgoing, has the
  wrong EtherType, is addressed to neither the port MAC nor the group
  address, or carries the port's own MAC as source. Frames are copied up to
  the buffer size; a longer frame is truncated, and the ARCP header check then
  rejects it.

### 6.2 Messaging (`msg.cpp`, `proto.cpp`) [FR-REL, FR-SEC, FR-STE]

**Encoding.** `beginMsg` writes the 24-byte header with the next `msg_id` and
this boot's `boot_id`. TLVs are appended with `Message::add`, which reserve room
for the SIG and AUTH TLVs and set `overflow` instead of writing past 1450 bytes.
`Message::finish` sets `body_len` and, when a key is configured, sets the AUTH
flag and appends `HMAC-SHA256(key, header ‖ TLVs)` truncated to 16 bytes. An
overflowed message is never sent.

**Multicast:** sent on every port. **Unicast:** sent on the port and to the
L2 address learned for that peer; an unknown or unreachable peer is an error
to the caller.

**Reliable unicast [FR-REL-1].** A message with ACK_REQ is copied into
`pending[]` with `tries = 1` and `next_try = now + 300 ms`. On each loop pass,
`retransmit` resends due entries with the same `msg_id`. It gives up and
logs once 4 transmissions are unacknowledged, or when the peer is gone. An
ACK TLV clears the matching `(peer, msg_id)` entry.

**Receive path (`receiveMsg`):**

```
frame -> arcp::parse_header (magic, version 1, body fits)  -- else drop
      -> origin == own ap_id                            -- drop
      -> arcp::verify (key policy, constant-time compare) -- drop + debug log
      -> BYE: if sequence is new -> peer_remove; done
      -> peer_get (create; table full -> drop)
      -> peer_accept_seq(boot_id, msg_id)
           duplicate -> re-ACK if ACK_REQ; done        [FR-REL-2]
      -> path learning: p->port = rx port, p->l2addr = Ethernet source [FR-REL-3]
      -> ACK if ACK_REQ
      -> rx_tlvs: dispatch each TLV (unknown types ignored [IR-10])
      -> new peer: next_hello = next_bss_status = 0 (introduce ourselves) [FR-DSC-3]
```

**Replay window (`acceptPeerSeq`).** `seqHi` is the highest `msg_id`
accepted and `seq_win` a 64-bit bitmap, where bit *i* means `seq_hi − i` has
been seen. A higher id shifts the window. An id inside the window is accepted
once. An id older than 64 is rejected. A message of any
`boot_id` other than the verified one is refused by the window. The receive
path then sends a CHALLENGE (16-byte nonce, `mChal`, 8 slots, one per origin
per 500 ms); a RESPONSE carrying the nonce within 3 s adopts its `boot_id`
(`arcp::resetSeq`) and creates the peer or logs a restart. A CHALLENGE is
answered by anyone, and the answerer re-sends HELLO/BSS_STATUS (≤ 1/s).

**TLV dispatch (`handleTlvs`):**

| TLV | Handling |
|---|---|
| AP_INFO | Store the peer name |
| BSS_INFO | `updatePeerBss`; if not yet installed → `syncNeighbors` after the message |
| BSS_LOAD | Attach load to the remote BSS (`has_load`) |
| STA_ENTRY | `updateRemoteSta` |
| RF_INFO | Replace the peer's RF list (≤ 4) |
| STA_EVENT | Update or forget the remote STA, then `onStaEvent` |
| STEER_REQ / RESP / RESULT | `onSteerReq` / `onSteerResp` / `onSteerResult` |
| ACK | `onAckReceived` |

**Splitting.** `sendStaStatus` starts a new message whenever the next
STA_ENTRY would not fit (`Message::room`), so any number of STAs (≤ 256) is
reported [FR-STE-2].

### 6.3 Peer management (`peer.cpp`) [FR-DSC, FR-STE-5]

`expirePeers` runs on every loop pass:
- it removes peers silent for longer than `peer_timeout_ms`;
- it removes remote BSSes no longer advertised, deleting their neighbor
  entries;
- it ages out remote STAs.

`removePeer` calls `onPeerLost` first:
- transactions negotiating with that peer move to their next candidate;
- reservations held for that peer are released.

It then removes the neighbor entries and remote STAs.

### 6.4 Local monitoring (`local.cpp`, `hapd.cpp`, `survey.cpp`) [FR-MON]

**hostapd connection.** `hapd::Conn::open` creates two client sockets per BSS: a
command socket and an event socket that has sent `ATTACH`. Each is bound at
`/tmp/donghoa-<pid>-<ifname>-<c|e><n>`. After `bind`, ownership is copied from
hostapd's socket, so a hostapd running as another user (OpenWrt: `network`)
can deliver its replies [IR-2]. Unsolicited `<N>` messages arriving on the
command socket are skipped.

**BSS refresh (`refreshBss`, every poll):**
1. `STATUS`, parsed for this ifname: freq → channel/band, BSSID, SSID,
   `num_sta`, TX power, HT/VHT/HE/EHT, width. On the transition to up, also
   `GET_CONFIG`: `secured` from `wpa`, and a warning when `mdid` is set but no
   FT AKM is configured.
2. Build `bss_info`. Capabilities always include BTM, RRM-NR and RRM-Beacon:
   the deployment must enable them in hostapd (documented). Then the 20 MHz
   op class, PHY type and BSSID Information.
3. Utilisation. The nl80211 survey gives Δbusy / Δactive × 255 between two
   samples on the same frequency. Without it, hostapd's `chan_util_avg` is
   used. The value is clamped to 254, smoothed with an EWMA of ¾ old value,
   and 255 means unknown [FR-MON-4].
   The survey is asynchronous and per radio. When a BSS comes up, its
   ifindex and wiphy are looked up again (`NL80211_CMD_GET_INTERFACE`;
   hostapd may have recreated the interface). Each poll uses the sample of
   the dump requested on the previous poll and then calls
   `Survey::request(wiphy, ifindex)`; BSSes of one wiphy share one dump. The
   reply is read in the main loop (`Src::SURVEY`). A sample older than
   3 × `sta_poll_interval_ms` + 1 s counts as no survey. Counters that do not
   grow (a driver that clears them on read) fall back to hostapd.
   The kernel runs the driver's `get_survey`, once per channel of the
   radio, inside the `sendto()`/`recv()` calls, so a slow driver still holds
   the loop for that time. It is measured per dump and shown in `STATUS`
   (`survey=nl80211 … last_us= max_us=`); a dump over 20 ms is logged once.
4. `bss_load`, including `accepting` = `policy::admit(...) == ACCEPT` with the
   current reservations counted [FR-ADM-2].
5. If the BSS came up or its info changed, clear every remote
   `nrInstalled` flag and run `syncNeighbors`.

**STA poll (`pollStas`):** two sources.
- *nl80211 station dump* (default when nl80211 is there and the BSS is not
  an AP MLD link): `pollStas` only queues `NL80211_CMD_GET_STATION` for the
  BSS's interface (`Survey::requestStations`, the same one-dump-in-flight
  queue as the survey). When the dump completes, the main loop calls
  `processStationDumps`: authorised stations (`nl::parseStation`, pure, in
  `nlparse.cpp`) get `applyStaSignal` (the kernel's `signal avg` when
  present) and `applyStaTraffic`; a STA seen for the first time on the BSS
  gets one hostapd `STA <addr>` for its capabilities. Unlisted STAs are
  pruned and the listed ones go to `onStaPoll` there. Measured on QEMU: 6
  hostapd STA round trips per 20 s instead of one per STA per BSS per
  second; a dump holds the loop ≤ 110 µs.
- *hostapd listing* every `STA_RESYNC_MS` (10 s), on the first poll, for
  AP MLD links, without nl80211, or after two dumps in a row that did not
  complete (`nlMissed`): walk `STA-FIRST`/`STA-NEXT`, at most 256 per BSS,
  and keep only `[AUTHORIZED]` STAs.
- `applyStaSample` updates RSSI (EWMA ¾, rounded), the low-sample count,
  throughput from Δbytes, rates and inactivity, and derives the capability
  flags [FR-MON-3].
- STAs of that BSS not seen in this poll are removed [FR-MON-5].
- Each STA seen in this poll then goes to `onStaPoll` (triggers).

**Events (`handleEvent`):**

| Event | Handling |
|---|---|
| `AP-STA-CONNECTED` | Create the STA, clear `away`, forget it as remote, multicast STA_EVENT(assoc), feed `onStaEvent` locally |
| `AP-STA-DISCONNECTED` | Ignored if the STA now belongs to another local BSS (move between local BSSes); otherwise multicast STA_EVENT(disassoc), `onLocalDisassoc`, remove |
| `BEACON-RESP-RX` | Parse the report body; a non-zero report mode or an unparsable body counts as "no report" |
| `BSS-TM-RESP` | Parse status and target BSSID → `onBtmResp` |

**Neighbor database (`syncNeighbors`) [FR-NBR]:**
- Local siblings (same SSID) are set on each other on every call. hostapd
  treats a repeated `SET_NEIGHBOR` as an update.
- A remote BSS is installed once in every local BSS of the same ESS and then
  flagged `nrInstalled` until its info changes.
- `buildNrHex` sets the Mobility Domain bit per receiving BSS, comparing
  MDIDs.
- `removeNeighbor` sends `REMOVE_NEIGHBOR` to every local BSS of that ESS.

### 6.5 Decision policy (`policy.cpp`) [FR-POL, FR-TRG, FR-ADM-1]

All policy is in pure functions of `(PolicyConfig, inputs)`. Two scoring
models exist. The linear one is the default. The throughput model
(`score_model 1`, experimental) replaces the dB floors and the additive
bonuses with one physical quantity: the throughput the STA can expect.
It is non-linear in RSSI (a few dB matter near the sensitivity limit and
not at all once the top MCS is reached) and it values channel width and
load multiplicatively. It also values the current link with the STA's own
downlink measurement of the serving BSS, like the candidates, rather than
the AP's uplink RSSI. The lookup table keeps `policy.cpp` integer-only.

```
policy::score(ctx{reason, cur_rssi, cur_band, cur_util, cur_peak},
             cand{band, est_rssi, util, sta_count, max_sta, accepting, peak}):
  ineligible if !accepting | est unknown | full | util >= util_admit_max | est < rssi_min_target
  floor = RSSI:   cur_rssi + rssi_hysteresis
          LOAD:   ineligible if util > util_high - lb_margin; cur_rssi - lb_rssi_tolerance
          BAND:   ineligible if band <= cur_band; rssi_min_target
          MANUAL: rssi_min_target
  ineligible if est < floor
  score = est + band_bonus(band) - util_weight * util / 10       (util unknown: no penalty)

score_model 1 (expected throughput), after the same hard gates:
  q(r)    = quality_lut[r - tput_rssi_mid]   0..1000, logistic, 0.3/dB, clamped at +-30 dB
  peak    = policy::peak_mbps(caps, width) * sta_nss   (top MCS, short GI: HT/VHT/HE tables)
  tput(x) = q(rssi_x) * peak_x * (100 - util_x) / 100  kbps (util unknown: 0 %)
  RSSI, BAND: ineligible if tput(target) * 100 < tput(current) * tput_gain_pct
  LOAD:       ineligible if util > util_high - lb_margin or tput(target) < tput(current)
  score   = tput(target)
  example: weak 5 GHz STA (-80 dBm, VHT80, 30 %) -> now 50 Mb/s;
           5 GHz VHT80 at -60 dBm, 40 %  -> 505 Mb/s (chosen)
           2.4 GHz HT20 at -55 dBm, 20 % -> 114 Mb/s (the linear model picks this one)

policy::admit(util, sta_count, reserved, max_sta):
  CAPACITY if max_sta && sta_count + reserved >= max_sta
  LOAD     if util >= util_admit_max
  ACCEPT   otherwise

policy::backoff_ms(failures) = min(steer_cooldown_ms * 2^failures, steer_backoff_max_ms)
```

### 6.6 Steering (`steer.cpp`) [FR-STR, FR-ADM]

#### 6.6.1 Source-side state machine

| State | Entered by | Deadline | Exits |
|---|---|---|---|
| MEASURE | `startSteer` after hostapd accepted the (single) Beacon Request and/or air monitor requests were sent | max(`beacon_req_timeout_ms`, `amon_duration_ms` + 500 ms) | Every candidate has an 11k report (with `score_model 1`, the serving BSS too); or, once no 11k report is pending, every candidate has any measurement; or a refused/empty 11k report with no monitor report pending; or the deadline → `evaluate` |
| NEGOTIATE | `advance` sent STEER_REQ | `steer_resp_timeout_ms` + 1500 ms | ACCEPT → BTM; reject, timeout or peer lost → next candidate |
| BTM | `sendBtm` accepted by hostapd | `btm_timeout_ms` | BSS-TM-RESP 0 → ROAM; ≠ 0 → BTM_REJECT; deadline → BTM_TIMEOUT; association seen → outcome |
| ROAM | BTM accept | `roam_timeout_ms` | Association at the candidate → SUCCESS; at another BSS → WRONG_TARGET; deadline → ROAM_TIMEOUT |

In BTM and ROAM, an association reported back at the source BSS is ignored.
A local disassociation aborts only in MEASURE and NEGOTIATE; in BTM and ROAM
the STA leaving is expected. `sendResult` sends STEER_RESULT from NEGOTIATE
on (a STEER_REQ went out, so the target may hold a slot), and the NEGOTIATE
timeout sends one (aborted) before moving to the next candidate, because a
lost STEER_RESP may hide an acceptance. Without these, a STA dropping during
NEGOTIATE left the target's reservation until `reserve_hold_ms`. In
`runLbRound`, an offload is judged only when the STA is seen elsewhere
(another local BSS, `away`, or `findRemoteSta`); a STA that just
disconnected gives no verdict. Fault injection for tests: `DROPRX` drops
received messages of one type in `receiveMsg`, before the ACK.

Contextual bandit for the target (FR-STR-11, feature guide 16): `evaluate`
stores each candidate's `banditCtx` and `banditPrior`; in active mode the
sorted list is re-sorted by `policy::banditValue` and, with
`bandit_epsilon_pct`, its top two swapped. `banditCredit` updates
`mBandit` at each end of a candidate's attempt: `onBtmResp` reject and the
BTM timeout with candidates left (−10), `onSteerResp` refusal and the
NEGOTIATE timeout (−2), and `endTxn` for the last candidate tried (outcome
reward). A success arms a `PingPongWatch`; `onHapdConnected` on the source
BSS within 60 s adds −10. Not persisted or shared.

#### 6.6.2 Steps

1. **`startSteer`:** refused when the STA already has a transaction, its BSS
   is down, or all 16 slots are busy.
2. **`buildPool`:** every local BSS that is up and every remote BSS with the
   same SSID, except the source. For BAND, only higher bands; with a forced
   target, only that BSSID. Except for MANUAL, only bands the STA can use
   (`policy::isBandUsable`: not blocked — 6 GHz for a WPA2-PSK AKM — and
   advertised in `supp_op_classes`, seen in use, or nothing advertised). At most 16. An empty pool applies the cooldown.
   When more qualify, each BSS gets `policy::candidatePoolRank`: a level
   measured for it in the last 2 min (`POOL_HINT_MS`, 11k or AP-side) ranks
   by that level above all others, then local BSSes, then unknown remote
   ones. A new BSS replaces the lowest-ranked entry only if it ranks
   strictly higher, so unknown remote BSSes keep the peer visit order. That
   order starts at `Sta::poolStart`, which moves to the first peer whose
   unknown BSS was left out; the next steer of the STA covers the next
   peers. The pool is then sorted by rank, so `requestBeacons` takes the
   channels of the most promising candidates when there are more than 8.
   Why: with a pool filled in plain peer-table order, a STA next to the
   peers beyond the first 16 BSSes was never steered (itest PASS 12 fails
   with the old code).
3. **`requestBeacons`:** collect the distinct (op class, channel) pairs of
   the candidates (with `score_model 1`, the serving channel first), up to 8,
   and send **one** `REQ_BEACON <sta> <hex>`. The hex comes from
   `buildBcnReqHex`: wildcard BSSID, the source's SSID subelement,
   Reporting Detail 0, mode and duration from config. Several channels are
   encoded as Channel 255 plus one AP Channel Report subelement (ID 51) per
   operating class. A STA handles one beacon measurement at a time: with
   back-to-back requests, wpa_supplicant answered the second with report
   mode "refused", and the steer then ran without measurements. hostapd
   answers `FAIL` for a mode the STA did not advertise (RM Enabled
   Capabilities, not visible through the control interface). The request
   is therefore retried in active, then passive mode (passive ≥ 120 TU), and
   the accepted mode is kept in `sta.bcnMode` for later steers. Only when
   all fail is the STA marked as lacking 11k (`bcn_unsupported`). Table mode
   is not a fallback, because it measures nothing new.
   **`requestMonitors`** runs in parallel (§6.10): STA_MONITOR_REQ multicast
   to every peer, and a local watch for local candidates; MEASURE ends early
   once every AP waited for has sent its STA_MONITOR_STATUS.
4. **Beacon reports:** stored in the STA's 16-entry cache (the oldest entry
   is replaced), whether or not a transaction is running. In MEASURE,
   evaluation happens as soon as every candidate (and, with `score_model 1`,
   the serving BSS) has a report newer than the transaction start
   [NFR-PRF-2]. One radio report produces one hostapd event per BSS, so the
   check runs on each event. A STA never reports a BSS it does not hear, so
   "every candidate" rarely happens with candidates on other APs: each
   report also sets `bcnQuietUntil` = now + `bcnQuietMs` (200 ms + 2 ×
   measurement duration, set in `requestBeacons`), and `tickSteer` ends the
   11k part once it passes. Measured on the QEMU testbed: a band steer with
   an unheard remote candidate went from 1.78 s (waiting out
   `beacon_req_timeout_ms`) to 0.80 s.
5. **`evaluate`:** fills the policy inputs:
   - estimated RSSI from a cached 11k report ≤ 10 s old, else from an air
     monitor result ≤ 10 s old (+ `amon_rssi_offset`); for MANUAL without
     either, `rssi_min_target`;
   - load from the local BSS (STA count + reservations), or from the
     remote BSS_LOAD when one has been received;
   - peak PHY rate of the candidate and of the serving BSS (caps, width,
     `sta_nss`), and the serving BSS's utilisation (throughput model);
   - with `score_model 1`, the current level from the STA's own report of
     the serving BSS when one is cached, instead of the AP-side RSSI.

   Then it scores, drops ineligible candidates and sorts by score.
6. **`advance`:** walks the sorted candidates.
   - Local: `policy::admit` locally, then `sendBtm`.
   - Remote: STEER_REQ (ACK_REQ) carrying txn id, STA, source and target
     BSSIDs, reason, measured RCPI, STA flags and current RSSI → NEGOTIATE.
   - List exhausted: in MEASURE (nothing was ever tried) → "no suitable
     candidate"; otherwise → ABORTED.
7. **`sendBtm`:**
   `BSS_TM_REQ <sta> pref=1 abridged=1 valid_int=<n> [disassoc_imminent=1 disassoc_timer=<t>] neighbor=<bssid>,<info>,<op>,<ch>,<phy>,0301ff`.
   - The Mobility Domain bit is added when the MDIDs match.
   - Subelement 3 sets candidate preference 255.
   - If hostapd refuses the command, the state is set to BTM, so the target
     still receives STEER_RESULT, and the transaction ends ABORTED, counted
     as a failure.
8. **`endTxn`:** logs the outcome and sends STEER_RESULT when the candidate
   is remote and BTM was reached. It applies cooldown or backoff (§6.5,
   [FR-STR-9]) and frees the slot.

#### 6.6.3 Target side

`onSteerReq`, in order:
- UNKNOWN_BSS if the target BSS is not local and up;
- BUSY if this AP has its own transaction for the STA;
- otherwise `policy::admit`.

On ACCEPT it takes a free or expired reservation slot, or answers BUSY when
none is left, and replies STEER_RESP (ACK_REQ) with `hold_ms`. Reservations
are released in `onStaEvent` (association at this AP), in
`onSteerResult` (matching txn and source), in `tickSteer` (expiry) and in
`onPeerLost` [FR-ADM-3].

#### 6.6.4 Triggers

- Per-STA roaming threshold (FR-TRG-7): `Sta::roamThr` (0 = `rssi_low`),
  `roamEvents`, `roamThrTs`. `policy::roamThreshold` gives the value used by
  the low-sample count (`applyStaSignal`, MLD links) and `isRssiTriggered`.
  `endTxn` of an RSSI steer applies `policy::updateRoamThrOutcome` (the gain
  is the chosen target's RCPI minus `SteerTxn::startRssi`); `onStaEvent`
  from a peer without a steer of ours applies `updateRoamThrSelf` to the
  live entry, or, when the STA already left locally (`onHapdDisconnected`
  records `leftRssi`/`leftTs` in its class record), to the record within
  5 s (`noteOwnRoamFromRecord`). `onStaPoll` applies `decayRoamThr` after
  10 min without events. Changes are stored in the device class record
  (`roamThr`, `roamEvents`) and sent as STA_ROAM by the class sharing code
  (`devclass.cpp`: immediate send, hand-over on association, rejoin sync).
- Q-learning of when to roam (FR-TRG-8, feature guide 15): `onStaPoll`
  builds `policy::RlFeatures` on a fresh sample (`Sta::sampleFresh`,
  `rssiPrev` from `applyStaSignal`), closes a pending WAIT with
  `rlRewardWait` (next = the new state), and records a decision below −60
  dBm (off by default: `rl_roam` 0, or `RL mode 0`). Shadow: the rule's decision; active: `rlChoose` on `mRl` (432 × 2
  values ×256, prior from `rlInit` at start). A STEER passes its state to
  the transaction through `mRlNextArmed`/`mRlNextState` (copied in
  `startSteer`, because a steer can end inside it); `endTxn` and
  `failTxnNoCandidate` give the terminal reward. A pending WAIT ends with
  −20 on a local disassociation below `rssi_low`, 0 on an own roam. Not
  persisted or shared yet.
- `onStaPoll`, after each STA sample:
  - skip if the STA is away, in cooldown, lacks 11v, or has a transaction
    [FR-TRG-5];
  - otherwise RSSI trigger first, then band trigger.
- `runLbRound`, every `lb_interval_ms`: for each overloaded BSS, pick
  the eligible STA with the lowest RSSI and start a LOAD steer. One STA per
  BSS per round limits churn. Feedback: the BSS remembers the offload
  (`lbCheck`, STA, start time, utilisation, utilisation- or count-
  triggered) and starts no other until it can judge it, 5 polls + 2 s after
  the start with the STA gone. `policy::isLbMoveEffective` asks for a drop
  of `lb_min_drop_pct`; after `lb_max_futile` futile utilisation-triggered
  moves, `lbHoldUntil` pauses the BSS for `lb_hold_ms`. Why: with
  `lb_only_idle`, the STAs moved use little airtime, and busy time of
  other networks does not move with them; without feedback every idle STA
  was pushed out every 10 s with no relief (itest PASS 14).
- Manual (`ctrl.cpp` `STEER`): clears the STA's cooldown and calls
  `startSteer(MANUAL, target)`.

### 6.7 Control interface (`ctrl.cpp`) [IR-3]

`LOG` shows every module's level; `LOG <level> [<module>...]` changes them at
run time. At debug level, `msg.cpp`'s `trace()` logs every ARCP frame sent,
retransmitted (`[retry]`) and received, with type, id, peer, port, flags and
the TLV list, built only when module `msg` is at debug.

The control socket is a non-blocking UNIX datagram socket. Each request is
one datagram (≤ 255 bytes). The reply is built in an 8 KiB `FixedString` and
sent back to the sender's address. Output that does not fit is truncated. The
commands only read state, except `STEER`.

`METRICS` formats the counters of `Daemon::mMetrics` (one
`metrics::BssCounters` per local BSS) and `mArcpMetrics`; they are plain
integers incremented where the event happens (`startSteer`, `endTxn`,
`failTxnNoCandidate`, `sendBtm`, `onBtmResp`, `onSteerReq`,
`onSteerResult`, `runLbRound`, `receiveMsg`, `unicast`, `retransmit`), so
counting costs nothing measurable. Zero values are left out to keep the
reply in one datagram. `CHECK` recomputes the consistency findings from the
current peer table (feature 18).

### 6.8 Configuration (`config.cpp`) [IR-1, FR-SEC-3]

`parseConfigLine` strips comments, splits key and value, and handles string keys
explicitly. Integer and boolean keys go through a table of offsets into
`Config`, so adding a parameter means one table line plus a default.
An unknown key or a bad number is an error. `loadConfig` additionally
requires at least one `bss` and one transport.

### 6.9 Security design [FR-SEC, NFR-SEC]

| Threat | Mitigation | Residual |
|---|---|---|
| Rogue AP injects state or steering commands | HMAC-SHA256/128 on every message; fail closed on mismatch in both directions; optional per-AP Ed25519 signatures | Without signatures, any holder of the group key is trusted |
| Replay within one boot | 64-entry per-peer window | — |
| Replay of recorded messages (earlier boot, unseen boot, removed peer) | Liveness check (`liveness_check 1`): a boot is adopted only through a fresh CHALLENGE / RESPONSE | Off by default: replay across boots possible until enabled |
| Shipped example key used in production | Refused at start-up (`KEY_PLACEHOLDER`) | — |
| Stolen AP configuration (group key) used to impersonate other APs | Per-AP Ed25519 signatures (`sign_seed`, `peer_key`): messages accepted only from listed origins, signed with their own key | A compromised AP speaks as itself until its `peer_key` line is removed on the other APs; keys distributed by hand |
| Rogue box joins an enrolled mesh | Enrollment only by approval of the fingerprint on a trusted AP (`ENROLL approve`); revocation spreads with a higher generation | Until its first welcome, a new AP trusts whoever welcomes it with its key (check `welcomed by`, or `ENROLL init` on the first AP); any trusted AP can approve |
| Offline guessing of a passphrase from a captured frame | PBKDF2-HMAC-SHA256, 100 000 iterations | Fixed salt (one key per mesh); a weak passphrase is still guessable, slowly; `hex:` keys avoid it |
| Timing attack on MAC check | Constant-time compare (`ctEqual`) | — |
| Leaking 802.11r keys | ARCP carries no key material (C-2) | — |
| Local control socket abuse | Filesystem permissions on `ctrl_socket` | No authentication beyond the file mode |
| Malformed frames | Bounds-checked header and TLV parsing; fixed buffers; length checks in every decoder | — |

### 6.10 Air monitor (`amon.cpp`) [FR-AMN, IR-13]

Purpose: measure STAs that give no 802.11k beacon report, because they lack
11k or ignore the request while busy, from the frames they transmit.

**Input.** Each `air_monitor <ifname>` is opened as an `AF_PACKET`
`ETH_P_ALL` socket bound to a radiotap monitor interface, with a classic BPF
filter attached (`amon_bpf`). The filter reads the radiotap length
(little-endian, byte 2) and passes only probe requests (FC 0x40) and data
frames with ToDS and not FromDS, power-save nulls included; 256 bytes per
frame are enough. `air_monitor_sim <port>` reads the same frames from UDP for
tests. `parseRadiotap` (`rrm.cpp`, pure) walks the present bitmaps (extended
words included), aligns TSFT/Flags/Rate/Channel/FHSS/dBm-signal fields,
rejects bad-FCS frames and frames without a signal, and returns the TA,
frequency and dBm.

**Driver per-STA RSSI API (`vendor_rssi.cpp`).** The second way to measure:
the STA's MAC address goes to the Wi-Fi driver, which measures the RSSI of
its frames on a BSS's radio. `vendor::isStaRssiSupported / startStaRssi /
readStaRssi / stopStaRssi` take the BSS ifname; start returns at once and
read is called once, at the watch end, so the loop never blocks. The vendor
bodies are placeholders (TODO(vendor), reporting unsupported) until the
chipset documentation is reviewed; their system calls will go into
`os.cpp`. `sta_rssi_sim <file>` selects a simulated driver whose lines
(`<ifname> <sta> <dBm>`, `unsupported`, `fail`) the itest rewrites while the
daemon runs.

**Watches.** `startAmonWatch` returns a `MonitorStatus`: UNSUPPORTED when the
AP has neither monitor nor `sta_rssi_api`, BUSY when the 16 slots are full,
FAILED / UNSUPPORTED when only the driver API exists and no BSS could start,
else MEASURED with (STA, requester, txn, until, driver BSS mask) in a slot. Every parsed frame whose TA matches an active watch adds its
signal to that watch's accumulator for the frame's frequency (up to 4
frequencies). `tickAmon` ends watches whose time is up. For each
accumulator it emits one STA_MONITOR_RESULT per local BSS that is up on that
frequency: average dBm, sample count, age of the last sample; for a BSS in
the driver mask, the driver's value replaces it. Results and then one
STA_MONITOR_STATUS (measured, not heard, or failed) go into one
STA_MONITOR_REPORT, reliable unicast to the requester, or straight to
`onAmonResult` / `onAmonStatus` when the requester is this AP. A request
that cannot start is answered at once with the status alone (`onAmonReq`).

**Results.** `onAmonResult` logs the result and stores it in the STA's
measurement cache as `MEAS_AMON`, with level = `policy::uplinkToDownlink`
(RSSI + the BSS's learned offset once calibrated, else + `amon_rssi_offset`),
the raw uplink value (`ulDbm`) and op class/channel from the BSS info.

**Uplink/downlink calibration.** Whenever a STA's cache holds an 11k level
and an AP-side level of the same BSS, both unused (`paired`) and within
`ULDL_PAIR_MS` (5 s), `pairUlDl` turns them into one sample `downlink −
uplink` for that BSS in `mCal` (64 entries, least recently updated
replaced) and marks both used: a burst of reports counts once.
`policy::addUlDlSample` keeps a cumulative mean for the first 8 samples,
then an EWMA of 1/8, rejecting |Δ| > 30 dB and, once calibrated, samples
more than 12 dB from the mean. The offset is learned on the source AP that
saw both measurements; it is not shared between APs yet. It then calls `onMonitorResult`,
which ends MEASURE early when `isMeasureComplete` allows it. The cache keeps
11k (`MeasSrc::STA_11K`) and monitor entries side by side; `levelLookup` prefers 11k.

**Requests.** `requestMonitors` (in `startSteer`) multicasts one
STA_MONITOR_REQ (no ACK_REQ) to every peer, starts a local watch for local
candidates, and fills `SteerTxn::monWait` with this AP (if its watch
started) and each peer that owns a candidate. `onAmonStatus` removes the
sender; when the list is empty, `amonPending` clears and MEASURE evaluates
unless an 11k report is still pending. At the MEASURE deadline
`tickSteer` logs each AP still in the list ("no measurement answer").
HELLO sets AIR_MONITOR when `canMeasureStas()` (monitor or `sta_rssi_api`);
it is informational, as every AP answers. `onAmonReq` answers peers. The `MONITOR <sta> [<ms>]` control command starts a local watch with
txn 0 for diagnostics.

**Cost.** Without monitors: no sockets, no flag, no requests, so behaviour
is unchanged (FR-AMN-6). With one: the BPF filter keeps beacons, ACKs and
downlink in the kernel; user space sees each STA's uplink frames on that
channel and does a 16-entry scan per frame.

### 6.11 Low-power device classification (`devclass.cpp`) [FR-LPC]

Purpose: recognise low-power (IoT) devices from their traffic, so that the
network can treat them differently (now: no automatic steering), and keep
that knowledge when a device moves between APs or an AP restarts. Method and
wire format: `docs/PROTOCOL.md` §8.

**Sampling.** `applyStaSample()` already turns hostapd's byte counters into a
throughput per poll; it hands the uplink (`rx_bytes`) and downlink (`tx_bytes`)
deltas and the elapsed time to `sampleTraffic()`. An MLD STA is sampled from
one link only, as for its throughput.

**Arithmetic (`policy.cpp`, pure, integer).** `addTrafficSample()` keeps the
mean (×16 fixed point, so a sensor's few bytes/s do not truncate to zero) and
the sum of squared deviations per direction (Welford). Rates are clamped to
2^25 bytes/s and n is halved with the sum of squares past 1024 samples, so the
sum fits 64 bits; the variance is kept, and "since the connection began" turns
into a long memory that also lets a re-purposed device change class.
`lpBehaviourScore()` returns S × 100 = α × √m2_up / √m2_down (n cancels):
no floating point, no division by zero (only-uplink-varies is `LP_S_MAX`).
`updateLpScore()` and `isLowPower()` implement θ ± 1 and the threshold with
hysteresis. `TrafficStats::lastActive` records whether the latest sample
moved data; `lpBehaviourScore()` gives no evidence on an idle poll. Found on
the QEMU testbed: an idle hwsim STA (0 B/s, window mean 3 B/s from rare
keepalives, σ_d = 0) scored S = ∞ on every poll and turned low-power, which
`lp_no_steer` then kept out of steering. A class already wrong before this
rule is not undone by idle polls (they are no evidence either way); it
clears when the STA moves real traffic, or when every AP restarts. `TrafficStats::upRecent16` is a moving average of the uplink
rate (weight 1/8); `lpBehaviourScore()` gives no evidence while it is above
`lp_max_mean_bps`, so a large upload does not count as sensor-like and the
gate reopens a few polls after the upload ends (a whole-window mean would
hold it for minutes). `isLpExcludedPhy()` tests the STA's negotiated PHYs
(`phyCaps`, from hostapd's `flags=[VHT][HE][EHT]`) against
`lp_exclude_vht/he/eht`; `sampleTraffic()` then skips the statistics and, for
a STA classified low-power, sets it back to normal and sends the change with
samples + 1 (records are versioned by samples).

**Table.** `mDevClass` holds 512 `DevClassRec` (STA, class, θ, samples,
source AP, time); a full table replaces its oldest record. `samples` is the
STA's evidence count and travels with θ, so along one STA's history it only
grows and serves as the record's version: a record replaces another only
when it has more samples. `corrected` marks a record that went from
low-power to normal; it is set by `storeDevClass()` and travels with later
normal updates of that record.

**Flows.**

| Event | Action |
|---|---|
| Class of a local STA changes | store; STA_CLASS (reliable) to every peer |
| Local STA entry created (association, daemon start) | `restoreDevClass()`: θ, class and samples from the table |
| Local STA entry dropped (disassociation, hostapd down, missed events) | `saveDevClass()` into the table |
| STA_EVENT assoc from a peer | `onPeerStaAssoc()`: the record, if any, to that peer |
| STA_CLASS received | table; the live local STA takes it over when it has more samples |
| New peer, or peer with a new `boot_id` | `syncDevClass()`: every low-power or `corrected` record, packed into as few messages as fit (plain normal records are skipped: they tell the peer nothing and would crowd the 32-entry retransmission queue) |

## 7. Interaction design (sequences)

### 7.1 Discovery

```
AP1                                   AP2 (starts)
 | <---- HELLO (multicast) ----------- |   AP1: unknown origin -> peer_get,
 |                                     |        next_hello = next_bss_status = 0
 | ----- HELLO, BSS_STATUS ----------> |   AP2 learns AP1
 | <---- BSS_STATUS ------------------ |   both: peer_bss_update -> nr_sync -> SET_NEIGHBOR
```

### 7.2 Steer to a peer's BSS (remote)

```
STA        AP1 donghoa/hostapd                         AP2 donghoa/hostapd
 |  trigger -> steer_start -> MEASURE                       |
 |<-REQ_BEACON (one Beacon Request, all candidate channels) |
 |--Beacon Report--> BEACON-RESP-RX -> evaluate -> advance  |
 |              |--- STEER_REQ (ACK_REQ) ---------------->  | steer_on_req: policy::admit,
 |              |<-- ACK, STEER_RESP accept, hold_ms -----  |   reservation
 |              |--- ACK ------------------------------->   |
 |<-BSS_TM_REQ (BTM Request, pref 255, MD bit) -- BTM state |
 |--BTM Response 0--> BSS-TM-RESP -> ROAM                   |
 |====== FT authentication + reassociation ===============> | AP-STA-CONNECTED:
 |              |<-- STA_EVENT assoc (multicast) ---------- |   reservation released
 |  steer_on_sta_event -> SUCCESS                           |
 |              |--- STEER_RESULT success (ACK_REQ) ------> | steer_on_result
```

### 7.3 Steer to a sibling BSS on the same AP (local)

The same as 7.2 without the NEGOTIATE exchange: `advance` admits locally.
Success is detected from the local `AP-STA-CONNECTED` on the target BSS. A
move between local BSSes may report CONNECTED on the new BSS before
DISCONNECTED on the old one, so `onHapdDisconnected` ignores a disconnect for a
STA that already belongs to the other BSS.

### 7.4 Failure paths

| Situation | Result |
|---|---|
| STA does not answer the Beacon Request | MEASURE deadline → evaluate with what is cached → probably "no candidate" (cooldown) |
| STA refuses the measurement (report mode refused or incapable) | With monitor reports pending: wait for them. Otherwise evaluate at once with cached reports; without any, only a manual steer can proceed (its level is taken as `rssi_min_target`) |
| STA without 11k, or silent while busy, and candidate APs have monitors | Monitor results stand in for the missing beacon reports (§6.10) |
| A monitor does not hear the STA (other channel, STA silent) | No report from that AP; the candidate stays unmeasured and ineligible |
| A candidate cannot be heard by the STA (e.g. a remote AP out of range) | No report for it: it is ineligible, and evaluation waits for the deadline (R11) |
| Throughput model finds no candidate worth `tput_gain_pct` | "No suitable candidate": plain cooldown, not a failure (e.g. band steering when 5 GHz is no faster) |
| Target refuses or does not answer | Next candidate; when none is left → ABORTED (no failure counted) |
| STA rejects the BTM (e.g. status 7) | BTM_REJECT, failure counted, STEER_RESULT to the target, which releases its reservation |
| STA accepts but never arrives | ROAM_TIMEOUT, failure counted; target reservation expires or is released by STEER_RESULT |
| Peer disappears during NEGOTIATE | `onPeerLost` → next candidate |

### 7.5 Steer of a STA without 802.11k (air monitor)

```
STA (no 11k)     AP1 (source)                         AP2 (monitor or driver API)
 |  RSSI trigger -> steer_start                            |
 |<- REQ_BEACON: hostapd FAIL (no RRM) -> bcn_unsupported  |
 |              |==== STA_MONITOR_REQ (multicast) ======>  | startAmonWatch (1000 ms)
 |~~ uplink frames on AP2's channel ~~~~~~~~~~~~~~~~~~~~~> | radiotap -> addAmonSample / driver
 |              |<--- REPORT: RESULT B2 -58, STATUS measured | tickAmon -> finishAmonWatch
 |  onAmonResult -> AIR_MONITOR level; onAmonStatus: all answered -> evaluate
 |              |---- STEER_REQ / RESP / BTM / ROAM as in 7.2
```

itest PASS 5 runs this with a monitor, PASS 11 with the simulated driver
API: there an AP without the API answers "unsupported" within 1 ms and the
source evaluates at once, instead of waiting out the 1.5 s timeout.

## 8. Error handling and recovery

| Fault | Detection | Recovery | SRS |
|---|---|---|---|
| Bad config | `loadConfig` | Exit non-zero with the line number (procd respawn limits apply) | IR-1 |
| Raw socket not permitted | `socket()` / `bind()` fail | Exit with a message naming `CAP_NET_RAW` | §2.4 |
| hostapd absent or restarted | open/command failure, timeout | BSS down, its STAs removed, reconnect every 5 s; on reconnect, neighbors reinstalled | FR-MON-6 |
| hostapd as another user | Replies never arrive | Socket ownership copied at bind time | IR-2 |
| nl80211 unavailable | `Survey::open` fails | Warning; hostapd utilisation used | IR-6 |
| Peer lost | Timeout, BYE | `removePeer` cleanup | FR-DSC-4,7 |
| Backhaul path lost | No more frames on that port | Unicast moves to the port of the next copy received | FR-REL-3 |
| Unacknowledged reliable message | 4 transmissions | Logged and dropped; the transaction times out on its own deadline | FR-REL-1 |
| Table full | Allocation scan fails | Log and skip (new peer, STA or reservation ignored, or BUSY) | NFR-CAP-1 |
| Message too large | `overflow` flag | Not sent, error logged (STA_STATUS splits beforehand) | IR-8 |
| Authentication failure | `arcp::verify` | Dropped, debug log | FR-SEC-1 |
| Monitor interface missing or not a monitor | `if_nametoindex` / `bind` / filter attach fails | Error logged with the `iw` command to create it; the AP runs without it and does not advertise AIR_MONITOR | IR-13 |
| Watch table full | No free watch | Warning; STA_MONITOR_STATUS busy to the requester at once | FR-AMN-3 |
| Driver per-STA RSSI API missing or failing | `isStaRssiSupported` false / start or read FAILED | Status unsupported / failed to the requester; monitors, if any, still measure | FR-AMN-3, FR-AMN-8 |
| A peer never answers a measurement request (multicast lost, old version) | MEASURE deadline | Logged per AP; evaluated with what arrived | FR-AMN-7 |

## 9. Deployment design

### 9.1 Generic Linux

Build with `make` (or `make CC=<cross-gcc>`). Install `donghoa` and `donghoa_cli`,
write the configuration, and run `donghoa -c <file>` with `CAP_NET_RAW`. Run as
root when hostapd runs as another user. hostapd requirements are listed in
`docs/ARCHITECTURE.md`.

### 9.2 OpenWrt [IR-7, NFR-POR-1]

| Item | Design |
|---|---|
| Package | `openwrt/donghoa/Makefile`, a feed package (`src-link donghoa <repo>/openwrt`) built from the working tree; installs `/usr/sbin/donghoa`, `/usr/sbin/donghoa_cli`, `/etc/init.d/donghoa`, conffile `/etc/donghoa.conf` |
| Build | `openwrt/build.sh [target] [release]`: downloads and verifies the official SDK, runs it in Docker (`openwrt/sdk.Dockerfile`, for hosts without gawk), passes the toolchain through the environment so the project's own `CFLAGS` are kept |
| Service | procd: `START=95` (after wireless), `respawn 3600 5 0`, `stderr 1` → logd. The daemon runs on `/etc/donghoa.conf`, or on the generated `/var/run/donghoa.conf` (next row); procd restarts it at `reload` when either file changed. A `wireless` reload trigger fires on uci/LuCI changes |
| BSS discovery [IR-12] | With no `bss` line in `/etc/donghoa.conf`, `start_service` lists AP interfaces from `ubus call network.wireless status` (netifd's view of `/etc/config/wireless`, with runtime ifnames). It waits until each has a socket in `/var/run/hostapd`, reads `mobility_domain`, `max_num_sta` and `ft_over_ds` from `/var/run/hostapd-*.conf` (effective values, UCI defaults applied), and writes `/etc/donghoa.conf` + generated `bss` lines to `/var/run/donghoa.conf`. A `wireless` reload trigger (5 s delay, after netifd restarted hostapd) regenerates the file; procd restarts the daemon when it changed. This avoids hard-coded `phyN-apM` names, which depend on probe order, and mitigates R4 |
| Runtime | hostapd runs as `network` inside ujail; `donghoa` runs as root, which allows the socket ownership hand-over |

### 9.3 Test environments

| Level | Environment | What it exercises |
|---|---|---|
| Unit | `make test`, pure modules only (261 checks) | Codecs, HMAC, 802.11 layouts incl. multi-channel Beacon Requests, radiotap parsing, monitor TLVs, parsers, both scoring models with the §6.5 scenarios, config |
| Integration | `make itest`: 3 real `donghoa` processes, UDP sim transport, `tests/mock_hostapd.py` (understands Channel 255 + AP Channel Reports) | Discovery, wrong key, remote RSSI roam, load balancing, air monitor (STA without 11k, radiotap frames injected into AP2's `air_monitor_sim` port), BYE (PASS 1–6); with `DONGHOA_ITEST_EXTRA="score_model 1"` the same under the throughput model |
| System | `openwrt/qemu/`: OpenWrt x86-64 VMs, real hostapd and wpa_supplicant on `mac80211_hwsim`, real raw-socket backhaul between VMs | Real hostapd formats, permissions, neighbor DB, band and manual steering with real 11k/11v/11r frames, cross-AP negotiation; one multi-channel Beacon Request answered in one report; throughput model refusing band steering at equal width and steering to a VHT80 BSS; `bss` lines generated from UCI and following an interface rename; a real monitor interface measuring a STA through BPF + `AF_PACKET` (−27 dBm, matching the station table) |

## 10. Design decisions

| # | Decision | Alternatives | Rationale |
|---|---|---|---|
| D1 | Custom Layer-2 protocol (ARCP) | IEEE 1905.1/EasyMesh; UDP/IP | 1905 excluded by requirement (C-1). Layer 2 needs no IP configuration on the backhaul and keeps working while IP is not yet set up. |
| D2 | Distributed: the source AP decides, the target admits | Central controller | No single point of failure. The source has the freshest STA data; the target protects its own capacity. |
| D3 | Measure with 11k before moving | Trust AP-side RSSI only | Only the STA knows how well it hears the target. Moving a STA blindly risks a worse link. |
| D4 | One candidate per BTM, preference 255 | Full candidate list | Matches the reservation made on exactly one target. WRONG_TARGET is still accepted as a non-failure. |
| D5 | Reservations on the target | Admit by load only | Prevents several sources from filling the same target at once. |
| D6 | hostapd control interface only | nl80211 frames from the daemon; patching hostapd | Works with stock hostapd; the 802.11 state machines stay in one place. |
| D7 | Raw genetlink for the survey | libnl | Removes a dependency for one request (C-4). |
| D8 | Single thread, no heap, fixed tables | Threads, dynamic structures | Small embedded targets, deterministic memory, no locking (C-5, C-6). |
| D9 | Sim transport inside `l2.cpp` | Network namespaces in tests | Tests run without root and use the exact frames and code paths above L2. |
| D10 | Path learning from the first copy of each new message | Static port per peer | Automatic failover between wired and Wi-Fi backhaul with no extra protocol. |
| D11 | One Beacon Request for all candidate channels (Channel 255 + AP Channel Reports) | One request per channel | A STA runs one beacon measurement at a time: wpa_supplicant refused a second, back-to-back request, so steers ran unmeasured. One request also means one scan and less airtime. |
| D12 | Expected-throughput scoring as an opt-in model (`score_model 1`), sigmoid as an integer lookup table | Replace the linear score; floating-point `exp()` | Physically meaningful ranking (width, load, saturation of RSSI) while the linear model stays the default until the model is calibrated (R12). The table keeps `policy.cpp` integer-only and pure. |
| D13 | OpenWrt `bss` lines from netifd's runtime view and the generated hostapd config | Read `/etc/config/wireless` only; hard-coded names | UCI often has no `ifname` and may leave `mobility_domain` to a default; netifd and the generated config give the real names and effective values. |
| D14 | Air monitor on request, per steer, in parallel with 11k; uplink RSSI compared with uplink RSSI | Continuous sniffing and broadcasting of all heard STAs; monitor only when 11k fails | Watching only requested STAs keeps CPU and ARCP traffic low; asking in parallel avoids an extra round when a busy STA ignores the Beacon Request. Monitor and source both measure the STA's transmissions, so the comparison is like for like. A kernel BPF filter drops beacons and downlink before they reach user space. |
| D15 | Low-power class records replicated on every AP, exchanged peer to peer | A master AP that stores the records (as in the classification method's original IEEE 1905.1 design) | ARCP has no master (D2) and 1905 is out of scope (C-1). Replication gives the same result (a roaming or restarted AP gets the class back) without a single point of failure; the table is small (512 × ~40 bytes). |
| D16 | Departures from the original method: θ bounded to 0..`lp_score_max`, hysteresis on the class, no score change while the STA is idle, long-memory statistics | Unbounded θ, one threshold, idle counting as "not low-power", exact statistics since association | Unbounded θ never lets a device change class again; one threshold flaps (and sends a message each time); an idle sensor is the typical low-power device and must not lose score for sleeping; exact sums overflow 64 bits within days. |
| D17 | Per-STA metrics from nl80211 station dumps, hostapd for capabilities | A hostapd `STA-NEXT` per STA per poll | One non-blocking dump per BSS; the loop no longer blocks on hostapd per STA (R3) |
| D18 | Ranked candidate pool when more than 16 BSSes qualify | Peer-table order | A STA next to a peer beyond the first 16 BSSes was never steered (itest PASS 12) |
| D19 | Uplink → downlink offset learned per BSS from STAs measured both ways | One global `amon_rssi_offset` | Each AP's TX power and antennas differ (R14) |
| D20 | Per-STA roaming threshold learned from outcomes, shared with the class records | One global `rssi_low` | Sticky clients are not pestered, cooperative ones roam earlier; no new message type |
| D21 | Tabular, integer Q-learning with a prior equal to the rule, off by default | Deep RL; a bandit for target choice first | Fits a single-threaded, heap-free daemon and tens of decisions a day; starting from the rule makes enabling it safe |
| D22 | Contextual bandit for the target: tabular contexts per candidate, value shrunk towards a gain-based prior, only reorders eligible candidates, off by default | LinUCB / Thompson sampling with features | Integer only, explainable (`BANDIT` shows every context), safe: never relaxes a gate |
| D23 | Per-AP Ed25519 signatures with a configured trust list, own implementation (radix 2^25.5 field, SHA-512), HMAC kept as an optional outer layer | Pairwise keys from a root key; a library (libsodium, mbedTLS) | Only per-AP asymmetric keys stop one compromised AP from speaking for the others; no library keeps the libc-only binary (`make check-deps`) |
| D24 | Key enrollment by fingerprint approval on any trusted AP; trust table as last-writer-wins registers (generation per ap_id) flooded over ARCP and kept on disk | A central CA key; trust on first use; a push-button window | No single point of failure or extra key to guard; nothing joins without an administrator; revocations cannot be undone by stale copies |

## 11. Known limitations and risks

| # | Item | Impact | Possible remedy |
|---|---|---|---|
| R1 | STA_EVENT is sent multicast without ACK_REQ, but the source detects success from it | A lost event turns a successful remote steer into ROAM_TIMEOUT, with backoff for that STA | Send STA_EVENT(assoc) with ACK_REQ to the AP named in a matching reservation, or confirm from STA_STATUS |
| R2 | Replay of recorded messages (NFR-SEC-2) | — | Closed in 2.10 by the liveness check (CHALLENGE / RESPONSE) |
| R3 | hostapd calls block the loop for up to 1 s each | Delayed timers while hostapd hangs (bounded, §4.3) | Mitigated in v2.2: per-STA metrics come from asynchronous nl80211 station dumps; hostapd is asked per poll only for each BSS's `STATUS`, plus a full listing every 10 s and one `STA <addr>` per new STA. Remaining: an asynchronous command queue for those |
| R4 | `hapd_parse_status` falls back to entry 0 when the ifname is not among `bss[i]` | On multi-BSS radios, a wrong configured ifname would report the first BSS. On OpenWrt, generated `bss` lines (IR-12) avoid wrong names | Fail instead of falling back |
| R5 | BTM/RRM/NR capabilities are always advertised | Wrong if hostapd lacks them; hostapd then rejects the commands and steering aborts | Read them from `GET_CONFIG` |
| R6 | Neighbor reports use 20 MHz op classes and carry no Multi-Link element | Less precise candidate info for wide-channel and Wi-Fi 7 STAs (an MLD STA learns the target AP MLD only from its beacons) | Derive op class from width; Basic Multi-Link element in neighbor reports |
| R7 | Control replies are limited to 8 KiB | `PEERS`/`STAS` output truncated in large deployments | Multi-datagram replies |
| R8 | ~~All log lines reach OpenWrt syslog at `daemon.err`~~ **Resolved (1.3):** the OpenWrt service runs `donghoa -s`, which logs through `syslog(3)` with real priorities | — | — |
| R9 | No automated tests for retransmission, path failover or peer timeout | Regressions there would go unnoticed | The replay window is unit-tested since v2.7 (`arcp::acceptSeq`); packet-loss and two-port itest scenarios remain (SRS §7) |
| R10 | ~~`PROTOCOL.md` said retransmitted "up to 4 times"~~ **Resolved (2.7):** the text now says 4 transmissions in total, as the code does | — | — |
| R11 | ~~Early evaluation waits for a report from every candidate, so an unheard remote candidate made every steer wait `beacon_req_timeout_ms`~~ **Resolved (2.1):** a quiet period of 200 ms + 2 measurement durations after the last report ends the 11k part (band steer 1.78 s → 0.80 s on QEMU) | — | — |
| R12 | Throughput model: peak rate assumes the STA matches the BSS capability with `sta_nss` streams; one sigmoid for all widths and bands | Over-estimates gain for low-end STAs (e.g. 1×1, HT-only) | Read STA HT/VHT/HE capabilities from hostapd `STA` output; calibrate per width from MCS sensitivity tables |
| R13 | Air monitors hear a STA only on their own channel (uplink data on that channel, probe requests when it scans) | APs on other channels rarely measure an active STA; in 5 GHz plans with one channel per AP the monitor helps mostly via probes | A dedicated scan radio, or a vendor off-channel air-monitor API feeding `amon.cpp` (`addAmonSample()` is the entry point) |
| R14 | Uplink RSSI stands in for the STA's downlink level | Biased when AP and STA TX power differ widely | Mitigated in v2.4: offset learned per BSS from STAs measured both ways (`amon_offset_learn`). Remaining: STAs of different TX power share one per-BSS offset; offsets are not shared between APs |
| R15 | Monitor interfaces are created outside DongHoa and lost on reboot or `wifi` restart; the BPF program has no unit test | Monitor silently missing after a restart (logged) | Create them from the OpenWrt init script, re-open on interface events; test the filter with a BPF interpreter |
| R16 | Low-power thresholds (`lp_threshold`, α per band) are not calibrated against real devices; S compares the variability of uplink and downlink, so a device that uploads steadily (low σ_u) may not qualify, and a phone uploading photos for a long time may | Misclassification: a device kept out of automatic steering, or steered | Collect traces of real IoT devices and phones; tune α per band; add more features (packet size, inactivity). Mitigated in part by `lp_max_mean_bps` (large uploads) and `lp_exclude_vht/eht`; a streaming camera exceeds the default gate and is not classified |
| R17 | Q-learning (FR-TRG-8): hand-designed rewards, a table per AP that is lost on restart and not shared; shadow mode learns only the rule's actions | Slow or uneven learning; a fresh AP starts from the prior again | Off by default; share tables over ARCP (weighted by visits), persist them, decision log for offline evaluation before active mode |
| R18 | Per-STA roaming threshold (FR-TRG-7) learns only from RSSI steers and own roams; a STA that only ever sends uplink frames can also drift into the low-power class (R16) and leave automatic steering | A sticky device is left alone (intended); a misclassified idle device is not steered | Range limits (−82..−65), 10 min drift back; magnitude floor or decay for low-power evidence (decision pending) |
| R19 | Target bandit (FR-STR-11): contexts describe candidates, not clients; the table is per AP, lost on restart | A single client's aversion to one AP is generalised to that kind of candidate; a fresh AP starts from the prior | Off by default; share/persist tables; per-STA exceptions if needed |

## 12. Traceability (SRS → design)

| SRS area | Design sections |
|---|---|
| IR-1 config, IR-3/4 control and CLI, IR-5 logging | 6.8, 6.7, 4.1 |
| IR-2 hostapd, IR-6 nl80211, IR-7/12 OpenWrt | 6.4, 9.2 |
| IR-8..11 ARCP transport | 6.1, 6.2, `docs/PROTOCOL.md` |
| FR-DSC discovery | 6.2, 6.3, 7.1 |
| FR-STE state exchange | 6.2, 6.3 |
| FR-NBR neighbor DB | 6.4 |
| FR-MON monitoring | 6.4 |
| FR-TRG, FR-POL (incl. FR-POL-4 throughput model) | 6.5, 6.6.4 |
| FR-STR transaction (incl. FR-STR-3 single Beacon Request) | 6.6.1–6.6.2, 7.2–7.4 |
| FR-ADM admission | 6.6.3 |
| FR-REL reliability | 6.2 |
| FR-SEC, NFR-SEC | 6.2, 6.9 |
| FR-AMN air monitor, IR-13 monitor interfaces | 6.10, 7.5 |
| FR-LPC low-power classification | 6.5, 6.11, `docs/PROTOCOL.md` §8 |
| NFR-PRF, NFR-CAP | 4.2, 4.3, 5.1 |
| NFR-REL | 8 |
| NFR-POR, NFR-MNT | 3, 9 |

## 13. Revision history

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-30 | First issue |
| 1.1 | 2026-10-31 | Product renamed DongHoa (binaries `donghoa`, `donghoa_cli`; protocol still ARCP). Expected-throughput scoring model (§6.5, D12, R12). One multi-channel Beacon Request per steer (§6.6.2, D11, R11). OpenWrt `bss` lines generated from UCI (§9.2, D13, IR-12). Updated sizes, failure paths, test environments and traceability |
| 1.2 | 2026-10-31 | Air monitor: new §6.10 and §7.5, `amon.c` in the module map and layering, event loop and timers, watch table in the data design, MEASURE rules with monitor reports, failure paths, error handling, tests (261 unit checks, itest PASS 1–6, real monitor on OpenWrt), D14, R13–R15, traceability |
| 1.3 | 2026-10-31 | Per-module logging (`log.[ch]`), run-time `LOG` command, ARCP frame trace, syslog output (R8 resolved); beacon-report mode fallback in `request_beacons` |
| 1.4 | 2026-11-01 | C++17 rewrite (MISRA C++:2023 based, no exceptions/RTTI/heap, libc only): layering with `os.cpp` as the single system-interface file, module catalogue, start-up sequence, data sizes (247,720 bytes), file and function names throughout. Behaviour and wire format unchanged |
| 1.5 | 2026-11-01 | Identifiers renamed to the naming convention of CODING_CONVENTION §4 (camelCase verb-first functions, `mMember`, `sStatic`, `UPPER_CASE` constants and enumerators); function names updated throughout. Behaviour unchanged |
| 1.6 | 2026-11-06 | Low-power (IoT) device classification: `devclass.cpp` in the module map, §6.11, D15–D16, R16, traceability (FR-LPC) |
| 1.7 | 2026-11-06 | §6.11: recent-uplink-rate gate, PHY exclusion (configurable, HE allowed), `corrected` records in the rejoin sync; R16 mitigations |
| 1.8 | 2026-11-06 | AP-side measurement per the four-step exchange: multicast STA_MONITOR_REQ, STA_MONITOR_STATUS from every AP, early end of MEASURE, `vendor_rssi.cpp` (driver per-STA RSSI API placeholder + simulation); §6.10, §7.5, failure paths |
| 1.9 | 2026-11-06 | §6.11: idle polls are no evidence (`lastActive`); QEMU system test S14 (measurement exchange) and S15 (low-power on real counters) |
| 2.0 | 2026-11-06 | §6.6: ranked candidate pool and per-STA peer rotation for networks with more than 16 candidate BSSes; 12-AP itest |
| 2.1 | 2026-11-06 | §6.6: 11k quiet period ends MEASURE; RSSI samples count only when fresh (`policy::isSignalFresh`, `inactive_msec`); `STATUS` util_src per BSS |
| 2.2 | 2026-11-06 | §6.4: per-STA metrics from nl80211 station dumps (`nlparse.cpp`, `Survey::requestStations`, `processStationDumps`), hostapd listing every 10 s; §6.6: load-balancing feedback and pause |
| 2.3 | 2026-11-07 | `MAX_BSS` 16 (local and per peer), `Survey::MAX_STA_IFS` 16; compile-time checks that HELLO and BSS_STATUS with 16 worst-case BSSes fit one ARCP message; extra `bss` lines skipped with a warning; data size re-measured |
| 2.4 | 2026-11-07 | §6.10: uplink/downlink offset learned per BSS (`pairUlDl`, `mCal`, `policy::addUlDlSample` / `uplinkToDownlink`), `CALIB`; R14 mitigated |
| 2.5 | 2026-11-07 | §6.6: per-STA roaming threshold (state, update points, sharing via STA_ROAM in the class records); class-record slot reset on eviction |
| 2.6 | 2026-11-07 | §6.6: Q-learning of when to roam (`policy::rl*`, `mRl`, decision hand-over to the transaction, rewards); `RL` command |
| 2.7 | 2026-11-07 | Documentation audit: `rrm_log.cpp` in the module catalogue; R3, R9 mitigated, R10, R11 resolved, new R17, R18; decisions D17–D21; data size re-measured (449,352 bytes); replay window moved to `arcp::acceptSeq` (unit-tested) |
| 2.8 | 2026-11-08 | §6.6: STEER_RESULT from NEGOTIATE on and on the NEGOTIATE timeout; load-balancing verdict only for a STA seen elsewhere; `DROPRX` fault injection |
| 2.9 | 2026-11-08 | §6.6: contextual bandit for the target (contexts, prior, credits, ping-pong watch); D22, R19 |
| 2.10 | 2026-11-08 | §6.9 security: liveness check (CHALLENGE / RESPONSE) before adopting a peer's boot; PBKDF2 passphrase keys; example key refused; R2 closed |
| 2.11 | 2026-11-08 | Per-AP Ed25519 signatures: modules `sha512`, `ed25519`; §6.9 threat row; D23; payload limit 1450 bytes; data size re-measured (460,832 bytes) |
| 2.12 | 2026-11-08 | Automatic key enrollment: modules `trust`, `enroll`; threat row; D24 |
| 2.13 | 2026-11-08 | Security off by default: `liveness_check` key (default 0); shipped configurations without `key` |
| 2.14 | 2026-11-12 | Observability: modules `metrics`, `consistency`, `check.cpp`; §6.7 `METRICS`, `CHECK`; POLICY TLV in HELLO; fuzz targets (`fuzz/`); data size re-measured (470,760 bytes) |
