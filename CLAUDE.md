# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DongHoa (binary `donghoa`) is a C++17 daemon, one per AP, that sits beside
hostapd and coordinates roaming, band steering and load balancing across
APs. The APs talk to each
other with **ARCP**, a custom Layer-2 protocol (raw Ethernet, EtherType
0x88B5). IEEE 1905 is out of scope by requirement. The target STAs support
802.11k, v and r. The wire spec is `docs/PROTOCOL.md`; the module map,
state machine and hostapd assumptions are in `docs/ARCHITECTURE.md`.
Per-feature explanations (data flow, algorithms, diagrams) are in
`docs/features/`; update the matching document when a feature changes.

## Commands

```sh
make                 # builds ./donghoa and ./donghoa_cli
make test            # unit tests (tests/test_unit.cpp, links only the pure modules)
make itest           # end-to-end: real donghoa processes + Python mock hostapd, no root
DONGHOA_KEEP_LOGS=1 python3 tests/itest.py   # keep per-AP debug logs in /tmp/donghoa-itest-*
# itest logs: apN.log with "=== Sn" scenario markers, merged.log = all APs by time.
# Run the OpenWrt SDK (x86-64 musl) binaries in the itest through the SDK's musl loader:
#   LD=$(ls build/openwrt/sdk-*/sdk/staging_dir/toolchain-*/lib/ld-musl-x86_64.so.1)
#   B=$(echo build/openwrt/sdk-*/sdk/build_dir/target-x86_64_musl/donghoa-1.0/.pkgdir/donghoa/usr/sbin)
#   DONGHOA_BIN="$LD $B/donghoa" DONGHOA_CLI_BIN="$LD $B/donghoa_cli" python3 tests/itest.py
make check-deps      # binaries must need libc only (no libstdc++.so)
make cppcheck        # static analysis (run in a container if cppcheck is missing)
make clean && make CXXFLAGS="-O1 -g -fsanitize=address,undefined" donghoa donghoa_cli && make itest
```

The unit tests form one binary with no filter. To focus on one area,
comment out calls in `main()` of `tests/test_unit.cpp`. Run `make itest`
after changing `donghoa` behaviour; it must still print `PASS 1`..`PASS 14`.

## Architecture essentials

- **Single-threaded `poll()` loop** (`main.cpp`, 100 ms tick), **no heap, no
  exceptions, no RTTI** (`-fno-exceptions -fno-rtti`). All state is
  `std::array`s in class `Daemon` (`daemon.hpp`), one static object in
  `main.cpp`. The coordination modules (`msg`, `peer`, `local`, `steer`,
  `devclass`, `amon`, `ctrl`) are member functions of `Daemon`, split across
  files.
- **`os.cpp` is the only file that touches POSIX:** system calls,
  `reinterpret_cast` to `sockaddr`, `<cstring>`, signals. Other files use
  `os::` functions with `os::Fd` (RAII), `ByteView`/`ByteSpan` and
  `std::string_view`. A new system call goes into `os.cpp`.
- **Pure, unit-testable layer:** `text`, `proto`, `rrm`, `policy`, `config`,
  `sha256`, `hapd_parse` and `nlparse` (nl80211 message parsing). Keep I/O out of these modules. Put new decision
  logic in `policy.cpp` and new 802.11 byte layouts in `rrm.cpp`.
- **I/O layer:** `l2.cpp` (raw sockets), `hapd.cpp` (hostapd control socket),
  `survey.cpp` (nl80211 via raw genetlink, deliberately no libnl dependency:
  channel survey and per-BSS station dumps for the per-STA metrics),
  `amon.cpp` (radiotap air monitors and the driver per-STA RSSI API; the
  frame parser itself is pure, in `rrm.cpp`), `vendor_rssi.cpp` (that driver
  API: vendor placeholder marked TODO(vendor), plus the `sta_rssi_sim` file
  simulation the itest uses) and `ctrl.cpp`.
- **Steering transaction:** `steer.cpp` runs MEASURE → NEGOTIATE → BTM → ROAM.
  NEGOTIATE (STEER_REQ/RESP with the target AP) is skipped for this AP's own
  sibling BSSes. Success means a `STA_EVENT` assoc arrives from the target. On
  failure the STA gets an exponential backoff (`policy::backoffMs`). The
  target side holds reservations in `mResv`.
- **Reliable unicast:** `Daemon::unicast` with `arcp::FLAG_ACK_REQ` queues the
  finished frame in `mPending`. A retransmission reuses its `msg_id`. A
  receiver drops duplicates with the per-peer 64-entry replay window
  (`acceptPeerSeq`) but ACKs them again.
- **Path learning:** the port that delivers the first copy of each new
  message becomes the unicast path to that peer (`receiveMsg`). This is how
  unicast fails over between wired and Wi-Fi backhaul.
- **"Sim" transport:** `sim_port` / `sim_peer` in the config carry the same
  Ethernet frames over UDP on loopback. That lets the itest run without
  CAP_NET_RAW. In sim configs, use bss ifnames that don't exist on the host
  (e.g. `ap1-wl0`). Otherwise the nl80211 survey queries a real radio.

## Conventions and gotchas

- Style: kernel-like layout (tabs, function brace on its own line), `//`
  comments. Naming (table in `docs/CODING_CONVENTION.md` §4): `PascalCase`
  types; `camelCase` functions starting with a verb (`startSteer`,
  `findPeer`, handlers `onSteerReq`, predicates `isBssOverloaded`),
  parameters, locals and public fields; private members `mName`; statics
  `sName`; constants and enumerators `UPPER_CASE` (`MAX_STA`,
  `MsgType::STA_EVENT`). Wire, config-key, log and command strings stay
  `snake_case`/upper case as they are. The Makefile's strict flags
  (`-Wconversion -Wsign-conversion -Wold-style-cast -Wuseless-cast
  -Wpedantic` …) must stay warning-free.
- **Never call a library function that can throw** (`std::string_view::substr`,
  `std::array::at`, anything allocating). It drags in `libstdc++.so`, which
  `make check-deps` rejects. Use `subView()` from `text.hpp`.
- Formatting is `formatTo(out, "x={} y={}", a, b)` into a `FixedString<N>`
  (`text.hpp`); `hex(v, width)`, `SsidText`, `Mac` have formatters. Numbers
  are parsed with `parseLong`/`parseLongTok`/`parseU64` (range-checked,
  `std::from_chars`).
- Logging is per module: a `.cpp` file that logs defines
  `constexpr LogModule LOG_MODULE{LogModule::<NAME>};` in its unnamed namespace and
  calls `logging::info(LOG_MODULE, "...", args)` (add a new module to
  `enum class LogModule` and `MODULE_NAMES` in `log.cpp`). Do not repeat the
  module name in messages; the tag adds it. `donghoa_cli <sock> LOG debug <module>`
  changes levels at run time.
- New and changed code follows `docs/CODING_CONVENTION.md` (MISRA C++:2023
  based): braces on every body, conditions written out, return values used or
  cast to `(void)`, `static_cast` only, `explicit` single-argument
  constructors, no macros besides include guards. Departures from Required
  rules need a deviation in §6 of that document; DEV-01..04 are confined to
  `os.cpp`.
- `src/proto.hpp` is the single source of truth for wire numbers. When you add
  a TLV or message, update `proto.{hpp,cpp}`, the table in `docs/PROTOCOL.md` and
  the round-trip tests together. Decoders must accept longer TLVs than they
  understand (forward compatibility).
- All wire fields are big-endian, except the 802.11 structures built in
  `rrm.cpp` (Neighbor Report BSSID Info, Beacon Request durations), which are
  little-endian as the 802.11 standard requires.
- `bss_load.util` runs 0..254. **255 means unknown**, so
  `policy::utilToPct()` returns -1 for it, and survey values are clamped to 254.
- The formats of hostapd ctrl output and events that the parsers rely on are
  listed under "Assumptions to verify" in `docs/ARCHITECTURE.md`. Don't treat
  them as verified against a specific hostapd release. If you touch
  `hapd_parse.cpp` or `local.cpp` event handling, update `tests/mock_hostapd.py` to
  match.
- 802.11r key distribution is hostapd's job (its RRB or local FT-PSK keys).
  ARCP must not carry key material.
