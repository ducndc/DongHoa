# DongHoa coding convention (MISRA C++ based)

| | |
|---|---|
| Applies to | `src/`, `tools/` (production code). `tests/` follows §4 and §5.9 only, and may use macros (§6.1) |
| Baseline standard | MISRA C++:2023 (guidelines for C++17) |
| Language | ISO C++17, `-fno-exceptions -fno-rtti`, no dynamic memory |
| Document version | 2.1, 2026-11-01 (2.1: naming conventions in §4; 1.x covered the C11 code base and MISRA C:2012) |
| Check | Compiler warnings (§7), `make check-deps`, `make cppcheck`, review checklist (§9) |

## 1. Purpose and status

DongHoa runs unattended on embedded APs and parses untrusted input from the
network, from hostapd and from the air. Version 2.0 of the daemon is written
in C++17 so that the compiler, not only review, enforces much of what the
C version needed MISRA C for: `enum class` instead of integer constants,
`std::array` with known bounds instead of pointer + length pairs,
`std::string_view` instead of NUL-terminated buffers, `std::optional`
instead of sentinel values, type-safe formatting instead of `printf`, and
RAII for file descriptors.

**Status:** DongHoa is *MISRA C++-based*, not certified compliant. No MISRA
C++:2023 checker is used yet (the free cppcheck MISRA addon covers MISRA C
only). Compliance rests on the compiler flags in §3, the confinement of all
system-interface code to one file (§6.2), and review against §9. Every
departure from a Required rule is a documented deviation (§6). None is
silent.

MISRA rule texts are copyrighted. This document gives rule numbers with
short paraphrases. **The numbers follow MISRA C++:2023 as the authors
understand it. Check them against a licensed copy before you cite them in an
assessment.**

## 2. Compliance model

| Category | Project rule |
|---|---|
| Mandatory | Always followed. No deviation possible. |
| Required | Followed, or a deviation is recorded in §6.2 (project-wide permit) or at the code (case deviation, §6.3). |
| Advisory | Followed, except the rules §6.1 *disapplies* for this project, with the reason given. |

## 3. Language and toolchain

- **C++17**, GCC or Clang. The OpenWrt package builds with the SDK's
  `TARGET_CXX` against musl.
- **No exceptions, no RTTI, no heap:** `-fno-exceptions -fno-rtti
  -fno-threadsafe-statics`. Nothing in `src/` calls `new`, `delete`,
  `malloc` or any standard facility that allocates (`std::string`,
  `std::vector`, `std::function`, …). The binaries are linked with
  `-Wl,--as-needed` and **must need only libc**: `make check-deps` fails if
  `libstdc++.so` or `libgcc_s.so` appears in `NEEDED`. A library function
  that can throw (`std::string_view::substr`, `std::array::at`) pulls in
  `libstdc++.so` through its `__throw_*` helper, so it is not used (§5.8).
- **Warnings:** the build uses `-Wall -Wextra -Wshadow -Wconversion
  -Wsign-conversion -Wold-style-cast -Wuseless-cast -Wcast-qual -Wpedantic`
  and must stay free of warnings. This applies to the normal build and to
  the sanitizer build (`-O1 -fsanitize=address,undefined`).
- **Implementation-defined behaviour** relied on (Rule 4.1.1 context):
  8-bit `char`, two's complement, `int` of at least 32 bits. Wire formats are
  encoded byte by byte, never by overlaying a struct on a buffer. The code
  must also build for 32-bit targets: do not mix `std::uint64_t` and
  `std::size_t` in one expression without a cast.

## 4. Layout and naming (project style)

MISRA does not prescribe layout. DongHoa keeps the kernel-like layout of the
C version:

- Tabs for indentation (width 8), lines ≤ 110 columns.
- A function's opening brace on its own line; K&R braces elsewhere.
- **Every** `if`, `else`, `for`, `while` and `do` body is a compound
  statement in braces (Rule 9.3.1).
- `//` comments. No commented-out code (Rule 5.7.2). No `/*` inside a
  comment (Rule 5.7.1).
- **Naming** (common C++ naming practice, adopted in version 2.1 of this
  document; names are descriptive, never `x`/`var1`, except short loop
  indexes such as `i`):

  | What | Style | Examples |
  |---|---|---|
  | Classes, structs, enums, type aliases | `PascalCase` noun | `Daemon`, `SteerTxn`, `RemoteBss`, `Millis` |
  | Functions and methods | `camelCase`, starting with a verb; event handlers start with `on`; predicates with `is`/`has` | `startSteer`, `findPeer`, `sendHello`, `onSteerReq`, `isBssOverloaded`, `hasBtmCapab` |
  | Accessors and conversions | `camelCase` noun or `xToY` | `flags()`, `msgId()`, `cStr()`, `freqToChan`, `beaconModeName` |
  | Parameters, local variables, public struct fields | `camelCase` | `durationMs`, `cfgPath`, `lowCount` |
  | Private data members | `m` + `PascalCase` | `mApId`, `mBss`, `mPending` |
  | Variables with static storage (namespace scope, DEV-05) | `s` + `PascalCase` | `sDaemon`, `sLevels`, `sStop` |
  | Constants (`constexpr`/`const`, any scope) and enumerators | `UPPER_CASE` | `MAX_STA`, `CMD_TIMEOUT_MS`, `LogModule::STEER`, `MsgType::STA_EVENT` |
  | Namespaces | lower case | `donghoa`, `os`, `arcp` |
  | Files | `snake_case` with `.hpp`/`.cpp`, no name of a system header | `hapd_parse.cpp` |

  No Hungarian `p`/`r` prefixes for pointers and references: the type says
  it. `UPPER_CASE` is usually reserved for macros; here it is safe because
  production code defines no macros besides include guards, and a constant
  that collides with a system macro is a compile error. Names that come
  from the C++ library or POSIX (`std::size_t`, `sockaddr_un::sun_path`)
  keep their own spelling. Strings on the wire, in the configuration file,
  in log messages and in control commands keep theirs too (`peer_timeout_ms`,
  `STAS`), so renaming code never changes behaviour.
- Namespaces: `donghoa` for everything, with nested `os`, `logging`,
  `policy`, `hapd`, `rrm`, `arcp` (wire format, `proto.hpp`).
- One declarator per declaration.
- Include guards `DONGHOA_<FILE>_HPP`. The project defines no other macros
  in production code (Rule 19.0.2).

## 5. Rules by topic

### 5.1 Types and conversions

| Rule | Requirement (paraphrase) | Project practice |
|---|---|---|
| 6.9.2 | Use fixed-width integer types, not the named standard ones, for sizes that matter | `std::uint8_t`…`std::uint64_t`, `std::size_t` for counts and indexes, `bool`. Plain `int` only for dBm values and small loop counts that interface with POSIX |
| 7.0.5, 7.0.6 | Conversions do not change signedness or narrow implicitly | `-Wconversion -Wsign-conversion` enforce it. Narrowing is a `static_cast` after a range check |
| 8.2.2 | No C-style or functional-notation casts | `-Wold-style-cast`. Use `static_cast`. |
| 8.2.3 | A cast does not remove `const` or `volatile` | `-Wcast-qual`; no `const_cast` anywhere |
| 8.2.5 | No `reinterpret_cast` | Only in `os.cpp`, for socket addresses (DEV-02) |
| 5.13.3, 5.13.4 | No octal constants; unsigned literals carry `U` | `0x1FFU`, `S_IRUSR \| S_IWUSR` |
| 10.2.1, 10.2.2 | Enumerations have an explicit underlying type; prefer scoped enums | `enum class MsgType : std::uint8_t`. Wire structs keep raw `std::uint8_t` fields, so an unknown value from the network is never cast into an enum (§5.9) |

### 5.2 Declarations, linkage and scope

| Rule | Project practice |
|---|---|
| 6.2.x, 6.5.x | Functions and objects used in one file go in an unnamed namespace. External declarations live in exactly one header |
| 6.4.1 | No shadowing (`-Wshadow`) |
| 6.7.1, 6.7.2 | No function-local `static` variables; no non-`const` variables at namespace scope. Exceptions are listed in DEV-05 |
| 15.1.3 | Single-argument constructors and conversion operators are `explicit` (`ByteView`, `ByteSpan`, `os::Fd`) |
| 15.0.1 | Special member functions follow the rule of zero; `os::Fd` and `hapd::Conn`, which own a resource, are move-only with copy deleted |
| 0.2.x | No unused variables, parameters, types or functions. Exception: protocol and 802.11 constants (§6.1) |

### 5.3 Initialization

| Rule | Project practice |
|---|---|
| 11.6.2 (Mandatory) | No object is read before it is set. Every struct member has a default member initializer (`std::uint8_t channel{0U};`), every local is initialized at its definition (`std::array<…> buf{};`) |
| 11.6.1 | Prefer brace initialization; `= default` constructors |

### 5.4 Expressions

| Rule | Project practice |
|---|---|
| 8.0.1 | Parenthesize when mixing operators of different precedence: `(a & MASK) != 0U` |
| 7.0.1, 7.0.2 | No implicit conversion between `bool` and numbers. Conditions are written out: `if (p != nullptr)`, `if (n != 0U)`, `if (!opt.has_value())` |
| 8.18.2, 8.19.1 | Assignments are not used as values; no comma operator |
| 8.14.1 | The right operand of `&&` / `\|\|` has no side effects |
| 8.20.1 | Unsigned arithmetic that could wrap is guarded or done in a wider type |
| 7.11.x | `nullptr`, never `0` or `NULL`, for pointers |

### 5.5 Control flow

| Rule | Project practice |
|---|---|
| 9.3.1 | Bodies of `if`/`else`/`for`/`while`/`do` are compound statements |
| 9.4.1 | An `if … else if` chain ends with an `else` (it may hold only a comment) |
| 9.4.2 | Every `switch` has a `default` and at least two clauses; each clause ends with `break` or `return`; no fall-through |
| 9.5.1 | Classic `for` loops have one loop counter, compared with `<`, not modified in the body. Prefer range-based `for` over `std::array` |
| 9.6.1 | No `goto`. RAII (`os::Fd`) replaces the C version's `goto fail` cleanup |
| 8.2.10 | No recursion (also keeps stack use bounded) |

### 5.6 Functions

| Rule | Project practice |
|---|---|
| 0.1.2 | A non-`void` return value is used, or explicitly discarded with `(void)` |
| — (Dir 4.7 heritage) | Every error a function can report is tested: socket calls, hostapd commands, parsers, `parseConfigLine` |
| 13.3.x | Parameters are not modified. Large objects are passed by `const &` and output parameters by `&`, not by pointer, unless "absent" is meaningful (`const Mac *target` may be `nullptr`) |
| 21.10.1 | No `<cstdarg>`. The `{}` formatter (`text.hpp`) takes a fixed array of typed `FmtArg`s built by a variadic template, so a mismatched argument is a compile error, not undefined behaviour |
| — | Functions are `noexcept` |

### 5.7 Pointers, arrays and buffers

| Rule | Project practice |
|---|---|
| 8.7.1, 8.7.2 | Pointer arithmetic stays inside one array. Code works on `ByteView`/`ByteSpan` (pointer + size) and indexes them; `first(n)` and `sub(off, n)` check bounds |
| 11.3.1 | No C-style arrays in new code: `std::array`. The kernel BPF program in `os.cpp` is the only C array (DEV-01) |
| 21.2.2 | No `<cstring>` functions (`memcpy`, `strlen`, `memcmp`, …) outside `os.cpp` (DEV-04). Byte copies use `copyBytes`, comparisons `equal()` or the type's `operator==` (`Mac`, `BssInfo`), never a byte compare over a struct with padding |
| 12.3.1 | No `union` |

### 5.8 Standard library

| Rule | Project practice |
|---|---|
| 21.6.1, 21.6.2 | **No dynamic memory.** All state is fixed-size: `std::array`, `FixedString<N>` (bounded, truncating, always NUL-terminated) |
| 21.2.1 | No `atoi`/`atol`/`atof`/`strtol`: numbers are parsed with `std::from_chars`, with range checks, through `parseLong`, `parseLongTok` and `parseU64` (`text.cpp`) |
| 30.0.1 | No C stdio. Output goes through `os::writeStderr`, `os::writeStdout` and `os::writeSyslog` |
| 21.10.3 | No `<csignal>` outside `os.cpp` (DEV-03) |
| 18.x | No exceptions: none thrown and none caught, and no library call that can throw. Use `subView()` instead of `std::string_view::substr`, `operator[]` after a bounds check instead of `at()`. `make check-deps` catches a slip, because the throw helper lives in `libstdc++.so` |
| 21.x (sorting) | The candidate list (≤ 16 entries) uses a stable insertion sort that moves an entry only past strictly lower scores, so equal scores keep their order |

### 5.9 External input and run-time safety

These rules carry the most weight in DongHoa, because it parses untrusted
bytes from four sources: ARCP frames, hostapd replies and events, netlink
messages and radiotap frames.

| Rule | Project practice |
|---|---|
| 4.1.3 (and Dir 4.14 heritage) | Every length and offset from outside is checked before use. Decoders (`arcp::decode`, `TlvReader`, `hapd::parse*`, `rrm::parseBcnRepHex`, `rrm::parseRadiotap`, the netlink attribute walk in `survey.cpp`) check sizes first and accept longer TLVs than they understand |
| 4.1.3 | No undefined behaviour: indexes range-checked, arithmetic on external values cannot overflow (wider type, then clamp), division only by non-zero, enum values from the wire validated before `static_cast` |
| 0.3.x | Floating point is used only in the throughput model's table set-up (`policy.cpp`), never on wire data |
| — (project) | Blocking calls are bounded (hostapd 1 s, netlink 0.5 s); the event loop has one thread |

## 6. Re-categorization and deviations

### 6.1 Advisory rules disapplied for this project

| Rule | Scope | Reason |
|---|---|---|
| Single point of exit | All code | MISRA C++:2023 has no such rule (MISRA C++:2008 Rule 6-6-5 and MISRA C:2012 Rule 15.5 did). Guard clauses with early `return` keep functions short |
| 0.2.x (unused declarations) | Protocol and 802.11 constants (`proto.hpp`, `rrm.hpp`) | The full set of wire values documents the standard and keeps future decoders consistent |
| 19.0.2 (function-like macros) | `tests/test_unit.cpp` only | `CHECK(c)` records `#c` and `__LINE__`, which a function cannot do in C++17 |
| 8.2.2 / `-Wold-style-cast`, `-Wuseless-cast` | `tests/test_unit.cpp` only | Test assertions; not shipped |

### 6.2 Deviation permits (Required rules, project-wide)

All four system-interface deviations are **confined to `src/os.cpp`**.
Every other file uses `os::` functions with C++ types (`os::Fd`,
`ByteView`, `std::string_view`, `std::optional`) and contains no POSIX
call, no `reinterpret_cast` and no `<cstring>` include. A new use goes into
`os.cpp`, never into the module that needs it.

| ID | Rule | Scope | Justification | Compensating measures |
|---|---|---|---|---|
| DEV-01 | 30.0.1, 11.3.1, 21.2.2 (`strerror`) | `os.cpp`: POSIX and Linux system calls (`socket`, `bind`, `sendto`, `recv`, `poll`, `ioctl`, `open`, `read`, `write`, `unlink`, `chown`, `clock_gettime`, `getrandom`, `syslog`, `strerror`) and the C array that holds the kernel BPF program | A daemon on Linux has no other way to reach the network, hostapd, nl80211 or the clock | Each call's result is tested; descriptors are owned by `os::Fd` (closed on every path); buffer sizes come from `std::array::size()` / `ByteSpan::size()` |
| DEV-02 | 8.2.5 | `os.cpp`: `reinterpret_cast` from `sockaddr_un`/`sockaddr_ll`/`sockaddr_in`/`sockaddr_nl` to `sockaddr *` | The POSIX socket interface takes `struct sockaddr *` | One helper (`asSockaddr`) per direction; the address structs are value-initialized (`{}`) and filled field by field |
| DEV-03 | 21.10.3 | `os.cpp`: `sigaction` for SIGINT/SIGTERM, SIGPIPE ignored | A service must stop cleanly (to send BYE) when procd stops it | The handler only writes a `volatile sig_atomic_t` flag, read through `os::stopRequested()` |
| DEV-04 | 21.2.2 | `os.cpp`: `std::memcpy`/`std::strlen` for `ifreq`, socket paths and native-endian netlink fields (`load_ne*`/`store_ne*`) | Kernel structures and host-order netlink integers have no portable byte-wise alternative | Lengths checked against the destination's `sizeof` first; netlink offsets checked against the received length |
| DEV-05 | 6.7.2 (and 6.7.1) | Namespace-scope state: the `Daemon` object (`main.cpp`), log levels (`log.cpp`), the hostapd reply-socket counter (`hapd.cpp`), the signal flag and the BPF program (`os.cpp`; `SO_ATTACH_FILTER` takes a non-`const` pointer) | Without a heap, the daemon's 240 KB of tables must have static storage: on the stack they would depend on the process stack limit. Putting them in `.bss` makes memory use known at link time (`size donghoa`) | Each object is in an unnamed namespace (internal linkage) and reached only through its module's functions; one thread, so no data races |

### 6.3 Case deviations

A departure from a Required rule outside §6.2 needs:

1. A comment on the line before: `// MISRA C++ Rule 8.2.5 deviation DEV-06: <reason>`.
2. A row added to §6.2 with justification and compensating measures, in the
   same change.
3. Agreement in review.

## 7. Enforcement

| Tool | Command | Expectation |
|---|---|---|
| Compiler | `make`; `make CXXFLAGS="-O1 -g -fsanitize=address,undefined" donghoa donghoa_cli` | Zero warnings with the flags in §3 |
| Dependencies | `make check-deps` | `libc` only: no `libstdc++.so`, no `libgcc_s.so` |
| Static analysis | `make cppcheck` (`--enable=warning,portability`; in a container if needed) | No findings |
| Confinement | `grep -lE '^#include <(cstring\|csignal)>\|reinterpret_cast\|::socket\|const_cast' src/* tools/*` | Only `src/os.cpp` |
| Tests | `make test`, `make itest`, and `openwrt/qemu/systest.sh` for releases | All pass; no sanitizer report |
| Review | §9 checklist | Each item checked |

cppcheck is run in a container on a host without it:

```sh
docker run --rm -u $(id -u):$(id -g) -v "$PWD":/src -w /src <image with cppcheck and make> make cppcheck
```

A commercial MISRA C++:2023 checker (for example Helix QAC, Parasoft
C/C++test, PC-lint Plus or Polyspace) would turn most of §5 into automatic
checks. When one is adopted, record its baseline in §8.

## 8. Baseline (2026-11-01)

Version 2.0 (`donghoa-1.0-r9`), the C++17 rewrite:

- `make` with the §3 flags: 0 warnings (GCC 13, and the OpenWrt 25.12 SDK
  toolchain for x86-64 musl).
- `make check-deps`: `NEEDED libc` only. On OpenWrt: `donghoa` 151 KB,
  `donghoa_cli` 33 KB (stripped); `.bss` 242 KB.
- `make cppcheck`: 0 findings. With `--enable=style`, cppcheck makes
  stylistic suggestions (`useStlAlgorithm`, `variableScope`) and reports
  some `knownConditionTrueFalse` false positives on loops over lengths it
  cannot track. These are not tracked.
- `make test`: 302/302 checks, also under ASan/UBSan. `make itest`: PASS
  1–6 with the linear and the throughput score model, and under
  ASan/UBSan. `systest.sh` on two OpenWrt VMs: 13/13.
- Confinement grep (§7): only `src/os.cpp`.

## 9. Review checklist

- [ ] Builds without warnings, normal and sanitizer; `make test`,
      `make itest` and `make check-deps` pass.
- [ ] No POSIX call, `reinterpret_cast`, `<cstring>` or `<csignal>` outside
      `src/os.cpp`.
- [ ] Every external input (network, hostapd, netlink, radiotap, config) is
      length-checked before use; wire enum values are validated before a
      `static_cast`.
- [ ] No heap, no exception, no throwing library call (`substr`, `at`), no
      recursion, no unbounded loop or blocking call.
- [ ] Braces on every body; conditions written out; every `switch` has
      `default` and `break`s; `if … else if` ends with `else`.
- [ ] Return values used or discarded with `(void)`; errors handled.
- [ ] `U` on unsigned literals; no implicit narrowing; `static_cast` only.
- [ ] Single-argument constructors `explicit`; members default-initialized.
- [ ] New wire values only in `src/proto.hpp`, with `docs/PROTOCOL.md` and
      the round-trip tests updated together.
- [ ] A new deviation is recorded in §6.2 in the same change.
