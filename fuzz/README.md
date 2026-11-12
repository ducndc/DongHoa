# Fuzz targets

libFuzzer harnesses for every parser that reads bytes from outside the
daemon. The parsers live in the pure layer, so each harness calls them
directly; no sockets, no daemon.

| Target | Inputs |
|---|---|
| `fuzz_arcp.cpp` | received ARCP frames: header, HMAC, Ed25519 signature, every TLV decoder, replay window; other bytes as a raw Ed25519 (key, signature, message) |
| `fuzz_radio.cpp` | first byte selects: radiotap frame (air monitor), nl80211 station-dump message, operating classes / extended capabilities |
| `fuzz_text.cpp` | first byte selects: hostapd `STATUS`, `STA`, events, hex 802.11 elements, configuration file, trust table file |

```sh
make fuzz                     # build, seed, run each target 60 s
make fuzz FUZZ_TIME=600       # longer
make fuzz-repro T=arcp F=build/fuzz/crash-arcp-<hash>   # replay a crash
```

Needs clang with libFuzzer (`FUZZ_CXX`, default `clang++-19`). Everything
goes to `build/fuzz/`: binaries, seeds (`make_seeds.py`), the growing corpus
(kept between runs), logs and crash inputs. A crash prints the sanitizer
report and fails the run.

The `key` configuration line is skipped by `fuzz_text`: its PBKDF2 (100,000
rounds) would make every input that contains it take ~50 ms. Its parsing is
covered by the unit tests.

When a new parser of outside input is added, add it to one of the targets
and give `make_seeds.py` one valid example.
