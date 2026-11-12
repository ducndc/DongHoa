CXX ?= g++
CXXFLAGS ?= -O2 -g
# C++17, no exceptions, no RTTI, no heap: the binaries need only libc
# (no libstdc++.so) on the router. See docs/CODING_CONVENTION.md.
# Always applied, also when CXXFLAGS is given on the command line.
DH_CXXFLAGS := -std=c++17 -fno-exceptions -fno-rtti -fno-threadsafe-statics \
            -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast \
            -Wuseless-cast -Wcast-qual -Wpedantic -Isrc
LDFLAGS ?=
DH_LDFLAGS := -Wl,--as-needed

CORE := src/text.cpp src/log.cpp src/os.cpp src/sha256.cpp src/sha512.cpp src/ed25519.cpp src/trust.cpp src/proto.cpp src/rrm.cpp \
        src/config.cpp src/policy.cpp src/hapd_parse.cpp src/nlparse.cpp src/consistency.cpp src/metrics.cpp
DAEMON := $(CORE) src/l2.cpp src/hapd.cpp src/survey.cpp src/peer.cpp src/local.cpp \
          src/msg.cpp src/steer.cpp src/amon.cpp src/ctrl.cpp src/rrm_log.cpp src/devclass.cpp src/vendor_rssi.cpp \
          src/enroll.cpp src/check.cpp \
          src/main.cpp
CLI := src/text.cpp src/os.cpp tools/donghoa_cli.cpp
TESTS := tests/test_unit

all: donghoa donghoa_cli

donghoa: $(DAEMON) src/*.hpp
	$(CXX) $(DH_CXXFLAGS) $(CXXFLAGS) -o $@ $(DAEMON) $(DH_LDFLAGS) $(LDFLAGS)

donghoa_cli: $(CLI) src/*.hpp
	$(CXX) $(DH_CXXFLAGS) $(CXXFLAGS) -o $@ $(CLI) $(DH_LDFLAGS) $(LDFLAGS)

tests/test_unit: tests/test_unit.cpp $(CORE) src/*.hpp
	$(CXX) $(DH_CXXFLAGS) $(CXXFLAGS) -Wno-old-style-cast -Wno-useless-cast -o $@ tests/test_unit.cpp $(CORE) $(DH_LDFLAGS) $(LDFLAGS)

test: $(TESTS)
	./tests/test_unit

# Two daemons + two mock hostapd instances over the UDP "sim" transport.
# No root needed.
itest: donghoa donghoa_cli
	python3 tests/itest.py

# The binaries must not depend on libstdc++.so (it is not on the router).
check-deps: donghoa donghoa_cli
	@! readelf -d donghoa donghoa_cli | grep -E 'NEEDED.*(libstdc\+\+|libgcc_s)' && echo "deps OK: libc only"

# General static analysis (cppcheck has no MISRA C++ addon; see
# docs/CODING_CONVENTION.md for how MISRA C++:2023 is enforced).
CPPCHECK = cppcheck --std=c++17 --language=c++ --enable=warning,portability --inline-suppr \
	-Isrc --suppress=missingIncludeSystem -q --template='{file}:{line}: {severity} {id}: {message}'
cppcheck:
	@$(CPPCHECK) src tools

# Coding-convention rules the compiler does not enforce (docs/CODING_CONVENTION.md §7)
style:
	@python3 tools/style_check.py

# libFuzzer targets for every parser of outside input (fuzz/README.md).
# Needs clang with libFuzzer. FUZZ_TIME: seconds per target.
FUZZ_CXX ?= clang++-19
FUZZ_TIME ?= 60
FUZZ_TARGETS := arcp radio text
FUZZ_FLAGS := -std=c++17 -fno-exceptions -fno-rtti -Isrc -O1 -g \
	-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined

build/fuzz/fuzz_%: fuzz/fuzz_%.cpp $(CORE) src/*.hpp
	@mkdir -p build/fuzz
	$(FUZZ_CXX) $(FUZZ_FLAGS) -o $@ $< $(CORE)

fuzz-build: $(FUZZ_TARGETS:%=build/fuzz/fuzz_%)

fuzz: fuzz-build
	python3 fuzz/make_seeds.py build/fuzz/seeds
	@set -e; for t in $(FUZZ_TARGETS); do \
		mkdir -p build/fuzz/corpus/$$t; \
		echo "== fuzz_$$t ($(FUZZ_TIME) s, log build/fuzz/$$t.log)"; \
		if ! build/fuzz/fuzz_$$t -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
			-artifact_prefix=build/fuzz/crash-$$t- \
			build/fuzz/corpus/$$t build/fuzz/seeds/$$t >build/fuzz/$$t.log 2>&1; then \
			grep -A40 -E '^==[0-9]+==ERROR|runtime error|deadly signal' build/fuzz/$$t.log | head -60; \
			exit 1; \
		fi; \
		grep -E 'stat::(number_of_executed_units|new_units_added)' build/fuzz/$$t.log; \
	done; echo "fuzz OK: no crashes"

# Re-run one saved input: make fuzz-repro T=arcp F=build/fuzz/crash-arcp-...
fuzz-repro: fuzz-build
	build/fuzz/fuzz_$(T) $(F)

clean:
	rm -f donghoa donghoa_cli $(TESTS)
	rm -rf build/fuzz

.PHONY: all test itest check-deps cppcheck style clean fuzz fuzz-build fuzz-repro
