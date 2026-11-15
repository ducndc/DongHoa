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

# Everything built lands under $(BUILD): objects in obj/, binaries in bin/.
# One object per source with header dependencies (-MMD), so an edit rebuilds
# only what uses it; use make -j. A second configuration lives beside the
# first under another BUILD, e.g.
#   make BUILD=build/asan CXXFLAGS="-O1 -g -fsanitize=address,undefined" itest
BUILD ?= build
OBJ := $(BUILD)/obj
BIN := $(BUILD)/bin

# The directory is the layer (docs/ARCHITECTURE.md): base <- core <- io <-
# daemon, and cli on base alone. A file dropped into a directory joins the
# matching binaries; base and core are also what the unit tests and the fuzz
# targets link, so they stay free of daemon state.
BASE_SRC := $(sort $(wildcard src/base/*.cpp))
CORE_SRC := $(sort $(wildcard src/core/*.cpp))
IO_SRC := $(sort $(wildcard src/io/*.cpp))
DAEMON_SRC := $(sort $(wildcard src/daemon/*.cpp))
PURE_SRC := $(BASE_SRC) $(CORE_SRC)
CLI_SRC := src/base/text.cpp src/base/os.cpp src/cli/donghoa_cli.cpp
TEST_SRC := $(sort $(wildcard tests/unit/*.cpp))
HDRS := $(wildcard src/*/*.hpp)

objs = $(patsubst %.cpp,$(OBJ)/%.o,$(1))
DAEMON_OBJ := $(call objs,$(PURE_SRC) $(IO_SRC) $(DAEMON_SRC))
CLI_OBJ := $(call objs,$(CLI_SRC))
TEST_OBJ := $(call objs,$(TEST_SRC) $(PURE_SRC))
ALL_OBJ := $(sort $(DAEMON_OBJ) $(CLI_OBJ) $(TEST_OBJ))

# make V=1 prints the full commands.
Q := $(if $(V),,@)

all: donghoa donghoa_cli

donghoa: $(BIN)/donghoa
donghoa_cli: $(BIN)/donghoa_cli

$(BIN)/donghoa: $(DAEMON_OBJ)
$(BIN)/donghoa_cli: $(CLI_OBJ)
$(BIN)/test_unit: $(TEST_OBJ)

$(BIN)/%:
	@mkdir -p $(@D)
	@echo "  LD   $@"
	$(Q)$(CXX) $(DH_CXXFLAGS) $(CXXFLAGS) -o $@ $^ $(DH_LDFLAGS) $(LDFLAGS)

# Test code may use casts the production code may not (CODING_CONVENTION §6.1).
$(OBJ)/tests/%.o: DH_CXXFLAGS += -Wno-old-style-cast -Wno-useless-cast

$(OBJ)/%.o: %.cpp
	@mkdir -p $(@D)
	@echo "  CXX  $<"
	$(Q)$(CXX) $(DH_CXXFLAGS) $(CXXFLAGS) -MMD -MP -c -o $@ $<

-include $(ALL_OBJ:.o=.d)

# make test T=policy runs only the tests whose name contains "policy".
test: $(BIN)/test_unit
	$(BIN)/test_unit $(T)

# Real daemons + mock hostapd instances over the UDP "sim" transport.
# No root needed.
DONGHOA_BIN ?= $(abspath $(BIN)/donghoa)
DONGHOA_CLI_BIN ?= $(abspath $(BIN)/donghoa_cli)
itest: donghoa donghoa_cli
	DONGHOA_BIN="$(DONGHOA_BIN)" DONGHOA_CLI_BIN="$(DONGHOA_CLI_BIN)" python3 tests/itest.py

# The binaries must not depend on libstdc++.so (it is not on the router).
check-deps: donghoa donghoa_cli
	@! readelf -d $(BIN)/donghoa $(BIN)/donghoa_cli | grep -E 'NEEDED.*(libstdc\+\+|libgcc_s)' \
		&& echo "deps OK: libc only"

# General static analysis (cppcheck has no MISRA C++ addon; see
# docs/CODING_CONVENTION.md for how MISRA C++:2023 is enforced).
CPPCHECK = cppcheck --std=c++17 --language=c++ --enable=warning,portability --inline-suppr \
	-Isrc --suppress=missingIncludeSystem -q --template='{file}:{line}: {severity} {id}: {message}'
cppcheck:
	@$(CPPCHECK) src

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

build/fuzz/fuzz_%: fuzz/fuzz_%.cpp $(PURE_SRC) $(HDRS)
	@mkdir -p build/fuzz
	$(FUZZ_CXX) $(FUZZ_FLAGS) -o $@ $< $(PURE_SRC)

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
	rm -rf $(OBJ) $(BIN) build/fuzz

.PHONY: all donghoa donghoa_cli test itest check-deps cppcheck style clean fuzz fuzz-build fuzz-repro
