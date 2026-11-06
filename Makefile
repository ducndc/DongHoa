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

CORE := src/text.cpp src/log.cpp src/os.cpp src/sha256.cpp src/proto.cpp src/rrm.cpp \
        src/config.cpp src/policy.cpp src/hapd_parse.cpp
DAEMON := $(CORE) src/l2.cpp src/hapd.cpp src/survey.cpp src/peer.cpp src/local.cpp \
          src/msg.cpp src/steer.cpp src/amon.cpp src/ctrl.cpp src/rrm_log.cpp src/devclass.cpp \
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

clean:
	rm -f donghoa donghoa_cli $(TESTS)

.PHONY: all test itest check-deps cppcheck clean
