CC ?= gcc
CXX ?= g++
CPPFLAGS ?=
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -pedantic
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS ?=
LDLIBS ?=

REF_BIN := build/ref/runfile
USER_BIN := build/user/runfile

.PHONY: all ref user clean

all: ref user

ref:
	@mkdir -p $(dir $(REF_BIN))
	@set -eu; \
	if [ -f sample/main.c ] && [ -f sample/main.cpp ]; then \
		echo "multiple entry files found for sample: sample/main.c sample/main.cpp" >&2; \
		exit 1; \
	elif [ -f sample/main.c ]; then \
		$(CC) -x c $(CPPFLAGS) $(CFLAGS) sample/main.c $(LDFLAGS) $(LDLIBS) -o $(REF_BIN); \
	elif [ -f sample/main.cpp ]; then \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) sample/main.cpp $(LDFLAGS) $(LDLIBS) -o $(REF_BIN); \
	else \
		echo "missing sample/main.c or sample/main.cpp" >&2; \
		exit 1; \
	fi

user:
	@mkdir -p $(dir $(USER_BIN))
	@set -eu; \
	if [ -f user/main.c ] && [ -f user/main.cpp ]; then \
		echo "multiple entry files found for user: user/main.c user/main.cpp" >&2; \
		exit 1; \
	elif [ -f user/main.c ]; then \
		$(CC) -x c $(CPPFLAGS) $(CFLAGS) user/main.c $(LDFLAGS) $(LDLIBS) -o $(USER_BIN); \
	elif [ -f user/main.cpp ]; then \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) user/main.cpp $(LDFLAGS) $(LDLIBS) -o $(USER_BIN); \
	else \
		echo "missing user/main.c or user/main.cpp" >&2; \
		exit 1; \
	fi

clean:
	rm -rf build
