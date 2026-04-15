CC       ?= gcc
CXX      ?= g++
CPPFLAGS ?=
CFLAGS   ?= -std=c11 -O2 -Wall -Wextra -pedantic
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic
LDFLAGS  ?=
LDLIBS   ?=
PROJECT  ?= 1

SHARED_P2 := shared/Project-2
REF_P1    := runfiles/Project-1/ref
USER_P1   := runfiles/Project-1/user
REF_P2    := runfiles/Project-2/ref
USER_P2   := runfiles/Project-2/user

.PHONY: all ref user p1ref clean

ifeq ($(PROJECT),2)

all: p1ref ref user

p1ref:
	@mkdir -p build/ref
	@set -eu; \
	if [ -f $(REF_P1)/main.c ] && [ -f $(REF_P1)/main.cpp ]; then \
		echo "multiple entry files: $(REF_P1)/main.c and $(REF_P1)/main.cpp" >&2; exit 1; \
	elif [ -f $(REF_P1)/main.c ]; then \
		$(CC) -x c $(CPPFLAGS) $(CFLAGS) $(REF_P1)/main.c $(LDFLAGS) $(LDLIBS) -o build/ref/p1asm; \
	elif [ -f $(REF_P1)/main.cpp ]; then \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(REF_P1)/main.cpp $(LDFLAGS) $(LDLIBS) -o build/ref/p1asm; \
	else \
		echo "missing $(REF_P1)/main.c or $(REF_P1)/main.cpp" >&2; exit 1; \
	fi

ref:
	@mkdir -p build/ref
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
		$(SHARED_P2)/cs311.c $(SHARED_P2)/util.c \
		$(REF_P2)/parse.c $(REF_P2)/run.c \
		-I$(SHARED_P2) $(LDLIBS) -o build/ref/p2sim

user:
	@mkdir -p build/user
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
		$(SHARED_P2)/cs311.c $(SHARED_P2)/util.c \
		$(USER_P2)/run.c $(USER_P2)/parse.c \
		-I$(SHARED_P2) $(LDLIBS) -o build/user/p2sim

else

all: ref user

ref:
	@mkdir -p build/ref
	@set -eu; \
	if [ -f $(REF_P1)/main.c ] && [ -f $(REF_P1)/main.cpp ]; then \
		echo "multiple entry files: $(REF_P1)/main.c and $(REF_P1)/main.cpp" >&2; exit 1; \
	elif [ -f $(REF_P1)/main.c ]; then \
		$(CC) -x c $(CPPFLAGS) $(CFLAGS) $(REF_P1)/main.c $(LDFLAGS) $(LDLIBS) -o build/ref/p1asm; \
	elif [ -f $(REF_P1)/main.cpp ]; then \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(REF_P1)/main.cpp $(LDFLAGS) $(LDLIBS) -o build/ref/p1asm; \
	else \
		echo "missing $(REF_P1)/main.c or $(REF_P1)/main.cpp" >&2; exit 1; \
	fi

user:
	@mkdir -p build/user
	@set -eu; \
	if [ -f $(USER_P1)/main.c ] && [ -f $(USER_P1)/main.cpp ]; then \
		echo "multiple entry files: $(USER_P1)/main.c and $(USER_P1)/main.cpp" >&2; exit 1; \
	elif [ -f $(USER_P1)/main.c ]; then \
		$(CC) -x c $(CPPFLAGS) $(CFLAGS) $(USER_P1)/main.c $(LDFLAGS) $(LDLIBS) -o build/user/p1asm; \
	elif [ -f $(USER_P1)/main.cpp ]; then \
		$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(USER_P1)/main.cpp $(LDFLAGS) $(LDLIBS) -o build/user/p1asm; \
	else \
		echo "missing $(USER_P1)/main.c or $(USER_P1)/main.cpp" >&2; exit 1; \
	fi

endif

clean:
	rm -rf build
