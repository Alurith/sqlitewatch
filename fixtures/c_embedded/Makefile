CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -Wextra -Wpedantic
LDFLAGS ?= -rdynamic

BINARY := fixture-sqlite-embedded
STRIPPED := $(BINARY)-stripped
SOURCES := fixture.c sqlite3.c

.PHONY: all fixture check-linkage check-symbols stripped clean

all: $(BINARY)

fixture: $(BINARY)

$(BINARY): $(SOURCES) sqlite3.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ fixture.c sqlite3.c

check-linkage: $(BINARY)
	@if ldd $(BINARY) | grep -qE 'libsqlite3(\\.so|\\.so\\.)'; then \
		echo 'unexpected dynamic libsqlite3 linkage'; exit 1; \
	fi
	@echo 'embedded SQLite linkage verified'

check-symbols: $(BINARY)
	@nm -g $(BINARY) | grep -E '[[:space:]]sqlite3_prepare_v2$$' >/dev/null || \
		(echo 'sqlite3_prepare_v2 symbol not found' >&2; exit 1)
	@echo 'sqlite3_prepare_v2 symbol verified'

stripped: $(SOURCES) sqlite3.h
	$(CC) $(CFLAGS) -o $(STRIPPED) fixture.c sqlite3.c
	strip --strip-all $(STRIPPED)

clean:
	rm -f $(BINARY) $(STRIPPED)
