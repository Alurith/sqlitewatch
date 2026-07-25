CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

.PHONY: all late long abrupt page-boundary check-linkage clean

all: fixture

fixture: fixture.c
	$(CC) $(CFLAGS) -o $@ $< -lsqlite3

late: fixture-late

fixture-late: fixture_late.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

long: fixture-long

fixture-long: fixture_long.c
	$(CC) $(CFLAGS) -o $@ $< -lsqlite3

abrupt: fixture-abrupt

fixture-abrupt: fixture_abrupt.c
	$(CC) $(CFLAGS) -o $@ $< -lsqlite3

page-boundary: fixture-page-boundary

fixture-page-boundary: fixture_page_boundary.c
	$(CC) $(CFLAGS) -o $@ $< -lsqlite3

check-linkage: fixture
	@ldd fixture | grep -E 'libsqlite3(\.so|\.so\.)' >/dev/null || (echo 'libsqlite3.so linkage not found' >&2; exit 1)
	@echo 'dynamic SQLite linkage verified'

clean:
	rm -f fixture fixture-late fixture-long fixture-abrupt fixture-page-boundary
