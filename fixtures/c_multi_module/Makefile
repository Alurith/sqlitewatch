CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

.PHONY: all clean

all: fixture libsqlite_complete.so libsqlite_incomplete.so

fixture: fixture.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

libsqlite_complete.so: sqlite_complete.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

libsqlite_incomplete.so: sqlite_incomplete.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

clean:
	rm -f fixture libsqlite_complete.so libsqlite_incomplete.so
