CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

.PHONY: all clean

all: fixture-fork-inherited

fixture-fork-inherited: fixture_fork_inherited.c
	$(CC) $(CFLAGS) -o $@ $< -lsqlite3

clean:
	rm -f fixture-fork-inherited
