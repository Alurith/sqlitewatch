# C embedded SQLite fixture

This fixture vendors the official SQLite 3.53.3 amalgamation without downloading
anything during a build.

- Release: SQLite 3.53.3
- Amalgamation: <https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip>
- `SQLITE_SOURCE_ID`: `2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62`
- SHA3-256 (`sqlite3.c`): `28e484abdaa43630e34040ef6ed92be973a1ad54107803d8af5145b889c23ed7`

Build and inspect the visible-symbol variant:

```bash
make -C fixtures/c_embedded
make -C fixtures/c_embedded check-linkage check-symbols
./fixtures/c_embedded/fixture-sqlite-embedded
```

The executable contains SQLite directly and is not linked with `libsqlite3`.
`make stripped` creates `fixture-sqlite-embedded-stripped`, whose symbols are
removed with `strip --strip-all`. It is a documented `UNSUPPORTED` case, not a
successful instrumentation result. SQLiteWatch does not use binary fingerprinting
to recover stripped symbols.

The target uses only an in-memory database and prints the stable marker
`name=Ada`; no database file is created.
