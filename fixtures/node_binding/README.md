# Optional Node SQLite binding fixture

The fixture pins `better-sqlite3` to **12.11.1**. It is intended for Node 25
(`process.versions.modules` is recorded by the integration test); Node is an
optional toolchain and is not a Python project dependency.

Install the native addon from this directory:

```bash
npm ci
node fixture.js
```

The script delays `require("better-sqlite3")` until after startup, uses an
in-memory database, and prints `names=Ada,Grace`. The integration test runs the
same script under SQLiteWatch and records Node version, ABI, architecture,
npm/binding installation diagnostics, and the resulting matrix status.

If Node/npm are absent, or npm cannot install a compatible prebuild/native
addon because of the local runtime or network, only this scenario is
`SKIPPED`. If the addon loads but `sqlite3_prepare_v2` cannot be found, the
scenario is `UNSUPPORTED`, not a passing or silent `NOT_DETECTED` result.
`node_modules/` is intentionally ignored and is never committed.
