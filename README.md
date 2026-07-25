# SQLiteWatch

SQLiteWatch is a Linux x86_64 runtime profiler for SQLite. It observes the
SQLite C API used by a target process, aggregates statement metrics, and can
enforce performance rules without application or ORM changes.

```bash
uv sync
uv run sqlitewatch -- python app.py
uv run sqlitewatch \
  --fail-fullscan-steps 10000 \
  --fail-vm-steps 1000000 \
  --fail-on-autoindex \
  -- pytest
```

Use Doctor before enabling CI rules:

```bash
uv run sqlitewatch doctor -- python app.py
```

## Reports

Terminal output is escaped so SQL and module metadata cannot inject terminal
control sequences. JSON can be written to stdout or atomically to a UTF-8 file:

```bash
uv run sqlitewatch --format json --output sqlitewatch.json -- python app.py
```

Reports contain normalized SQL and may therefore contain literals or other
sensitive application data. Treat report files as sensitive artifacts and set
retention and access policies accordingly.

## CI outcome

Exit-code precedence is:

1. report output failure: `74`;
2. instrumentation or inconclusive-rule evaluation: `70`;
3. target signal: `128 + signal`;
4. non-zero target exit code;
5. performance-rule violation: `1`;
6. success: `0`.

With rules enabled, incomplete observations—null metrics, truncated or failed
SQL capture, unmatched/unfinished executions, conflicting lifecycle payloads,
or agent-reported observation loss—are inconclusive and fail closed with `70`.
Without rules they remain visible
warnings. Identical duplicate events are diagnostic and do not make evaluation
inconclusive.

## Scope and limits

- Linux x86_64 and the primary target process only.
- Dynamic or embedded SQLite is supported when the required symbols are
  discoverable in the same active module.
- Stripped SQLite binary fingerprinting and child-process aggregation are out
  of scope.
- SQL capture defaults to 64 KiB and is configurable up to 1 MiB with
  `--max-sql-length`.
- The normal CLI uses bounded streaming analysis. Programmatic callers that
  retain raw events have a default safety limit of 1,000,000 events.

See [`spec.md`](spec.md) for the behavioral contract and
[`architecture.md`](architecture.md) for implementation details.
