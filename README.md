# SQLiteWatch

SQLiteWatch is a runtime profiler for SQLite applications on Linux. It observes the SQLite C API without requiring changes to your application, ORM, or database code.

It can:

- capture SQL executed by an application and its child processes;
- aggregate equivalent queries;
- report full scans, sorts, automatic indexes, and SQLite VM work;
- follow wrappers, workers, subprocesses, and development autoreloaders;
- enforce optional performance limits in local development or CI;
- verify SQLite compatibility with a dedicated Doctor command.

SQLiteWatch currently supports Linux x86_64 and Python 3.11–3.13.

## Installation

Install a specific released version directly from its Git tag:

```bash
uv tool install "git+https://github.com/Alurith/sqlitewatch.git@v0.2.0"
```

This installs SQLiteWatch in an isolated environment and makes the `sqlitewatch` command available globally. To reinstall or switch to that exact version:

```bash
uv tool install --force "git+https://github.com/Alurith/sqlitewatch.git@v0.2.0"
```

You can also run SQLiteWatch from a source checkout:

```bash
git clone https://github.com/Alurith/sqlitewatch.git
cd sqlitewatch
uv sync --locked
uv run sqlitewatch -- <command> [arguments...]
```

The `--` separator is required. Options before it belong to SQLiteWatch; everything after it is the command being observed.

## Basic usage

Profile a Python application:

```bash
sqlitewatch -- python app.py
```

Profile a test suite:

```bash
sqlitewatch -- pytest
```

Profile a Django development server:

```bash
sqlitewatch -- python manage.py runserver
```

SQLiteWatch follows child processes by default, including Django's autoreloader. For a long-running server, exercise the application normally and press `Ctrl-C` when you want SQLiteWatch to produce the report.

When profiling a different project, run the SQLiteWatch executable while remaining in the target project's directory:

```bash
/path/to/sqlitewatch/.venv/bin/sqlitewatch -- uv run -m your_application
```

## Understanding the report

The terminal report starts with a clear operational result:

- `WORKING`: SQLite activity was measured successfully;
- `WORKING WITH WARNINGS`: measurement worked, but some activity could not be evaluated completely;
- `PARTIAL`: SQLite was observed with incomplete instrumentation or process coverage;
- `SQLITE NOT DETECTED`: no SQLite activity was found;
- `FAILED`: instrumentation could not complete.

The default terminal output is intentionally concise. It hides healthy queries and shows only query patterns with potential concerns:

- `FULL_SCAN`;
- `SORT`;
- `AUTO_INDEX`;
- configured rule violations.

Equivalent query patterns are grouped together. The report includes execution counts and aggregate metrics for each problem pattern.

A warning does not necessarily mean the application failed. For example, a data-quality warning means SQLiteWatch worked but could not evaluate every observed operation with full confidence.

## Complete JSON report

Use JSON when you need every query, process, module, and metric:

```bash
sqlitewatch --format json -- python app.py
```

Write the report to a file:

```bash
sqlitewatch \
  --format json \
  --output sqlitewatch.json \
  -- python app.py
```

The JSON report uses schema version 3 and includes process-tree and process-instance information.

Reports may contain SQL literals or other application data. Treat them as potentially sensitive artifacts.

## Doctor

Doctor checks whether SQLiteWatch can detect and instrument the SQLite implementation used by an application:

```bash
sqlitewatch doctor -- python app.py
```

For a server:

```bash
sqlitewatch doctor -- python manage.py runserver
```

Generate some application activity, then press `Ctrl-C` to see the result.

Doctor reports:

- whether SQLite was detected;
- the SQLite version;
- whether the required hooks and metrics are available;
- which processes contain supported SQLite modules;
- whether complete SQLite activity was observed.

Doctor runs the target application like the normal command because it must observe real runtime activity. The difference is the result: Doctor reports compatibility, while the normal command reports query performance.

Use Doctor when SQLiteWatch does not capture queries, when adopting it in a new application, or before enabling CI rules.

## Performance rules

SQLiteWatch can fail when a query exceeds configured limits:

```bash
sqlitewatch \
  --fail-fullscan-steps 10000 \
  --fail-vm-steps 1000000 \
  --fail-on-autoindex \
  -- pytest
```

Available rules:

- `--fail-fullscan-steps N`: fail when a query exceeds `N` full-scan steps;
- `--fail-vm-steps N`: fail when a query exceeds `N` SQLite VM steps;
- `--fail-on-autoindex`: fail when SQLite uses an automatic index.

When rules are enabled, incomplete measurement fails safely instead of reporting a misleading pass.

## Process scope

Child processes are followed automatically. To observe only the root command:

```bash
sqlitewatch --no-follow-children -- python app.py
```

This is useful when the root process is the only intended target. It is usually not appropriate for wrappers, workers, or autoreloading servers.

## Exit codes

SQLiteWatch preserves application failures and provides dedicated codes for its own outcomes:

- `0`: successful run with no rule violations;
- `1`: one or more performance rules failed;
- `70`: instrumentation failed, or rule evaluation was incomplete;
- `74`: the report could not be written;
- application exit codes and signals are preserved when they take precedence.
