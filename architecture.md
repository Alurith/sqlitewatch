
# SQLiteWatch — Architecture

## 1. Purpose

This document describes the proposed internal architecture of SQLiteWatch.

SQLiteWatch is a runtime SQLite profiler designed to observe SQL statements executed by an arbitrary application without requiring changes to the application's source code, ORM, framework, or SQLite integration.

The public execution model is:

```bash
sqlitewatch [options] -- <command> [args...]
```

Examples:

```bash
sqlitewatch -- pytest
sqlitewatch -- python manage.py test
sqlitewatch -- node app.js
sqlitewatch -- ./application
```

SQLiteWatch launches or attaches to the target process, instruments the SQLite C API, collects runtime statement metrics, aggregates the results, evaluates configured rules, and produces a report.

The architecture must remain independent from the implementation language used to build SQLiteWatch.

---

# 2. Architectural Goals

The architecture is designed around the following goals.

## 2.1 Application independence

SQLiteWatch must not depend on:

* application language;
* framework;
* ORM;
* SQLite driver;
* application architecture.

The integration point is the SQLite native API rather than the framework or database abstraction layer.

---

## 2.2 Zero application changes

The target application must not:

* import SQLiteWatch;
* register middleware;
* install ORM plugins;
* modify database connections;
* change SQL queries;
* use a custom SQLite build.

The application should execute normally under SQLiteWatch.

---

## 2.3 Runtime observation

SQLiteWatch analyzes statements that are actually executed.

It does not primarily perform static SQL analysis.

The core data flow is:

```text
Application
    │
    ▼
SQLite C API
    │
    ├── statement preparation
    ├── statement execution
    ├── statement reset
    └── statement finalization
    │
    ▼
SQLiteWatch instrumentation
    │
    ▼
Runtime metrics
```

---

## 2.4 Cross-platform design

The high-level architecture must support:

```text
Linux
macOS
Windows
```

Platform-specific mechanisms may be required internally.

Those mechanisms must be isolated behind a common instrumentation interface.

---

## 2.5 Support dynamic and embedded SQLite

SQLiteWatch should support both:

```text
Application
    │
    ▼
libsqlite3.so / sqlite3.dll
```

and:

```text
Application or native module
    │
    └── sqlite3.c compiled into binary
```

Support for embedded SQLite depends on SQLite functions being discoverable and instrumentable at runtime.

---

# 3. High-Level Architecture

SQLiteWatch is divided into five major layers.

```text
┌─────────────────────────────────┐
│          SQLiteWatch CLI        │
│                                 │
│ configuration                   │
│ command execution               │
│ exit code management            │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│       Process Controller        │
│                                 │
│ target process lifecycle        │
│ process discovery               │
│ child process handling          │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│      Instrumentation Layer      │
│                                 │
│ SQLite discovery                │
│ native function interception    │
│ runtime event generation        │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│       Analysis Engine           │
│                                 │
│ statement tracking              │
│ query normalization             │
│ statistics aggregation          │
│ rule evaluation                 │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│        Reporting Layer          │
│                                 │
│ human-readable report           │
│ JSON output                     │
│ CI result                       │
└─────────────────────────────────┘
```

Each layer must communicate through explicit interfaces so that individual implementations can be replaced independently.

---

# 4. CLI Layer

The CLI is the main user-facing component.

Example:

```bash
sqlitewatch \
    --fail-fullscan-steps 10000 \
    --fail-vm-steps 1000000 \
    -- pytest
```

Responsibilities:

* parse SQLiteWatch options;
* identify the target command;
* load configuration;
* initialize the process controller;
* initialize instrumentation;
* receive analysis results;
* generate the final report;
* determine the final exit code.

The CLI must not contain platform-specific instrumentation logic.

Conceptually:

```text
CLI
 │
 ├── Config
 │
 ├── ProcessController
 │
 ├── Analyzer
 │
 └── Reporter
```

---

# 5. Process Controller

The Process Controller manages the lifecycle of the target application.

Responsibilities:

* start the target process;
* configure the instrumentation environment;
* attach instrumentation when necessary;
* monitor process termination;
* optionally detect child processes;
* collect the target process exit code.

Example:

```text
sqlitewatch
    │
    ▼
ProcessController
    │
    ├── start pytest
    │
    ├── activate instrumentation
    │
    ▼
pytest
```

The Process Controller must distinguish between:

```text
target process failure
```

and:

```text
SQLiteWatch rule failure
```

---

# 6. Instrumentation Layer

The Instrumentation Layer is the component responsible for observing SQLite.

This is the most technically sensitive part of SQLiteWatch.

Its public interface should remain independent from the concrete instrumentation technology.

Conceptually:

```text
InstrumentationEngine
    │
    ├── start(process)
    ├── discover_sqlite()
    ├── attach()
    ├── receive_events()
    └── stop()
```

Possible implementations may use:

* dynamic library interposition;
* runtime function hooking;
* dynamic binary instrumentation;
* operating-system-specific instrumentation APIs.

The implementation strategy is not part of SQLiteWatch's public API.

---

# 7. SQLite Discovery

The Instrumentation Layer must detect where SQLite is located inside the target process.

Possible cases:

## Dynamic SQLite

```text
process
   │
   ▼
libsqlite3.so
```

or:

```text
process
   │
   ▼
sqlite3.dll
```

The SQLite API is exposed by a dynamically loaded library.

---

## Embedded SQLite

```text
process
   │
   ▼
native module
   │
   └── sqlite3.c
```

Examples may include:

* SQLite compiled directly into an executable;
* SQLite compiled into a native language extension;
* SQLite included inside a Node native addon;
* SQLite included inside another shared library.

The instrumentation layer must search loaded executable modules for the required SQLite functions.

---

# 8. Required SQLite API

The minimum SQLite functions required by the profiler are:

```text
sqlite3_prepare_v2
sqlite3_prepare_v3
sqlite3_reset
sqlite3_finalize
sqlite3_stmt_status
```

Depending on implementation details, additional functions may be observed.

Possible examples:

```text
sqlite3_open
sqlite3_open_v2
sqlite3_close
sqlite3_close_v2
sqlite3_step
```

The MVP should minimize the number of intercepted functions.

---

# 9. Statement Lifecycle Tracking

SQLiteWatch tracks the lifecycle of each prepared statement.

The main internal identifier is the native:

```text
sqlite3_stmt*
```

A statement context is created after successful preparation.

Conceptually:

```text
StatementContext
{
    statement_pointer
    sql
    database_connection
    execution_number
    last_metrics
}
```

The lifecycle is:

```text
sqlite3_prepare_v2
        │
        ▼
StatementContext created
        │
        ▼
Application executes statement
        │
        ▼
sqlite3_reset
        │
        ├── collect metrics
        └── statement remains active
```

or:

```text
sqlite3_finalize
        │
        ├── collect final metrics
        └── destroy StatementContext
```

---

# 10. Metric Collection

Metrics are collected through the standard:

```text
sqlite3_stmt_status()
```

API.

The MVP uses:

```text
SQLITE_STMTSTATUS_FULLSCAN_STEP
SQLITE_STMTSTATUS_SORT
SQLITE_STMTSTATUS_AUTOINDEX
SQLITE_STMTSTATUS_VM_STEP
```

The instrumentation layer should emit an execution event equivalent to:

```json
{
  "type": "statement_execution",
  "statement_id": "0x12345678",
  "sql": "SELECT * FROM users WHERE email = ?",
  "fullscan_steps": 15000,
  "sorts": 0,
  "autoindex": 0,
  "vm_steps": 43000
}
```

The exact serialization format is an implementation detail.

---

# 11. Instrumentation Events

The instrumentation layer communicates with the analysis engine through events.

The minimum event set is:

```text
SQLiteDetected
StatementPrepared
StatementExecuted
StatementFinalized
InstrumentationError
ProcessStarted
ProcessExited
```

Example:

```text
StatementPrepared
    │
    ▼
{
    statement_id,
    sql,
    database_id
}
```

Example:

```text
StatementExecuted
    │
    ▼
{
    statement_id,
    fullscan_steps,
    vm_steps,
    sorts,
    autoindex
}
```

The event model decouples instrumentation from analysis.

This allows the instrumentation technology to change without modifying the analysis engine.

---

# 12. Analysis Engine

The Analysis Engine receives instrumentation events and builds the final performance model.

Responsibilities:

* track statements;
* normalize SQL;
* aggregate equivalent queries;
* calculate totals;
* calculate maximum values;
* evaluate configured thresholds;
* rank problematic queries.

Conceptually:

```text
Instrumentation Events
        │
        ▼
Statement Tracker
        │
        ▼
Query Normalizer
        │
        ▼
Query Aggregator
        │
        ▼
Rule Engine
```

---

# 13. Query Normalization

Prepared statements typically already provide naturally normalized SQL.

Example:

```sql
SELECT * FROM users WHERE id = ?
```

However, some applications may generate literal SQL:

```sql
SELECT * FROM users WHERE id = 42
```

SQLiteWatch may optionally normalize literals.

Normalization must be conservative.

Incorrectly merging different queries is considered worse than failing to merge equivalent queries.

The normalization component should therefore be isolated:

```text
QueryNormalizer
    │
    ├── normalize(sql)
    └── fingerprint(sql)
```

A query fingerprint is used as the aggregation key.

---

# 14. Query Aggregation

Each normalized query has an aggregate record.

Conceptually:

```text
QueryAggregate
{
    fingerprint
    representative_sql

    executions

    total_fullscan_steps
    max_fullscan_steps

    total_vm_steps
    max_vm_steps

    total_sorts
    total_autoindex
}
```

Example:

```text
SELECT * FROM users WHERE email = ?

executions           425
total fullscan       4,250,000
max fullscan         10,000
total vm steps       13,720,312
max vm steps         45,231
sorts                0
autoindex            0
```

---

# 15. Rule Engine

The Rule Engine evaluates query aggregates against configured policies.

Initial rules:

```text
FullScanRule
VmStepsRule
AutoIndexRule
```

Possible future rules:

```text
SortRule
RegressionRule
ExecutionCountRule
```

Each rule receives a query aggregate and returns:

```text
PASS
WARNING
FAIL
```

with optional metadata.

Example:

```text
FullScanRule

threshold = 10000

query.max_fullscan_steps = 150000

result = FAIL
```

Rules must remain independent from the instrumentation implementation.

---

# 16. Reporting Layer

The reporting layer converts analysis results into user-facing output.

Initial formats:

```text
terminal
JSON
```

Possible future formats:

```text
JUnit
SARIF
HTML
```

The reporter receives only structured analysis data.

It must not access instrumentation internals.

Conceptually:

```text
AnalysisResult
      │
      ├── TerminalReporter
      └── JsonReporter
```

---

# 17. SQLiteWatch Exit Code

SQLiteWatch must account for two independent outcomes.

```text
Target process result
SQLiteWatch analysis result
```

Possible state:

```text
Target: PASS
SQLiteWatch: PASS
→ success
```

```text
Target: PASS
SQLiteWatch: FAIL
→ failure
```

```text
Target: FAIL
SQLiteWatch: PASS
→ failure
```

```text
Target: FAIL
SQLiteWatch: FAIL
→ failure
```

SQLiteWatch must preserve enough information to distinguish target failures from performance policy failures.

---

# 18. Doctor Mode Architecture

Doctor mode validates instrumentation compatibility.

Example:

```bash
sqlitewatch doctor -- python manage.py test
```

The process controller launches the target application with instrumentation enabled.

The instrumentation layer then reports:

```text
SQLite detected
SQLite module
SQLite linkage model
Required functions
Instrumentation status
```

Conceptually:

```text
Doctor
  │
  ▼
Process Controller
  │
  ▼
Instrumentation Discovery
  │
  ├── SQLite found?
  ├── module identified?
  ├── prepare found?
  ├── finalize found?
  └── stmt_status found?
```

The main objective is preventing silent instrumentation failures.

---

# 19. Dynamic SQLite Strategy

For dynamically linked SQLite:

```text
Application
    │
    ▼
SQLite shared library
```

the instrumentation engine should locate exported SQLite symbols and intercept them directly.

Conceptually:

```text
Loaded modules
      │
      ▼
Find SQLite module
      │
      ▼
Resolve sqlite3_prepare_v2
      │
      ▼
Install hook
```

This is expected to be the simplest instrumentation scenario.

---

# 20. Embedded SQLite Strategy

For embedded SQLite:

```text
Application
    │
    ▼
Native module
    │
    └── SQLite implementation
```

SQLiteWatch attempts to locate SQLite functions within loaded modules.

Three outcomes are possible.

### Symbols directly available

```text
sqlite3_prepare_v2
sqlite3_finalize
sqlite3_stmt_status
```

Instrumentation proceeds normally.

### Symbols discoverable internally

The instrumentation backend may resolve their addresses and attach directly.

Instrumentation proceeds if the backend supports this scenario.

### Functions not discoverable

SQLiteWatch reports:

```text
SQLite detected
Instrumentation unsupported
```

The MVP does not attempt advanced binary fingerprinting.

---

# 21. Process Tree

An application may create child processes.

Example:

```text
sqlitewatch
    │
    ▼
pytest
    │
    ├── worker 1
    ├── worker 2
    └── worker 3
```

SQLite may be used by:

* the parent process;
* child processes;
* both.

The architecture should allow instrumentation of multiple processes.

The MVP may initially support only the primary process.

However, process identity must be included in the internal event model.

Example:

```json
{
  "process_id": 1234,
  "statement_id": "0x12345678"
}
```

This prevents future architectural changes when child-process support is added.

---

# 22. Threads

SQLite may be used concurrently by multiple threads.

Instrumentation hooks must therefore be thread-safe.

Statement identity cannot be based only on SQL.

The combination:

```text
process
+
native statement pointer
```

must uniquely identify a live statement.

Internal tracking structures must support concurrent events.

Instrumentation callbacks must perform minimal work.

---

# 23. Multiple Databases

A single process may open multiple SQLite databases.

Example:

```text
application
    │
    ├── app.sqlite3
    ├── cache.sqlite3
    └── :memory:
```

The architecture should allow queries to be associated with a database when this information is available.

The MVP report may aggregate all databases together.

The internal data model should nevertheless retain:

```text
database_id
```

to allow future filtering.

---

# 24. Event Transport

Instrumentation typically executes inside or alongside the target process.

The analysis engine may execute inside the SQLiteWatch controller process.

Therefore an event transport layer may be required.

Possible implementations:

```text
in-process callbacks
IPC
shared memory
pipes
sockets
instrumentation framework messaging
```

The architecture should expose an abstract event channel:

```text
Instrumentation
      │
      │ StatementEvent
      ▼
EventChannel
      │
      ▼
Analysis Engine
```

The transport implementation must not affect the analysis model.

---

# 25. Performance Considerations

Instrumentation runs on a potentially hot database execution path.

Hooks must therefore perform minimal synchronous work.

The instrumentation layer should avoid:

* synchronous disk writes;
* complex SQL parsing;
* report generation;
* expensive symbol resolution after startup;
* `EXPLAIN QUERY PLAN` on every query.

Recommended flow:

```text
SQLite hook
   │
   ├── collect raw metrics
   ├── build lightweight event
   ▼
Event queue
   │
   ▼
Analysis outside hot path
```

Aggregation should occur outside critical SQLite calls whenever possible.

---

# 26. Failure Handling

Instrumentation failure must never be silently interpreted as successful profiling.

Possible failures include:

```text
SQLite not detected
SQLite functions not found
instrumentation backend failure
event channel failure
target process terminated unexpectedly
```

The instrumentation layer must report explicit state:

```text
ACTIVE
UNSUPPORTED
FAILED
NOT_DETECTED
```

CI mode should fail when SQLite activity is expected but cannot be observed.

---

# 27. Safety

SQLiteWatch is a passive observer.

Instrumentation must never intentionally:

* modify SQL;
* modify SQL parameters;
* change query results;
* alter SQLite return values;
* modify transactions;
* modify database configuration;
* create indexes;
* execute additional write queries.

The target application's behavior must remain functionally equivalent.

---

# 28. EXPLAIN QUERY PLAN

`EXPLAIN QUERY PLAN` is not part of the primary runtime instrumentation path.

Primary detection uses:

```text
sqlite3_stmt_status()
```

Future diagnostic flows may run EXPLAIN only after identifying a problematic query.

Conceptually:

```text
Runtime execution
      │
      ▼
Problem detected
      │
      ▼
Optional diagnostics
      │
      ▼
EXPLAIN QUERY PLAN
```

This functionality should live in a separate diagnostic component.

---

# 29. Baseline Architecture

Baseline comparison is not required for the first MVP iteration but should fit naturally into the architecture.

```text
Current AnalysisResult
          │
          ▼
Baseline Comparator
          │
          ◄──── baseline.json
          │
          ▼
RegressionResult
```

The comparator should operate on query fingerprints and aggregated metrics.

It must not depend on runtime instrumentation.

---

# 30. Proposed Internal Modules

A possible logical module structure is:

```text
sqlitewatch
│
├── cli
│
├── config
│
├── process
│
│   ├── launcher
│   └── process_tree
│
├── instrumentation
│   ├── engine
│   ├── discovery
│   ├── symbols
│   └── events
│
├── analysis
│   ├── statements
│   ├── normalization
│   ├── aggregation
│   └── rules
│
├── reporting
│   ├── terminal
│   └── json
│
├── baseline
│
└── doctor
```

This structure is conceptual and independent from implementation language.

---

# 31. Instrumentation Backend

The instrumentation subsystem should expose a common interface.

Conceptually:

```text
InstrumentationBackend
│
├── launch(command)
├── attach(process)
├── discover_modules()
├── resolve_function(name)
├── install_hook(function)
├── emit_event(event)
└── detach()
```

Different backends may eventually exist.

Example:

```text
InstrumentationBackend
        │
        ├── RuntimeInstrumentationBackend
        ├── DynamicLinkerBackend
        └── PlatformNativeBackend
```

The rest of SQLiteWatch must not depend on which backend is selected.

---

# 32. POC Instrumentation Technology

For the initial proof of concept, a dynamic instrumentation framework should be evaluated before implementing custom platform-specific hooking.

Frida is a candidate for the POC because it provides:

* runtime native function interception;
* module enumeration;
* native symbol lookup;
* support for multiple operating systems;
* instrumentation of running native processes.

Frida is not considered part of the SQLiteWatch public architecture.

It is an initial implementation candidate for the `InstrumentationBackend`.

Conceptually:

```text
SQLiteWatch
      │
      ▼
InstrumentationBackend
      │
      ▼
Frida-based POC
```

A future implementation could replace it with another backend without changing:

* CLI;
* event model;
* analysis engine;
* rules;
* reports.

---

# 33. POC Architecture

The first technical POC should be intentionally minimal.

```text
SQLiteWatch Controller
        │
        ▼
Instrumentation Backend
        │
        ▼
Target Process
        │
        ▼
sqlite3_prepare_v2
        │
        ▼
Capture SQL
        │
        ▼
Send event to Controller
```

The POC does not initially need:

* aggregation;
* rules;
* reports;
* baseline support.

The first goal is simply:

```text
sqlitewatch -- <application>
```

produces:

```text
SQLite query detected:

SELECT * FROM users WHERE id = ?
```

---

# 34. POC Validation Matrix

The instrumentation POC should be tested against at least:

```text
1. C application dynamically linked to SQLite

2. C application with sqlite3.c embedded

3. Python standard sqlite3 module

4. Django using SQLite

5. Node native SQLite binding
```

For each environment the POC records:

```text
SQLite detected
SQLite location
dynamic or embedded
required symbols found
instrumentation successful
SQL captured
```

Example matrix:

```text
                         Detect   Hook   SQL
C dynamic                  ✓       ✓      ✓
C embedded                 ✓       ✓      ✓
Python sqlite3             ✓       ✓      ✓
Django                     ✓       ✓      ✓
Node SQLite                ?       ?      ?
```

The architecture is considered validated when the same instrumentation abstraction works across multiple application ecosystems.

---

# 35. MVP Implementation Stages

## Stage 1 — Instrumentation POC

Goal:

```text
Intercept sqlite3_prepare_v2
```

Deliverables:

```text
process launcher
SQLite discovery
function interception
SQL capture
```

---

## Stage 2 — Statement tracking

Add:

```text
sqlite3_prepare_v2
sqlite3_prepare_v3
sqlite3_reset
sqlite3_finalize
```

Maintain:

```text
sqlite3_stmt* → StatementContext
```

---

## Stage 3 — Runtime metrics

Add:

```text
sqlite3_stmt_status
```

Collect:

```text
FULLSCAN_STEP
VM_STEP
SORT
AUTOINDEX
```

---

## Stage 4 — Analysis

Add:

```text
query normalization
query aggregation
threshold rules
```

---

## Stage 5 — CLI report

Implement:

```text
sqlitewatch -- pytest
```

with:

```text
human-readable report
JSON report
exit code
```

---

## Stage 6 — CI mode

Implement:

```text
--fail-fullscan-steps
--fail-vm-steps
--fail-on-autoindex
```

---

## Stage 7 — Doctor

Implement:

```text
sqlitewatch doctor -- <command>
```

to validate instrumentation support.

---

# 36. Future Architecture

Features intentionally outside the initial MVP include:

```text
baseline comparison
regression detection
query plan diagnostics
index suggestions
N+1 detection
call-stack attribution
source code attribution
HTTP request correlation
SARIF output
JUnit output
multi-process aggregation
historical reports
```

These features should be implemented on top of the event and analysis architecture rather than inside the instrumentation layer.

---

# 37. Core Architectural Principle

SQLiteWatch should maintain a strict separation between:

```text
HOW SQLite is observed
```

and:

```text
WHAT SQLiteWatch does with the observations
```

Therefore:

```text
Instrumentation
      │
      ▼
Events
      │
      ▼
Analysis
      │
      ▼
Rules
      │
      ▼
Reports
```

The instrumentation technology may change.

The application's programming language may change.

The SQLite integration may change.

The analysis model and user experience should remain stable.

The architectural objective is ultimately to make the following command possible:

```bash
sqlitewatch --fail-fullscan-steps 10000 -- pytest
```

without SQLiteWatch needing to know what Django, Python, pytest, or the application's ORM are.
