"use strict";

// This file runs in Frida's JavaScript runtime, not Node.js.
const PROTOCOL_VERSION = 1;
const SQLITE_OK = 0, SQLITE_BUSY = 5, SQLITE_LOCKED = 6, SQLITE_ROW = 100, SQLITE_DONE = 101;
const SQLITE_STMTSTATUS_FULLSCAN_STEP = 1, SQLITE_STMTSTATUS_SORT = 2;
const SQLITE_STMTSTATUS_AUTOINDEX = 3, SQLITE_STMTSTATUS_VM_STEP = 4;
const SQLITE_STMTSTATUS_RESET_FLAG = 0; // passive observer: never reset target counters
const defaultConfig = { max_sql_length: 65536, doctor: false };
const config = (typeof SQLITEWATCH_CONFIG === "object" && SQLITEWATCH_CONFIG) || defaultConfig;
const maxSqlLength = Number.isSafeInteger(Number(config.max_sql_length)) && Number(config.max_sql_length) > 0
  ? Math.min(Number(config.max_sql_length), 1048576) : defaultConfig.max_sql_length;
const doctor = config.doctor === true;

const SYMBOLS = ["sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_step", "sqlite3_reset", "sqlite3_finalize", "sqlite3_stmt_status", "sqlite3_libversion"];
const PREPARE = ["sqlite3_prepare_v2", "sqlite3_prepare_v3"];
const LIFECYCLE = ["sqlite3_step", "sqlite3_reset", "sqlite3_finalize"];
const HOOKS = {};
const hookedAddresses = new Set();
const hookedSymbolNames = new Set();
const inspectedModules = new Set();
const moduleRecords = new Map();
const statementContexts = new Map();
const lifecycleQueue = [];
const MAX_LIFECYCLE_QUEUE = 4096;
let lifecycleSequence = 0;
let hookCount = 0;
let transportFailed = false;
let statusSent = false;
let observer;

function emitNow(type, fields) {
  const payload = Object.assign({ type: type, protocol_version: PROTOCOL_VERSION }, fields || {});
  try { send(payload); }
  catch (_) { transportFailed = true; }
}

function fail(phase, error, fatal) {
  emitNow("instrumentation_error", { phase: phase, message: String(error), pid: Process.id, fatal: fatal !== false });
}

function queueLifecycle(type, fields) {
  if (transportFailed) return;
  if (lifecycleQueue.length >= MAX_LIFECYCLE_QUEUE) {
    transportFailed = true;
    fail("transport", "lifecycle queue overflow", true);
    return;
  }
  lifecycleQueue.push(Object.assign({ type: type, protocol_version: PROTOCOL_VERSION }, fields));
  if (lifecycleQueue.length >= 64) flushLifecycle();
}

function flushLifecycle() {
  if (transportFailed || lifecycleQueue.length === 0) return;
  const events = lifecycleQueue.splice(0, lifecycleQueue.length);
  try {
    send({ type: "lifecycle_batch", protocol_version: PROTOCOL_VERSION, sequence: ++lifecycleSequence, events: events });
  } catch (error) {
    transportFailed = true;
    fail("transport", "lifecycle batch send failed: " + String(error), true);
  }
}
setInterval(flushLifecycle, 25);

function pointerString(pointer) { return pointer.toString().toLowerCase(); }
function moduleName(module) { return module.name || "<anonymous>"; }
function moduleKey(module) { return module.path || moduleName(module); }
function linkageFor(module) {
  const basename = (module.path || "").split("/").pop().toLowerCase();
  return /^libsqlite3\.so(?:\..*)?$/.test(basename) || basename === "libsqlite3.dylib" || basename === "sqlite3.dll" ? "dynamic" : "embedded_or_unknown";
}
function isSqliteCandidate(module) { return (moduleName(module) + " " + (module.path || "")).toLowerCase().indexOf("sqlite") !== -1; }
function usableAddress(address) { return address !== null && address !== undefined && (typeof address.isNull !== "function" || !address.isNull()); }
function sorted(values) { return Array.from(values).sort(); }

// Frida 17 resolution order: exports first, then symbols, then enumeration.
function findSymbol(module, name) {
  let address = null;
  try { address = module.findExportByName(name); } catch (_) {}
  if (!usableAddress(address) && typeof module.findSymbolByName === "function") try { address = module.findSymbolByName(name); } catch (_) {}
  if (!usableAddress(address) && typeof module.enumerateSymbols === "function") {
    try {
      const symbols = module.enumerateSymbols();
      for (let i = 0; i < symbols.length; i++) if (symbols[i].name === name && usableAddress(symbols[i].address)) { address = symbols[i].address; break; }
    } catch (_) { /* enumeration is a startup/candidate-only fallback */ }
  }
  return usableAddress(address) ? address : null;
}

function reportDetected(module, name, address) {
  emitNow("sqlite_detected", { pid: Process.id, module: moduleName(module), path: module.path || "", symbol: name, address: pointerString(address), linkage: linkageFor(module) });
}

function emptyRecord(module, scanned) {
  return { module: module, candidate: isSqliteCandidate(module), scanned: scanned, symbols: new Map(), metricReader: null, hooksAttempted: new Set(), hooksInstalled: new Set(), hooksFailed: new Set(), reasons: new Set(), sqliteVersion: null };
}

function moduleReasons(record) {
  const reasons = new Set(record.reasons);
  if (!record.scanned) reasons.add("module not scanned: late non-SQLite module scan is intentionally unsafe");
  if (record.scanned) {
    const prepare = PREPARE.some(name => record.hooksInstalled.has(name));
    if (!prepare) reasons.add("missing prepare entrypoint");
    const missingLifecycle = LIFECYCLE.filter(name => !record.hooksInstalled.has(name));
    if (missingLifecycle.length) reasons.add("missing lifecycle hooks: " + missingLifecycle.join(", "));
    if (!record.symbols.has("sqlite3_stmt_status")) reasons.add("sqlite3_stmt_status absent");
    else if (record.metricReader === null) reasons.add("sqlite3_stmt_status is not invocable");
    if (record.candidate && record.symbols.size === 0) reasons.add("SQLite candidate has no discoverable symbols; binary fingerprinting is out of scope");
  }
  return sorted(reasons);
}

function emitCapability(record) {
  if (!doctor) return;
  const present = sorted(record.symbols.keys());
  const missing = SYMBOLS.filter(name => present.indexOf(name) === -1).sort();
  emitNow("module_capability", {
    pid: Process.id, module: moduleName(record.module), path: record.module.path || "", linkage: linkageFor(record.module), candidate: record.candidate, scanned: record.scanned,
    symbols_present: present, symbols_missing: missing, metric_reader: record.metricReader !== null,
    hooks_attempted: sorted(record.hooksAttempted), hooks_installed: sorted(record.hooksInstalled), hooks_failed: sorted(record.hooksFailed),
    reasons: moduleReasons(record), sqlite_version: record.sqliteVersion
  });
}

function installHook(module, name, address, handlers, record) {
  const addressKey = pointerString(address), nameKey = moduleKey(module) + ":" + name;
  record.hooksAttempted.add(name);
  if (hookedAddresses.has(addressKey) || hookedSymbolNames.has(nameKey)) {
    record.hooksFailed.add(name); record.reasons.add("hook deduplicated: " + name); return false;
  }
  hookedAddresses.add(addressKey); hookedSymbolNames.add(nameKey);
  try {
    Interceptor.attach(address, handlers);
    hookCount++; record.hooksInstalled.add(name); reportDetected(module, name, address); return true;
  } catch (error) {
    hookedAddresses.delete(addressKey); hookedSymbolNames.delete(nameKey);
    record.hooksFailed.add(name); record.reasons.add("hook attach failed: " + name);
    fail("hook", error, false); return false;
  }
}

function readSql(sqlPointer, nByte, tailPointer) {
  if (sqlPointer === null || sqlPointer.isNull() || !Number.isInteger(nByte)) return { sql: "", sql_truncated: false, captured_bytes: 0 };
  const ceiling = maxSqlLength + 1;
  let available = nByte < 0 ? ceiling : Math.min(nByte, ceiling);
  if (!Number.isSafeInteger(available) || available <= 0) return { sql: "", sql_truncated: false, captured_bytes: 0 };
  try {
    if (tailPointer !== null && !tailPointer.isNull()) {
      const tail = tailPointer.readPointer();
      if (tail.isNull() || tail.compare(sqlPointer) < 0) return { sql: "", sql_truncated: false, captured_bytes: 0 };
      const distance = tail.sub(sqlPointer).toUInt32();
      if (distance > 0) available = Math.min(available, distance);
    }
    const bytes = [];
    for (let i = 0; i < available; i++) { const byte = sqlPointer.add(i).readU8(); if (byte === 0) break; bytes.push(byte); }
    const truncated = bytes.length === available && (nByte < 0 || nByte > maxSqlLength);
    let length = Math.min(bytes.length, maxSqlLength);
    while (length > 0 && (bytes[length - 1] & 0xc0) === 0x80) length--;
    const scratch = Memory.alloc(length + 1);
    scratch.writeByteArray(new Uint8Array(bytes.slice(0, length))); scratch.add(length).writeU8(0);
    return { sql: scratch.readUtf8String(length), sql_truncated: truncated, captured_bytes: length };
  } catch (_) {
    // A target-owned pointer is never dereferenced again after a failed read.
    return { sql: "", sql_truncated: false, captured_bytes: 0 };
  }
}

function contextKey(statement) { return Process.id + ":" + pointerString(statement); }
function lookupContext(statement) { return statement === null || statement.isNull() ? null : statementContexts.get(contextKey(statement)) || null; }
function removeContext(statement) { if (statement !== null && !statement.isNull()) statementContexts.delete(contextKey(statement)); }
function dataQuality(context, reason) { fail("data_quality", reason + " for " + context.statement, false); }

function snapshot(context, statement) {
  if (context.metricReader === null) return null;
  try {
    const result = { fullscan_steps: context.metricReader(statement, SQLITE_STMTSTATUS_FULLSCAN_STEP, SQLITE_STMTSTATUS_RESET_FLAG), vm_steps: context.metricReader(statement, SQLITE_STMTSTATUS_VM_STEP, SQLITE_STMTSTATUS_RESET_FLAG), sorts: context.metricReader(statement, SQLITE_STMTSTATUS_SORT, SQLITE_STMTSTATUS_RESET_FLAG), autoindex: context.metricReader(statement, SQLITE_STMTSTATUS_AUTOINDEX, SQLITE_STMTSTATUS_RESET_FLAG) };
    for (const key in result) if (!Number.isInteger(result[key]) || result[key] < 0) return null;
    return result;
  } catch (_) { return null; }
}
function executionMetrics(context, statement) {
  const current = snapshot(context, statement), previous = context.lastMetrics; context.lastMetrics = current;
  if (current === null || previous === null) return null;
  const result = {};
  for (const key in current) { const delta = current[key] - previous[key]; if (!Number.isInteger(delta) || delta < 0) { dataQuality(context, "counter decreased or overflowed"); return null; } result[key] = delta; }
  return result;
}
function finishActiveExecution(context, tid, boundary, metrics) {
  if (context.activeExecutionNumber === null) return;
  const values = metrics || { fullscan_steps: null, vm_steps: null, sorts: null, autoindex: null };
  queueLifecycle("statement_executed", { pid: Process.id, tid: tid, module: context.module, statement: context.statement, database: context.database, execution_number: context.activeExecutionNumber, sqlite_rc: context.lastStepRc === null ? SQLITE_OK : context.lastStepRc, boundary: boundary, fullscan_steps: values.fullscan_steps, vm_steps: values.vm_steps, sorts: values.sorts, autoindex: values.autoindex });
  context.activeExecutionNumber = null; context.lastStepRc = null; context.ownerTid = null; context.stepDepth = 0;
}

function installPrepare(module, address, abi, metricReader, record) {
  return installHook(module, abi.name, address, {
    onEnter(args) { this.db = args[abi.db]; this.sql = args[abi.sql]; this.nByte = args[abi.nByte].toInt32(); this.ppStmt = args[abi.ppStmt]; this.tail = args[abi.tail]; this.tid = Process.getCurrentThreadId(); },
    onLeave(retval) {
      if (retval.toInt32() !== SQLITE_OK || this.ppStmt === null || this.ppStmt.isNull()) return;
      try {
        const statement = this.ppStmt.readPointer(); if (statement.isNull()) return;
        const captured = readSql(this.sql, this.nByte, this.tail);
        const context = { statement: pointerString(statement), database: pointerString(this.db), module: moduleName(module), metricReader: metricReader, lastMetrics: null, nextExecutionNumber: 0, activeExecutionNumber: null, lastStepRc: null, ownerTid: null, stepDepth: 0 };
        context.lastMetrics = snapshot(context, statement); statementContexts.set(contextKey(statement), context);
        queueLifecycle("statement_prepared", { pid: Process.id, tid: this.tid, module: context.module, statement: context.statement, database: context.database, sql: captured.sql, sqlite_rc: SQLITE_OK, sql_truncated: captured.sql_truncated, captured_bytes: captured.captured_bytes });
      } catch (error) { fail("statement_pointer", error, false); }
    }
  }, record);
}
function installStep(module, address, record) {
  return installHook(module, "sqlite3_step", address, {
    onEnter(args) { this.statement = args[0]; this.tid = Process.getCurrentThreadId(); this.statementContext = lookupContext(this.statement); if (this.statementContext && this.statementContext.ownerTid !== null && this.statementContext.ownerTid !== this.tid) { dataQuality(this.statementContext, "concurrent statement ownership conflict"); this.statementContext = null; } else if (this.statementContext) { this.statementContext.ownerTid = this.tid; this.statementContext.stepDepth++; } },
    onLeave(retval) { const context = this.statementContext; if (!context) return; context.stepDepth--; if (context.stepDepth > 0) { dataQuality(context, "reentrant sqlite3_step"); return; } if (context.activeExecutionNumber === null) context.activeExecutionNumber = ++context.nextExecutionNumber; const rc = retval.toInt32(); context.lastStepRc = rc; if (rc === SQLITE_ROW || rc === SQLITE_BUSY || rc === SQLITE_LOCKED) return; finishActiveExecution(context, this.tid, rc === SQLITE_DONE ? "done" : "error", executionMetrics(context, this.statement)); }
  }, record);
}
function installReset(module, address, record) {
  return installHook(module, "sqlite3_reset", address, {
    onEnter(args) { this.statement = args[0]; this.tid = Process.getCurrentThreadId(); this.statementContext = lookupContext(this.statement); this.metrics = null; if (this.statementContext && this.statementContext.activeExecutionNumber !== null) { if (this.statementContext.ownerTid !== null && this.statementContext.ownerTid !== this.tid) { dataQuality(this.statementContext, "concurrent reset conflict"); this.statementContext = null; } else this.metrics = executionMetrics(this.statementContext, this.statement); } },
    onLeave(_) { if (this.statementContext) finishActiveExecution(this.statementContext, this.tid, "reset", this.metrics); }
  }, record);
}
function installFinalize(module, address, record) {
  return installHook(module, "sqlite3_finalize", address, {
    onEnter(args) { this.statement = args[0]; this.tid = Process.getCurrentThreadId(); this.statementContext = lookupContext(this.statement); this.metrics = this.statementContext && this.statementContext.activeExecutionNumber !== null ? executionMetrics(this.statementContext, this.statement) : null; },
    onLeave(retval) { try { if (!this.statementContext) return; finishActiveExecution(this.statementContext, this.tid, "finalize", this.metrics); queueLifecycle("statement_finalized", { pid: Process.id, tid: this.tid, module: this.statementContext.module, statement: this.statementContext.statement, database: this.statementContext.database, executions: this.statementContext.nextExecutionNumber, sqlite_rc: retval.toInt32() }); } finally { removeContext(this.statement); flushLifecycle(); } }
  }, record);
}
HOOKS.sqlite3_prepare_v2 = (m, a, r, record) => installPrepare(m, a, { name: "sqlite3_prepare_v2", db: 0, sql: 1, nByte: 2, ppStmt: 3, tail: 4 }, r, record);
HOOKS.sqlite3_prepare_v3 = (m, a, r, record) => installPrepare(m, a, { name: "sqlite3_prepare_v3", db: 0, sql: 1, nByte: 2, ppStmt: 4, tail: 5 }, r, record);
HOOKS.sqlite3_step = (m, a, _reader, record) => installStep(m, a, record);
HOOKS.sqlite3_reset = (m, a, _reader, record) => installReset(m, a, record);
HOOKS.sqlite3_finalize = (m, a, _reader, record) => installFinalize(m, a, record);

function discoverVersion(record) {
  const address = record.symbols.get("sqlite3_libversion"); if (!address) return;
  try { const value = new NativeFunction(address, "pointer", [])(); if (value && !value.isNull()) record.sqliteVersion = value.readUtf8String(); } catch (_) { record.reasons.add("sqlite3_libversion unavailable"); }
}
function inspectModule(module, allowUnknown) {
  const key = moduleKey(module);
  // Module observers announce existing modules before the explicit startup
  // scan. Do not mark those as inspected here, otherwise embedded SQLite in
  // the executable would be skipped forever.
  if (!allowUnknown && !isSqliteCandidate(module)) { const record = emptyRecord(module, false); moduleRecords.set(key, record); emitCapability(record); return; }
  if (inspectedModules.has(key)) return;
  inspectedModules.add(key); const record = emptyRecord(module, true);
  for (const name of SYMBOLS) { const address = findSymbol(module, name); if (address !== null) { record.symbols.set(name, address); reportDetected(module, name, address); } }
  const metric = record.symbols.get("sqlite3_stmt_status");
  if (metric) try { record.metricReader = new NativeFunction(metric, "int", ["pointer", "int", "int"]); } catch (_) { record.reasons.add("sqlite3_stmt_status is not invocable"); }
  discoverVersion(record);
  for (const name in HOOKS) { const address = record.symbols.get(name); if (address) HOOKS[name](module, address, record.metricReader, record); }
  moduleRecords.set(key, record); emitCapability(record);
}
function currentStatus() {
  const records = Array.from(moduleRecords.values());
  const active = records.some(record => PREPARE.some(name => record.hooksInstalled.has(name)) && LIFECYCLE.every(name => record.hooksInstalled.has(name)) && record.metricReader !== null);
  if (transportFailed) return { status: "FAILED", reason: "lifecycle transport failed" };
  if (active) return { status: "ACTIVE", reason: null };
  if (records.some(record => record.candidate || record.symbols.size)) return { status: "DETECTED_UNSUPPORTED", reason: moduleReasons(records.find(record => record.candidate || record.symbols.size))[0] || "SQLite capability incomplete" };
  return { status: "NOT_DETECTED", reason: "SQLite lifecycle/metric symbols not found in loaded modules" };
}
function sendStatus() { const value = currentStatus(); emitNow("instrumentation_status", { pid: Process.id, status: value.status, hooks: hookCount, reason: value.reason }); statusSent = true; }
function start() {
  if (Process.platform !== "linux" || Process.arch !== "x64" || Process.pointerSize !== 8) { fail("platform", "PoC supports only Linux x86_64 with 8-byte pointers", true); emitNow("instrumentation_status", { pid: Process.id, status: "FAILED", hooks: 0, reason: "unsupported platform" }); return; }
  try {
    observer = Process.attachModuleObserver({
      onAdded: function (module) { inspectModule(module, false); if (statusSent) sendStatus(); },
      onRemoved: function (module) { inspectedModules.delete(moduleKey(module)); moduleRecords.delete(moduleKey(module)); }
    });
    const modules = Process.enumerateModules(); for (let i = 0; i < modules.length; i++) inspectModule(modules[i], true);
    sendStatus(); emitNow("backend_ready", { pid: Process.id, arch: Process.arch, platform: Process.platform });
  } catch (error) { fail("discovery", error, true); emitNow("instrumentation_status", { pid: Process.id, status: "FAILED", hooks: hookCount, reason: String(error) }); }
}
start();
