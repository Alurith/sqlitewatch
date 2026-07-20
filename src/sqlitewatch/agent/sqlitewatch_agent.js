"use strict";

// This file runs inside Frida's JavaScript runtime, not Node.js.
const PROTOCOL_VERSION = 1;
const SQLITE_OK = 0;
const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_STMTSTATUS_FULLSCAN_STEP = 1;
const SQLITE_STMTSTATUS_SORT = 2;
const SQLITE_STMTSTATUS_AUTOINDEX = 3;
const SQLITE_STMTSTATUS_VM_STEP = 4;
// Passive observer only: sqlite3_stmt_status(..., 1) is forbidden because it
// would reset counters owned by the target application.
const SQLITE_STMTSTATUS_RESET_FLAG = 0;
const defaultConfig = { max_sql_length: 65536 };
const config = (typeof SQLITEWATCH_CONFIG === "object" && SQLITEWATCH_CONFIG) || defaultConfig;
const maxSqlLength = Number(config.max_sql_length) > 0 ? Number(config.max_sql_length) : defaultConfig.max_sql_length;

const hookedAddresses = new Set();
const hookedSymbolNames = new Set();
const inspectedModules = new Set();
const moduleRecords = new Map();
const statementContexts = new Map();
let hookCount = 0;
let statusSent = false;
let observer;

function event(type, fields) {
  const payload = Object.assign({ type: type, protocol_version: PROTOCOL_VERSION }, fields || {});
  try {
    send(payload);
  } catch (error) {
    try { send({
      type: "instrumentation_error",
      protocol_version: PROTOCOL_VERSION,
      phase: "send",
      message: String(error),
      fatal: true
    }); } catch (_) { /* Frida is already detaching. */ }
  }
}

function fail(phase, error, fatal) {
  event("instrumentation_error", {
    phase: phase,
    message: String(error),
    pid: Process.id,
    fatal: fatal !== false
  });
}

function pointerString(pointer) {
  return pointer.toString().toLowerCase();
}

function moduleName(module) {
  return module.name || "<anonymous>";
}

function moduleKey(module) {
  return module.path || moduleName(module);
}

function linkageFor(module) {
  const path = module.path || "";
  const basename = path.split("/").pop().toLowerCase();
  if (/^libsqlite3\.so(?:\..*)?$/.test(basename) ||
      basename === "libsqlite3.dylib" || basename === "sqlite3.dll") {
    return "dynamic";
  }
  return "embedded_or_unknown";
}

function isSqliteCandidate(module) {
  const text = (moduleName(module) + " " + (module.path || "")).toLowerCase();
  return text.indexOf("sqlite") !== -1;
}

function usableAddress(address) {
  return address !== null && address !== undefined &&
    (typeof address.isNull !== "function" || !address.isNull());
}

// Frida 17 resolution order: exports first, then symbols, then enumeration.
function findSymbol(module, name) {
  let address = null;
  try { address = module.findExportByName(name); } catch (_) { address = null; }
  if (!usableAddress(address) && typeof module.findSymbolByName === "function") {
    try { address = module.findSymbolByName(name); } catch (_) { address = null; }
  }
  if (!usableAddress(address) && typeof module.enumerateSymbols === "function") {
    try {
      const symbols = module.enumerateSymbols();
      for (let i = 0; i < symbols.length; i++) {
        if (symbols[i].name === name && usableAddress(symbols[i].address)) {
          address = symbols[i].address;
          break;
        }
      }
    } catch (_) { /* Symbol enumeration is only a fallback. */ }
  }
  return usableAddress(address) ? address : null;
}

function safeTailLength(sqlPointer, tailPointer) {
  try {
    if (tailPointer === null || tailPointer.isNull()) return null;
    const tail = tailPointer.readPointer();
    if (tail.isNull() || tail.compare(sqlPointer) <= 0) return null;
    const distance = tail.sub(sqlPointer).toUInt32();
    if (distance > 0 && distance <= maxSqlLength + 1) return distance;
  } catch (_) { /* An optional tail pointer is not an instrumentation failure. */ }
  return null;
}

function readSql(sqlPointer, nByte, tailPointer) {
  if (sqlPointer === null || sqlPointer.isNull()) {
    return { sql: "", sql_truncated: false, captured_bytes: 0 };
  }
  let available = nByte < 0 ? maxSqlLength + 1 : Math.min(nByte, maxSqlLength + 1);
  const tailLength = safeTailLength(sqlPointer, tailPointer);
  if (tailLength !== null) available = Math.min(available, tailLength);
  if (available <= 0) return { sql: "", sql_truncated: false, captured_bytes: 0 };

  try {
    const bytes = [];
    for (let i = 0; i < available; i++) {
      try {
        const byte = sqlPointer.add(i).readU8();
        if (byte === 0) break;
        bytes.push(byte);
      } catch (_) {
        break;
      }
    }
    const reachedLimit = bytes.length === available;
    const truncatedByLimit = reachedLimit && (nByte < 0 || nByte > maxSqlLength);
    let length = Math.min(bytes.length, maxSqlLength);
    while (length > 0 && (bytes[length - 1] & 0xc0) === 0x80) length--;
    const scratch = Memory.alloc(length + 1);
    scratch.writeByteArray(new Uint8Array(bytes.slice(0, length)));
    scratch.add(length).writeU8(0);
    return {
      sql: scratch.readUtf8String(length),
      sql_truncated: truncatedByLimit,
      captured_bytes: length
    };
  } catch (error) {
    fail("sql_read", error, false);
    return { sql: "", sql_truncated: false, captured_bytes: 0 };
  }
}

function contextKey(statement) {
  return String(Process.id) + ":" + pointerString(statement);
}

function createContext(statement, database, module, sql, tid, metricReader) {
  const context = {
    statement: pointerString(statement),
    database: pointerString(database),
    module: module,
    sql: sql,
    preparedTid: tid,
    metricReader: metricReader,
    lastMetrics: null,
    nextExecutionNumber: 0,
    activeExecutionNumber: null,
    lastStepRc: null
  };
  statementContexts.set(contextKey(statement), context);
  context.lastMetrics = readMetricSnapshot(context, statement);
  return context;
}

function lookupContext(statement) {
  if (statement === null || statement.isNull()) return null;
  return statementContexts.get(contextKey(statement)) || null;
}

function removeContext(statement) {
  if (statement !== null && !statement.isNull()) statementContexts.delete(contextKey(statement));
}

function readMetricSnapshot(context, statement) {
  if (context.metricReader === null) {
    fail("stmt_status", "missing sqlite3_stmt_status reader for statement module", false);
    return null;
  }
  try {
    // All four calls are passive reads; SQLITE_STMTSTATUS_RESET_FLAG is always 0.
    const snapshot = {
      fullscan_steps: context.metricReader(statement, SQLITE_STMTSTATUS_FULLSCAN_STEP, SQLITE_STMTSTATUS_RESET_FLAG),
      vm_steps: context.metricReader(statement, SQLITE_STMTSTATUS_VM_STEP, SQLITE_STMTSTATUS_RESET_FLAG),
      sorts: context.metricReader(statement, SQLITE_STMTSTATUS_SORT, SQLITE_STMTSTATUS_RESET_FLAG),
      autoindex: context.metricReader(statement, SQLITE_STMTSTATUS_AUTOINDEX, SQLITE_STMTSTATUS_RESET_FLAG)
    };
    const names = ["fullscan_steps", "vm_steps", "sorts", "autoindex"];
    for (let i = 0; i < names.length; i++) {
      const value = snapshot[names[i]];
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
        fail("stmt_status", "invalid " + names[i] + " value: " + String(value), false);
        return null;
      }
    }
    return snapshot;
  } catch (error) {
    fail("stmt_status", error, false);
    return null;
  }
}

function executionMetrics(context, statement) {
  const current = readMetricSnapshot(context, statement);
  const previous = context.lastMetrics;
  // Always establish a fresh baseline, including after a failed/decreasing read.
  context.lastMetrics = current;
  if (current === null || previous === null) return null;
  const metrics = {};
  const names = ["fullscan_steps", "vm_steps", "sorts", "autoindex"];
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    const delta = current[name] - previous[name];
    if (!Number.isInteger(delta) || delta < 0) {
      fail("stmt_status_delta", "counter decreased or overflowed: " + name, false);
      return null;
    }
    metrics[name] = delta;
  }
  return metrics;
}

function finishActiveExecution(context, tid, boundary, metrics) {
  if (context.activeExecutionNumber === null) return false;
  const values = metrics === null ? {
    fullscan_steps: null, vm_steps: null, sorts: null, autoindex: null
  } : metrics;
  event("statement_executed", {
    pid: Process.id,
    tid: tid,
    module: context.module,
    statement: context.statement,
    database: context.database,
    execution_number: context.activeExecutionNumber,
    sqlite_rc: context.lastStepRc === null ? SQLITE_OK : context.lastStepRc,
    boundary: boundary,
    fullscan_steps: values.fullscan_steps,
    vm_steps: values.vm_steps,
    sorts: values.sorts,
    autoindex: values.autoindex
  });
  context.activeExecutionNumber = null;
  context.lastStepRc = null;
  return true;
}

function installPrepare(module, address, abi, metricReader) {
  return installHook(module, abi.name, address, {
    onEnter: function (args) {
      this.db = args[abi.db];
      this.sqlPointer = args[abi.sql];
      this.nByte = args[abi.nByte].toInt32();
      this.ppStmt = args[abi.ppStmt];
      this.pzTail = args[abi.pzTail];
      this.module = moduleName(module);
      this.metricReader = metricReader;
      this.tid = Process.getCurrentThreadId();
    },
    onLeave: function (retval) {
      const rc = retval.toInt32();
      if (rc !== SQLITE_OK) return;
      if (this.ppStmt === null || this.ppStmt.isNull()) {
        fail("statement_pointer", abi.name + " sqlite3_stmt** was null", false);
        return;
      }
      let statement;
      try { statement = this.ppStmt.readPointer(); }
      catch (error) {
        fail("statement_pointer", error, false);
        return;
      }
      if (statement.isNull()) return;
      const captured = readSql(this.sqlPointer, this.nByte, this.pzTail);
      createContext(statement, this.db, this.module, captured.sql, this.tid, this.metricReader);
      event("statement_prepared", {
        pid: Process.id,
        tid: this.tid,
        module: this.module,
        statement: pointerString(statement),
        database: pointerString(this.db),
        sql: captured.sql,
        sqlite_rc: rc,
        sql_truncated: captured.sql_truncated,
        captured_bytes: captured.captured_bytes
      });
    }
  });
}

function installPrepareV2(module, address, metricReader) {
  return installPrepare(module, address, {
    name: "sqlite3_prepare_v2", db: 0, sql: 1, nByte: 2, ppStmt: 3, pzTail: 4
  }, metricReader);
}

function installPrepareV3(module, address, metricReader) {
  return installPrepare(module, address, {
    name: "sqlite3_prepare_v3", db: 0, sql: 1, nByte: 2, ppStmt: 4, pzTail: 5
  }, metricReader);
}

function installStep(module, address) {
  return installHook(module, "sqlite3_step", address, {
    onEnter: function (args) {
      this.statement = args[0];
      this.tid = Process.getCurrentThreadId();
    },
    onLeave: function (retval) {
      const context = lookupContext(this.statement);
      if (context === null) return;
      if (context.activeExecutionNumber === null) {
        context.activeExecutionNumber = ++context.nextExecutionNumber;
      }
      const rc = retval.toInt32();
      context.lastStepRc = rc;
      if (rc === SQLITE_ROW || rc === SQLITE_BUSY || rc === SQLITE_LOCKED) return;
      const metrics = executionMetrics(context, this.statement);
      finishActiveExecution(context, this.tid, rc === SQLITE_DONE ? "done" : "error", metrics);
    }
  });
}

function installReset(module, address) {
  return installHook(module, "sqlite3_reset", address, {
    onEnter: function (args) {
      this.statement = args[0];
      this.tid = Process.getCurrentThreadId();
      this.resetContext = lookupContext(this.statement);
      this.metrics = this.resetContext !== null && this.resetContext.activeExecutionNumber !== null
        ? executionMetrics(this.resetContext, this.statement) : null;
    },
    onLeave: function (_) {
      if (this.resetContext !== null) finishActiveExecution(this.resetContext, this.tid, "reset", this.metrics);
    }
  });
}

function installFinalize(module, address) {
  return installHook(module, "sqlite3_finalize", address, {
    onEnter: function (args) {
      this.statement = args[0];
      this.tid = Process.getCurrentThreadId();
      this.statementContext = lookupContext(this.statement);
      this.metrics = this.statementContext !== null && this.statementContext.activeExecutionNumber !== null
        ? executionMetrics(this.statementContext, this.statement) : null;
    },
    onLeave: function (retval) {
      try {
        const context = this.statementContext;
        if (context === null) return;
        finishActiveExecution(context, this.tid, "finalize", this.metrics);
        event("statement_finalized", {
          pid: Process.id,
          tid: this.tid,
          module: context.module,
          statement: context.statement,
          database: context.database,
          executions: context.nextExecutionNumber,
          sqlite_rc: retval.toInt32()
        });
      } finally {
        // Do not retain a pointer after SQLite has completed finalization.
        removeContext(this.statement);
      }
    }
  });
}

const HOOKS = {
  sqlite3_prepare_v2: installPrepareV2,
  sqlite3_prepare_v3: installPrepareV3,
  sqlite3_step: installStep,
  sqlite3_reset: installReset,
  sqlite3_finalize: installFinalize
};
const PREPARE_SYMBOLS = ["sqlite3_prepare_v2", "sqlite3_prepare_v3"];
const LIFECYCLE_SYMBOLS = ["sqlite3_step", "sqlite3_reset", "sqlite3_finalize"];
const METRIC_SYMBOLS = ["sqlite3_stmt_status"];

function reportDetected(module, name, address) {
  event("sqlite_detected", {
    pid: Process.id,
    module: moduleName(module),
    path: module.path || "",
    symbol: name,
    address: pointerString(address),
    linkage: linkageFor(module)
  });
}

function installHook(module, name, address, handlers) {
  const key = pointerString(address);
  const symbolKey = moduleKey(module) + ":" + name;
  if (hookedAddresses.has(key) || hookedSymbolNames.has(symbolKey)) return false;
  hookedAddresses.add(key);
  hookedSymbolNames.add(symbolKey);
  try {
    Interceptor.attach(address, handlers);
    hookCount++;
    reportDetected(module, name, address);
    return true;
  } catch (error) {
    hookedAddresses.delete(key);
    hookedSymbolNames.delete(symbolKey);
    fail("hook", error, false);
    return false;
  }
}

function inspectModule(module, allowUnknown) {
  // Frida can crash a target while enumerateSymbols() scans arbitrary native
  // modules from an onAdded callback. The startup scan still covers embedded
  // SQLite in any already-loaded module; late loads are restricted to modules
  // whose own name/path identifies them as SQLite candidates.
  if (!allowUnknown && !isSqliteCandidate(module)) return;
  const key = moduleKey(module);
  if (inspectedModules.has(key)) return;
  inspectedModules.add(key);
  const resolved = new Set();
  let metricReader = null;
  const metricAddress = findSymbol(module, "sqlite3_stmt_status");
  if (metricAddress !== null) {
    resolved.add("sqlite3_stmt_status");
    reportDetected(module, "sqlite3_stmt_status", metricAddress);
    try {
      metricReader = new NativeFunction(metricAddress, "int", ["pointer", "int", "int"]);
    } catch (error) {
      fail("stmt_status", error, false);
    }
  }
  for (const name in HOOKS) {
    const address = findSymbol(module, name);
    if (address === null) continue;
    const installer = HOOKS[name];
    const installed = name === "sqlite3_prepare_v2" || name === "sqlite3_prepare_v3"
      ? installer(module, address, metricReader)
      : installer(module, address);
    if (installed) resolved.add(name);
  }
  if (resolved.size > 0 || isSqliteCandidate(module)) {
    moduleRecords.set(key, { module: module, symbols: resolved, metricReader: metricReader });
  }
}

function moduleReason(record) {
  const hasPrepare = PREPARE_SYMBOLS.some(function (name) { return record.symbols.has(name); });
  if (!hasPrepare) return "no prepare entrypoint";
  const missing = LIFECYCLE_SYMBOLS.filter(function (name) { return !record.symbols.has(name); });
  if (missing.length > 0) return "missing lifecycle symbols: " + missing.join(", ");
  if (!record.symbols.has("sqlite3_stmt_status")) return "missing metric symbol: sqlite3_stmt_status";
  return null;
}

function currentStatus() {
  const records = Array.from(moduleRecords.values());
  const active = records.some(function (record) { return moduleReason(record) === null; });
  if (active) return { status: "ACTIVE", reason: null };
  if (records.length > 0) {
    const reasons = records.map(moduleReason).filter(function (reason) { return reason !== null; });
    return { status: "DETECTED_UNSUPPORTED", reason: reasons[0] || "no prepare entrypoint" };
  }
  return { status: "NOT_DETECTED", reason: "SQLite lifecycle/metric symbols not found in loaded modules" };
}

function sendStatus() {
  const value = currentStatus();
  event("instrumentation_status", {
    pid: Process.id,
    status: value.status,
    hooks: hookCount,
    reason: value.reason
  });
  statusSent = true;
}

function start() {
  if (Process.platform !== "linux" || Process.arch !== "x64" || Process.pointerSize !== 8) {
    fail("platform", "PoC supports only Linux x86_64 with 8-byte pointers", true);
    event("instrumentation_status", { pid: Process.id, status: "FAILED", hooks: 0, reason: "unsupported platform" });
    return;
  }
  try {
    observer = Process.attachModuleObserver({
      onAdded: function (module) {
        inspectModule(module, false);
        if (statusSent) sendStatus();
      },
      onRemoved: function (module) {
        inspectedModules.delete(moduleKey(module));
        moduleRecords.delete(moduleKey(module));
      }
    });
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) inspectModule(modules[i], true);
    sendStatus();
    event("backend_ready", { pid: Process.id, arch: Process.arch, platform: Process.platform });
  } catch (error) {
    fail("discovery", error, true);
    event("instrumentation_status", { pid: Process.id, status: "FAILED", hooks: hookCount, reason: String(error) });
  }
}

start();
