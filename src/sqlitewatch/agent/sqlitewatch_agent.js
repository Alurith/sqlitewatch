"use strict";

// This file runs inside Frida's JavaScript runtime, not Node.js.
const PROTOCOL_VERSION = 1;
const SQLITE_OK = 0;
const defaultConfig = { max_sql_length: 65536 };
const config = (typeof SQLITEWATCH_CONFIG === "object" && SQLITEWATCH_CONFIG) || defaultConfig;
const maxSqlLength = Number(config.max_sql_length) > 0 ? Number(config.max_sql_length) : defaultConfig.max_sql_length;
const hookedAddresses = new Set();
const inspectedModules = new Set();
let hookCount = 0;
let readySent = false;
let statusSent = false;
let activeStatusSent = false;
let observer;

function event(type, fields) {
  const payload = Object.assign({ type: type, protocol_version: PROTOCOL_VERSION }, fields || {});
  try {
    send(payload);
  } catch (error) {
    // A failed transport is itself observable by the controller when possible.
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

function linkageFor(module) {
  const path = module.path || "";
  return path.indexOf(".so") !== -1 ? "dynamic" : "embedded_or_unknown";
}

function isSqliteCandidate(module) {
  const text = (moduleName(module) + " " + (module.path || "")).toLowerCase();
  return text.indexOf("sqlite") !== -1;
}

function usableAddress(address) {
  return address !== null && address !== undefined &&
    (typeof address.isNull !== "function" || !address.isNull());
}

function findPrepare(module) {
  let address = null;
  try { address = module.findExportByName("sqlite3_prepare_v2"); } catch (_) { address = null; }
  if (!usableAddress(address) && typeof module.findSymbolByName === "function") {
    try { address = module.findSymbolByName("sqlite3_prepare_v2"); } catch (_) { address = null; }
  }
  if (!usableAddress(address) && typeof module.enumerateSymbols === "function") {
    try {
      const symbols = module.enumerateSymbols();
      for (let i = 0; i < symbols.length; i++) {
        if (symbols[i].name === "sqlite3_prepare_v2") {
          if (usableAddress(symbols[i].address)) address = symbols[i].address;
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
    // Read bytes one at a time. A bounded bulk read can cross an unmapped
    // page when a short C string is near a page boundary.
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
    const text = scratch.readUtf8String(length);
    return {
      sql: text,
      sql_truncated: truncatedByLimit,
      captured_bytes: length
    };
  } catch (error) {
    fail("sql_read", error, false);
    return { sql: "", sql_truncated: false, captured_bytes: 0 };
  }
}

function installHook(module, address) {
  const key = pointerString(address);
  if (hookedAddresses.has(key)) return false;
  hookedAddresses.add(key);
  try {
    Interceptor.attach(address, {
      onEnter: function (args) {
        this.db = args[0];
        this.sqlPointer = args[1];
        this.nByte = args[2].toInt32();
        this.ppStmt = args[3];
        this.pzTail = args[4];
        this.module = moduleName(module);
        this.tid = Process.getCurrentThreadId();
      },
      onLeave: function (retval) {
        const rc = retval.toInt32();
        if (rc !== SQLITE_OK) return;
        if (this.ppStmt === null || this.ppStmt.isNull()) {
          fail("statement_pointer", "sqlite3_stmt** was null", false);
          return;
        }
        let stmt;
        try {
          stmt = this.ppStmt.readPointer();
        } catch (error) {
          fail("statement_pointer", error, false);
          return;
        }
        if (stmt.isNull()) return;
        const captured = readSql(this.sqlPointer, this.nByte, this.pzTail);
        event("statement_prepared", {
          pid: Process.id,
          tid: this.tid,
          module: this.module,
          statement: pointerString(stmt),
          database: pointerString(this.db),
          sql: captured.sql,
          sqlite_rc: rc,
          sql_truncated: captured.sql_truncated,
          captured_bytes: captured.captured_bytes
        });
      }
    });
    hookCount++;
    event("sqlite_detected", {
      pid: Process.id,
      module: moduleName(module),
      path: module.path || "",
      symbol: "sqlite3_prepare_v2",
      address: key,
      linkage: linkageFor(module)
    });
    if (statusSent && !activeStatusSent) {
      event("instrumentation_status", { pid: Process.id, status: "ACTIVE", hooks: hookCount });
      activeStatusSent = true;
    }
    return true;
  } catch (error) {
    hookedAddresses.delete(key);
    fail("hook", error, false);
    return false;
  }
}

function inspectModule(module) {
  const moduleKey = module.path || moduleName(module);
  if (inspectedModules.has(moduleKey)) return;
  inspectedModules.add(moduleKey);
  const address = findPrepare(module);
  if (address !== null) installHook(module, address);
  else if (isSqliteCandidate(module)) {
    event("instrumentation_status", {
      pid: Process.id,
      status: "DETECTED_UNSUPPORTED",
      hooks: hookCount,
      reason: "sqlite3_prepare_v2 symbol not found"
    });
    statusSent = true;
  }
}

function sendInitialStatus() {
  if (statusSent) return;
  event("instrumentation_status", {
    pid: Process.id,
    status: hookCount > 0 ? "ACTIVE" : "NOT_DETECTED",
    hooks: hookCount,
    reason: hookCount > 0 ? null : "sqlite3_prepare_v2 not found in loaded modules"
  });
  statusSent = true;
  if (hookCount > 0) activeStatusSent = true;
}

function start() {
  if (Process.platform !== "linux" || Process.arch !== "x64" || Process.pointerSize !== 8) {
    fail("platform", "PoC supports only Linux x86_64 with 8-byte pointers", true);
    event("instrumentation_status", {
      pid: Process.id,
      status: "FAILED",
      hooks: 0,
      reason: "unsupported platform"
    });
    return;
  }
  try {
    // Install the observer before the initial scan so a late dlopen cannot race it.
    observer = Process.attachModuleObserver({
      onAdded: function (module) { inspectModule(module); },
      onRemoved: function (module) {
        // Hooks remain valid for the lifetime of the native invocation; removed
        // modules are only omitted from future diagnostics.
        inspectedModules.delete(module.path || moduleName(module));
      }
    });
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) inspectModule(modules[i]);
    sendInitialStatus();
    event("backend_ready", {
      pid: Process.id,
      arch: Process.arch,
      platform: Process.platform
    });
    readySent = true;
  } catch (error) {
    fail("discovery", error, true);
    event("instrumentation_status", {
      pid: Process.id,
      status: "FAILED",
      hooks: hookCount,
      reason: String(error)
    });
  }
}

start();
