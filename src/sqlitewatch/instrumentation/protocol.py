"""Versioned, dependency-free validation for Frida messages.

The protocol deliberately rejects unknown fields.  Lifecycle events may be
transported in an ordered ``lifecycle_batch`` envelope, but are expanded before
reaching the controller so consumers still see the original event stream.
"""

from __future__ import annotations

from dataclasses import asdict
import re
from typing import Any, Mapping

from ..events import (
    PROTOCOL_VERSION, BackendReady, Event, InstrumentationError,
    InstrumentationStatus, LauncherReady, ModuleCapability, ProcessExited,
    SqliteDetected, StatementExecuted, StatementFinalized, StatementPrepared,
)

_POINTER = re.compile(r"^0x[0-9a-f]+$")
_SYMBOLS = {
    "sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_step", "sqlite3_reset",
    "sqlite3_finalize", "sqlite3_stmt_status", "sqlite3_libversion",
}
_TYPES = {
    "backend_ready", "launcher_ready", "sqlite_detected", "module_capability",
    "instrumentation_status", "statement_prepared", "statement_executed",
    "statement_finalized", "instrumentation_error", "process_exited", "lifecycle_batch",
}
_ALLOWED_FIELDS = {
    "backend_ready": {"type", "protocol_version", "pid", "arch", "platform"},
    "launcher_ready": {"type", "protocol_version", "pid", "arch", "platform"},
    "sqlite_detected": {"type", "protocol_version", "pid", "module", "path", "symbol", "address", "linkage"},
    "module_capability": {"type", "protocol_version", "pid", "module", "path", "linkage", "candidate", "scanned", "symbols_present", "symbols_missing", "metric_reader", "hooks_attempted", "hooks_installed", "hooks_failed", "reasons", "sqlite_version"},
    "instrumentation_status": {"type", "protocol_version", "status", "pid", "hooks", "reason"},
    "statement_prepared": {"type", "protocol_version", "pid", "tid", "module", "statement", "database", "sql", "sqlite_rc", "sql_truncated", "captured_bytes"},
    "statement_executed": {"type", "protocol_version", "pid", "tid", "module", "statement", "database", "execution_number", "sqlite_rc", "boundary", "fullscan_steps", "vm_steps", "sorts", "autoindex"},
    "statement_finalized": {"type", "protocol_version", "pid", "tid", "module", "statement", "database", "executions", "sqlite_rc"},
    "instrumentation_error": {"type", "protocol_version", "phase", "message", "pid", "fatal", "sqlite_rc"},
    "process_exited": {"type", "protocol_version", "pid", "exit_code", "signal"},
    "lifecycle_batch": {"type", "protocol_version", "sequence", "events"},
}
_LIFECYCLE_TYPES = {"statement_prepared", "statement_executed", "statement_finalized"}


class ProtocolError(ValueError):
    def __init__(self, message: str, *, payload: Any = None):
        super().__init__(message)
        self.payload = payload


def _mapping(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ProtocolError("event payload must be an object", payload=payload)
    return payload


def _common(payload: Mapping[str, Any], expected: str) -> None:
    if payload.get("type") != expected:
        raise ProtocolError(f"expected event type {expected!r}", payload=payload)
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported or missing protocol_version", payload=payload)


def _required(payload: Mapping[str, Any], *names: str) -> None:
    missing = [name for name in names if name not in payload]
    if missing:
        raise ProtocolError(f"missing required fields: {', '.join(missing)}", payload=payload)


def _known_fields(payload: Mapping[str, Any], event_type: str) -> None:
    unknown = sorted(set(payload) - _ALLOWED_FIELDS[event_type])
    if unknown:
        raise ProtocolError(f"unknown fields for {event_type}: {', '.join(unknown)}", payload=payload)


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProtocolError(f"{name} must be a positive integer")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f"{name} must be a non-negative integer")
    return value


def _pointer(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _POINTER.fullmatch(value):
        raise ProtocolError(f"{name} must match 0x[0-9a-f]+")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be a string")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    return None if value is None else _string(value, name)


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{name} must be an integer")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"{name} must be a boolean")
    return value


def _symbols(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or item not in _SYMBOLS for item in value):
        raise ProtocolError(f"{name} must be a list of known SQLite symbols")
    if value != sorted(set(value)):
        raise ProtocolError(f"{name} must be unique and sorted")
    return tuple(value)


def payload_to_event(payload: Any) -> Event:
    """Validate and convert one non-batch agent payload."""
    data = _mapping(payload)
    event_type = data.get("type")
    if event_type not in _TYPES or event_type == "lifecycle_batch":
        raise ProtocolError(f"unknown event type: {event_type!r}", payload=payload)
    _common(data, event_type)
    _known_fields(data, event_type)

    if event_type == "backend_ready":
        _required(data, "pid")
        return BackendReady(_positive_int(data["pid"], "pid"), arch=_string(data.get("arch", "x64"), "arch"), platform=_string(data.get("platform", "linux"), "platform"))
    if event_type == "launcher_ready":
        _required(data, "pid")
        return LauncherReady(_positive_int(data["pid"], "pid"), arch=_string(data.get("arch", "x64"), "arch"), platform=_string(data.get("platform", "linux"), "platform"))
    if event_type == "sqlite_detected":
        _required(data, "pid", "module", "path", "symbol", "address")
        return SqliteDetected(_positive_int(data["pid"], "pid"), _string(data["module"], "module"), _string(data["path"], "path"), _string(data["symbol"], "symbol"), _pointer(data["address"], "address"), _optional_string(data.get("linkage"), "linkage"))
    if event_type == "module_capability":
        _required(data, "pid", "module", "path", "linkage", "candidate", "scanned", "symbols_present", "symbols_missing", "metric_reader", "hooks_attempted", "hooks_installed", "hooks_failed", "reasons")
        linkage = _string(data["linkage"], "linkage")
        if linkage not in {"dynamic", "embedded_or_unknown"}:
            raise ProtocolError("invalid linkage")
        reasons = data["reasons"]
        if not isinstance(reasons, list) or any(not isinstance(reason, str) or not reason for reason in reasons) or reasons != sorted(set(reasons)):
            raise ProtocolError("reasons must be unique, non-empty, and sorted")
        return ModuleCapability(
            _positive_int(data["pid"], "pid"), _string(data["module"], "module"), _string(data["path"], "path"), linkage,  # type: ignore[arg-type]
            _bool(data["candidate"], "candidate"), _bool(data["scanned"], "scanned"),
            _symbols(data["symbols_present"], "symbols_present"), _symbols(data["symbols_missing"], "symbols_missing"),
            _bool(data["metric_reader"], "metric_reader"), _symbols(data["hooks_attempted"], "hooks_attempted"),
            _symbols(data["hooks_installed"], "hooks_installed"), _symbols(data["hooks_failed"], "hooks_failed"),
            tuple(reasons), _optional_string(data.get("sqlite_version"), "sqlite_version"),
        )
    if event_type == "instrumentation_status":
        _required(data, "pid", "status")
        status = _string(data["status"], "status")
        if status not in {"ACTIVE", "DETECTED_UNSUPPORTED", "FAILED", "NOT_DETECTED"}:
            raise ProtocolError(f"unknown instrumentation status: {status!r}")
        return InstrumentationStatus(status, _positive_int(data["pid"], "pid"), _nonnegative_int(data.get("hooks", 0), "hooks"), _optional_string(data.get("reason"), "reason"))
    if event_type == "statement_prepared":
        _required(data, "pid", "tid", "module", "statement", "database", "sql")
        captured = data.get("captured_bytes")
        return StatementPrepared(_positive_int(data["pid"], "pid"), _positive_int(data["tid"], "tid"), _string(data["module"], "module"), _pointer(data["statement"], "statement"), _pointer(data["database"], "database"), _string(data["sql"], "sql"), _integer(data.get("sqlite_rc", 0), "sqlite_rc"), _bool(data.get("sql_truncated", False), "sql_truncated"), None if captured is None else _nonnegative_int(captured, "captured_bytes"))
    if event_type == "statement_executed":
        _required(data, "pid", "tid", "module", "statement", "database", "execution_number", "sqlite_rc", "boundary")
        boundary = _string(data["boundary"], "boundary")
        if boundary not in {"done", "error", "reset", "finalize"}:
            raise ProtocolError(f"unknown execution boundary: {boundary!r}")
        metrics = _execution_metrics(data)
        return StatementExecuted(_positive_int(data["pid"], "pid"), _positive_int(data["tid"], "tid"), _string(data["module"], "module"), _pointer(data["statement"], "statement"), _pointer(data["database"], "database"), _positive_int(data["execution_number"], "execution_number"), _integer(data["sqlite_rc"], "sqlite_rc"), boundary, *metrics)  # type: ignore[arg-type]
    if event_type == "statement_finalized":
        _required(data, "pid", "tid", "module", "statement", "database", "executions", "sqlite_rc")
        return StatementFinalized(_positive_int(data["pid"], "pid"), _positive_int(data["tid"], "tid"), _string(data["module"], "module"), _pointer(data["statement"], "statement"), _pointer(data["database"], "database"), _nonnegative_int(data["executions"], "executions"), _integer(data["sqlite_rc"], "sqlite_rc"))
    if event_type == "instrumentation_error":
        _required(data, "phase", "message")
        pid = data.get("pid")
        sqlite_rc = data.get("sqlite_rc")
        return InstrumentationError(_string(data["phase"], "phase"), _string(data["message"], "message"), None if pid is None else _positive_int(pid, "pid"), _bool(data.get("fatal", True), "fatal"), None if sqlite_rc is None else _integer(sqlite_rc, "sqlite_rc"))
    _required(data, "pid")
    exit_code, signal = data.get("exit_code"), data.get("signal")
    exit_code = None if exit_code is None else _nonnegative_int(exit_code, "exit_code")
    signal = None if signal is None else _positive_int(signal, "signal")
    if exit_code is not None and signal is not None:
        raise ProtocolError("process_exited cannot contain both exit_code and signal")
    return ProcessExited(_positive_int(data["pid"], "pid"), exit_code, signal)


def _execution_metrics(payload: Mapping[str, Any]) -> tuple[int | None, int | None, int | None, int | None]:
    names = ("fullscan_steps", "vm_steps", "sorts", "autoindex")
    if missing := [name for name in names if name not in payload]:
        raise ProtocolError(f"missing required metric fields: {', '.join(missing)}", payload=payload)
    values = tuple(None if payload[name] is None else _nonnegative_int(payload[name], name) for name in names)
    if any(value is None for value in values) and any(value is not None for value in values):
        raise ProtocolError("statement_executed metrics must be all integers or all null", payload=payload)
    return values  # type: ignore[return-value]


def payload_to_events(payload: Any) -> tuple[Event, ...]:
    """Expand a payload atomically; an invalid batch returns no partial events."""
    data = _mapping(payload)
    if data.get("type") != "lifecycle_batch":
        return (payload_to_event(data),)
    _common(data, "lifecycle_batch")
    _known_fields(data, "lifecycle_batch")
    _required(data, "sequence", "events")
    _positive_int(data["sequence"], "sequence")
    members = data["events"]
    if not isinstance(members, list) or not members:
        raise ProtocolError("lifecycle_batch events must be a non-empty list", payload=payload)
    events = tuple(payload_to_event(member) for member in members)
    if any(getattr(event, "type") not in _LIFECYCLE_TYPES for event in events):
        raise ProtocolError("lifecycle_batch contains a non-lifecycle event", payload=payload)
    return events


def event_to_payload(event: Event) -> dict[str, Any]:
    payload = asdict(event)
    return payload if isinstance(event, StatementExecuted) else {key: value for key, value in payload.items() if value is not None}


def frida_message_to_events(message: Mapping[str, Any]) -> tuple[Event, ...]:
    if message.get("type") == "send":
        return payload_to_events(message.get("payload"))
    if message.get("type") == "error":
        description = message.get("description") or message.get("stack") or "unknown Frida error"
        return (InstrumentationError(phase="frida", message=str(description), fatal=True),)
    raise ProtocolError(f"unsupported Frida message type: {message.get('type')!r}", payload=message)


def frida_message_to_event(message: Mapping[str, Any]) -> Event:
    """Backward-compatible single-event adapter; batches must use the expander."""
    events = frida_message_to_events(message)
    if len(events) != 1:
        raise ProtocolError("lifecycle_batch requires frida_message_to_events", payload=message)
    return events[0]
