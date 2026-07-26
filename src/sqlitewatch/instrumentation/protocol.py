"""Strict protocol-v3 validation for Frida target streams.

Every target payload is attributed to one host-generated process image. Ordered
lifecycle batches are expanded atomically before they reach the controller.
"""

from __future__ import annotations

from dataclasses import asdict
import re
from typing import Any, Mapping

from ..events import (
    LEGACY_PROCESS_INSTANCE,
    PROTOCOL_VERSION,
    BackendReady,
    Event,
    InstrumentationError,
    InstrumentationStatus,
    LauncherReady,
    ModuleCapability,
    ProcessExited,
    SqliteDetected,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
    StatementStarted,
)

_POINTER = re.compile(r"^0x[0-9a-f]+$")
_PROCESS_INSTANCE = re.compile(r"^(?:legacy|p[1-9][0-9]*-i[1-9][0-9]*)$")
_SYMBOLS = {
    "sqlite3_prepare_v2",
    "sqlite3_prepare_v3",
    "sqlite3_step",
    "sqlite3_reset",
    "sqlite3_finalize",
    "sqlite3_stmt_status",
    "sqlite3_libversion",
}
_TYPES = {
    "backend_ready",
    "launcher_ready",
    "sqlite_detected",
    "module_capability",
    "instrumentation_status",
    "statement_prepared",
    "statement_started",
    "statement_executed",
    "statement_finalized",
    "instrumentation_error",
    "process_exited",
    "lifecycle_batch",
}
_TARGET_TYPES = _TYPES - {"launcher_ready", "lifecycle_batch"}
_ALLOWED_FIELDS = {
    "backend_ready": {
        "type", "protocol_version", "process_instance", "pid", "arch", "platform",
    },
    "launcher_ready": {"type", "protocol_version", "pid", "arch", "platform"},
    "sqlite_detected": {
        "type", "protocol_version", "process_instance", "pid", "module", "path",
        "base", "symbol", "address", "linkage",
    },
    "module_capability": {
        "type", "protocol_version", "process_instance", "pid", "module", "path",
        "base", "linkage", "candidate", "scanned", "symbols_present",
        "symbols_missing", "metric_reader", "hooks_attempted", "hooks_installed",
        "hooks_failed", "reasons", "sqlite_version",
    },
    "instrumentation_status": {
        "type", "protocol_version", "process_instance", "status", "pid", "hooks",
        "reason", "sql_capture_limit",
    },
    "statement_prepared": {
        "type", "protocol_version", "process_instance", "pid", "tid", "module",
        "module_path", "module_base", "statement", "database", "sql", "sqlite_rc",
        "sql_truncated", "captured_bytes", "sql_capture_failed",
    },
    "statement_started": {
        "type", "protocol_version", "process_instance", "pid", "tid", "module",
        "module_path", "module_base", "statement", "database", "execution_number",
    },
    "statement_executed": {
        "type", "protocol_version", "process_instance", "pid", "tid", "module",
        "module_path", "module_base", "statement", "database", "execution_number",
        "sqlite_rc", "boundary", "fullscan_steps", "vm_steps", "sorts", "autoindex",
    },
    "statement_finalized": {
        "type", "protocol_version", "process_instance", "pid", "tid", "module",
        "module_path", "module_base", "statement", "database", "executions", "sqlite_rc",
    },
    "instrumentation_error": {
        "type", "protocol_version", "process_instance", "phase", "message", "pid",
        "fatal", "sqlite_rc", "data_loss",
    },
    "process_exited": {
        "type", "protocol_version", "process_instance", "pid", "exit_code", "signal",
    },
    "lifecycle_batch": {
        "type", "protocol_version", "process_instance", "sequence", "ack_required", "events",
    },
}
_LIFECYCLE_TYPES = {
    "statement_prepared", "statement_started", "statement_executed", "statement_finalized",
}
_ACK_FIELDS = {"type", "protocol_version", "process_instance", "sequence"}


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
        raise ProtocolError(
            f"unknown fields for {event_type}: {', '.join(unknown)}", payload=payload
        )


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
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProtocolError(f"{name} must be valid UTF-8 text") from exc
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


def _process_instance(value: Any) -> str:
    if not isinstance(value, str) or not _PROCESS_INSTANCE.fullmatch(value):
        raise ProtocolError(
            "process_instance must be 'legacy' or a host-generated p<PID>-i<IMAGE> identifier"
        )
    return value


def _symbols(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or item not in _SYMBOLS for item in value
    ):
        raise ProtocolError(f"{name} must be a list of known SQLite symbols")
    if value != sorted(set(value)):
        raise ProtocolError(f"{name} must be unique and sorted")
    return tuple(value)


def _validate_attribution(
    event: Event,
    *,
    expected_pid: int | None,
    expected_process_instance: str | None,
    payload: Any,
) -> None:
    if expected_pid is not None and getattr(event, "pid", None) != expected_pid:
        raise ProtocolError(
            f"event pid does not match callback stream pid {expected_pid}", payload=payload
        )
    if (
        expected_process_instance is not None
        and getattr(event, "process_instance", None) != expected_process_instance
    ):
        raise ProtocolError(
            "event process_instance does not match callback stream", payload=payload
        )


def payload_to_event(
    payload: Any,
    *,
    expected_pid: int | None = None,
    expected_process_instance: str | None = None,
) -> Event:
    """Validate and convert one non-batch agent payload."""
    data = _mapping(payload)
    event_type = data.get("type")
    if event_type not in _TYPES or event_type == "lifecycle_batch":
        raise ProtocolError(f"unknown event type: {event_type!r}", payload=payload)
    _common(data, event_type)
    _known_fields(data, event_type)

    instance: str | None = None
    if event_type in _TARGET_TYPES:
        _required(data, "process_instance")
        instance = _process_instance(data["process_instance"])

    if event_type == "backend_ready":
        _required(data, "pid")
        event: Event = BackendReady(
            _positive_int(data["pid"], "pid"),
            arch=_string(data.get("arch", "x64"), "arch"),
            platform=_string(data.get("platform", "linux"), "platform"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "launcher_ready":
        _required(data, "pid")
        event = LauncherReady(
            _positive_int(data["pid"], "pid"),
            arch=_string(data.get("arch", "x64"), "arch"),
            platform=_string(data.get("platform", "linux"), "platform"),
        )
    elif event_type == "sqlite_detected":
        _required(data, "pid", "module", "path", "base", "symbol", "address")
        event = SqliteDetected(
            _positive_int(data["pid"], "pid"),
            _string(data["module"], "module"),
            _string(data["path"], "path"),
            _string(data["symbol"], "symbol"),
            _pointer(data["address"], "address"),
            _optional_string(data.get("linkage"), "linkage"),
            _pointer(data["base"], "base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "module_capability":
        _required(
            data,
            "pid", "module", "path", "base", "linkage", "candidate", "scanned",
            "symbols_present", "symbols_missing", "metric_reader", "hooks_attempted",
            "hooks_installed", "hooks_failed", "reasons",
        )
        linkage = _string(data["linkage"], "linkage")
        if linkage not in {"dynamic", "embedded_or_unknown"}:
            raise ProtocolError("invalid linkage")
        reasons = data["reasons"]
        if (
            not isinstance(reasons, list)
            or any(not isinstance(reason, str) or not reason for reason in reasons)
            or reasons != sorted(set(reasons))
        ):
            raise ProtocolError("reasons must be unique, non-empty, and sorted")
        event = ModuleCapability(
            _positive_int(data["pid"], "pid"),
            _string(data["module"], "module"),
            _string(data["path"], "path"),
            linkage,  # type: ignore[arg-type]
            _bool(data["candidate"], "candidate"),
            _bool(data["scanned"], "scanned"),
            _symbols(data["symbols_present"], "symbols_present"),
            _symbols(data["symbols_missing"], "symbols_missing"),
            _bool(data["metric_reader"], "metric_reader"),
            _symbols(data["hooks_attempted"], "hooks_attempted"),
            _symbols(data["hooks_installed"], "hooks_installed"),
            _symbols(data["hooks_failed"], "hooks_failed"),
            tuple(_string(reason, "reasons item") for reason in reasons),
            _optional_string(data.get("sqlite_version"), "sqlite_version"),
            _pointer(data["base"], "base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "instrumentation_status":
        _required(data, "pid", "status")
        status = _string(data["status"], "status")
        if status not in {
            "ACTIVE", "PARTIAL", "DETECTED_UNSUPPORTED", "FAILED", "NOT_DETECTED",
        }:
            raise ProtocolError(f"unknown instrumentation status: {status!r}")
        capture_limit = data.get("sql_capture_limit")
        event = InstrumentationStatus(
            status,
            _positive_int(data["pid"], "pid"),
            _nonnegative_int(data.get("hooks", 0), "hooks"),
            _optional_string(data.get("reason"), "reason"),
            None if capture_limit is None else _positive_int(capture_limit, "sql_capture_limit"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "statement_prepared":
        _required(
            data,
            "pid", "tid", "module", "module_path", "module_base", "statement",
            "database", "sql", "sql_truncated", "captured_bytes", "sql_capture_failed",
        )
        sql = _string(data["sql"], "sql")
        truncated = _bool(data["sql_truncated"], "sql_truncated")
        captured = _nonnegative_int(data["captured_bytes"], "captured_bytes")
        capture_failed = _bool(data["sql_capture_failed"], "sql_capture_failed")
        if captured != len(sql.encode("utf-8")):
            raise ProtocolError(
                "captured_bytes must equal the UTF-8 byte length of sql", payload=payload
            )
        if capture_failed and (sql or truncated or captured):
            raise ProtocolError(
                "failed SQL capture must have empty, non-truncated SQL", payload=payload
            )
        event = StatementPrepared(
            _positive_int(data["pid"], "pid"),
            _positive_int(data["tid"], "tid"),
            _string(data["module"], "module"),
            _pointer(data["statement"], "statement"),
            _pointer(data["database"], "database"),
            sql,
            _integer(data.get("sqlite_rc", 0), "sqlite_rc"),
            truncated,
            captured,
            capture_failed,
            _string(data["module_path"], "module_path"),
            _pointer(data["module_base"], "module_base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "statement_started":
        _required(
            data,
            "pid", "tid", "module", "module_path", "module_base", "statement",
            "database", "execution_number",
        )
        event = StatementStarted(
            _positive_int(data["pid"], "pid"),
            _positive_int(data["tid"], "tid"),
            _string(data["module"], "module"),
            _pointer(data["statement"], "statement"),
            _pointer(data["database"], "database"),
            _positive_int(data["execution_number"], "execution_number"),
            _string(data["module_path"], "module_path"),
            _pointer(data["module_base"], "module_base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "statement_executed":
        _required(
            data,
            "pid", "tid", "module", "module_path", "module_base", "statement",
            "database", "execution_number", "sqlite_rc", "boundary",
        )
        boundary = _string(data["boundary"], "boundary")
        if boundary not in {"done", "error", "reset", "finalize"}:
            raise ProtocolError(f"unknown execution boundary: {boundary!r}")
        metrics = _execution_metrics(data)
        event = StatementExecuted(
            _positive_int(data["pid"], "pid"),
            _positive_int(data["tid"], "tid"),
            _string(data["module"], "module"),
            _pointer(data["statement"], "statement"),
            _pointer(data["database"], "database"),
            _positive_int(data["execution_number"], "execution_number"),
            _integer(data["sqlite_rc"], "sqlite_rc"),
            boundary,  # type: ignore[arg-type]
            *metrics,
            _string(data["module_path"], "module_path"),
            _pointer(data["module_base"], "module_base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "statement_finalized":
        _required(
            data,
            "pid", "tid", "module", "module_path", "module_base", "statement",
            "database", "executions", "sqlite_rc",
        )
        event = StatementFinalized(
            _positive_int(data["pid"], "pid"),
            _positive_int(data["tid"], "tid"),
            _string(data["module"], "module"),
            _pointer(data["statement"], "statement"),
            _pointer(data["database"], "database"),
            _nonnegative_int(data["executions"], "executions"),
            _integer(data["sqlite_rc"], "sqlite_rc"),
            _string(data["module_path"], "module_path"),
            _pointer(data["module_base"], "module_base"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    elif event_type == "instrumentation_error":
        _required(data, "phase", "message")
        pid = data.get("pid")
        sqlite_rc = data.get("sqlite_rc")
        event = InstrumentationError(
            _string(data["phase"], "phase"),
            _string(data["message"], "message"),
            None if pid is None else _positive_int(pid, "pid"),
            _bool(data.get("fatal", True), "fatal"),
            None if sqlite_rc is None else _integer(sqlite_rc, "sqlite_rc"),
            _bool(data.get("data_loss", False), "data_loss"),
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )
    else:
        _required(data, "pid")
        exit_code, signal = data.get("exit_code"), data.get("signal")
        exit_code = None if exit_code is None else _nonnegative_int(exit_code, "exit_code")
        signal = None if signal is None else _positive_int(signal, "signal")
        if exit_code is not None and signal is not None:
            raise ProtocolError("process_exited cannot contain both exit_code and signal")
        event = ProcessExited(
            _positive_int(data["pid"], "pid"),
            exit_code,
            signal,
            process_instance=instance or LEGACY_PROCESS_INSTANCE,
        )

    if event_type != "launcher_ready":
        _validate_attribution(
            event,
            expected_pid=expected_pid,
            expected_process_instance=expected_process_instance,
            payload=payload,
        )
    return event


def _execution_metrics(
    payload: Mapping[str, Any],
) -> tuple[int | None, int | None, int | None, int | None]:
    names = ("fullscan_steps", "vm_steps", "sorts", "autoindex")
    if missing := [name for name in names if name not in payload]:
        raise ProtocolError(
            f"missing required metric fields: {', '.join(missing)}", payload=payload
        )
    values = tuple(
        None if payload[name] is None else _nonnegative_int(payload[name], name)
        for name in names
    )
    if any(value is None for value in values) and any(value is not None for value in values):
        raise ProtocolError(
            "statement_executed metrics must be all integers or all null", payload=payload
        )
    return values  # type: ignore[return-value]


def payload_to_events(
    payload: Any,
    *,
    expected_pid: int | None = None,
    expected_process_instance: str | None = None,
) -> tuple[Event, ...]:
    """Expand a payload atomically; an invalid batch returns no partial events."""
    data = _mapping(payload)
    if data.get("type") != "lifecycle_batch":
        return (
            payload_to_event(
                data,
                expected_pid=expected_pid,
                expected_process_instance=expected_process_instance,
            ),
        )
    _common(data, "lifecycle_batch")
    _known_fields(data, "lifecycle_batch")
    _required(data, "process_instance", "sequence", "ack_required", "events")
    instance = _process_instance(data["process_instance"])
    if expected_process_instance is not None and instance != expected_process_instance:
        raise ProtocolError("lifecycle batch process_instance does not match callback stream")
    _positive_int(data["sequence"], "sequence")
    _bool(data["ack_required"], "ack_required")
    members = data["events"]
    if not isinstance(members, list) or not members:
        raise ProtocolError("lifecycle_batch events must be a non-empty list", payload=payload)
    events = tuple(
        payload_to_event(
            member,
            expected_pid=expected_pid,
            expected_process_instance=instance,
        )
        for member in members
    )
    if any(getattr(event, "type") not in _LIFECYCLE_TYPES for event in events):
        raise ProtocolError(
            "lifecycle_batch contains a non-lifecycle event", payload=payload
        )
    return events


def validate_lifecycle_acknowledged(
    payload: Any, *, expected_process_instance: str
) -> int:
    data = _mapping(payload)
    _common(data, "lifecycle_acknowledged")
    if set(data) != _ACK_FIELDS:
        raise ProtocolError("invalid lifecycle acknowledgement fields", payload=payload)
    if _process_instance(data.get("process_instance")) != expected_process_instance:
        raise ProtocolError("lifecycle acknowledgement stream mismatch", payload=payload)
    return _positive_int(data.get("sequence"), "sequence")


def event_to_payload(event: Event) -> dict[str, Any]:
    payload = {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in asdict(event).items()
    }
    return (
        payload
        if isinstance(event, StatementExecuted)
        else {key: value for key, value in payload.items() if value is not None}
    )


def frida_message_to_events(
    message: Mapping[str, Any],
    *,
    expected_pid: int | None = None,
    expected_process_instance: str | None = None,
) -> tuple[Event, ...]:
    if message.get("type") == "send":
        return payload_to_events(
            message.get("payload"),
            expected_pid=expected_pid,
            expected_process_instance=expected_process_instance,
        )
    if message.get("type") == "error":
        description = message.get("description") or message.get("stack") or "unknown Frida error"
        return (
            InstrumentationError(
                phase="frida",
                message=str(description),
                pid=expected_pid,
                fatal=True,
                data_loss=True,
                process_instance=expected_process_instance or LEGACY_PROCESS_INSTANCE,
            ),
        )
    raise ProtocolError(
        f"unsupported Frida message type: {message.get('type')!r}", payload=message
    )


def frida_message_to_event(
    message: Mapping[str, Any],
    *,
    expected_pid: int | None = None,
    expected_process_instance: str | None = None,
) -> Event:
    """Backward-compatible single-event adapter; batches use the expander."""
    events = frida_message_to_events(
        message,
        expected_pid=expected_pid,
        expected_process_instance=expected_process_instance,
    )
    if len(events) != 1:
        raise ProtocolError("lifecycle_batch requires frida_message_to_events", payload=message)
    return events[0]
