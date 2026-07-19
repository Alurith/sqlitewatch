"""Versioned, dependency-free event protocol for Frida messages."""

from __future__ import annotations

from dataclasses import asdict
import re
from typing import Any, Mapping

from ..events import (
    PROTOCOL_VERSION,
    BackendReady,
    Event,
    InstrumentationError,
    InstrumentationStatus,
    ProcessExited,
    SqliteDetected,
    StatementPrepared,
)

_POINTER = re.compile(r"^0x[0-9a-f]+$")
_TYPES = {
    "backend_ready",
    "sqlite_detected",
    "instrumentation_status",
    "statement_prepared",
    "instrumentation_error",
    "process_exited",
}
_ALLOWED_FIELDS = {
    "backend_ready": {"type", "protocol_version", "pid", "arch", "platform"},
    "sqlite_detected": {"type", "protocol_version", "pid", "module", "path", "symbol", "address", "linkage"},
    "instrumentation_status": {"type", "protocol_version", "status", "pid", "hooks", "reason"},
    "statement_prepared": {"type", "protocol_version", "pid", "tid", "module", "statement", "database", "sql", "sqlite_rc", "sql_truncated", "captured_bytes"},
    "instrumentation_error": {"type", "protocol_version", "phase", "message", "pid", "fatal", "sqlite_rc"},
    "process_exited": {"type", "protocol_version", "pid", "exit_code", "signal"},
}


class ProtocolError(ValueError):
    """A malformed or unsupported event payload."""

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


def payload_to_event(payload: Any) -> Event:
    """Validate and convert one agent payload into an immutable domain event."""
    data = _mapping(payload)
    event_type = data.get("type")
    if event_type not in _TYPES:
        raise ProtocolError(f"unknown event type: {event_type!r}", payload=payload)
    _common(data, event_type)
    _known_fields(data, event_type)

    if event_type == "backend_ready":
        _required(data, "pid")
        return BackendReady(
            pid=_positive_int(data["pid"], "pid"),
            arch=str(data.get("arch", "x64")),
            platform=str(data.get("platform", "linux")),
        )
    if event_type == "sqlite_detected":
        _required(data, "pid", "module", "path", "symbol", "address")
        return SqliteDetected(
            pid=_positive_int(data["pid"], "pid"),
            module=_string(data["module"], "module"),
            path=_string(data["path"], "path"),
            symbol=_string(data["symbol"], "symbol"),
            address=_pointer(data["address"], "address"),
            linkage=_optional_string(data.get("linkage"), "linkage"),
        )
    if event_type == "instrumentation_status":
        _required(data, "pid", "status")
        status = _string(data["status"], "status")
        if status not in {"ACTIVE", "DETECTED_UNSUPPORTED", "FAILED", "NOT_DETECTED"}:
            raise ProtocolError(f"unknown instrumentation status: {status!r}")
        return InstrumentationStatus(
            pid=_positive_int(data["pid"], "pid"),
            status=status,
            hooks=_nonnegative_int(data.get("hooks", 0), "hooks"),
            reason=_optional_string(data.get("reason"), "reason"),
        )
    if event_type == "statement_prepared":
        _required(data, "pid", "tid", "module", "statement", "database", "sql")
        captured = data.get("captured_bytes")
        if captured is not None:
            captured = _nonnegative_int(captured, "captured_bytes")
        return StatementPrepared(
            pid=_positive_int(data["pid"], "pid"),
            tid=_positive_int(data["tid"], "tid"),
            module=_string(data["module"], "module"),
            statement=_pointer(data["statement"], "statement"),
            database=_pointer(data["database"], "database"),
            sql=_string(data["sql"], "sql"),
            sqlite_rc=_integer(data.get("sqlite_rc", 0), "sqlite_rc"),
            sql_truncated=_bool(data.get("sql_truncated", False), "sql_truncated"),
            captured_bytes=captured,
        )
    if event_type == "instrumentation_error":
        _required(data, "phase", "message")
        pid = data.get("pid")
        if pid is not None:
            pid = _positive_int(pid, "pid")
        sqlite_rc = data.get("sqlite_rc")
        if sqlite_rc is not None:
            sqlite_rc = _integer(sqlite_rc, "sqlite_rc")
        return InstrumentationError(
            phase=_string(data["phase"], "phase"),
            message=_string(data["message"], "message"),
            pid=pid,
            fatal=_bool(data.get("fatal", True), "fatal"),
            sqlite_rc=sqlite_rc,
        )

    _required(data, "pid")
    exit_code = data.get("exit_code")
    signal = data.get("signal")
    if exit_code is not None:
        exit_code = _nonnegative_int(exit_code, "exit_code")
    if signal is not None:
        signal = _positive_int(signal, "signal")
    if exit_code is not None and signal is not None:
        raise ProtocolError("process_exited cannot contain both exit_code and signal")
    return ProcessExited(
        pid=_positive_int(data["pid"], "pid"), exit_code=exit_code, signal=signal
    )


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be a string")
    return value


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{name} must be an integer")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"{name} must be a boolean")
    return value


def event_to_payload(event: Event) -> dict[str, Any]:
    payload = asdict(event)
    payload = {key: value for key, value in payload.items() if value is not None}
    return payload


def frida_message_to_event(message: Mapping[str, Any]) -> Event:
    """Translate Frida's two message forms without treating errors as no activity."""
    if message.get("type") == "send":
        return payload_to_event(message.get("payload"))
    if message.get("type") == "error":
        description = message.get("description") or message.get("stack") or "unknown Frida error"
        return InstrumentationError(phase="frida", message=str(description), fatal=True)
    raise ProtocolError(f"unsupported Frida message type: {message.get('type')!r}", payload=message)
