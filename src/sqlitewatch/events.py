"""Domain events exchanged by the controller and Frida agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

PROTOCOL_VERSION = 1
InstrumentationState = str


@dataclass(frozen=True, slots=True)
class BackendReady:
    pid: int
    protocol_version: int = PROTOCOL_VERSION
    arch: str = "x64"
    platform: str = "linux"
    type: str = field(default="backend_ready", init=False)


@dataclass(frozen=True, slots=True)
class LauncherReady:
    """The gated launcher is attached and may safely be resumed."""

    pid: int
    protocol_version: int = PROTOCOL_VERSION
    arch: str = "x64"
    platform: str = "linux"
    type: str = field(default="launcher_ready", init=False)


@dataclass(frozen=True, slots=True)
class SqliteDetected:
    pid: int
    module: str
    path: str
    symbol: str
    address: str
    linkage: str | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="sqlite_detected", init=False)


@dataclass(frozen=True, slots=True)
class InstrumentationStatus:
    status: InstrumentationState
    pid: int
    hooks: int = 0
    reason: str | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="instrumentation_status", init=False)


@dataclass(frozen=True, slots=True)
class StatementPrepared:
    pid: int
    tid: int
    module: str
    statement: str
    database: str
    sql: str
    sqlite_rc: int = 0
    sql_truncated: bool = False
    captured_bytes: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="statement_prepared", init=False)


@dataclass(frozen=True, slots=True)
class StatementExecuted:
    pid: int
    tid: int
    module: str
    statement: str
    database: str
    execution_number: int
    sqlite_rc: int
    boundary: Literal["done", "error", "reset", "finalize"]
    fullscan_steps: int | None = None
    vm_steps: int | None = None
    sorts: int | None = None
    autoindex: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="statement_executed", init=False)


@dataclass(frozen=True, slots=True)
class StatementFinalized:
    pid: int
    tid: int
    module: str
    statement: str
    database: str
    executions: int
    sqlite_rc: int
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="statement_finalized", init=False)


@dataclass(frozen=True, slots=True)
class InstrumentationError:
    phase: str
    message: str
    pid: int | None = None
    fatal: bool = True
    sqlite_rc: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="instrumentation_error", init=False)


@dataclass(frozen=True, slots=True)
class ProcessExited:
    pid: int
    exit_code: int | None = None
    signal: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    type: str = field(default="process_exited", init=False)


Event: TypeAlias = (
    BackendReady
    | LauncherReady
    | SqliteDetected
    | InstrumentationStatus
    | StatementPrepared
    | StatementExecuted
    | StatementFinalized
    | InstrumentationError
    | ProcessExited
)


@dataclass(frozen=True, slots=True)
class RunResult:
    pid: int | None
    target_exit_code: int | None
    signal: int | None
    events: tuple[Event, ...] = ()
    instrumentation_status: InstrumentationState = "NOT_DETECTED"
    instrumentation_failed: bool = False
    instrumentation_error: str | None = None

    @property
    def exit_code(self) -> int:
        """Return the CLI result while keeping target status separately available."""
        if self.instrumentation_failed:
            return 70
        if self.signal is not None:
            return 128 + self.signal
        return self.target_exit_code if self.target_exit_code is not None else 70

    @property
    def statements(self) -> tuple[StatementPrepared, ...]:
        """Prepared statements, retained as the Phase 0–2 compatibility alias."""
        return tuple(event for event in self.events if isinstance(event, StatementPrepared))

    @property
    def executions(self) -> tuple[StatementExecuted, ...]:
        return tuple(event for event in self.events if isinstance(event, StatementExecuted))

    @property
    def finalized_statements(self) -> tuple[StatementFinalized, ...]:
        return tuple(event for event in self.events if isinstance(event, StatementFinalized))

    def as_dict(self) -> dict[str, Any]:
        from .instrumentation.protocol import event_to_payload

        return {
            "pid": self.pid,
            "target_exit_code": self.target_exit_code,
            "signal": self.signal,
            "instrumentation_status": self.instrumentation_status,
            "instrumentation_failed": self.instrumentation_failed,
            "events": [event_to_payload(event) for event in self.events],
        }
