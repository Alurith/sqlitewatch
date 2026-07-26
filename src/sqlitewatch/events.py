"""Domain events exchanged by the controller and Frida agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

PROTOCOL_VERSION = 3
LEGACY_PROCESS_INSTANCE = "legacy"
InstrumentationState = str
DoctorState = Literal[
    "FAILED", "NOT_DETECTED", "DETECTED_UNSUPPORTED", "NO_ACTIVITY", "PARTIAL", "ACTIVE"
]


@dataclass(frozen=True, slots=True)
class BackendReady:
    pid: int
    protocol_version: int = PROTOCOL_VERSION
    arch: str = "x64"
    platform: str = "linux"
    process_instance: str = LEGACY_PROCESS_INSTANCE
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
    """Legacy per-symbol detection event retained for the normal-run protocol."""

    pid: int
    module: str
    path: str
    symbol: str
    address: str
    linkage: str | None = None
    base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="sqlite_detected", init=False)


@dataclass(frozen=True, slots=True)
class ModuleCapability:
    """Complete, same-module discovery record used by Doctor.

    Tuples intentionally make the inventory stable and immutable at the domain
    boundary.  A record is emitted after each inspected module and can be
    replaced by a later record for the same module in the reducer.
    """

    pid: int
    module: str
    path: str
    linkage: Literal["dynamic", "embedded_or_unknown"]
    candidate: bool
    scanned: bool
    symbols_present: tuple[str, ...]
    symbols_missing: tuple[str, ...]
    metric_reader: bool
    hooks_attempted: tuple[str, ...]
    hooks_installed: tuple[str, ...]
    hooks_failed: tuple[str, ...]
    reasons: tuple[str, ...]
    sqlite_version: str | None = None
    base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="module_capability", init=False)


@dataclass(frozen=True, slots=True)
class InstrumentationStatus:
    status: InstrumentationState
    pid: int
    hooks: int = 0
    reason: str | None = None
    sql_capture_limit: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
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
    sql_capture_failed: bool = False
    module_path: str = ""
    module_base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="statement_prepared", init=False)

    def __post_init__(self) -> None:
        if self.captured_bytes is None:
            object.__setattr__(self, "captured_bytes", len(self.sql.encode("utf-8")))


@dataclass(frozen=True, slots=True)
class StatementStarted:
    pid: int
    tid: int
    module: str
    statement: str
    database: str
    execution_number: int
    module_path: str = ""
    module_base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="statement_started", init=False)


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
    module_path: str = ""
    module_base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
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
    module_path: str = ""
    module_base: str = "0x0"
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="statement_finalized", init=False)


@dataclass(frozen=True, slots=True)
class InstrumentationError:
    phase: str
    message: str
    pid: int | None = None
    fatal: bool = True
    sqlite_rc: int | None = None
    data_loss: bool = False
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="instrumentation_error", init=False)


@dataclass(frozen=True, slots=True)
class ProcessExited:
    pid: int
    exit_code: int | None = None
    signal: int | None = None
    protocol_version: int = PROTOCOL_VERSION
    process_instance: str = LEGACY_PROCESS_INSTANCE
    type: str = field(default="process_exited", init=False)


Event: TypeAlias = (
    BackendReady | LauncherReady | SqliteDetected | ModuleCapability |
    InstrumentationStatus | StatementPrepared | StatementStarted |
    StatementExecuted | StatementFinalized | InstrumentationError | ProcessExited
)


@dataclass(frozen=True, slots=True)
class ProcessImage:
    instance: str
    pid: int
    origin: str
    identifier: str | None
    instrumentation_status: str
    instrumented: bool
    coverage_complete: bool
    detach_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.instance:
            raise ValueError("process image instance cannot be empty")
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("process image pid must be a positive integer")
        if not self.origin:
            raise ValueError("process image origin cannot be empty")
        if self.instrumentation_status not in {
            "FAILED", "PARTIAL", "ACTIVE", "DETECTED_UNSUPPORTED", "NOT_DETECTED",
        }:
            raise ValueError("invalid process image instrumentation status")


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    pid: int
    parent_pid: int | None
    depth: int
    root: bool
    images: tuple[ProcessImage, ...]
    active_at_root_exit: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("observed process pid must be a positive integer")
        if self.parent_pid is not None and (
            isinstance(self.parent_pid, bool)
            or not isinstance(self.parent_pid, int)
            or self.parent_pid <= 0
        ):
            raise ValueError("observed process parent pid must be positive or None")
        if isinstance(self.depth, bool) or not isinstance(self.depth, int) or self.depth < 0:
            raise ValueError("observed process depth must be a non-negative integer")
        if not self.images:
            raise ValueError("observed processes require at least one image")
        if any(image.pid != self.pid for image in self.images):
            raise ValueError("all process images must belong to the observed pid")


@dataclass(frozen=True, slots=True)
class ProcessTreeResult:
    follow_children: bool
    root_pid: int | None
    complete: bool
    processes: tuple[ObservedProcess, ...]
    max_followed_processes: int
    max_process_images: int
    omitted_images: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.follow_children, bool) or not isinstance(self.complete, bool):
            raise TypeError("process tree policy flags must be booleans")
        for name in ("max_followed_processes", "max_process_images"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(self.omitted_images, bool)
            or not isinstance(self.omitted_images, int)
            or self.omitted_images < 0
        ):
            raise ValueError("omitted_images must be a non-negative integer")
        if self.root_pid is None:
            if self.processes:
                raise ValueError("a process tree without a root pid must be empty")
        elif not any(process.pid == self.root_pid and process.root for process in self.processes):
            raise ValueError("process tree root pid must identify a root process")
        if len({process.pid for process in self.processes}) != len(self.processes):
            raise ValueError("process tree process pids must be unique")

    @property
    def process_count(self) -> int:
        return len(self.processes)

    @property
    def image_count(self) -> int:
        return sum(len(process.images) for process in self.processes)

    @property
    def active_at_root_exit(self) -> int:
        return sum(process.active_at_root_exit for process in self.processes)


@dataclass(frozen=True, slots=True)
class RunResult:
    pid: int | None
    target_exit_code: int | None
    signal: int | None
    events: tuple[Event, ...] = ()
    instrumentation_status: InstrumentationState = "NOT_DETECTED"
    instrumentation_failed: bool = False
    instrumentation_error: str | None = None
    sql_capture_limit: int | None = None
    events_retained: bool = True
    process_tree: ProcessTreeResult | None = None

    @property
    def exit_code(self) -> int:
        if self.instrumentation_failed:
            return 70
        if self.signal is not None:
            return 128 + self.signal
        return self.target_exit_code if self.target_exit_code is not None else 70

    @property
    def statements(self) -> tuple[StatementPrepared, ...]:
        return tuple(event for event in self.events if isinstance(event, StatementPrepared))

    @property
    def started_executions(self) -> tuple[StatementStarted, ...]:
        return tuple(event for event in self.events if isinstance(event, StatementStarted))

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


def effective_process_tree(run: RunResult) -> ProcessTreeResult:
    """Return the explicit tree or a deterministic legacy root-only summary."""
    if run.process_tree is not None:
        return run.process_tree
    processes: tuple[ObservedProcess, ...] = ()
    if run.pid is not None:
        image = ProcessImage(
            instance=LEGACY_PROCESS_INSTANCE,
            pid=run.pid,
            origin="legacy",
            identifier=None,
            instrumentation_status=run.instrumentation_status,
            instrumented=not run.instrumentation_failed,
            coverage_complete=not run.instrumentation_failed,
        )
        processes = (ObservedProcess(run.pid, None, 0, True, (image,)),)
    return ProcessTreeResult(
        follow_children=False,
        root_pid=run.pid,
        complete=not run.instrumentation_failed,
        processes=processes,
        max_followed_processes=1,
        max_process_images=1,
    )
