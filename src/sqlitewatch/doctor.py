"""Pure Doctor reduction and its independent exit policy."""

from __future__ import annotations

from dataclasses import dataclass

from .events import (
    DoctorState, InstrumentationError, InstrumentationStatus, ModuleCapability,
    RunResult, SqliteDetected, StatementPrepared,
)

_PREPARE = frozenset({"sqlite3_prepare_v2", "sqlite3_prepare_v3"})
_LIFECYCLE = frozenset({"sqlite3_step", "sqlite3_reset", "sqlite3_finalize"})
_REQUIRED = _PREPARE | _LIFECYCLE | {"sqlite3_stmt_status"}


@dataclass(frozen=True, slots=True)
class DoctorModule:
    pid: int
    module: str
    path: str
    linkage: str
    candidate: bool
    scanned: bool
    symbols_present: tuple[str, ...]
    symbols_missing: tuple[str, ...]
    metric_reader: bool
    hooks_attempted: tuple[str, ...]
    hooks_installed: tuple[str, ...]
    hooks_failed: tuple[str, ...]
    reasons: tuple[str, ...]
    sqlite_version: str | None
    complete: bool


@dataclass(frozen=True, slots=True)
class DoctorResult:
    status: DoctorState
    pid: int | None
    target_exit_code: int | None
    signal: int | None
    modules: tuple[DoctorModule, ...]
    activity_count: int
    reasons: tuple[str, ...]
    limitations: tuple[str, ...] = (
        "Linux x86_64 only; only the primary target process is instrumented.",
        "Child processes are released but are not instrumented or aggregated.",
        "Binary fingerprinting for stripped SQLite is out of scope.",
    )


@dataclass(frozen=True, slots=True)
class DoctorOutcome:
    target_exit_code: int | None
    signal: int | None
    application_failed: bool
    doctor_failed: bool
    exit_code: int


def _module(event: ModuleCapability) -> DoctorModule:
    installed = frozenset(event.hooks_installed)
    present = frozenset(event.symbols_present)
    complete = (
        event.scanned
        and bool(_PREPARE & installed)
        and _LIFECYCLE <= installed
        and "sqlite3_stmt_status" in present
        and event.metric_reader
    )
    return DoctorModule(
        event.pid, event.module, event.path, event.linkage, event.candidate,
        event.scanned, event.symbols_present, event.symbols_missing,
        event.metric_reader, event.hooks_attempted, event.hooks_installed,
        event.hooks_failed, event.reasons, event.sqlite_version, complete,
    )


def reduce_events(run: RunResult) -> DoctorResult:
    """Reduce raw events without inferring support from a module name alone."""
    by_module: dict[tuple[str, str], DoctorModule] = {}
    fatal_reasons: list[str] = []
    observed_symbol = False
    for event in run.events:
        if isinstance(event, ModuleCapability):
            module = _module(event)
            by_module[(module.path, module.module)] = module
        elif isinstance(event, SqliteDetected):
            observed_symbol = True
        elif isinstance(event, InstrumentationError) and event.fatal:
            fatal_reasons.append(f"{event.phase}: {event.message}")
        elif isinstance(event, InstrumentationStatus) and event.status == "FAILED":
            fatal_reasons.append(event.reason or "agent reported FAILED")
    modules = tuple(sorted(by_module.values(), key=lambda item: (item.path, item.module)))
    if run.instrumentation_failed:
        fatal_reasons.append(run.instrumentation_error or "controller reported instrumentation failure")
    if fatal_reasons:
        return DoctorResult("FAILED", run.pid, run.target_exit_code, run.signal, modules, 0, tuple(sorted(set(fatal_reasons))))

    detected = observed_symbol or any(module.candidate or module.symbols_present for module in modules)
    complete_modules = tuple(module for module in modules if module.complete)
    if not detected:
        return DoctorResult("NOT_DETECTED", run.pid, run.target_exit_code, run.signal, modules, 0, ("No SQLite candidate or observable SQLite symbol in the primary target process.",))
    if not complete_modules:
        reasons = sorted({reason for module in modules for reason in module.reasons})
        if not reasons:
            reasons = ["No single module has all required usable SQLite capabilities."]
        return DoctorResult("DETECTED_UNSUPPORTED", run.pid, run.target_exit_code, run.signal, modules, 0, tuple(reasons))

    activity = sum(1 for event in run.events if isinstance(event, StatementPrepared) and event.pid == run.pid)
    if not activity:
        return DoctorResult("NO_ACTIVITY", run.pid, run.target_exit_code, run.signal, modules, 0, ("A fully hookable SQLite module was observed, but no statement was prepared by the target.",))
    return DoctorResult("ACTIVE", run.pid, run.target_exit_code, run.signal, modules, activity, ())


def resolve_doctor_outcome(result: DoctorResult) -> DoctorOutcome:
    application_failed = result.signal is not None or (result.target_exit_code is not None and result.target_exit_code != 0)
    doctor_failed = result.status != "ACTIVE"
    if doctor_failed:
        code = 70
    elif result.signal is not None:
        code = 128 + result.signal
    elif result.target_exit_code is not None and result.target_exit_code != 0:
        code = result.target_exit_code
    else:
        code = 0
    return DoctorOutcome(result.target_exit_code, result.signal, application_failed, doctor_failed, code)
