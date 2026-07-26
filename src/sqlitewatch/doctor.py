"""Pure process-aware Doctor reduction and its independent exit policy."""

from __future__ import annotations

from dataclasses import dataclass

from .events import (
    DoctorState,
    InstrumentationError,
    InstrumentationStatus,
    ModuleCapability,
    ProcessTreeResult,
    RunResult,
    SqliteDetected,
    StatementPrepared,
    effective_process_tree,
)

_PREPARE = frozenset({"sqlite3_prepare_v2", "sqlite3_prepare_v3"})
_LIFECYCLE = frozenset({"sqlite3_step", "sqlite3_reset", "sqlite3_finalize"})


@dataclass(frozen=True, slots=True)
class DoctorModule:
    process_instance: str
    pid: int
    module: str
    path: str
    base: str
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
    complete_activity_count: int
    incomplete_activity_count: int
    reasons: tuple[str, ...]
    limitations: tuple[str, ...] = ()
    process_tree: ProcessTreeResult | None = None


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
        event.process_instance,
        event.pid,
        event.module,
        event.path,
        event.base,
        event.linkage,
        event.candidate,
        event.scanned,
        event.symbols_present,
        event.symbols_missing,
        event.metric_reader,
        event.hooks_attempted,
        event.hooks_installed,
        event.hooks_failed,
        event.reasons,
        event.sqlite_version,
        complete,
    )


def _limitations(tree: ProcessTreeResult) -> tuple[str, ...]:
    scope = (
        "Root target and recursively gated descendants are instrumented."
        if tree.follow_children
        else "Intentional root-only scope (--no-follow-children); descendants are not instrumented."
    )
    coverage = (
        "Observed process-tree coverage is complete."
        if tree.complete
        else "Observed process-tree coverage is incomplete; see process-tree inventory and reasons."
    )
    return (
        "Linux x86_64 only.",
        scope,
        coverage,
        "Binary fingerprinting for stripped SQLite is out of scope.",
    )


def reduce_events(run: RunResult) -> DoctorResult:
    """Reduce all in-scope process-image events without cross-stream borrowing."""
    tree = effective_process_tree(run)
    root_instances = {
        image.instance
        for process in tree.processes
        if process.root
        for image in process.images
    }
    by_module: dict[tuple[str, int, str, str], DoctorModule] = {}
    fatal_reasons: list[str] = []
    partial_reasons: list[str] = []
    prepared_events: list[StatementPrepared] = []
    observed_symbol = False

    for event in run.events:
        if isinstance(event, ModuleCapability):
            module = _module(event)
            by_module[
                (module.process_instance, module.pid, module.path, module.base)
            ] = module
        elif isinstance(event, SqliteDetected):
            observed_symbol = True
        elif isinstance(event, StatementPrepared):
            prepared_events.append(event)
        elif isinstance(event, InstrumentationError):
            if event.fatal:
                fatal_reasons.append(f"{event.phase}: {event.message}")
            elif event.phase == "process_coverage" and event.data_loss:
                partial_reasons.append(f"process coverage: {event.message}")
        elif isinstance(event, InstrumentationStatus):
            if event.status == "FAILED":
                if event.process_instance in root_instances:
                    fatal_reasons.append(
                        event.reason or "root agent reported FAILED"
                    )
                else:
                    partial_reasons.append(
                        event.reason or "descendant agent reported FAILED"
                    )
            elif event.status == "PARTIAL":
                partial_reasons.append(
                    event.reason or "agent reported partial SQLite coverage"
                )

    modules = tuple(
        sorted(
            by_module.values(),
            key=lambda item: (
                item.process_instance,
                item.pid,
                item.path,
                item.base,
                item.module,
            ),
        )
    )
    if run.instrumentation_status == "PARTIAL":
        partial_reasons.append("run reported partial process/image coverage")
    if not tree.complete:
        partial_reasons.append("process-tree coverage is incomplete")
    if run.instrumentation_status == "FAILED" and not run.instrumentation_failed:
        fatal_reasons.append("run reported FAILED instrumentation status")
    if run.instrumentation_failed:
        fatal_reasons.append(
            run.instrumentation_error
            or "controller reported instrumentation failure"
        )

    limitations = _limitations(tree)
    if fatal_reasons:
        return DoctorResult(
            "FAILED",
            run.pid,
            run.target_exit_code,
            run.signal,
            modules,
            0,
            0,
            0,
            tuple(sorted(set(fatal_reasons))),
            limitations,
            tree,
        )

    detected = observed_symbol or any(
        module.candidate or module.symbols_present for module in modules
    )
    complete_modules = tuple(module for module in modules if module.complete)
    complete_identities = {
        (module.process_instance, module.pid, module.path, module.base)
        for module in complete_modules
    }
    complete_legacy_names = {
        (module.process_instance, module.pid, module.module)
        for module in complete_modules
    }

    def complete_activity(event: StatementPrepared) -> bool:
        return (
            event.process_instance,
            event.pid,
            event.module_path,
            event.module_base,
        ) in complete_identities or (
            event.module_path == ""
            and event.module_base == "0x0"
            and (event.process_instance, event.pid, event.module)
            in complete_legacy_names
        )

    complete_count = sum(complete_activity(event) for event in prepared_events)
    incomplete_count = len(prepared_events) - complete_count

    if incomplete_count:
        identities = sorted(
            {
                f"{event.process_instance}/pid={event.pid}/"
                f"{event.module_path or event.module}@{event.module_base}"
                for event in prepared_events
                if not complete_activity(event)
            }
        )
        partial_reasons.append(
            f"Observed {incomplete_count} statement preparation(s) in incomplete "
            "or unknown process module(s): " + ", ".join(identities)
        )

    if partial_reasons:
        return DoctorResult(
            "PARTIAL",
            run.pid,
            run.target_exit_code,
            run.signal,
            modules,
            len(prepared_events),
            complete_count,
            incomplete_count,
            tuple(sorted(set(partial_reasons))),
            limitations,
            tree,
        )
    if not detected:
        return DoctorResult(
            "NOT_DETECTED",
            run.pid,
            run.target_exit_code,
            run.signal,
            modules,
            0,
            0,
            0,
            ("No SQLite candidate or observable SQLite symbol in the in-scope process tree.",),
            limitations,
            tree,
        )
    if not complete_modules:
        reasons = sorted({reason for module in modules for reason in module.reasons})
        if not reasons:
            reasons = ["No single process image/module has all required usable SQLite capabilities."]
        return DoctorResult(
            "DETECTED_UNSUPPORTED",
            run.pid,
            run.target_exit_code,
            run.signal,
            modules,
            len(prepared_events),
            0,
            len(prepared_events),
            tuple(reasons),
            limitations,
            tree,
        )
    if not complete_count:
        return DoctorResult(
            "NO_ACTIVITY",
            run.pid,
            run.target_exit_code,
            run.signal,
            modules,
            0,
            0,
            0,
            (
                "At least one fully hookable SQLite module was observed, but no "
                "statement was prepared anywhere in the in-scope process tree.",
            ),
            limitations,
            tree,
        )
    return DoctorResult(
        "ACTIVE",
        run.pid,
        run.target_exit_code,
        run.signal,
        modules,
        len(prepared_events),
        complete_count,
        0,
        (),
        limitations,
        tree,
    )


def resolve_doctor_outcome(result: DoctorResult) -> DoctorOutcome:
    application_failed = result.signal is not None or (
        result.target_exit_code is not None and result.target_exit_code != 0
    )
    doctor_failed = result.status != "ACTIVE"
    if doctor_failed:
        code = 70
    elif result.signal is not None:
        code = 128 + result.signal
    elif result.target_exit_code is not None and result.target_exit_code != 0:
        code = result.target_exit_code
    else:
        code = 0
    return DoctorOutcome(
        result.target_exit_code,
        result.signal,
        application_failed,
        doctor_failed,
        code,
    )
