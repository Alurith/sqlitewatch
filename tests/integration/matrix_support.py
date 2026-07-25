"""Shared validation records for the runtime-metrics integration matrix."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Literal, Sequence

from sqlitewatch.events import (
    InstrumentationError,
    InstrumentationStatus,
    RunResult,
    SqliteDetected,
    StatementExecuted,
    StatementPrepared,
)

PREPARE_SYMBOLS = ("sqlite3_prepare_v2", "sqlite3_prepare_v3")
LIFECYCLE_SYMBOLS = ("sqlite3_step", "sqlite3_reset", "sqlite3_finalize")
METRIC_SYMBOLS = ("sqlite3_stmt_status",)
REQUIRED_SYMBOLS = PREPARE_SYMBOLS + LIFECYCLE_SYMBOLS + METRIC_SYMBOLS
MatrixStatus = Literal["PASS", "SKIPPED", "UNSUPPORTED", "FAIL"]


@dataclass(frozen=True, slots=True)
class MatrixRecord:
    scenario: str
    status: MatrixStatus
    command: tuple[str, ...]
    target_exit_code: int | None
    sqlite_detected: bool
    module: str | None
    path: str | None
    linkage: str | None
    required_symbols: tuple[str, ...]
    symbols_found: tuple[str, ...]
    hook_installed: bool
    lifecycle_active: bool
    metrics_active: bool
    prepared_v2: bool
    prepared_v3: bool
    executions_observed: bool
    finalizations_observed: bool
    metrics_observed: bool
    sql_captured: bool
    functional_output_ok: bool
    reason: str | None = None

    def diagnostic(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=list)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _reason_from_result(result: RunResult) -> str | None:
    errors = [event.message for event in result.events if isinstance(event, InstrumentationError)]
    if result.instrumentation_error:
        errors.insert(0, result.instrumentation_error)
    return "; ".join(_unique(errors)) or None


def _symbols_by_module(
    detections: Sequence[SqliteDetected],
) -> dict[tuple[str, str], set[str]]:
    found: dict[tuple[str, str], set[str]] = {}
    for event in detections:
        found.setdefault((event.path, event.base), set()).add(event.symbol)
    return found


def _lifecycle_active(detections: Sequence[SqliteDetected]) -> bool:
    return any(
        bool(symbols.intersection(PREPARE_SYMBOLS)) and set(LIFECYCLE_SYMBOLS).issubset(symbols)
        for symbols in _symbols_by_module(detections).values()
    )


def _metrics_active(detections: Sequence[SqliteDetected]) -> bool:
    return any(
        bool(symbols.intersection(PREPARE_SYMBOLS))
        and set(LIFECYCLE_SYMBOLS).issubset(symbols)
        and set(METRIC_SYMBOLS).issubset(symbols)
        for symbols in _symbols_by_module(detections).values()
    )


def _complete_module_identities(
    detections: Sequence[SqliteDetected],
) -> set[tuple[str, str]]:
    return {
        identity
        for identity, symbols in _symbols_by_module(detections).items()
        if bool(symbols.intersection(PREPARE_SYMBOLS))
        and set(LIFECYCLE_SYMBOLS).issubset(symbols)
        and set(METRIC_SYMBOLS).issubset(symbols)
    }


def _complete_metrics(event: StatementExecuted) -> bool:
    values = (event.fullscan_steps, event.vm_steps, event.sorts, event.autoindex)
    return all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values)


def build_matrix_record(
    *,
    scenario: str,
    command: Sequence[str],
    result: RunResult | None,
    expected_sql: str | Sequence[str] | None = None,
    functional_output_ok: bool = False,
    skip_reason: str | None = None,
) -> MatrixRecord:
    """Build a record without allowing module-split or metric-free PASSes."""
    command_tuple = tuple(str(part) for part in command)
    if result is None:
        if not skip_reason:
            raise ValueError("result is required unless skip_reason is provided")
        return MatrixRecord(
            scenario=scenario, status="SKIPPED", command=command_tuple, target_exit_code=None,
            sqlite_detected=False, module=None, path=None, linkage=None,
            required_symbols=REQUIRED_SYMBOLS, symbols_found=(), hook_installed=False,
            lifecycle_active=False, metrics_active=False, prepared_v2=False, prepared_v3=False,
            executions_observed=False, finalizations_observed=False, metrics_observed=False,
            sql_captured=False, functional_output_ok=False, reason=skip_reason,
        )

    detections = [event for event in result.events if isinstance(event, SqliteDetected)]
    statuses = [event for event in result.events if isinstance(event, InstrumentationStatus)]
    statements = [event for event in result.events if isinstance(event, StatementPrepared)]
    executions = list(result.executions)
    symbols_found = _unique([event.symbol for event in detections])
    expected = {expected_sql} if isinstance(expected_sql, str) else set(expected_sql or ())
    sql_captured = bool(expected) and any(event.sql in expected for event in statements)
    lifecycle_active = _lifecycle_active(detections)
    metrics_active = _metrics_active(detections)
    hook_installed = any(event.status == "ACTIVE" and event.hooks > 0 for event in statuses)
    executions_observed = bool(executions)
    finalizations_observed = bool(result.finalized_statements)
    metrics_observed = bool(executions) and all(_complete_metrics(event) for event in executions)
    complete_identities = _complete_module_identities(detections)
    activity_supported = bool(statements) and all(
        (event.module_path, event.module_base) in complete_identities
        or (event.module_path == "" and event.module_base == "0x0"
            and any(detection.module == event.module for detection in detections))
        for event in statements
    )
    unsupported = (
        not metrics_active
        and (result.instrumentation_status == "DETECTED_UNSUPPORTED" or any(
            event.status == "DETECTED_UNSUPPORTED" for event in statuses
        ))
    )
    target_failed = result.target_exit_code not in (None, 0) or result.signal is not None
    reason = _reason_from_result(result)

    if unsupported:
        status: MatrixStatus = "UNSUPPORTED"
        reason = reason or "SQLite lifecycle or metric symbols are unavailable"
    elif result.instrumentation_failed or target_failed or result.instrumentation_status != "ACTIVE":
        status = "FAIL"
        reason = reason or (f"target exited with code {result.target_exit_code}" if target_failed else "instrumentation failed")
    elif (bool(detections) and metrics_active and hook_installed and sql_captured
          and activity_supported and executions_observed and finalizations_observed and metrics_observed
          and functional_output_ok):
        status = "PASS"
    else:
        status = "FAIL"
        missing = []
        if not detections:
            missing.append("SQLite detection")
        if not lifecycle_active:
            missing.append("complete lifecycle hooks")
        if not metrics_active:
            missing.append("sqlite3_stmt_status in the lifecycle module")
        if not hook_installed:
            missing.append("active hook")
        if not sql_captured:
            missing.append("expected SQL")
        if not activity_supported:
            missing.append("activity in a complete SQLite module")
        if not executions_observed:
            missing.append("statement execution")
        if not finalizations_observed:
            missing.append("statement finalization")
        if not metrics_observed:
            missing.append("complete execution metrics")
        if not functional_output_ok:
            missing.append("functional output")
        reason = reason or "missing " + ", ".join(missing)

    statement_modules = {event.module for event in statements}
    first_detection = next((event for event in detections if event.module in statement_modules), detections[0] if detections else None)
    return MatrixRecord(
        scenario=scenario, status=status, command=command_tuple,
        target_exit_code=result.target_exit_code, sqlite_detected=bool(detections),
        module=first_detection.module if first_detection else None,
        path=first_detection.path if first_detection else None,
        linkage=first_detection.linkage if first_detection else None,
        required_symbols=REQUIRED_SYMBOLS, symbols_found=symbols_found,
        hook_installed=hook_installed, lifecycle_active=lifecycle_active, metrics_active=metrics_active,
        prepared_v2="sqlite3_prepare_v2" in symbols_found,
        prepared_v3="sqlite3_prepare_v3" in symbols_found,
        executions_observed=executions_observed,
        finalizations_observed=finalizations_observed,
        metrics_observed=metrics_observed,
        sql_captured=sql_captured, functional_output_ok=functional_output_ok, reason=reason,
    )


def assert_matrix_pass(record: MatrixRecord) -> None:
    assert record.status == "PASS", record.diagnostic()


__all__ = [
    "LIFECYCLE_SYMBOLS", "METRIC_SYMBOLS", "MatrixRecord", "MatrixStatus", "PREPARE_SYMBOLS",
    "REQUIRED_SYMBOLS", "assert_matrix_pass", "build_matrix_record",
]
