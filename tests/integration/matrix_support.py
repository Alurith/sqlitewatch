"""Shared validation records for the Phase 2 integration matrix.

This module intentionally lives under ``tests``: the matrix is a validation
contract, not part of SQLiteWatch's production event protocol.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Literal, Sequence

from sqlitewatch.events import (
    InstrumentationError,
    InstrumentationStatus,
    RunResult,
    SqliteDetected,
    StatementPrepared,
)

REQUIRED_SYMBOLS = ("sqlite3_prepare_v2",)
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
    sql_captured: bool
    functional_output_ok: bool
    reason: str | None = None

    def diagnostic(self) -> str:
        """Return a compact, complete record suitable for pytest assertions."""
        return json.dumps(asdict(self), sort_keys=True, default=list)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _reason_from_result(result: RunResult) -> str | None:
    errors = [
        event.message
        for event in result.events
        if isinstance(event, InstrumentationError)
    ]
    if result.instrumentation_error:
        errors.insert(0, result.instrumentation_error)
    return "; ".join(_unique(errors)) or None


def build_matrix_record(
    *,
    scenario: str,
    command: Sequence[str],
    result: RunResult | None,
    expected_sql: str | Sequence[str] | None = None,
    functional_output_ok: bool = False,
    skip_reason: str | None = None,
) -> MatrixRecord:
    """Build and classify one scenario from a controller result.

    ``skip_reason`` represents a prerequisite that was unavailable before the
    target validation started.  A result with an explicit
    ``DETECTED_UNSUPPORTED`` status is deliberately not treated as a skip.
    """

    command_tuple = tuple(str(part) for part in command)
    if result is None:
        if not skip_reason:
            raise ValueError("result is required unless skip_reason is provided")
        return MatrixRecord(
            scenario=scenario,
            status="SKIPPED",
            command=command_tuple,
            target_exit_code=None,
            sqlite_detected=False,
            module=None,
            path=None,
            linkage=None,
            required_symbols=REQUIRED_SYMBOLS,
            symbols_found=(),
            hook_installed=False,
            sql_captured=False,
            functional_output_ok=False,
            reason=skip_reason,
        )

    detections = [event for event in result.events if isinstance(event, SqliteDetected)]
    statuses = [
        event for event in result.events if isinstance(event, InstrumentationStatus)
    ]
    statements = [event for event in result.events if isinstance(event, StatementPrepared)]
    symbols_found = _unique([event.symbol for event in detections])
    expected = ({expected_sql} if isinstance(expected_sql, str) else set(expected_sql or ()))
    sql_captured = bool(expected) and any(event.sql in expected for event in statements)
    hook_installed = any(event.status == "ACTIVE" and event.hooks > 0 for event in statuses)
    unsupported = (
        not hook_installed
        and (
            result.instrumentation_status == "DETECTED_UNSUPPORTED"
            or any(event.status == "DETECTED_UNSUPPORTED" for event in statuses)
        )
    )
    target_failed = result.target_exit_code not in (None, 0) or result.signal is not None
    reason = _reason_from_result(result)

    if unsupported:
        status: MatrixStatus = "UNSUPPORTED"
        reason = reason or "sqlite3_prepare_v2 was detected as unavailable"
    elif result.instrumentation_failed or target_failed:
        status = "FAIL"
        reason = reason or (
            f"target exited with code {result.target_exit_code}"
            if target_failed
            else "instrumentation failed"
        )
    elif (
        bool(detections)
        and bool(symbols_found)
        and hook_installed
        and sql_captured
        and functional_output_ok
    ):
        status = "PASS"
    else:
        status = "FAIL"
        missing = []
        if not detections:
            missing.append("SQLite detection")
        if not symbols_found:
            missing.append("required symbol")
        if not hook_installed:
            missing.append("active hook")
        if not sql_captured:
            missing.append("expected SQL")
        if not functional_output_ok:
            missing.append("functional output")
        reason = reason or "missing " + ", ".join(missing)

    statement_modules = {event.module for event in statements}
    first_detection = next(
        (event for event in detections if event.module in statement_modules),
        detections[0] if detections else None,
    )
    return MatrixRecord(
        scenario=scenario,
        status=status,
        command=command_tuple,
        target_exit_code=result.target_exit_code,
        sqlite_detected=bool(detections),
        module=first_detection.module if first_detection else None,
        path=first_detection.path if first_detection else None,
        linkage=first_detection.linkage if first_detection else None,
        required_symbols=REQUIRED_SYMBOLS,
        symbols_found=symbols_found,
        hook_installed=hook_installed,
        sql_captured=sql_captured,
        functional_output_ok=functional_output_ok,
        reason=reason,
    )


def assert_matrix_pass(record: MatrixRecord) -> None:
    assert record.status == "PASS", record.diagnostic()


__all__ = [
    "MatrixRecord",
    "MatrixStatus",
    "REQUIRED_SYMBOLS",
    "assert_matrix_pass",
    "build_matrix_record",
]
