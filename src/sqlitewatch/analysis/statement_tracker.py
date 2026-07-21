"""Reconstruct safe statement lifetimes from ordered raw lifecycle events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..events import Event, StatementExecuted, StatementFinalized, StatementPrepared


@dataclass(frozen=True, slots=True)
class TrackedExecution:
    pid: int
    module: str
    database: str
    sql: str
    fullscan_steps: int
    vm_steps: int
    sorts: int
    autoindex: int


@dataclass(frozen=True, slots=True)
class TrackingQuality:
    observed_executions: int = 0
    metric_bearing_executions: int = 0
    null_metric_executions: int = 0
    unmatched_executions: int = 0
    truncated_sql_executions: int = 0
    duplicate_executions: int = 0
    conflicted_executions: int = 0


@dataclass(frozen=True, slots=True)
class TrackingOutcome:
    executions: tuple[TrackedExecution, ...]
    quality: TrackingQuality


@dataclass(frozen=True, slots=True)
class _ExecutionIdentity:
    pid: int
    statement: str
    lifetime: int
    execution_number: int
    boundary: str


@dataclass(slots=True)
class _Lifetime:
    occurrence: int
    module: str
    database: str
    sql: str
    sql_truncated: bool
    seen_payloads: dict[_ExecutionIdentity, set[StatementExecuted]] = field(default_factory=dict)
    candidates: dict[_ExecutionIdentity, TrackedExecution] = field(default_factory=dict)


class StatementTracker:
    """Track one active lifetime per ``(pid, sqlite3_stmt*)`` pointer."""

    def track(self, events: Iterable[Event]) -> TrackingOutcome:
        active: dict[tuple[int, str], _Lifetime] = {}
        occurrences: dict[tuple[int, str], int] = {}
        completed: list[TrackedExecution] = []
        observed = metric_bearing = null_metrics = unmatched = truncated = duplicates = conflicts = 0

        for event in events:
            if isinstance(event, StatementPrepared):
                key = (event.pid, event.statement)
                previous = active.pop(key, None)
                if previous is not None:
                    # Pointer reuse before finalization makes only the former
                    # future ambiguous; observations already completed remain valid.
                    completed.extend(previous.candidates.values())
                occurrence = occurrences.get(key, 0) + 1
                occurrences[key] = occurrence
                active[key] = _Lifetime(
                    occurrence=occurrence,
                    module=event.module,
                    database=event.database,
                    sql=event.sql,
                    sql_truncated=event.sql_truncated,
                )
                continue

            if isinstance(event, StatementFinalized):
                key = (event.pid, event.statement)
                lifetime = active.get(key)
                if lifetime is not None and lifetime.module == event.module and lifetime.database == event.database:
                    completed.extend(lifetime.candidates.values())
                    del active[key]
                continue

            if not isinstance(event, StatementExecuted):
                continue

            observed += 1
            metrics = _complete_metrics(event)
            if metrics is None:
                null_metrics += 1
            else:
                metric_bearing += 1

            key = (event.pid, event.statement)
            lifetime = active.get(key)
            if lifetime is None or lifetime.module != event.module or lifetime.database != event.database:
                unmatched += 1
                continue

            identity = _ExecutionIdentity(
                event.pid, event.statement, lifetime.occurrence, event.execution_number, event.boundary
            )
            payloads = lifetime.seen_payloads.setdefault(identity, set())
            if payloads:
                if event in payloads:
                    duplicates += 1
                    continue
                conflicts += 1
                payloads.add(event)
                lifetime.candidates.pop(identity, None)
                continue
            payloads.add(event)

            if lifetime.sql_truncated:
                truncated += 1
                continue
            if metrics is None:
                continue

            lifetime.candidates[identity] = TrackedExecution(
                pid=event.pid,
                module=event.module,
                database=event.database,
                sql=lifetime.sql,
                fullscan_steps=metrics[0],
                vm_steps=metrics[1],
                sorts=metrics[2],
                autoindex=metrics[3],
            )

        candidates = tuple(completed) + tuple(
            candidate
            for lifetime in active.values()
            for candidate in lifetime.candidates.values()
        )
        return TrackingOutcome(
            executions=candidates,
            quality=TrackingQuality(
                observed_executions=observed,
                metric_bearing_executions=metric_bearing,
                null_metric_executions=null_metrics,
                unmatched_executions=unmatched,
                truncated_sql_executions=truncated,
                duplicate_executions=duplicates,
                conflicted_executions=conflicts,
            ),
        )


def _complete_metrics(event: StatementExecuted) -> tuple[int, int, int, int] | None:
    values = (event.fullscan_steps, event.vm_steps, event.sorts, event.autoindex)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError("statement execution metrics must be all integers or all null")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        raise ValueError("statement execution metrics must be non-negative integers")
    return values  # type: ignore[return-value]
