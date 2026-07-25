"""Reconstruct bounded, safe statement lifetimes from ordered lifecycle events."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..events import (
    Event, StatementExecuted, StatementFinalized, StatementPrepared, StatementStarted,
)

# Ordered Frida batches make duplicates local in practice. Keeping a bounded
# window preserves exact duplicate/conflict handling without retaining every
# execution of a long-lived prepared statement.
_RECENT_EXECUTION_WINDOW = 64


@dataclass(frozen=True, slots=True)
class TrackedExecution:
    pid: int
    module: str
    module_path: str
    module_base: str
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
    sql_capture_failed_executions: int = 0
    duplicate_executions: int = 0
    conflicted_executions: int = 0
    unfinished_executions: int = 0


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


@dataclass(slots=True)
class _PendingExecution:
    event: StatementExecuted
    candidate: TrackedExecution | None


@dataclass(slots=True)
class _Lifetime:
    occurrence: int
    module: str
    module_path: str
    module_base: str
    database: str
    sql: str
    sql_truncated: bool
    sql_capture_failed: bool
    pending: OrderedDict[_ExecutionIdentity, _PendingExecution] = field(default_factory=OrderedDict)
    started: dict[int, StatementStarted] = field(default_factory=dict)
    committed_execution_number: int = 0


class StatementTracker:
    """Incrementally track one active lifetime per ``(pid, sqlite3_stmt*)``.

    ``consume``/``finish`` are the bounded path used by the CLI reducer.  The
    convenience ``track`` method retains completed executions for callers that
    explicitly request a materialized outcome.
    """

    def __init__(self, on_execution: Callable[[TrackedExecution], None] | None = None):
        self._on_execution = on_execution
        self._reset()

    def _reset(self) -> None:
        self._active: dict[tuple[int, str], _Lifetime] = {}
        self._next_occurrence = 0
        self._completed: list[TrackedExecution] = []
        self._observed = 0
        self._metric_bearing = 0
        self._null_metrics = 0
        self._unmatched = 0
        self._truncated = 0
        self._capture_failed = 0
        self._duplicates = 0
        self._conflicts = 0
        self._unfinished = 0
        self._finished = False

    def track(self, events: Iterable[Event]) -> TrackingOutcome:
        self._reset()
        for event in events:
            self.consume(event)
        return self.finish()

    def consume(self, event: Event) -> None:
        if self._finished:
            raise RuntimeError("cannot consume events after tracker finish")

        if isinstance(event, StatementPrepared):
            self._consume_prepared(event)
        elif isinstance(event, StatementStarted):
            self._consume_started(event)
        elif isinstance(event, StatementFinalized):
            self._consume_finalized(event)
        elif isinstance(event, StatementExecuted):
            self._consume_executed(event)

    def finish(self) -> TrackingOutcome:
        if not self._finished:
            for lifetime in self._active.values():
                self._flush_lifetime(lifetime)
            self._active.clear()
            self._finished = True
        return TrackingOutcome(
            executions=tuple(self._completed),
            quality=TrackingQuality(
                observed_executions=self._observed,
                metric_bearing_executions=self._metric_bearing,
                null_metric_executions=self._null_metrics,
                unmatched_executions=self._unmatched,
                truncated_sql_executions=self._truncated,
                sql_capture_failed_executions=self._capture_failed,
                duplicate_executions=self._duplicates,
                conflicted_executions=self._conflicts,
                unfinished_executions=self._unfinished,
            ),
        )

    def _consume_prepared(self, event: StatementPrepared) -> None:
        key = (event.pid, event.statement)
        previous = self._active.pop(key, None)
        if previous is not None:
            # Already completed observations remain valid when SQLite reuses a
            # pointer before a finalization event reaches the controller.
            self._flush_lifetime(previous)
        self._next_occurrence += 1
        self._active[key] = _Lifetime(
            occurrence=self._next_occurrence,
            module=event.module,
            module_path=event.module_path,
            module_base=event.module_base,
            database=event.database,
            sql=event.sql,
            sql_truncated=event.sql_truncated,
            sql_capture_failed=event.sql_capture_failed,
        )

    def _consume_finalized(self, event: StatementFinalized) -> None:
        key = (event.pid, event.statement)
        lifetime = self._active.get(key)
        if lifetime is not None and _same_lifetime(lifetime, event):
            self._flush_lifetime(lifetime)
            del self._active[key]

    def _consume_started(self, event: StatementStarted) -> None:
        lifetime = self._active.get((event.pid, event.statement))
        if lifetime is None or not _same_lifetime(lifetime, event):
            self._unmatched += 1
            return
        previous = lifetime.started.get(event.execution_number)
        if previous is not None:
            if previous == event:
                self._duplicates += 1
            else:
                self._conflicts += 1
            return
        if event.execution_number <= lifetime.committed_execution_number or any(
            identity.execution_number == event.execution_number
            for identity in lifetime.pending
        ):
            self._conflicts += 1
            return
        lifetime.started[event.execution_number] = event

    def _consume_executed(self, event: StatementExecuted) -> None:
        self._observed += 1
        metrics = _complete_metrics(event)
        if metrics is None:
            self._null_metrics += 1
        else:
            self._metric_bearing += 1

        lifetime = self._active.get((event.pid, event.statement))
        if lifetime is None or not _same_lifetime(lifetime, event):
            self._unmatched += 1
            return

        lifetime.started.pop(event.execution_number, None)
        identity = _ExecutionIdentity(
            event.pid, event.statement, lifetime.occurrence, event.execution_number
        )
        previous = lifetime.pending.get(identity)
        if previous is not None:
            if event == previous.event:
                self._duplicates += 1
            else:
                self._conflicts += 1
                previous.candidate = None
            return

        # A payload arriving after it left the bounded ordered window cannot be
        # proven identical. Treat it as a conflict so CI remains fail-closed.
        if event.execution_number <= lifetime.committed_execution_number:
            self._conflicts += 1
            return

        candidate: TrackedExecution | None = None
        if lifetime.sql_capture_failed:
            self._capture_failed += 1
        elif lifetime.sql_truncated:
            self._truncated += 1
        elif metrics is not None:
            candidate = TrackedExecution(
                pid=event.pid,
                module=event.module,
                module_path=event.module_path,
                module_base=event.module_base,
                database=event.database,
                sql=lifetime.sql,
                fullscan_steps=metrics[0],
                vm_steps=metrics[1],
                sorts=metrics[2],
                autoindex=metrics[3],
            )
        lifetime.pending[identity] = _PendingExecution(event, candidate)
        while len(lifetime.pending) > _RECENT_EXECUTION_WINDOW:
            old_identity, pending = lifetime.pending.popitem(last=False)
            lifetime.committed_execution_number = max(
                lifetime.committed_execution_number, old_identity.execution_number
            )
            self._emit(pending.candidate)

    def _flush_lifetime(self, lifetime: _Lifetime) -> None:
        self._unfinished += len(lifetime.started)
        lifetime.started.clear()
        for identity, pending in lifetime.pending.items():
            lifetime.committed_execution_number = max(
                lifetime.committed_execution_number, identity.execution_number
            )
            self._emit(pending.candidate)
        lifetime.pending.clear()

    def _emit(self, execution: TrackedExecution | None) -> None:
        if execution is None:
            return
        if self._on_execution is None:
            self._completed.append(execution)
        else:
            self._on_execution(execution)


def _same_lifetime(
    lifetime: _Lifetime,
    event: StatementStarted | StatementExecuted | StatementFinalized,
) -> bool:
    return (
        lifetime.module == event.module
        and lifetime.module_path == event.module_path
        and lifetime.module_base == event.module_base
        and lifetime.database == event.database
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
