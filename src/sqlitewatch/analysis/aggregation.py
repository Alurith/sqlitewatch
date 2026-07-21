"""Scoped query aggregation over completed SQLiteWatch runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from ..events import RunResult
from .normalization import normalize_sql
from .statement_tracker import StatementTracker, TrackingQuality


@dataclass(frozen=True, slots=True)
class QueryScope:
    pid: int
    module: str
    database: str

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("scope pid must be a positive integer")
        if not isinstance(self.module, str) or not isinstance(self.database, str):
            raise TypeError("scope module and database must be strings")


@dataclass(frozen=True, slots=True)
class QueryAggregate:
    scope: QueryScope
    fingerprint: str
    normalized_sql: str
    executions: int
    total_fullscan_steps: int
    max_fullscan_steps: int
    total_vm_steps: int
    max_vm_steps: int
    total_sorts: int
    total_autoindex: int
    signals: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.fingerprint) != 64 or any(character not in "0123456789abcdef" for character in self.fingerprint):
            raise ValueError("fingerprint must be a SHA-256 hexadecimal digest")
        _nonnegative_fields(self, (
            "executions", "total_fullscan_steps", "max_fullscan_steps", "total_vm_steps",
            "max_vm_steps", "total_sorts", "total_autoindex",
        ))
        if self.executions == 0:
            raise ValueError("query aggregates require at least one execution")
        expected_signals = _signals(self.total_autoindex, self.max_fullscan_steps, self.total_sorts)
        if self.signals != expected_signals:
            raise ValueError("query aggregate signals do not match its metrics")


@dataclass(frozen=True, slots=True)
class DataQuality:
    observed_executions: int
    metric_bearing_executions: int
    null_metric_executions: int
    unmatched_executions: int
    truncated_sql_executions: int
    duplicate_executions: int
    conflicted_executions: int

    def __post_init__(self) -> None:
        _nonnegative_fields(self, (
            "observed_executions", "metric_bearing_executions", "null_metric_executions",
            "unmatched_executions", "truncated_sql_executions", "duplicate_executions",
            "conflicted_executions",
        ))
        if self.metric_bearing_executions + self.null_metric_executions != self.observed_executions:
            raise ValueError("observed executions must have either complete or null metrics")


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    aggregates: tuple[QueryAggregate, ...]
    data_quality: DataQuality
    instrumentation_status: str
    instrumentation_failed: bool


@dataclass(slots=True)
class _AggregateBuilder:
    scope: QueryScope
    fingerprint: str
    normalized_sql: str
    executions: int = 0
    total_fullscan_steps: int = 0
    max_fullscan_steps: int = 0
    total_vm_steps: int = 0
    max_vm_steps: int = 0
    total_sorts: int = 0
    total_autoindex: int = 0

    def add(self, *, fullscan_steps: int, vm_steps: int, sorts: int, autoindex: int) -> None:
        values = (fullscan_steps, vm_steps, sorts, autoindex)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("aggregate builders require complete non-negative metrics")
        self.executions += 1
        self.total_fullscan_steps += fullscan_steps
        self.max_fullscan_steps = max(self.max_fullscan_steps, fullscan_steps)
        self.total_vm_steps += vm_steps
        self.max_vm_steps = max(self.max_vm_steps, vm_steps)
        self.total_sorts += sorts
        self.total_autoindex += autoindex

    def freeze(self) -> QueryAggregate:
        return QueryAggregate(
            scope=self.scope,
            fingerprint=self.fingerprint,
            normalized_sql=self.normalized_sql,
            executions=self.executions,
            total_fullscan_steps=self.total_fullscan_steps,
            max_fullscan_steps=self.max_fullscan_steps,
            total_vm_steps=self.total_vm_steps,
            max_vm_steps=self.max_vm_steps,
            total_sorts=self.total_sorts,
            total_autoindex=self.total_autoindex,
            signals=_signals(self.total_autoindex, self.max_fullscan_steps, self.total_sorts),
        )


def analyze_run(run: RunResult) -> AnalysisResult:
    """Derive deterministic, scoped aggregates from one completed raw run."""
    outcome = StatementTracker().track(run.events)
    builders: dict[tuple[int, str, str, str], _AggregateBuilder] = {}
    normalized_cache: dict[str, tuple[str, str]] = {}

    for execution in outcome.executions:
        normalized, fingerprint = normalized_cache.setdefault(
            execution.sql,
            _normalized_fingerprint(execution.sql),
        )
        scope = QueryScope(execution.pid, execution.module, execution.database)
        key = (scope.pid, scope.module, scope.database, fingerprint)
        builder = builders.get(key)
        if builder is None:
            builder = _AggregateBuilder(scope=scope, fingerprint=fingerprint, normalized_sql=normalized)
            builders[key] = builder
        builder.add(
            fullscan_steps=execution.fullscan_steps,
            vm_steps=execution.vm_steps,
            sorts=execution.sorts,
            autoindex=execution.autoindex,
        )

    aggregates = tuple(sorted((builder.freeze() for builder in builders.values()), key=_ranking_key))
    quality = _data_quality(outcome.quality)
    return AnalysisResult(
        aggregates=aggregates,
        data_quality=quality,
        instrumentation_status=run.instrumentation_status,
        instrumentation_failed=run.instrumentation_failed,
    )


def _data_quality(quality: TrackingQuality) -> DataQuality:
    return DataQuality(
        observed_executions=quality.observed_executions,
        metric_bearing_executions=quality.metric_bearing_executions,
        null_metric_executions=quality.null_metric_executions,
        unmatched_executions=quality.unmatched_executions,
        truncated_sql_executions=quality.truncated_sql_executions,
        duplicate_executions=quality.duplicate_executions,
        conflicted_executions=quality.conflicted_executions,
    )


def _normalized_fingerprint(sql: str) -> tuple[str, str]:
    normalized = normalize_sql(sql)
    return normalized, sha256(normalized.encode("utf-8")).hexdigest()


def _ranking_key(aggregate: QueryAggregate) -> tuple[int, int, int, int, int, int, int, str]:
    return (
        -int(aggregate.total_autoindex > 0),
        -int(aggregate.max_fullscan_steps > 0),
        -aggregate.max_fullscan_steps,
        -aggregate.max_vm_steps,
        -aggregate.total_vm_steps,
        -aggregate.total_fullscan_steps,
        -aggregate.total_sorts,
        aggregate.fingerprint,
    )


def _signals(total_autoindex: int, max_fullscan_steps: int, total_sorts: int) -> tuple[str, ...]:
    return tuple(
        signal
        for signal, present in (
            ("AUTO_INDEX", total_autoindex > 0),
            ("FULL_SCAN", max_fullscan_steps > 0),
            ("SORT", total_sorts > 0),
        )
        if present
    )


def _nonnegative_fields(value: object, names: tuple[str, ...]) -> None:
    for name in names:
        field_value = getattr(value, name)
        if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
