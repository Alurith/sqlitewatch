"""Scoped, incrementally reducible query aggregation."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256

from ..events import Event, InstrumentationError, RunResult
from .normalization import normalize_sql
from .statement_tracker import StatementTracker, TrackedExecution, TrackingQuality

_NORMALIZATION_CACHE_LIMIT = 4096


@dataclass(frozen=True, slots=True)
class QueryScope:
    pid: int
    module: str
    database: str
    module_path: str = ""
    module_base: str = "0x0"

    def __post_init__(self) -> None:
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 0:
            raise ValueError("scope pid must be a positive integer")
        if any(
            not isinstance(value, str)
            for value in (self.module, self.database, self.module_path, self.module_base)
        ):
            raise TypeError("scope module identity and database must be strings")


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
        if len(self.fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.fingerprint
        ):
            raise ValueError("fingerprint must be a SHA-256 hexadecimal digest")
        _nonnegative_fields(self, (
            "executions", "total_fullscan_steps", "max_fullscan_steps", "total_vm_steps",
            "max_vm_steps", "total_sorts", "total_autoindex",
        ))
        if self.executions == 0:
            raise ValueError("query aggregates require at least one execution")
        expected_signals = _signals(
            self.total_autoindex, self.max_fullscan_steps, self.total_sorts
        )
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
    sql_capture_failed_executions: int = 0
    unfinished_executions: int = 0
    instrumentation_data_loss_events: int = 0

    def __post_init__(self) -> None:
        _nonnegative_fields(self, (
            "observed_executions", "metric_bearing_executions", "null_metric_executions",
            "unmatched_executions", "truncated_sql_executions", "duplicate_executions",
            "conflicted_executions", "sql_capture_failed_executions",
            "unfinished_executions", "instrumentation_data_loss_events",
        ))
        if self.metric_bearing_executions + self.null_metric_executions != self.observed_executions:
            raise ValueError("observed executions must have either complete or null metrics")

    @property
    def incomplete_reasons(self) -> tuple[str, ...]:
        """Stable reason codes for observations excluded due to data loss."""
        return tuple(
            reason
            for reason, count in (
                ("NULL_METRICS", self.null_metric_executions),
                ("UNMATCHED_EXECUTIONS", self.unmatched_executions),
                ("TRUNCATED_SQL", self.truncated_sql_executions),
                ("SQL_CAPTURE_FAILED", self.sql_capture_failed_executions),
                ("CONFLICTED_EXECUTIONS", self.conflicted_executions),
                ("UNFINISHED_EXECUTIONS", self.unfinished_executions),
                ("INSTRUMENTATION_DATA_LOSS", self.instrumentation_data_loss_events),
            )
            if count
        )


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    aggregates: tuple[QueryAggregate, ...]
    data_quality: DataQuality
    instrumentation_status: str
    instrumentation_failed: bool
    evaluation_complete: bool = True
    incomplete_reasons: tuple[str, ...] = ()
    sql_capture_limit: int | None = None

    def __post_init__(self) -> None:
        expected = self.data_quality.incomplete_reasons
        if self.incomplete_reasons != expected:
            raise ValueError("analysis incomplete reasons must match data quality")
        if self.evaluation_complete != (not expected):
            raise ValueError("analysis completeness must match data quality")


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
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
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
            signals=_signals(
                self.total_autoindex, self.max_fullscan_steps, self.total_sorts
            ),
        )


class AnalysisReducer:
    """Consume lifecycle events without retaining the complete raw stream."""

    def __init__(self) -> None:
        self._builders: dict[tuple[int, str, str, str, str, str], _AggregateBuilder] = {}
        self._normalized_cache: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._instrumentation_data_loss_events = 0
        self._tracker = StatementTracker(on_execution=self._consume_execution)
        self._finished = False

    def consume(self, event: Event) -> None:
        if self._finished:
            raise RuntimeError("cannot consume events after analysis finish")
        if isinstance(event, InstrumentationError) and event.data_loss:
            self._instrumentation_data_loss_events += 1
        self._tracker.consume(event)

    def finish(self, run: RunResult) -> AnalysisResult:
        if self._finished:
            raise RuntimeError("analysis reducer is already finished")
        tracking = self._tracker.finish()
        self._finished = True
        quality = _data_quality(
            tracking.quality, self._instrumentation_data_loss_events
        )
        reasons = quality.incomplete_reasons
        return AnalysisResult(
            aggregates=tuple(sorted(
                (builder.freeze() for builder in self._builders.values()),
                key=_ranking_key,
            )),
            data_quality=quality,
            instrumentation_status=run.instrumentation_status,
            instrumentation_failed=run.instrumentation_failed,
            evaluation_complete=not reasons,
            incomplete_reasons=reasons,
            sql_capture_limit=run.sql_capture_limit,
        )

    def _consume_execution(self, execution: TrackedExecution) -> None:
        cached = self._normalized_cache.pop(execution.sql, None)
        if cached is None:
            cached = _normalized_fingerprint(execution.sql)
        self._normalized_cache[execution.sql] = cached
        if len(self._normalized_cache) > _NORMALIZATION_CACHE_LIMIT:
            self._normalized_cache.popitem(last=False)
        normalized, fingerprint = cached
        scope = QueryScope(
            execution.pid,
            execution.module,
            execution.database,
            execution.module_path,
            execution.module_base,
        )
        key = (
            scope.pid, scope.module, scope.module_path, scope.module_base,
            scope.database, fingerprint,
        )
        builder = self._builders.get(key)
        if builder is None:
            builder = _AggregateBuilder(
                scope=scope, fingerprint=fingerprint, normalized_sql=normalized
            )
            self._builders[key] = builder
        builder.add(
            fullscan_steps=execution.fullscan_steps,
            vm_steps=execution.vm_steps,
            sorts=execution.sorts,
            autoindex=execution.autoindex,
        )


def analyze_run(run: RunResult) -> AnalysisResult:
    """Derive deterministic, scoped aggregates from one materialized run."""
    reducer = AnalysisReducer()
    for event in run.events:
        reducer.consume(event)
    return reducer.finish(run)


def _data_quality(
    quality: TrackingQuality, instrumentation_data_loss_events: int = 0
) -> DataQuality:
    return DataQuality(
        observed_executions=quality.observed_executions,
        metric_bearing_executions=quality.metric_bearing_executions,
        null_metric_executions=quality.null_metric_executions,
        unmatched_executions=quality.unmatched_executions,
        truncated_sql_executions=quality.truncated_sql_executions,
        duplicate_executions=quality.duplicate_executions,
        conflicted_executions=quality.conflicted_executions,
        sql_capture_failed_executions=quality.sql_capture_failed_executions,
        unfinished_executions=quality.unfinished_executions,
        instrumentation_data_loss_events=instrumentation_data_loss_events,
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
