from dataclasses import FrozenInstanceError

import pytest

from sqlitewatch.analysis import AnalysisResult, DataQuality, QueryAggregate, QueryScope, analyze_run
from sqlitewatch.events import RunResult, StatementExecuted, StatementFinalized, StatementPrepared


METRICS = dict(fullscan_steps=3, vm_steps=10, sorts=0, autoindex=0)


def prepared(*, pid=1, module="sqlite", statement="0x1", database="0x2", sql="SELECT value FROM t"):
    return StatementPrepared(pid, 1, module, statement, database, sql)


def executed(*, pid=1, module="sqlite", statement="0x1", database="0x2", number=1, boundary="done", **metrics):
    return StatementExecuted(pid, 1, module, statement, database, number, 101, boundary, **(METRICS | metrics))


def finalized(*, pid=1, module="sqlite", statement="0x1", database="0x2"):
    return StatementFinalized(pid, 1, module, statement, database, 1, 0)


def result(*events):
    return RunResult(1, 0, None, tuple(events), "ACTIVE")


def test_empty_result_and_domain_records_are_immutable_and_comparable():
    analysis = analyze_run(result())
    assert analysis == AnalysisResult((), DataQuality(0, 0, 0, 0, 0, 0, 0), "ACTIVE", False)
    with pytest.raises(FrozenInstanceError):
        analysis.data_quality.observed_executions = 1  # type: ignore[misc]
    with pytest.raises(ValueError):
        DataQuality(1, 0, 0, 0, 0, 0, 0)
    with pytest.raises(ValueError):
        QueryScope(0, "m", "d")


def test_scoped_aggregation_tracks_totals_maxima_and_signals():
    analysis = analyze_run(result(
        prepared(sql=" SELECT value  FROM t "),
        executed(number=1, fullscan_steps=3, vm_steps=10, sorts=1, autoindex=0),
        executed(number=2, fullscan_steps=5, vm_steps=12, sorts=0, autoindex=2),
        finalized(),
    ))
    aggregate = analysis.aggregates[0]
    assert aggregate.normalized_sql == "SELECT value FROM t"
    assert aggregate.executions == 2
    assert (aggregate.total_fullscan_steps, aggregate.max_fullscan_steps) == (8, 5)
    assert (aggregate.total_vm_steps, aggregate.max_vm_steps) == (22, 12)
    assert (aggregate.total_sorts, aggregate.total_autoindex) == (1, 2)
    assert aggregate.signals == ("AUTO_INDEX", "FULL_SCAN", "SORT")


def test_equivalent_sql_merges_but_scope_differences_do_not():
    events = (
        prepared(pid=1, module="a", database="0x2", statement="0x1", sql="SELECT  value FROM t"),
        executed(pid=1, module="a", database="0x2", statement="0x1"), finalized(pid=1, module="a", database="0x2", statement="0x1"),
        prepared(pid=1, module="a", database="0x3", statement="0x2", sql=" SELECT value\nFROM t "),
        executed(pid=1, module="a", database="0x3", statement="0x2"), finalized(pid=1, module="a", database="0x3", statement="0x2"),
        prepared(pid=2, module="b", database="0x2", statement="0x1", sql="SELECT value FROM t"),
        executed(pid=2, module="b", database="0x2", statement="0x1"), finalized(pid=2, module="b", database="0x2", statement="0x1"),
    )
    analysis = analyze_run(result(*events))
    assert len(analysis.aggregates) == 3
    assert {aggregate.scope for aggregate in analysis.aggregates} == {
        QueryScope(1, "a", "0x2"), QueryScope(1, "a", "0x3"), QueryScope(2, "b", "0x2"),
    }


def test_null_truncated_unmatched_duplicates_and_conflicts_are_quality_only():
    nulls = dict(fullscan_steps=None, vm_steps=None, sorts=None, autoindex=None)
    events = (
        prepared(statement="0x1"),
        executed(statement="0x1", number=1),
        executed(statement="0x1", number=1),
        executed(statement="0x1", number=1, vm_steps=11),
        finalized(statement="0x1"),
        prepared(statement="0x2", sql="SELECT incomplete",),
        # Replace this prepared event with truncated metadata while retaining scope.
        StatementPrepared(1, 1, "sqlite", "0x3", "0x2", "SELECT cut", sql_truncated=True),
        executed(statement="0x3", number=1, **nulls),
        executed(statement="0x4", number=1),
    )
    analysis = analyze_run(result(*events))
    quality = analysis.data_quality
    assert not analysis.aggregates
    assert (quality.observed_executions, quality.metric_bearing_executions, quality.null_metric_executions) == (5, 4, 1)
    assert (quality.truncated_sql_executions, quality.unmatched_executions) == (1, 1)
    assert (quality.duplicate_executions, quality.conflicted_executions) == (1, 1)


def test_finalization_and_pointer_reuse_keep_lifetimes_separate():
    analysis = analyze_run(result(
        prepared(sql="SELECT first"), executed(), finalized(),
        prepared(sql="SELECT second"), executed(number=1), finalized(),
        executed(number=2),
    ))
    assert {aggregate.normalized_sql for aggregate in analysis.aggregates} == {"SELECT first", "SELECT second"}
    assert analysis.data_quality.unmatched_executions == 1


@pytest.mark.parametrize("boundary", ["done", "error", "reset", "finalize"])
def test_all_execution_boundaries_aggregate_when_metrics_are_complete(boundary):
    analysis = analyze_run(result(prepared(), executed(boundary=boundary), finalized()))
    assert analysis.aggregates[0].executions == 1


def test_ranking_is_independent_of_lifecycle_input_order():
    first = (prepared(statement="0x1", sql="SELECT slow"), executed(statement="0x1", vm_steps=100), finalized(statement="0x1"))
    second = (prepared(statement="0x2", sql="SELECT indexed"), executed(statement="0x2", autoindex=1), finalized(statement="0x2"))
    left = analyze_run(result(*first, *second))
    right = analyze_run(result(*second, *first))
    assert left.aggregates == right.aggregates
    assert left.aggregates[0].normalized_sql == "SELECT indexed"


def test_aggregate_rejects_inconsistent_metric_data():
    with pytest.raises(ValueError):
        QueryAggregate(QueryScope(1, "m", "d"), "0" * 64, "SELECT 1", 1, 0, 0, 0, 0, 0, 0, ("FULL_SCAN",))
