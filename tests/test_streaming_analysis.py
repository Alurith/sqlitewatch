import tracemalloc

from sqlitewatch.analysis import AnalysisReducer, analyze_run
from sqlitewatch.analysis import aggregation
from sqlitewatch.events import (
    RunResult,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)


METRICS = dict(fullscan_steps=0, vm_steps=1, sorts=0, autoindex=0)


def _execution(number):
    return StatementExecuted(
        1, 1, "sqlite", "0x1", "0x2", number, 101, "done", **METRICS
    )


def test_streaming_and_materialized_analysis_produce_identical_results():
    events = (
        StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1"),
        _execution(1),
        _execution(2),
        StatementFinalized(1, 1, "sqlite", "0x1", "0x2", 2, 0),
    )
    materialized_run = RunResult(
        1, 0, None, events, "ACTIVE", sql_capture_limit=65536
    )
    materialized = analyze_run(materialized_run)

    reducer = AnalysisReducer()
    for event in events:
        reducer.consume(event)
    streamed = reducer.finish(
        RunResult(
            1, 0, None, (), "ACTIVE", sql_capture_limit=65536,
            events_retained=False,
        )
    )
    assert streamed == materialized


def test_normalization_cache_computes_each_sql_once(monkeypatch):
    calls = 0
    original = aggregation._normalized_fingerprint

    def counted(sql):
        nonlocal calls
        calls += 1
        return original(sql)

    monkeypatch.setattr(aggregation, "_normalized_fingerprint", counted)
    reducer = AnalysisReducer()
    reducer.consume(StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1"))
    for number in range(1, 10_001):
        reducer.consume(_execution(number))
    reducer.consume(StatementFinalized(1, 1, "sqlite", "0x1", "0x2", 10_000, 0))
    analysis = reducer.finish(RunResult(1, 0, None, (), "ACTIVE"))
    assert analysis.aggregates[0].executions == 10_000
    assert calls == 1


def test_normalization_cache_is_bounded_when_raw_variants_share_one_aggregate():
    reducer = AnalysisReducer()
    for number in range(5000):
        statement = f"0x{number + 1:x}"
        whitespace = "".join(
            "\t" if number & (1 << bit) else " " for bit in range(13)
        )
        reducer.consume(
            StatementPrepared(1, 1, "sqlite", statement, "0x2", f"SELECT{whitespace}1")
        )
        reducer.consume(
            StatementExecuted(
                1, 1, "sqlite", statement, "0x2", 1, 101, "done", **METRICS
            )
        )
        reducer.consume(
            StatementFinalized(1, 1, "sqlite", statement, "0x2", 1, 0)
        )
    analysis = reducer.finish(RunResult(1, 0, None, (), "ACTIVE"))
    assert len(analysis.aggregates) == 1
    assert analysis.aggregates[0].executions == 5000
    assert len(reducer._normalized_cache) == aggregation._NORMALIZATION_CACHE_LIMIT


def test_streaming_reducer_keeps_200k_execution_memory_bounded():
    reducer = AnalysisReducer()
    reducer.consume(StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1"))
    tracemalloc.start()
    for number in range(1, 200_001):
        reducer.consume(_execution(number))
    reducer.consume(StatementFinalized(1, 1, "sqlite", "0x1", "0x2", 200_000, 0))
    analysis = reducer.finish(RunResult(1, 0, None, (), "ACTIVE"))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert analysis.aggregates[0].executions == 200_000
    assert peak < 8 * 1024 * 1024
