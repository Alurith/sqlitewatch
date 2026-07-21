import json

from sqlitewatch.analysis import analyze_run
from sqlitewatch.events import RunResult, StatementExecuted, StatementFinalized, StatementPrepared
from sqlitewatch.reporting import analysis_to_dict, render_json, render_terminal


def _analysis(*, null=False):
    metrics = dict(fullscan_steps=None, vm_steps=None, sorts=None, autoindex=None) if null else dict(fullscan_steps=2, vm_steps=9, sorts=1, autoindex=0)
    events = (
        StatementPrepared(7, 1, "sqlite", "0x1", "0x2", "SELECT  café FROM t"),
        StatementExecuted(7, 1, "sqlite", "0x1", "0x2", 1, 101, "done", **metrics),
        StatementFinalized(7, 1, "sqlite", "0x1", "0x2", 1, 0),
    )
    return analyze_run(RunResult(7, 0, None, events, "ACTIVE"))


def test_terminal_report_contains_summary_scope_metrics_and_signals():
    text = render_terminal(_analysis())
    assert "Observed executions: 1" in text
    assert "pid=7 module=sqlite database=0x2" in text
    assert "SELECT café FROM t" in text
    assert "Fullscan steps: total=2 max=2" in text
    assert "Signals: FULL_SCAN, SORT" in text


def test_terminal_report_does_not_present_missing_metrics_as_zero():
    text = render_terminal(_analysis(null=True))
    assert "Null-metric executions: 1" in text
    assert "No metric-bearing executions were observed" in text
    assert "Fullscan steps:" not in text


def test_json_schema_is_stable_utf8_and_deterministic():
    analysis = _analysis()
    payload = analysis_to_dict(analysis)
    assert payload["summary"] == {
        "observed_executions": 1, "metric_bearing_executions": 1, "unique_scoped_queries": 1,
    }
    query = payload["queries"][0]
    assert query["scope"] == {"pid": 7, "module": "sqlite", "database": "0x2"}
    assert query["fullscan_steps"] == {"total": 2, "max": 2}
    assert query["signals"] == ["FULL_SCAN", "SORT"]
    rendered = render_json(analysis)
    assert rendered.endswith("\n")
    assert json.loads(rendered) == payload
    assert render_json(analysis) == rendered
    assert "café" in rendered
