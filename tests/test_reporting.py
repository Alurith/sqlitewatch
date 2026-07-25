import json

import pytest

from sqlitewatch.analysis import RuleConfig, analyze_run, evaluate_rules
from sqlitewatch.events import RunResult, StatementExecuted, StatementFinalized, StatementPrepared
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.reporting import (
    ReportData,
    analysis_to_dict,
    render_json,
    render_run_json,
    render_run_terminal,
    render_terminal,
    run_report_to_dict,
)


def _analysis(*, null=False):
    metrics = dict(fullscan_steps=None, vm_steps=None, sorts=None, autoindex=None) if null else dict(fullscan_steps=2, vm_steps=9, sorts=1, autoindex=0)
    events = (
        StatementPrepared(7, 1, "sqlite", "0x1", "0x2", "SELECT  café FROM t"),
        StatementExecuted(7, 1, "sqlite", "0x1", "0x2", 1, 101, "done", **metrics),
        StatementFinalized(7, 1, "sqlite", "0x1", "0x2", 1, 0),
    )
    return analyze_run(
        RunResult(7, 0, None, events, "ACTIVE", sql_capture_limit=4096)
    )


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


def _report(*, config=RuleConfig(), target_exit=0, status="ACTIVE", instrumentation_failed=False):
    analysis = _analysis()
    run = RunResult(7, target_exit, None, instrumentation_status=status, instrumentation_failed=instrumentation_failed)
    rules = evaluate_rules(analysis, config)
    return ReportData(analysis, rules, resolve_outcome(run, rules))


def test_complete_reports_include_matching_outcome_and_rule_data():
    report = _report(config=RuleConfig(fail_fullscan_steps=1, fail_vm_steps=8))
    payload = run_report_to_dict(report)
    assert payload["schema_version"] == 2
    assert payload["rules"]["enabled"] is True
    assert payload["instrumentation"]["sql_capture_limit"] == 4096
    assert [item["rule"] for item in payload["rules"]["violations"]] == ["FULLSCAN_STEPS", "VM_STEPS"]
    assert [item["observed"] for item in payload["rules"]["violations"]] == [2, 9]
    assert payload["outcome"] == {
        "application_failure": False,
        "instrumentation_failure": False,
        "performance_rule_failure": True,
        "evaluation_incomplete": False,
        "exit_code": 1,
    }
    rendered = render_run_json(report)
    assert rendered.endswith("\n")
    assert json.loads(rendered) == payload
    assert render_run_json(report) == rendered
    assert "café" in rendered
    terminal = render_run_terminal(report)
    assert "Application failure: False" in terminal
    assert "Performance rule failure: True" in terminal
    assert "[1] FULLSCAN_STEPS" in terminal
    assert "Observed: 2" in terminal
    assert "Threshold: 1" in terminal


def test_complete_report_preserves_simultaneous_application_and_instrumentation_failures():
    application = _report(config=RuleConfig(fail_fullscan_steps=1), target_exit=7)
    instrumentation = _report(config=RuleConfig(fail_fullscan_steps=1), instrumentation_failed=True)
    application_payload = run_report_to_dict(application)
    instrumentation_payload = run_report_to_dict(instrumentation)
    assert application_payload["outcome"]["application_failure"] is True
    assert application_payload["outcome"]["performance_rule_failure"] is True
    assert application_payload["outcome"]["exit_code"] == 7
    assert instrumentation_payload["outcome"]["instrumentation_failure"] is True
    assert instrumentation_payload["outcome"]["exit_code"] == 70


def test_report_data_rejects_inconsistent_components():
    analysis = _analysis()
    rules = evaluate_rules(analysis, RuleConfig())
    outcome = resolve_outcome(RunResult(7, 0, None, instrumentation_status="NOT_DETECTED"), rules)
    with pytest.raises(ValueError):
        ReportData(analysis, rules, outcome)


def test_json_schema_is_stable_utf8_and_deterministic():
    analysis = _analysis()
    payload = analysis_to_dict(analysis)
    assert payload["summary"] == {
        "observed_executions": 1, "metric_bearing_executions": 1, "unique_scoped_queries": 1,
    }
    query = payload["queries"][0]
    assert query["scope"] == {
        "pid": 7, "module": "sqlite", "module_path": "",
        "module_base": "0x0", "database": "0x2",
    }
    assert query["fullscan_steps"] == {"total": 2, "max": 2}
    assert query["signals"] == ["FULL_SCAN", "SORT"]
    rendered = render_json(analysis)
    assert rendered.endswith("\n")
    assert json.loads(rendered) == payload
    assert render_json(analysis) == rendered
    assert "café" in rendered
