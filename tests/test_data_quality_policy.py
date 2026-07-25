import json

import pytest

from sqlitewatch.analysis import RuleConfig, analyze_run, evaluate_rules
from sqlitewatch.events import (
    InstrumentationError, RunResult, StatementExecuted, StatementPrepared,
    StatementStarted,
)
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.reporting import ReportData, render_run_json, render_run_terminal


METRICS = dict(fullscan_steps=1, vm_steps=9, sorts=0, autoindex=0)
NULL_METRICS = dict(fullscan_steps=None, vm_steps=None, sorts=None, autoindex=None)


def _prepared(**changes):
    values = {
        "pid": 1,
        "tid": 1,
        "module": "sqlite",
        "statement": "0x1",
        "database": "0x2",
        "sql": "SELECT 1",
    }
    values.update(changes)
    return StatementPrepared(**values)


def _executed(**changes):
    values = {
        "pid": 1,
        "tid": 1,
        "module": "sqlite",
        "statement": "0x1",
        "database": "0x2",
        "execution_number": 1,
        "sqlite_rc": 101,
        "boundary": "done",
        **METRICS,
    }
    values.update(changes)
    return StatementExecuted(**values)


def _events(category):
    if category == "NULL_METRICS":
        return (_prepared(), _executed(**NULL_METRICS))
    if category == "TRUNCATED_SQL":
        return (_prepared(sql_truncated=True), _executed())
    if category == "SQL_CAPTURE_FAILED":
        return (
            _prepared(sql="", captured_bytes=0, sql_capture_failed=True),
            _executed(),
        )
    if category == "UNMATCHED_EXECUTIONS":
        return (_executed(),)
    if category == "CONFLICTED_EXECUTIONS":
        return (_prepared(), _executed(), _executed(vm_steps=10))
    if category == "UNFINISHED_EXECUTIONS":
        return (
            _prepared(),
            StatementStarted(1, 1, "sqlite", "0x1", "0x2", 1),
        )
    if category == "INSTRUMENTATION_DATA_LOSS":
        return (
            _prepared(),
            _executed(),
            InstrumentationError(
                "data_quality", "concurrent statement ownership conflict",
                fatal=False, data_loss=True,
            ),
        )
    raise AssertionError(category)


@pytest.mark.parametrize(
    "category",
    [
        "NULL_METRICS",
        "TRUNCATED_SQL",
        "SQL_CAPTURE_FAILED",
        "UNMATCHED_EXECUTIONS",
        "CONFLICTED_EXECUTIONS",
        "UNFINISHED_EXECUTIONS",
        "INSTRUMENTATION_DATA_LOSS",
    ],
)
def test_incomplete_data_is_warning_without_rules_and_failure_with_rules(category):
    run = RunResult(1, 0, None, _events(category), "ACTIVE")
    analysis = analyze_run(run)
    assert not analysis.evaluation_complete
    assert category in analysis.incomplete_reasons

    informational = evaluate_rules(analysis, RuleConfig())
    informational_outcome = resolve_outcome(run, informational)
    assert informational.inconclusive and not informational.passed
    assert not informational_outcome.instrumentation_failed
    assert informational_outcome.exit_code == 0
    assert "Evaluation warning" in render_run_terminal(
        ReportData(analysis, informational, informational_outcome)
    )

    enforced = evaluate_rules(analysis, RuleConfig(fail_vm_steps=0))
    enforced_outcome = resolve_outcome(run, enforced)
    assert not enforced.passed
    assert enforced_outcome.instrumentation_failed
    assert enforced_outcome.exit_code == 70
    if category == "INSTRUMENTATION_DATA_LOSS":
        assert enforced_outcome.performance_rule_failed
        assert enforced.violations
    payload = json.loads(
        render_run_json(ReportData(analysis, enforced, enforced_outcome))
    )
    assert payload["rules"]["passed"] is False
    assert category in payload["rules"]["incomplete_reasons"]
    assert payload["outcome"]["evaluation_incomplete"] is True


def test_unrelated_nonfatal_agent_diagnostic_is_not_declared_data_loss():
    run = RunResult(
        1, 0, None,
        (
            _prepared(), _executed(),
            InstrumentationError("hook", "unused candidate hook failed", fatal=False),
        ),
        "ACTIVE",
    )
    analysis = analyze_run(run)
    assert analysis.evaluation_complete
    rules = evaluate_rules(analysis, RuleConfig(fail_vm_steps=100))
    assert resolve_outcome(run, rules).exit_code == 0


def test_same_execution_number_with_different_boundaries_is_conflicting():
    run = RunResult(
        1, 0, None,
        (_prepared(), _executed(boundary="done"), _executed(boundary="reset")),
        "ACTIVE",
    )
    analysis = analyze_run(run)
    assert analysis.data_quality.conflicted_executions == 1
    assert not analysis.evaluation_complete
    assert not analysis.aggregates


def test_identical_duplicate_is_diagnostic_but_evaluation_remains_complete():
    execution = _executed()
    run = RunResult(1, 0, None, (_prepared(), execution, execution), "ACTIVE")
    analysis = analyze_run(run)
    assert analysis.evaluation_complete
    assert analysis.data_quality.duplicate_executions == 1
    assert analysis.aggregates[0].executions == 1
    rules = evaluate_rules(analysis, RuleConfig(fail_vm_steps=100))
    assert rules.passed
    assert resolve_outcome(run, rules).exit_code == 0
