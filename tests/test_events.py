import pytest

from sqlitewatch.analysis import QueryAggregate, QueryScope, RuleConfig, RuleEvaluation, RuleViolation
from sqlitewatch.events import (
    RunResult, StatementExecuted, StatementFinalized, StatementPrepared,
    StatementStarted,
)
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.instrumentation.protocol import ProtocolError, event_to_payload, payload_to_event


METRICS = dict(fullscan_steps=1, vm_steps=2, sorts=0, autoindex=0)


def test_statement_round_trip_unicode_and_pointer_strings():
    event = StatementPrepared(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", sql="SELECT café FROM users WHERE id = ?",
    )
    assert payload_to_event(event_to_payload(event)) == event


def test_truncated_sql_metadata_round_trip():
    event = StatementPrepared(
        pid=1, tid=1, module="x", statement="0x1", database="0x2", sql="SELECT",
        sql_truncated=True, captured_bytes=6,
    )
    assert payload_to_event(event_to_payload(event)).sql_truncated


@pytest.mark.parametrize("metrics", [METRICS, dict(fullscan_steps=0, vm_steps=0, sorts=0, autoindex=0), dict(fullscan_steps=None, vm_steps=None, sorts=None, autoindex=None)])
def test_execution_metrics_round_trip(metrics):
    event = StatementExecuted(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", execution_number=2, sqlite_rc=101, boundary="done", **metrics,
    )
    payload = event_to_payload(event)
    assert payload["protocol_version"] == 2
    assert payload_to_event(payload) == event


def test_started_round_trip_and_run_result_collection():
    event = StatementStarted(
        123, 456, "libsqlite3.so.0", "0x123456", "0x987654", 2,
        "/usr/lib/libsqlite3.so.0", "0x1000",
    )
    assert payload_to_event(event_to_payload(event)) == event
    assert RunResult(123, 0, None, (event,)).started_executions == (event,)


def test_finalized_round_trip():
    event = StatementFinalized(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", executions=2, sqlite_rc=0,
    )
    assert payload_to_event(event_to_payload(event)) == event


def test_run_result_exposes_lifecycle_collections_without_changing_prepared_alias():
    prepared = StatementPrepared(1, 1, "x", "0x1", "0x2", "SELECT 1")
    executed = StatementExecuted(1, 1, "x", "0x1", "0x2", 1, 101, "done", **METRICS)
    finalized = StatementFinalized(1, 1, "x", "0x1", "0x2", 1, 0)
    result = RunResult(1, 0, None, events=(prepared, executed, finalized))
    assert result.statements == (prepared,)
    assert result.executions == (executed,)
    assert result.finalized_statements == (finalized,)


def test_outcome_resolves_exit_code_precedence_and_preserves_all_failures():
    no_rules = RuleEvaluation(RuleConfig(), ())
    query = QueryAggregate(
        QueryScope(1, "sqlite", "0x1"), "0" * 64, "SELECT 1", 1,
        1, 1, 0, 0, 0, 0, ("FULL_SCAN",),
    )
    rule_violation = RuleEvaluation(
        RuleConfig(fail_fullscan_steps=0),
        (RuleViolation("FULLSCAN_STEPS", query, 1, 0),),
    )

    success = resolve_outcome(RunResult(1, 0, None, instrumentation_status="ACTIVE"), no_rules)
    performance = resolve_outcome(RunResult(1, 0, None, instrumentation_status="ACTIVE"), rule_violation)
    target = resolve_outcome(RunResult(1, 7, None, instrumentation_status="ACTIVE"), rule_violation)
    signaled = resolve_outcome(RunResult(1, None, 9, instrumentation_status="ACTIVE"), rule_violation)
    fatal = resolve_outcome(RunResult(1, 7, None, instrumentation_status="ACTIVE", instrumentation_failed=True), rule_violation)

    assert (success.application_failed, success.instrumentation_failed, success.performance_rule_failed, success.exit_code) == (False, False, False, 0)
    assert (performance.application_failed, performance.instrumentation_failed, performance.performance_rule_failed, performance.exit_code) == (False, False, True, 1)
    assert (target.application_failed, target.instrumentation_failed, target.performance_rule_failed, target.exit_code) == (True, False, True, 7)
    assert (signaled.application_failed, signaled.instrumentation_failed, signaled.performance_rule_failed, signaled.exit_code) == (True, False, True, 137)
    assert (fatal.application_failed, fatal.instrumentation_failed, fatal.performance_rule_failed, fatal.exit_code) == (True, True, True, 70)


@pytest.mark.parametrize("status", ["NOT_DETECTED", "DETECTED_UNSUPPORTED"])
def test_outcome_treats_inactive_instrumentation_as_fatal_only_when_rules_are_enabled(status):
    without_rules = resolve_outcome(RunResult(1, 0, None, instrumentation_status=status), RuleEvaluation(RuleConfig(), ()))
    with_rules = resolve_outcome(
        RunResult(1, 0, None, instrumentation_status=status),
        RuleEvaluation(RuleConfig(fail_vm_steps=0), ()),
    )
    assert (without_rules.instrumentation_failed, without_rules.exit_code) == (False, 0)
    assert (with_rules.instrumentation_failed, with_rules.exit_code) == (True, 70)


def test_outcome_treats_failed_status_as_fatal_even_without_rules():
    outcome = resolve_outcome(RunResult(1, 0, None, instrumentation_status="FAILED"), RuleEvaluation(RuleConfig(), ()))
    assert (outcome.instrumentation_failed, outcome.exit_code) == (True, 70)


def test_invalid_payloads_are_rejected():
    base = {
        "type": "statement_prepared", "protocol_version": 2, "pid": 1, "tid": 1,
        "module": "x", "module_path": "/tmp/x", "module_base": "0x10",
        "statement": "1234", "database": "0x2", "sql": "SELECT 1",
        "sql_truncated": False, "captured_bytes": 8, "sql_capture_failed": False,
    }
    with pytest.raises(ProtocolError, match="statement"):
        payload_to_event(base)
    with pytest.raises(ProtocolError):
        payload_to_event({"type": "unknown", "protocol_version": 2})
