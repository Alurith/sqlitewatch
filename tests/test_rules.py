from dataclasses import FrozenInstanceError

import pytest

from sqlitewatch.analysis import (
    AnalysisResult,
    DataQuality,
    QueryAggregate,
    QueryScope,
    RuleConfig,
    evaluate_rules,
)
from sqlitewatch.events import RunResult, StatementExecuted, StatementFinalized, StatementPrepared


def aggregate(
    *,
    sql="SELECT value FROM t",
    fullscan_total=0,
    fullscan_max=0,
    vm_total=0,
    vm_max=0,
    autoindex=0,
):
    signals = tuple(
        signal
        for signal, present in (
            ("AUTO_INDEX", autoindex > 0),
            ("FULL_SCAN", fullscan_max > 0),
            ("SORT", False),
        )
        if present
    )
    return QueryAggregate(
        QueryScope(1, "sqlite", "0x1"),
        "0" * 64,
        sql,
        2,
        fullscan_total,
        fullscan_max,
        vm_total,
        vm_max,
        0,
        autoindex,
        signals,
    )


def analysis(*aggregates):
    return AnalysisResult(aggregates, DataQuality(0, 0, 0, 0, 0, 0, 0), "ACTIVE", False)


def test_rule_config_defaults_zero_and_immutability():
    config = RuleConfig(fail_fullscan_steps=0, fail_vm_steps=0, fail_on_autoindex=True)
    assert RuleConfig().enabled is False
    assert config.enabled is True
    with pytest.raises(FrozenInstanceError):
        config.fail_vm_steps = 1  # type: ignore[misc]


@pytest.mark.parametrize("value", [-1, True, False, 1.5, "1", object()])
def test_rule_config_rejects_invalid_thresholds(value):
    with pytest.raises((TypeError, ValueError)):
        RuleConfig(fail_fullscan_steps=value)  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        RuleConfig(fail_vm_steps=value)  # type: ignore[arg-type]


def test_rule_config_rejects_non_boolean_autoindex_flag():
    with pytest.raises(TypeError):
        RuleConfig(fail_on_autoindex=1)  # type: ignore[arg-type]


def test_thresholds_use_strict_maximum_not_total():
    query = aggregate(fullscan_total=100, fullscan_max=5, vm_total=200, vm_max=10)
    equal = evaluate_rules(analysis(query), RuleConfig(fail_fullscan_steps=5, fail_vm_steps=10))
    assert not equal.failed

    fullscan = evaluate_rules(analysis(query), RuleConfig(fail_fullscan_steps=4))
    vm = evaluate_rules(analysis(query), RuleConfig(fail_vm_steps=9))
    assert [(item.rule, item.observed, item.threshold) for item in fullscan.violations] == [
        ("FULLSCAN_STEPS", 5, 4)
    ]
    assert [(item.rule, item.observed, item.threshold) for item in vm.violations] == [
        ("VM_STEPS", 10, 9)
    ]


def test_autoindex_is_opt_in_and_multiple_violations_have_fixed_order():
    query = aggregate(fullscan_total=9, fullscan_max=5, vm_total=18, vm_max=10, autoindex=2)
    assert not evaluate_rules(analysis(query), RuleConfig()).failed

    evaluation = evaluate_rules(
        analysis(query),
        RuleConfig(fail_fullscan_steps=0, fail_vm_steps=0, fail_on_autoindex=True),
    )
    assert [violation.rule for violation in evaluation.violations] == [
        "AUTOINDEX",
        "FULLSCAN_STEPS",
        "VM_STEPS",
    ]
    assert [violation.observed for violation in evaluation.violations] == [2, 5, 10]
    assert [violation.threshold for violation in evaluation.violations] == [None, 0, 0]
    with pytest.raises(FrozenInstanceError):
        evaluation.violations[0].observed = 0  # type: ignore[misc]


def test_violation_order_uses_deterministic_aggregate_order_not_lifecycle_order():
    metrics = dict(fullscan_steps=1, vm_steps=1, sorts=0, autoindex=0)
    slow = (
        StatementPrepared(1, 1, "sqlite", "0x1", "0x1", "SELECT slow"),
        StatementExecuted(1, 1, "sqlite", "0x1", "0x1", 1, 101, "done", **metrics),
        StatementFinalized(1, 1, "sqlite", "0x1", "0x1", 1, 0),
    )
    indexed = (
        StatementPrepared(1, 1, "sqlite", "0x2", "0x1", "SELECT indexed"),
        StatementExecuted(1, 1, "sqlite", "0x2", "0x1", 1, 101, "done", **(metrics | {"autoindex": 1})),
        StatementFinalized(1, 1, "sqlite", "0x2", "0x1", 1, 0),
    )
    from sqlitewatch.analysis import analyze_run

    first = analyze_run(RunResult(1, 0, None, slow + indexed, "ACTIVE"))
    second = analyze_run(RunResult(1, 0, None, indexed + slow, "ACTIVE"))
    config = RuleConfig(fail_fullscan_steps=0, fail_on_autoindex=True)
    assert evaluate_rules(first, config).violations == evaluate_rules(second, config).violations
