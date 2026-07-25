from dataclasses import FrozenInstanceError

import pytest

from sqlitewatch.doctor import reduce_events, resolve_doctor_outcome
from sqlitewatch.events import InstrumentationError, ModuleCapability, RunResult, StatementPrepared


SYMBOLS = ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status")
HOOKS = ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step")


def module(*, name="libsqlite3.so.0", path=None, base="0x0", candidate=True, scanned=True, symbols=SYMBOLS, metric=True, hooks=HOOKS, failed=(), reasons=()):
    return ModuleCapability(
        41, name, path or "/usr/lib/" + name, "dynamic", candidate, scanned,
        tuple(sorted(symbols)), tuple(sorted(set(("sqlite3_finalize", "sqlite3_libversion", "sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status")) - set(symbols))),
        metric, tuple(sorted(HOOKS)), tuple(sorted(hooks)), tuple(sorted(failed)), tuple(sorted(reasons)), "3.45.0", base,
    )


def run(*events, failed=False):
    return RunResult(41, 0, None, tuple(events), "FAILED" if failed else "ACTIVE", failed, "backend failed" if failed else None)


def prepared(pid=41, *, name="libsqlite3.so.0", path=None, base="0x0"):
    return StatementPrepared(
        pid, 1, name, "0x1", "0x2", "SELECT 1",
        module_path=path or "/usr/lib/" + name, module_base=base,
    )


@pytest.mark.parametrize("events,status", [
    ((), "NOT_DETECTED"),
    ((module(symbols=(), metric=False, hooks=(), reasons=("no symbols",)),), "DETECTED_UNSUPPORTED"),
    ((module(),), "NO_ACTIVITY"),
    ((module(), prepared()), "ACTIVE"),
    ((module(), InstrumentationError("frida", "detached", fatal=True)), "FAILED"),
])
def test_reducer_covers_the_doctor_state_matrix(events, status):
    result = reduce_events(run(*events))
    assert result.status == status
    assert resolve_doctor_outcome(result).exit_code == (0 if status == "ACTIVE" else 70)


def test_capabilities_cannot_be_composed_across_modules():
    left = module(name="left", hooks=("sqlite3_prepare_v2",), symbols=("sqlite3_prepare_v2", "sqlite3_stmt_status"))
    right = module(name="right", hooks=("sqlite3_finalize", "sqlite3_reset", "sqlite3_step"), symbols=("sqlite3_finalize", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status"))
    assert reduce_events(run(left, right, prepared())).status == "PARTIAL"


@pytest.mark.parametrize("kwargs", [
    {"metric": False},
    {"hooks": ("sqlite3_prepare_v2", "sqlite3_step", "sqlite3_reset")},
    {"failed": ("sqlite3_finalize",), "hooks": ("sqlite3_prepare_v2", "sqlite3_step", "sqlite3_reset")},
])
def test_unusable_metric_or_lifecycle_hook_prevents_active(kwargs):
    assert reduce_events(run(module(**kwargs), prepared())).status == "PARTIAL"


def test_only_target_pid_counts_as_activity_and_records_are_immutable_and_sorted():
    result = reduce_events(run(module(name="z"), module(name="a"), prepared(pid=99)))
    assert result.status == "NO_ACTIVITY"
    assert [item.module for item in result.modules] == ["a", "z"]
    with pytest.raises(FrozenInstanceError):
        result.status = "ACTIVE"  # type: ignore[misc]


def test_activity_is_correlated_by_path_and_base_not_duplicate_module_name():
    complete = module(name="sqlite.so", path="/complete/sqlite.so", base="0x1000")
    incomplete = module(
        name="sqlite.so", path="/plugin/sqlite.so", base="0x2000",
        hooks=("sqlite3_prepare_v2",),
        symbols=("sqlite3_prepare_v2",), metric=False,
    )
    activity = prepared(
        name="sqlite.so", path="/plugin/sqlite.so", base="0x2000"
    )
    result = reduce_events(run(complete, incomplete, activity))
    assert result.status == "PARTIAL"
    assert result.complete_activity_count == 0
    assert result.incomplete_activity_count == 1


def test_two_complete_modules_count_only_their_own_activity():
    left = module(name="sqlite.so", path="/left/sqlite.so", base="0x1000")
    right = module(name="sqlite.so", path="/right/sqlite.so", base="0x2000")
    result = reduce_events(run(
        left,
        right,
        prepared(name="sqlite.so", path="/left/sqlite.so", base="0x1000"),
        StatementPrepared(
            41, 1, "sqlite.so", "0x2", "0x2", "SELECT 2",
            module_path="/right/sqlite.so", module_base="0x2000",
        ),
    ))
    assert result.status == "ACTIVE"
    assert result.complete_activity_count == 2
    assert result.incomplete_activity_count == 0


def test_controller_failure_precedes_candidate_support_and_application_failure_is_preserved():
    result = reduce_events(RunResult(41, 7, None, (module(),), "FAILED", True, "transport: lost"))
    outcome = resolve_doctor_outcome(result)
    assert result.status == "FAILED"
    assert outcome.application_failed is True
    assert outcome.exit_code == 70
