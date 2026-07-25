from dataclasses import FrozenInstanceError

import pytest

from sqlitewatch.doctor import reduce_events, resolve_doctor_outcome
from sqlitewatch.events import InstrumentationError, ModuleCapability, RunResult, StatementPrepared


SYMBOLS = ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status")
HOOKS = ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step")


def module(*, name="libsqlite3.so.0", candidate=True, scanned=True, symbols=SYMBOLS, metric=True, hooks=HOOKS, failed=(), reasons=()):
    return ModuleCapability(
        41, name, "/usr/lib/" + name, "dynamic", candidate, scanned,
        tuple(sorted(symbols)), tuple(sorted(set(("sqlite3_finalize", "sqlite3_libversion", "sqlite3_prepare_v2", "sqlite3_prepare_v3", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status")) - set(symbols))),
        metric, tuple(sorted(HOOKS)), tuple(sorted(hooks)), tuple(sorted(failed)), tuple(sorted(reasons)), "3.45.0",
    )


def run(*events, failed=False):
    return RunResult(41, 0, None, tuple(events), "FAILED" if failed else "ACTIVE", failed, "backend failed" if failed else None)


def prepared(pid=41):
    return StatementPrepared(pid, 1, "libsqlite3.so.0", "0x1", "0x2", "SELECT 1")


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
    assert reduce_events(run(left, right, prepared())).status == "DETECTED_UNSUPPORTED"


@pytest.mark.parametrize("kwargs", [
    {"metric": False},
    {"hooks": ("sqlite3_prepare_v2", "sqlite3_step", "sqlite3_reset")},
    {"failed": ("sqlite3_finalize",), "hooks": ("sqlite3_prepare_v2", "sqlite3_step", "sqlite3_reset")},
])
def test_unusable_metric_or_lifecycle_hook_prevents_active(kwargs):
    assert reduce_events(run(module(**kwargs), prepared())).status == "DETECTED_UNSUPPORTED"


def test_only_target_pid_counts_as_activity_and_records_are_immutable_and_sorted():
    result = reduce_events(run(module(name="z"), module(name="a"), prepared(pid=99)))
    assert result.status == "NO_ACTIVITY"
    assert [item.module for item in result.modules] == ["a", "z"]
    with pytest.raises(FrozenInstanceError):
        result.status = "ACTIVE"  # type: ignore[misc]


def test_controller_failure_precedes_candidate_support_and_application_failure_is_preserved():
    result = reduce_events(RunResult(41, 7, None, (module(),), "FAILED", True, "transport: lost"))
    outcome = resolve_doctor_outcome(result)
    assert result.status == "FAILED"
    assert outcome.application_failed is True
    assert outcome.exit_code == 70
