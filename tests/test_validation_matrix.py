from tests.integration.matrix_support import REQUIRED_SYMBOLS, build_matrix_record
from sqlitewatch.events import (
    InstrumentationError,
    InstrumentationStatus,
    RunResult,
    SqliteDetected,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)

COMMAND = ("fixture",)
SQL = "SELECT name FROM users WHERE id = ?"


def active_result(*events, target_exit_code=0, instrumentation_failed=False):
    return RunResult(123, target_exit_code, None, tuple(events), "ACTIVE", instrumentation_failed)


def detections(*symbols):
    return tuple(
        SqliteDetected(123, "libsqlite3.so.0", "/usr/lib/libsqlite3.so.0", symbol, f"0x{1000 + i:x}", "dynamic")
        for i, symbol in enumerate(symbols)
    )


def status(value="ACTIVE", hooks=5):
    return InstrumentationStatus(pid=123, status=value, hooks=hooks)


def prepared(sql=SQL):
    return StatementPrepared(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", sql)


def lifecycle_events():
    return (
        StatementExecuted(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 1, 101, "done"),
        StatementFinalized(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 1, 0),
    )


def test_matrix_pass_contains_complete_lifecycle_contract():
    record = build_matrix_record(
        scenario="c-dynamic", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), prepared(), *lifecycle_events()),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "PASS"
    assert record.required_symbols == REQUIRED_SYMBOLS
    assert record.lifecycle_active and record.prepared_v2
    assert record.executions_observed and record.finalizations_observed


def test_prepare_v3_only_is_a_complete_lifecycle_contract():
    symbols = ("sqlite3_prepare_v3", "sqlite3_step", "sqlite3_reset", "sqlite3_finalize")
    record = build_matrix_record(
        scenario="v3-only", command=COMMAND,
        result=active_result(*detections(*symbols), status(), prepared(), *lifecycle_events()),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "PASS"
    assert record.prepared_v3 and not record.prepared_v2


def test_incomplete_lifecycle_is_explicitly_unsupported():
    result = RunResult(
        123, 0, None,
        (status("DETECTED_UNSUPPORTED", 2),), "DETECTED_UNSUPPORTED",
    )
    record = build_matrix_record(scenario="embedded-stripped", command=COMMAND, result=result, expected_sql=SQL, functional_output_ok=True)
    assert record.status == "UNSUPPORTED"
    assert "unavailable" in (record.reason or "")


def test_prepared_but_not_executed_can_never_pass():
    record = build_matrix_record(
        scenario="prepared-only", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), prepared()),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "FAIL"
    assert not record.executions_observed


def test_nonzero_target_or_fatal_instrumentation_is_fail():
    target_record = build_matrix_record(
        scenario="c-dynamic", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), prepared(), *lifecycle_events(), target_exit_code=7),
        expected_sql=SQL, functional_output_ok=True,
    )
    error_record = build_matrix_record(
        scenario="python", command=COMMAND,
        result=RunResult(123, 0, None, (InstrumentationError("frida", "load failed"),), "FAILED", True, "frida: load failed"),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert target_record.status == "FAIL"
    assert error_record.status == "FAIL"


def test_reset_reuse_and_finalize_cleanup_are_represented():
    events = (
        prepared(),
        StatementExecuted(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 1, 100, "reset"),
        StatementExecuted(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 2, 101, "done"),
        StatementFinalized(123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 2, 0),
    )
    record = build_matrix_record(
        scenario="reset-reuse", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), *events),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "PASS"
