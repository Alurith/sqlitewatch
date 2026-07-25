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
METRICS = dict(fullscan_steps=1, vm_steps=2, sorts=0, autoindex=0)


def active_result(*events, target_exit_code=0, instrumentation_failed=False):
    return RunResult(123, target_exit_code, None, tuple(events), "ACTIVE", instrumentation_failed)


def detections(*symbols, module="libsqlite3.so.0"):
    path = "/usr/lib/" + module
    return tuple(
        SqliteDetected(
            123, module, path, symbol, f"0x{1000 + i:x}", "dynamic", "0x100000",
        )
        for i, symbol in enumerate(symbols)
    )


def status(value="ACTIVE", hooks=5): return InstrumentationStatus(pid=123, status=value, hooks=hooks)
def prepared(sql=SQL):
    return StatementPrepared(
        123, 123, "libsqlite3.so.0", "0x2000", "0x3000", sql,
        module_path="/usr/lib/libsqlite3.so.0", module_base="0x100000",
    )


def lifecycle_events(metrics=METRICS):
    return (
        StatementExecuted(
            123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 1, 101, "done",
            **metrics, module_path="/usr/lib/libsqlite3.so.0", module_base="0x100000",
        ),
        StatementFinalized(
            123, 123, "libsqlite3.so.0", "0x2000", "0x3000", 1, 0,
            module_path="/usr/lib/libsqlite3.so.0", module_base="0x100000",
        ),
    )


def test_matrix_pass_contains_complete_metric_contract():
    record = build_matrix_record(
        scenario="c-dynamic", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), prepared(), *lifecycle_events()),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "PASS"
    assert record.required_symbols == REQUIRED_SYMBOLS
    assert record.lifecycle_active and record.metrics_active and record.metrics_observed


def test_lifecycle_without_stmt_status_is_explicitly_unsupported():
    result = RunResult(123, 0, None, (status("DETECTED_UNSUPPORTED", 4),), "DETECTED_UNSUPPORTED")
    record = build_matrix_record(scenario="missing-metrics", command=COMMAND, result=result, expected_sql=SQL, functional_output_ok=True)
    assert record.status == "UNSUPPORTED"
    assert "unavailable" in (record.reason or "")


def test_symbols_cannot_be_combined_across_modules():
    lifecycle = ("sqlite3_prepare_v2", "sqlite3_step", "sqlite3_reset", "sqlite3_finalize")
    result = active_result(
        *detections(*lifecycle, module="module-a"),
        *detections("sqlite3_stmt_status", module="module-b"),
        status(), prepared(), *lifecycle_events(),
    )
    record = build_matrix_record(scenario="split-modules", command=COMMAND, result=result, expected_sql=SQL, functional_output_ok=True)
    assert record.status == "FAIL"
    assert not record.metrics_active


def test_all_null_metrics_are_valid_protocol_but_cannot_pass_matrix():
    record = build_matrix_record(
        scenario="unavailable", command=COMMAND,
        result=active_result(*detections(*REQUIRED_SYMBOLS), status(), prepared(), *lifecycle_events({
            "fullscan_steps": None, "vm_steps": None, "sorts": None, "autoindex": None,
        })),
        expected_sql=SQL, functional_output_ok=True,
    )
    assert record.status == "FAIL"
    assert not record.metrics_observed


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
