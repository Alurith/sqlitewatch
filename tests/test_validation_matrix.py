from tests.integration.matrix_support import build_matrix_record
from sqlitewatch.events import (
    InstrumentationError,
    InstrumentationStatus,
    RunResult,
    SqliteDetected,
    StatementPrepared,
)


COMMAND = ("fixture",)
SQL = "SELECT name FROM users WHERE id = ?"


def active_result(*events, target_exit_code=0, instrumentation_failed=False):
    return RunResult(
        pid=123,
        target_exit_code=target_exit_code,
        signal=None,
        events=tuple(events),
        instrumentation_status="ACTIVE",
        instrumentation_failed=instrumentation_failed,
    )


def detected(address="0x1000"):
    return SqliteDetected(
        pid=123,
        module="libsqlite3.so.0",
        path="/usr/lib/libsqlite3.so.0",
        symbol="sqlite3_prepare_v2",
        address=address,
        linkage="dynamic",
    )


def status(value="ACTIVE", hooks=1):
    return InstrumentationStatus(pid=123, status=value, hooks=hooks)


def prepared(sql=SQL):
    return StatementPrepared(
        pid=123,
        tid=123,
        module="libsqlite3.so.0",
        statement="0x2000",
        database="0x3000",
        sql=sql,
    )


def test_matrix_pass_contains_the_complete_contract():
    record = build_matrix_record(
        scenario="c-dynamic",
        command=COMMAND,
        result=active_result(detected(), status(), prepared()),
        expected_sql=SQL,
        functional_output_ok=True,
    )

    assert record.status == "PASS"
    assert record.sqlite_detected
    assert record.module == "libsqlite3.so.0"
    assert record.path == "/usr/lib/libsqlite3.so.0"
    assert record.linkage == "dynamic"
    assert record.required_symbols == ("sqlite3_prepare_v2",)
    assert record.symbols_found == ("sqlite3_prepare_v2",)
    assert record.hook_installed
    assert record.sql_captured
    assert record.functional_output_ok


def test_missing_prerequisite_is_a_scenario_local_skip():
    record = build_matrix_record(
        scenario="node",
        command=("node", "fixture.js"),
        result=None,
        skip_reason="node --version: command not found; npm unavailable",
    )

    assert record.status == "SKIPPED"
    assert "node" in (record.reason or "")
    assert record.required_symbols == ("sqlite3_prepare_v2",)


def test_detected_unsupported_is_not_a_protocol_success():
    result = RunResult(
        pid=123,
        target_exit_code=0,
        signal=None,
        events=(
            status("DETECTED_UNSUPPORTED", hooks=0),
            InstrumentationStatus(
                pid=123,
                status="DETECTED_UNSUPPORTED",
                hooks=0,
                reason="sqlite3_prepare_v2 symbol not found",
            ),
        ),
        instrumentation_status="DETECTED_UNSUPPORTED",
    )
    record = build_matrix_record(
        scenario="embedded-stripped",
        command=COMMAND,
        result=result,
        expected_sql=SQL,
        functional_output_ok=True,
    )

    assert record.status == "UNSUPPORTED"
    assert record.status not in {"ACTIVE", "PASS"}
    assert "unavailable" in (record.reason or "")


def test_nonzero_target_or_fatal_instrumentation_is_fail():
    target_record = build_matrix_record(
        scenario="c-dynamic",
        command=COMMAND,
        result=active_result(detected(), status(), prepared(), target_exit_code=7),
        expected_sql=SQL,
        functional_output_ok=True,
    )
    error_record = build_matrix_record(
        scenario="python",
        command=COMMAND,
        result=RunResult(
            pid=123,
            target_exit_code=0,
            signal=None,
            events=(InstrumentationError(phase="frida", message="load failed"),),
            instrumentation_status="FAILED",
            instrumentation_failed=True,
            instrumentation_error="frida: load failed",
        ),
        expected_sql=SQL,
        functional_output_ok=True,
    )

    assert target_record.status == "FAIL"
    assert target_record.target_exit_code == 7
    assert error_record.status == "FAIL"
    assert "load failed" in (error_record.reason or "")


def test_multiple_modules_deduplicate_symbols_and_keep_sql_requirement_strict():
    result = active_result(
        detected("0x1000"),
        detected("0x2000"),
        status("ACTIVE", hooks=2),
        prepared("SELECT other"),
    )
    record = build_matrix_record(
        scenario="python",
        command=COMMAND,
        result=result,
        expected_sql=SQL,
        functional_output_ok=True,
    )

    assert record.status == "FAIL"
    assert record.symbols_found == ("sqlite3_prepare_v2",)
    assert not record.sql_captured
    assert "expected SQL" in (record.reason or "")


def test_missing_or_wrong_sql_can_never_pass():
    for statements in ((), (prepared("SELECT 1"),)):
        record = build_matrix_record(
            scenario="python",
            command=COMMAND,
            result=active_result(detected(), status(), *statements),
            expected_sql=SQL,
            functional_output_ok=True,
        )
        assert record.status == "FAIL"
        assert not record.sql_captured
