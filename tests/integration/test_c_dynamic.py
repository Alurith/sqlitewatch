from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from sqlitewatch.analysis import analyze_run
from sqlitewatch.events import StatementExecuted, StatementFinalized, StatementPrepared
from sqlitewatch.process import ControllerConfig, ProcessController
from sqlitewatch.reporting import render_json, render_terminal
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"
SQL = "SELECT name FROM users WHERE id = ?"
V3_SQL = "SELECT 42"
TAIL_SQL = "SELECT 314159;"
UTF8_BOUNDARY_SQL = ("SELECT 1 AS café", "SELECT 1 AS 中", "SELECT 1 AS 😀")
SCAN_SQL = "SELECT value FROM scan_rows WHERE value = ?"
SORT_SQL = "SELECT value FROM scan_rows ORDER BY value DESC"
AUTOINDEX_SQL = "SELECT count(*) FROM join_left AS l JOIN join_right AS r ON l.join_key = r.join_key WHERE l.payload = ?"


def _execution_for_sql(result, sql):
    statement = next(event for event in result.statements if event.sql == sql)
    start = result.events.index(statement)
    end = next(
        index for index, event in enumerate(result.events[start + 1:], start + 1)
        if isinstance(event, StatementFinalized) and event.statement == statement.statement
    )
    return [event for event in result.events[start + 1:end] if isinstance(event, StatementExecuted)]


@pytest.mark.integration
def test_dynamic_fixture_is_instrumented(native_tools_available):
    if subprocess.run(["pkg-config", "--exists", "sqlite3"], check=False).returncode != 0:
        pytest.skip("SQLite development files are unavailable (pkg-config --exists sqlite3)")
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "clean"], check=True)
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    linkage = subprocess.run(["ldd", str(FIXTURE_DIR / "fixture")], capture_output=True, text=True, check=True)
    assert "sqlite3.so" in linkage.stdout

    command = (str(FIXTURE_DIR / "fixture"),)
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    result = ProcessController().run(list(command))
    instrumented = subprocess.run([sys.executable, "-m", "sqlitewatch", "--", *command], capture_output=True, text=True, check=False)
    assert result.target_exit_code == 0
    assert result.instrumentation_status == "ACTIVE"
    assert normal.stdout == "name=Ada\n"
    assert normal.stdout in instrumented.stdout

    prepared = [event for event in result.events if isinstance(event, StatementPrepared)]
    assert any(event.sql == SQL for event in prepared)
    assert any(event.sql == V3_SQL for event in prepared)
    tail_statement = next(event for event in prepared if event.sql == TAIL_SQL)
    assert not tail_statement.sql_truncated
    assert not tail_statement.sql_capture_failed
    for sql in UTF8_BOUNDARY_SQL:
        statement = next(event for event in prepared if event.sql == sql)
        assert statement.captured_bytes == len(sql.encode("utf-8"))
        assert not statement.sql_truncated
        assert not statement.sql_capture_failed

    scan_executions = _execution_for_sql(result, SCAN_SQL)
    assert len(scan_executions) == 2
    assert [event.execution_number for event in scan_executions] == [1, 2]
    assert all(event.fullscan_steps > 0 and event.vm_steps > 0 for event in scan_executions)
    # The baseline advances at reset, so repeated identical work is a delta,
    # not the cumulative value after both cycles.
    assert scan_executions[0].fullscan_steps == scan_executions[1].fullscan_steps
    assert scan_executions[0].vm_steps == scan_executions[1].vm_steps

    sort_execution = _execution_for_sql(result, SORT_SQL)
    assert len(sort_execution) == 1
    assert sort_execution[0].sorts > 0 and sort_execution[0].vm_steps > 0

    autoindex_execution = _execution_for_sql(result, AUTOINDEX_SQL)
    assert len(autoindex_execution) == 1
    assert autoindex_execution[0].autoindex > 0

    executions = [event for event in result.events if isinstance(event, StatementExecuted)]
    assert executions
    assert all(
        event.fullscan_steps is not None and event.vm_steps is not None
        and event.sorts is not None and event.autoindex is not None
        and min(event.fullscan_steps, event.vm_steps, event.sorts, event.autoindex) >= 0
        for event in executions
    )
    assert any(isinstance(event, StatementFinalized) for event in result.events)

    analysis = analyze_run(result)
    scan_aggregate = next(aggregate for aggregate in analysis.aggregates if aggregate.normalized_sql == SCAN_SQL)
    assert scan_aggregate.executions == 2
    assert scan_aggregate.total_fullscan_steps == sum(event.fullscan_steps for event in scan_executions)
    assert scan_aggregate.max_fullscan_steps == max(event.fullscan_steps for event in scan_executions)
    sort_aggregate = next(aggregate for aggregate in analysis.aggregates if aggregate.normalized_sql == SORT_SQL)
    autoindex_aggregate = next(aggregate for aggregate in analysis.aggregates if aggregate.normalized_sql == AUTOINDEX_SQL)
    assert sort_aggregate.total_sorts > 0
    assert autoindex_aggregate.total_autoindex > 0
    assert SCAN_SQL in render_terminal(analysis)
    assert SCAN_SQL in render_json(analysis)
    assert next(
        aggregate for aggregate in analysis.aggregates
        if aggregate.normalized_sql == TAIL_SQL
    ).executions == 1

    record = build_matrix_record(
        scenario="c-dynamic", command=command, result=result,
        expected_sql=(SQL, V3_SQL), functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.linkage == "dynamic"
    assert record.prepared_v2 and record.prepared_v3
    assert record.metrics_active and record.metrics_observed


@pytest.mark.integration
def test_abrupt_exit_after_row_is_inconclusive_not_false_rule_pass(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "abrupt"], check=True)
    target = str(FIXTURE_DIR / "fixture-abrupt")
    for command in ([target, "fast"], [target]):
        result = ProcessController().run(command)
        analysis = analyze_run(result)
        assert result.target_exit_code == 0
        assert "UNFINISHED_EXECUTIONS" in analysis.incomplete_reasons

    completed = subprocess.run(
        [
            sys.executable, "-m", "sqlitewatch", "--format=json",
            "--fail-vm-steps=100", "--", target,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    payload = json.loads(completed.stdout)
    assert completed.returncode == 70
    assert payload["evaluation"]["complete"] is False
    assert payload["rules"]["passed"] is False
    assert "UNFINISHED_EXECUTIONS" in payload["rules"]["incomplete_reasons"]


@pytest.mark.integration
def test_sql_capture_stops_at_unreadable_page_boundary(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "page-boundary"], check=True)
    result = ProcessController().run([str(FIXTURE_DIR / "fixture-page-boundary")])
    statement = next(event for event in result.statements if event.sql == "SELECT 1 AS café")
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    assert not statement.sql_truncated
    assert not statement.sql_capture_failed


@pytest.mark.integration
def test_long_sql_capture_uses_bounded_bulk_reads(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "long"], check=True)
    started = time.monotonic()
    result = ProcessController().run([str(FIXTURE_DIR / "fixture-long")])
    elapsed = time.monotonic() - started
    long_statements = [event for event in result.statements if len(event.sql) >= 60 * 1024]
    assert result.target_exit_code == 0
    assert len(long_statements) == 200
    assert all(not event.sql_truncated for event in long_statements)
    # The former per-byte NativePointer.readU8 loop took about 17 seconds for
    # this workload on the reference host; bulk capture stays comfortably below.
    assert elapsed < 10.0


@pytest.mark.integration
def test_tail_beyond_capture_limit_is_truncated_only_by_the_limit(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    result = ProcessController().run(
        [str(FIXTURE_DIR / "fixture")], ControllerConfig(max_sql_length=13)
    )
    statement = next(
        event for event in result.statements if event.sql == "SELECT 314159"
    )
    assert statement.sql_truncated
    assert not statement.sql_capture_failed
    assert statement.captured_bytes == 13


@pytest.mark.integration
def test_utf8_capture_limits_never_emit_partial_codepoints(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    for limit in (13, 14, 15, 16, 17):
        result = ProcessController().run(
            [str(FIXTURE_DIR / "fixture")],
            ControllerConfig(max_sql_length=limit),
        )
        expected = Counter()
        for sql in UTF8_BOUNDARY_SQL:
            raw = sql.encode("utf-8")
            captured = raw[:limit].decode("utf-8", errors="ignore")
            expected[(captured, limit < len(raw), len(captured.encode("utf-8")))] += 1
        observed = Counter(
            (event.sql, event.sql_truncated, event.captured_bytes)
            for event in result.statements
            if event.sql.startswith("SELECT 1 AS")
        )
        assert observed == expected
        assert all(
            not event.sql_capture_failed
            for event in result.statements
            if event.sql.startswith("SELECT 1 AS")
        )


@pytest.mark.integration
def test_stdout_is_utf8_when_ambient_python_encoding_is_ascii(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    completed = subprocess.run(
        [
            sys.executable, "-m", "sqlitewatch", "--format=json", "--",
            str(FIXTURE_DIR / "fixture"),
        ],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "ascii"},
        check=False,
    )
    assert completed.returncode == 0
    payload = json.loads(completed.stdout.decode("utf-8"))
    assert any("café" in query["sql"] for query in payload["queries"])
    assert b"Traceback" not in completed.stderr


@pytest.mark.integration
def test_ci_rules_json_streams_and_target_failure_precedence(native_tools_available, tmp_path):
    if subprocess.run(["pkg-config", "--exists", "sqlite3"], check=False).returncode != 0:
        pytest.skip("SQLite development files are unavailable (pkg-config --exists sqlite3)")
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    target = str(FIXTURE_DIR / "fixture")

    def run_cli(*options, command=(target,)):
        return subprocess.run(
            [sys.executable, "-m", "sqlitewatch", *options, "--", *command],
            capture_output=True,
            text=True,
            check=False,
        )

    assert run_cli("--fail-fullscan-steps", "1000000000").returncode == 0
    fullscan = run_cli("--format=json", "--fail-fullscan-steps", "0")
    vm = run_cli("--format=json", "--fail-vm-steps", "0")
    autoindex = run_cli("--format=json", "--fail-on-autoindex")
    assert (fullscan.returncode, vm.returncode, autoindex.returncode) == (1, 1, 1)
    for completed, rule in (
        (fullscan, "FULLSCAN_STEPS"),
        (vm, "VM_STEPS"),
        (autoindex, "AUTOINDEX"),
    ):
        payload = json.loads(completed.stdout)
        assert any(item["rule"] == rule for item in payload["rules"]["violations"])
        assert completed.stdout.endswith("\n")
        assert "name=Ada\n" in completed.stderr

    multiple = run_cli("--format=json", "--fail-fullscan-steps", "0", "--fail-vm-steps", "0", "--fail-on-autoindex")
    multiple_payload = json.loads(multiple.stdout)
    assert multiple.returncode == 1
    assert {item["rule"] for item in multiple_payload["rules"]["violations"]} == {
        "AUTOINDEX", "FULLSCAN_STEPS", "VM_STEPS",
    }

    simultaneous = run_cli("--format=json", "--fail-fullscan-steps", "0", command=(target, "fail-after-work"))
    simultaneous_payload = json.loads(simultaneous.stdout)
    assert simultaneous.returncode == 7
    assert simultaneous_payload["outcome"]["application_failure"] is True
    assert simultaneous_payload["outcome"]["performance_rule_failure"] is True

    report_path = tmp_path / "report.json"
    to_file = run_cli("--format=json", "--output", str(report_path), "--fail-fullscan-steps", "0")
    file_payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert to_file.returncode == 1
    assert to_file.stdout == "name=Ada\n"
    assert file_payload["schema_version"] == 2
    assert file_payload["outcome"]["exit_code"] == 1

    no_sqlite = run_cli("--fail-fullscan-steps", "0", command=("/bin/true",))
    assert no_sqlite.returncode == 70
