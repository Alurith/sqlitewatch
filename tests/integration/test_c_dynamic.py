from pathlib import Path
import subprocess
import sys

import pytest

from sqlitewatch.events import StatementExecuted, StatementFinalized, StatementPrepared
from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"
SQL = "SELECT name FROM users WHERE id = ?"
V3_SQL = "SELECT 42"
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

    record = build_matrix_record(
        scenario="c-dynamic", command=command, result=result,
        expected_sql=(SQL, V3_SQL), functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.linkage == "dynamic"
    assert record.prepared_v2 and record.prepared_v3
    assert record.metrics_active and record.metrics_observed
