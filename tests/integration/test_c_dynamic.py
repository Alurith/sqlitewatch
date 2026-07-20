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
    reused = next(event for event in prepared if event.sql == SQL)
    prepared_index = result.events.index(reused)
    final_index = next(
        index for index, event in enumerate(result.events[prepared_index + 1:], prepared_index + 1)
        if isinstance(event, StatementFinalized) and event.statement == reused.statement
    )
    lifecycle = result.events[prepared_index + 1:final_index + 1]
    executions = [event for event in lifecycle if isinstance(event, StatementExecuted)]
    assert [(event.execution_number, event.boundary) for event in executions] == [(1, "done"), (2, "done")]
    assert not any(event.boundary == "error" and event.sqlite_rc == 100 for event in executions)
    finalization = lifecycle[-1]
    assert isinstance(finalization, StatementFinalized)
    assert finalization.executions == 2
    # A recycled address has a fresh context and therefore restarts at execution 1.
    for later in prepared:
        if later is not reused and later.statement == reused.statement:
            later_index = result.events.index(later)
            later_executions = [
                event for event in result.events[later_index + 1:]
                if isinstance(event, StatementExecuted) and event.statement == later.statement
            ]
            assert later_executions[0].execution_number == 1
            break

    record = build_matrix_record(
        scenario="c-dynamic", command=command, result=result,
        expected_sql=(SQL, V3_SQL), functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.linkage == "dynamic"
    assert record.prepared_v2 and record.prepared_v3
    assert record.executions_observed and record.finalizations_observed
