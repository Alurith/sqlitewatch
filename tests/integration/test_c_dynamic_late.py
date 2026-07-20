from pathlib import Path
import subprocess
import sys

import pytest

from sqlitewatch.events import StatementExecuted, StatementFinalized
from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"
SQL = "SELECT name FROM users WHERE id = ?"


@pytest.mark.integration
def test_late_loaded_sqlite_is_observed(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "late"], check=True)
    linkage = subprocess.run(
        ["ldd", str(FIXTURE_DIR / "fixture-late")],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "sqlite3.so" not in linkage.stdout

    command = (str(FIXTURE_DIR / "fixture-late"),)
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [sys.executable, "-m", "sqlitewatch", "--", *command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.target_exit_code == 0
    assert any(event.sql == SQL for event in result.statements)
    assert len(result.statements) == len({(event.statement, event.sql) for event in result.statements})
    executions = [event for event in result.events if isinstance(event, StatementExecuted)]
    assert executions
    assert all(event.fullscan_steps is not None and event.vm_steps is not None for event in executions)
    assert any(isinstance(event, StatementFinalized) for event in result.events)
    assert normal.stdout in instrumented.stdout

    record = build_matrix_record(
        scenario="c-dynamic-dlopen",
        command=command,
        result=result,
        expected_sql=SQL,
        functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.lifecycle_active
