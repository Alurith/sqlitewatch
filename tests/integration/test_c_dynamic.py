from pathlib import Path
import subprocess
import sys

import pytest

from sqlitewatch.events import InstrumentationStatus, SqliteDetected
from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"
SQL = "SELECT name FROM users WHERE id = ?"


@pytest.mark.integration
def test_dynamic_fixture_is_instrumented(native_tools_available):
    if subprocess.run(["pkg-config", "--exists", "sqlite3"], check=False).returncode != 0:
        pytest.skip("SQLite development files are unavailable (pkg-config --exists sqlite3)")
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "clean"], check=True)
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    linkage = subprocess.run(
        ["ldd", str(FIXTURE_DIR / "fixture")],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "sqlite3.so" in linkage.stdout

    command = (str(FIXTURE_DIR / "fixture"),)
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [sys.executable, "-m", "sqlitewatch", "--", *command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.target_exit_code == 0
    assert result.instrumentation_status == "ACTIVE"
    assert any(
        isinstance(event, SqliteDetected)
        and "libsqlite3.so" in event.module
        and event.linkage == "dynamic"
        for event in result.events
    )
    assert any(
        isinstance(event, InstrumentationStatus)
        and event.status == "ACTIVE"
        and event.hooks > 0
        for event in result.events
    )
    assert normal.stdout == "name=Ada\n"
    assert normal.stdout in instrumented.stdout

    record = build_matrix_record(
        scenario="c-dynamic",
        command=command,
        result=result,
        expected_sql=SQL,
        functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.linkage == "dynamic"
