from pathlib import Path
import subprocess

import pytest

from sqlitewatch.events import InstrumentationStatus, SqliteDetected
from sqlitewatch.process import ProcessController


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"


@pytest.mark.integration
def test_dynamic_fixture_is_instrumented(native_tools_available):
    if subprocess.run(["pkg-config", "--exists", "sqlite3"], check=False).returncode != 0:
        pytest.skip("SQLite development files are unavailable")
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "clean"], check=True)
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    linkage = subprocess.run(["ldd", str(FIXTURE_DIR / "fixture")], capture_output=True, text=True, check=True)
    assert "sqlite3.so" in linkage.stdout

    normal = subprocess.run([str(FIXTURE_DIR / "fixture")], capture_output=True, text=True, check=True)
    result = ProcessController().run([str(FIXTURE_DIR / "fixture")])
    assert result.target_exit_code == 0
    assert result.instrumentation_status == "ACTIVE"
    assert any(isinstance(event, SqliteDetected) and "sqlite3.so" in event.module for event in result.events)
    assert any(event.sql == "SELECT name FROM users WHERE id = ?" for event in result.statements)
    assert normal.stdout == "name=Ada\n"
