from pathlib import Path
import subprocess

import pytest

from sqlitewatch.process import ProcessController


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_dynamic"


@pytest.mark.integration
def test_late_loaded_sqlite_is_observed(native_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "late"], check=True)
    linkage = subprocess.run(["ldd", str(FIXTURE_DIR / "fixture-late")], capture_output=True, text=True, check=True)
    assert "sqlite3.so" not in linkage.stdout
    result = ProcessController().run([str(FIXTURE_DIR / "fixture-late")])
    assert result.target_exit_code == 0
    assert any(event.sql == "SELECT name FROM users WHERE id = ?" for event in result.statements)
