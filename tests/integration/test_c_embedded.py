from pathlib import Path
import subprocess
import sys

import pytest

from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_embedded"
FIXTURE = FIXTURE_DIR / "fixture-sqlite-embedded"
STRIPPED = FIXTURE_DIR / "fixture-sqlite-embedded-stripped"
SQL = "SELECT name FROM users WHERE id = ?"


@pytest.mark.integration
def test_embedded_fixture_and_stripped_limit(embedded_tools_available):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "clean"], check=True)
    subprocess.run(["make", "-C", str(FIXTURE_DIR)], check=True)
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "check-linkage", "check-symbols"], check=True)

    linkage = subprocess.run(["ldd", str(FIXTURE)], capture_output=True, text=True, check=True)
    assert "libsqlite3" not in linkage.stdout
    symbols = subprocess.run(["nm", "-g", str(FIXTURE)], capture_output=True, text=True, check=True)
    assert "sqlite3_prepare_v2" in symbols.stdout

    command = (str(FIXTURE),)
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [sys.executable, "-m", "sqlitewatch", "--", *command],
        capture_output=True,
        text=True,
        check=False,
    )
    assert normal.stdout == "name=Ada\n"
    assert normal.stdout in instrumented.stdout
    assert result.target_exit_code == 0

    record = build_matrix_record(
        scenario="c-embedded-visible",
        command=command,
        result=result,
        expected_sql=SQL,
        functional_output_ok=normal.stdout in instrumented.stdout,
    )
    assert record.status == "PASS", record.diagnostic()
    assert record.linkage == "embedded_or_unknown"
    assert record.lifecycle_active
    assert record.executions_observed and record.finalizations_observed

    subprocess.run(["make", "-C", str(FIXTURE_DIR), "stripped"], check=True)
    stripped_command = (str(STRIPPED),)
    stripped_normal = subprocess.run(
        stripped_command, capture_output=True, text=True, check=True
    )
    stripped_result = ProcessController().run(list(stripped_command))
    stripped_record = build_matrix_record(
        scenario="c-embedded-stripped",
        command=stripped_command,
        result=stripped_result,
        expected_sql=SQL,
        functional_output_ok=stripped_normal.stdout == normal.stdout,
    )
    assert stripped_normal.stdout == "name=Ada\n"
    assert stripped_record.status == "UNSUPPORTED", stripped_record.diagnostic()
    assert stripped_record.status != "PASS"
