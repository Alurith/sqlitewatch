from pathlib import Path
import subprocess
import sys

import pytest

from sqlitewatch.events import InstrumentationStatus
from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "fixtures" / "python_sqlite.py"
SQL = "SELECT name FROM users WHERE id = ?"


@pytest.mark.integration
def test_python_stdlib_sqlite_is_instrumented(native_tools_available):
    normal = subprocess.run(
        [sys.executable, str(FIXTURE)], capture_output=True, text=True, check=True
    )
    assert normal.stdout == "names=Ada\n"

    command = (sys.executable, str(FIXTURE))
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [
            sys.executable,
            "-m",
            "sqlitewatch",
            "--",
            sys.executable,
            str(FIXTURE),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "names=Ada" in instrumented.stdout
    assert normal.stdout in instrumented.stdout
    assert result.target_exit_code == 0

    record = build_matrix_record(
        scenario="python-stdlib",
        command=command,
        result=result,
        expected_sql=SQL,
        functional_output_ok=normal.stdout in instrumented.stdout,
    )
    if record.status == "UNSUPPORTED":
        assert any(
            isinstance(event, InstrumentationStatus)
            and event.status == "DETECTED_UNSUPPORTED"
            for event in result.events
        )
    else:
        assert record.status == "PASS", record.diagnostic()
        assert record.module and record.path
        assert record.linkage in {"dynamic", "embedded_or_unknown"}
        assert record.lifecycle_active
        assert record.executions_observed
