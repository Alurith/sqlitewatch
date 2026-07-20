"""End-to-end matrix summary without a persistent report artifact."""

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import MatrixRecord, build_matrix_record


ROOT = Path(__file__).parents[2]
C_DYNAMIC = ROOT / "fixtures" / "c_dynamic" / "fixture"
C_EMBEDDED = ROOT / "fixtures" / "c_embedded" / "fixture-sqlite-embedded"
PYTHON_FIXTURE = ROOT / "fixtures" / "python_sqlite.py"
NODE_DIR = ROOT / "fixtures" / "node_binding"
NODE_FIXTURE = NODE_DIR / "fixture.js"


def _run_and_record(
    scenario: str,
    command: tuple[str, ...],
    expected_sql: str | tuple[str, ...],
    expected_output: str,
) -> MatrixRecord:
    normal = subprocess.run(command, capture_output=True, text=True, check=True)
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [sys.executable, "-m", "sqlitewatch", "--", *command],
        capture_output=True,
        text=True,
        check=False,
    )
    return build_matrix_record(
        scenario=scenario,
        command=command,
        result=result,
        expected_sql=expected_sql,
        functional_output_ok=(
            normal.stdout == expected_output and expected_output in instrumented.stdout
        ),
    )


@pytest.mark.integration
def test_complete_matrix_does_not_hide_failures(native_tools_available):
    subprocess.run(["make", "-C", str(C_DYNAMIC.parent)], check=True)
    subprocess.run(["make", "-C", str(C_EMBEDDED.parent)], check=True)

    records = [
        _run_and_record("c-dynamic", (str(C_DYNAMIC),), "SELECT name FROM users WHERE id = ?", "name=Ada\n"),
        _run_and_record(
            "c-embedded-visible",
            (str(C_EMBEDDED),),
            "SELECT name FROM users WHERE id = ?",
            "name=Ada\n",
        ),
        _run_and_record(
            "python-stdlib",
            (sys.executable, str(PYTHON_FIXTURE)),
            "SELECT name FROM users WHERE id = ?",
            "names=Ada\n",
        ),
    ]

    if shutil.which("node") is None or shutil.which("npm") is None:
        records.append(
            build_matrix_record(
                scenario="node-better-sqlite3",
                command=("node", str(NODE_FIXTURE)),
                result=None,
                skip_reason="node/npm unavailable for optional scenario",
            )
        )
    else:
        addon = NODE_DIR / "node_modules" / "better-sqlite3"
        if not addon.is_dir():
            install = subprocess.run(
                ["npm", "ci"], cwd=NODE_DIR, capture_output=True, text=True, check=False
            )
        else:
            install = None
        if install is not None and install.returncode != 0:
            records.append(
                build_matrix_record(
                    scenario="node-better-sqlite3",
                    command=("node", str(NODE_FIXTURE)),
                    result=None,
                    skip_reason=(
                        "npm ci unavailable; command=npm ci; "
                        f"stderr={install.stderr.strip()}"
                    ),
                )
            )
        elif not addon.is_dir():
            records.append(
                build_matrix_record(
                    scenario="node-better-sqlite3",
                    command=("node", str(NODE_FIXTURE)),
                    result=None,
                    skip_reason="npm ci completed without better-sqlite3",
                )
            )
        else:
            records.append(
                _run_and_record(
                    "node-better-sqlite3",
                    ("node", str(NODE_FIXTURE)),
                    (
                        "SELECT name FROM users WHERE id = ?",
                        "SELECT name FROM users ORDER BY name",
                    ),
                    "names=Ada,Grace\n",
                )
            )

    summary = "; ".join(f"{record.scenario}={record.status}" for record in records)
    assert records[0].status == "PASS", summary
    assert records[1].status == "PASS", summary
    assert records[2].status in {"PASS", "UNSUPPORTED"}, summary
    assert records[3].status in {"PASS", "SKIPPED", "UNSUPPORTED"}, summary
    assert all(record.status != "PASS" or record.sql_captured for record in records), summary
    assert all(record.status != "PASS" or (record.metrics_active and record.metrics_observed) for record in records), summary
