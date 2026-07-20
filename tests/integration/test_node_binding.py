from __future__ import annotations

import json
from pathlib import Path
import platform
import subprocess
import sys

import pytest

from sqlitewatch.events import InstrumentationStatus, StatementExecuted, StatementFinalized
from sqlitewatch.process import ProcessController
from tests.integration.matrix_support import build_matrix_record


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "node_binding"
FIXTURE = FIXTURE_DIR / "fixture.js"
SQL = "SELECT name FROM users WHERE id = ?"
SORT_SQL = "SELECT name FROM users ORDER BY name"


def _completed(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=FIXTURE_DIR, capture_output=True, text=True, check=False)


def _runtime_details() -> str:
    details: list[str] = []
    for command in (
        ["node", "--version"],
        ["npm", "--version"],
        ["node", "-p", "process.versions.modules"],
        ["node", "-p", "process.arch"],
    ):
        completed = _completed(command)
        value = (completed.stdout or completed.stderr).strip()
        details.append(f"{' '.join(command)}={value or 'unknown'}")
    package = FIXTURE_DIR / "node_modules" / "better-sqlite3" / "package.json"
    if package.is_file():
        details.append(f"better-sqlite3={json.loads(package.read_text())['version']}")
    else:
        details.append("better-sqlite3=not-installed")
    details.append(f"arch={platform.machine()}")
    return "; ".join(details)


def _environmental_failure(completed: subprocess.CompletedProcess[str]) -> bool:
    text = f"{completed.stdout}\n{completed.stderr}".lower()
    markers = (
        "cannot find module",
        "node_module_version",
        "prebuild-install",
        "gyp",
        "glibc",
        "incompatible",
        "unsupported",
    )
    return any(marker in text for marker in markers)


@pytest.mark.integration
def test_node_binding_is_optional_and_matrix_classified(node_tools_available):
    check = _completed(["node", "--check", str(FIXTURE)])
    assert check.returncode == 0, check.stderr

    addon = FIXTURE_DIR / "node_modules" / "better-sqlite3"
    if not addon.is_dir():
        install_command = ["npm", "ci"]
        installed = _completed(install_command)
        if installed.returncode != 0:
            pytest.skip(
                "Node binding installation unavailable; "
                f"command={' '.join(install_command)}; {_runtime_details()}; "
                f"stderr={installed.stderr.strip()}"
            )
    if not addon.is_dir():
        pytest.skip(
            "better-sqlite3 was not installed; "
            f"command=npm ci; {_runtime_details()}"
        )

    normal = _completed(["node", str(FIXTURE)])
    if normal.returncode != 0:
        if _environmental_failure(normal):
            pytest.skip(
                "Node binding is incompatible with this environment; "
                f"command=node fixture.js; {_runtime_details()}; "
                f"stderr={normal.stderr.strip()}"
            )
        assert normal.returncode == 0, normal.stderr
    assert normal.stdout == "names=Ada,Grace\n"

    command = ("node", str(FIXTURE))
    result = ProcessController().run(list(command))
    instrumented = subprocess.run(
        [sys.executable, "-m", "sqlitewatch", "--", "node", str(FIXTURE)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert normal.stdout in instrumented.stdout
    assert result.target_exit_code == 0

    record = build_matrix_record(
        scenario="node-better-sqlite3",
        command=command,
        result=result,
        expected_sql=(SQL, SORT_SQL),
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
        assert record.sql_captured
        assert record.prepared_v3
        assert record.executions_observed and record.finalizations_observed
        assert record.metrics_active and record.metrics_observed
        sorted_statement = next(event for event in result.statements if event.sql == SORT_SQL)
        start = result.events.index(sorted_statement)
        end = next(
            index for index, event in enumerate(result.events[start + 1:], start + 1)
            if isinstance(event, StatementFinalized) and event.statement == sorted_statement.statement
        )
        sorted_executions = [event for event in result.events[start + 1:end] if isinstance(event, StatementExecuted)]
        assert any(event.sorts > 0 for event in sorted_executions)
        assert record.module and record.path
