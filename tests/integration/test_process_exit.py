import json
import os
from pathlib import Path
import sys

import pytest

from sqlitewatch.process import ControllerConfig, ProcessController


ROOT = Path(__file__).parents[2]
EXIT_FIXTURE = ROOT / "tests" / "fixtures" / "exit_code.py"
ADVERSARY_FIXTURE = ROOT / "tests" / "fixtures" / "process_adversary.py"


@pytest.mark.integration
def test_target_exit_code_is_preserved(native_tools_available):
    # Fast targets repeatedly exercise the race that formerly produced ECHILD.
    for expected in (0, 7):
        for _ in range(3):
            result = ProcessController().run(["python", str(EXIT_FIXTURE), str(expected)])
            assert result.target_exit_code == expected
            assert result.exit_code == expected
            assert not result.instrumentation_failed


@pytest.mark.integration
def test_target_signal_is_preserved(native_tools_available):
    result = ProcessController().run(["python", str(EXIT_FIXTURE), "signal"])
    assert result.target_exit_code is None
    assert result.signal == 15
    assert result.exit_code == 143
    assert not result.instrumentation_failed


@pytest.mark.integration
def test_same_controller_and_backend_support_two_consecutive_runs(native_tools_available):
    controller = ProcessController()
    fixture = ROOT / "fixtures" / "python_sqlite.py"
    first = controller.run([sys.executable, str(fixture)])
    second = controller.run([sys.executable, str(fixture)])
    assert (first.target_exit_code, second.target_exit_code) == (0, 0)
    assert (first.instrumentation_status, second.instrumentation_status) == (
        "ACTIVE", "ACTIVE",
    )
    assert not first.instrumentation_failed and not second.instrumentation_failed
    assert first.executions and second.executions


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["ignore", "forge"])
def test_failure_cleanup_kills_target_and_launcher_and_rejects_forgery(
    native_tools_available, tmp_path, mode,
):
    pid_file = tmp_path / f"{mode}.json"
    result = ProcessController().run(
        [sys.executable, str(ADVERSARY_FIXTURE), mode, str(pid_file)],
        ControllerConfig(
            completion_timeout=2.0 if mode == "forge" else 0.2,
            cleanup_timeout=0.4,
        ),
    )
    pids = json.loads(pid_file.read_text(encoding="utf-8"))
    assert result.instrumentation_failed
    if mode == "forge":
        assert "completion peer pid" in (result.instrumentation_error or "")
    else:
        assert "timed out" in (result.instrumentation_error or "")
    assert all(not os.path.exists(f"/proc/{pid}") for pid in pids.values())
