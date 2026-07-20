from pathlib import Path

import pytest

from sqlitewatch.process import ProcessController


ROOT = Path(__file__).parents[2]
EXIT_FIXTURE = ROOT / "tests" / "fixtures" / "exit_code.py"


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
