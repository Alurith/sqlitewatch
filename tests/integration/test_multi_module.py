from pathlib import Path
import subprocess

import pytest

from sqlitewatch.analysis import RuleConfig, analyze_run, evaluate_rules
from sqlitewatch.doctor import reduce_events, resolve_doctor_outcome
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.process import ControllerConfig, ProcessController


ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "fixtures" / "c_multi_module"


@pytest.mark.integration
def test_incomplete_active_module_cannot_borrow_complete_module_coverage(
    native_tools_available,
):
    subprocess.run(["make", "-C", str(FIXTURE_DIR), "clean", "all"], check=True)
    command = [str(FIXTURE_DIR / "fixture")]

    result = ProcessController().run(command)
    assert result.target_exit_code == 0
    assert result.instrumentation_status == "PARTIAL"
    analysis = analyze_run(result)
    rules = evaluate_rules(analysis, RuleConfig(fail_vm_steps=0))
    outcome = resolve_outcome(result, rules)
    assert outcome.instrumentation_failed
    assert outcome.exit_code == 70

    doctor_run = ProcessController().run(command, ControllerConfig(doctor=True))
    doctor = reduce_events(doctor_run)
    assert doctor.status == "PARTIAL"
    assert doctor.complete_activity_count == 0
    assert doctor.incomplete_activity_count == 1
    assert resolve_doctor_outcome(doctor).exit_code == 70
