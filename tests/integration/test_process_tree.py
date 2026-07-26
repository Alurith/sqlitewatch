import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import pytest

from sqlitewatch.analysis import RuleConfig, analyze_run, evaluate_rules
from sqlitewatch.doctor import reduce_events
from sqlitewatch.events import InstrumentationError, StatementPrepared
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.process import ControllerConfig, ProcessController


ROOT = Path(__file__).parents[2]
PYTHON_FIXTURE = ROOT / "tests" / "fixtures" / "process_tree.py"
C_FIXTURE_DIR = ROOT / "fixtures" / "c_process_tree"
MARKER_SQL = "SELECT value FROM process_tree_marker WHERE value = ?"


def _run(mode, *args, config=None):
    return ProcessController().run(
        [sys.executable, str(PYTHON_FIXTURE), mode, *map(str, args)],
        config,
    )


def _marker_events(result):
    return [
        event
        for event in result.events
        if isinstance(event, StatementPrepared) and event.sql == MARKER_SQL
    ]


def _wait_gone(pid, timeout=3.0):
    deadline = time.monotonic() + timeout
    while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
        time.sleep(0.02)
    return not os.path.exists(f"/proc/{pid}")


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mode", "expected_depth"),
    [("child-sql", 1), ("grandchild-sql", 2)],
)
def test_default_follows_sql_only_in_child_or_grandchild(
    native_tools_available, mode, expected_depth,
):
    result = _run(mode)
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    assert result.process_tree.follow_children
    events = _marker_events(result)
    assert events
    depth_by_instance = {
        image.instance: process.depth
        for process in result.process_tree.processes
        for image in process.images
    }
    assert {depth_by_instance[event.process_instance] for event in events} == {
        expected_depth
    }


@pytest.mark.integration
def test_nested_uv_posix_spawn_exec_only_child_recovers_real_parent(
    native_tools_available,
):
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv executable is unavailable")
    result = ProcessController().run(
        [
            uv,
            "run",
            "--project",
            str(ROOT),
            "python",
            str(PYTHON_FIXTURE),
            "child-sql",
        ]
    )
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    assert _marker_events(result)
    direct_children = [
        process
        for process in result.process_tree.processes
        if process.parent_pid == result.pid
    ]
    assert direct_children
    assert any(image.origin == "exec" for image in direct_children[0].images)


@pytest.mark.integration
def test_doctor_attributes_child_module_and_activity_to_its_stream(
    native_tools_available,
):
    run = _run("child-sql", config=ControllerConfig(doctor=True))
    doctor = reduce_events(run)
    assert doctor.status == "ACTIVE"
    child_pids = {
        process.pid for process in run.process_tree.processes if process.depth == 1
    }
    assert child_pids
    assert any(
        module.pid in child_pids
        and module.process_instance.startswith(f"p{module.pid}-")
        for module in doctor.modules
    )
    assert doctor.complete_activity_count > 0


@pytest.mark.integration
def test_root_only_opt_out_excludes_child_sql_without_coverage_loss(
    native_tools_available,
):
    result = _run("child-sql", config=ControllerConfig(follow_children=False))
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    assert not result.process_tree.follow_children
    assert result.process_tree.complete
    assert len(result.process_tree.processes) == 1
    assert not _marker_events(result)
    assert not any(
        isinstance(event, InstrumentationError)
        and event.phase == "process_coverage"
        for event in result.events
    )


@pytest.mark.integration
def test_autoreload_and_exec_images_are_reinstrumented(native_tools_available):
    reloaded = _run("autoreload")
    marker_streams = {
        (event.process_instance, event.pid) for event in _marker_events(reloaded)
    }
    assert reloaded.target_exit_code == 0
    assert not reloaded.instrumentation_failed
    assert len(marker_streams) == 2
    marker_aggregates = [
        aggregate
        for aggregate in analyze_run(reloaded).aggregates
        if aggregate.normalized_sql == MARKER_SQL
    ]
    assert len(marker_aggregates) == 2
    assert len({item.scope.process_instance for item in marker_aggregates}) == 2

    executed = _run("exec-same-pid")
    assert executed.target_exit_code == 0
    root = executed.process_tree.processes[0]
    assert len(root.images) == 2
    assert root.images[0].detach_reason == "process-replaced"
    assert {event.process_instance for event in _marker_events(executed)} == {
        root.images[1].instance
    }

    fork_exec = _run("fork-exec")
    assert fork_exec.target_exit_code == 0
    child = next(
        process for process in fork_exec.process_tree.processes if process.depth == 1
    )
    assert [image.origin for image in child.images] == ["fork", "exec"]
    assert _marker_events(fork_exec)


@pytest.mark.integration
def test_process_cap_and_fast_child_never_leave_a_gate_stopped(
    native_tools_available,
):
    capped = _run(
        "child-sql",
        config=ControllerConfig(max_followed_processes=1),
    )
    assert capped.target_exit_code == 0
    assert not capped.instrumentation_failed
    assert capped.instrumentation_status == "PARTIAL"
    assert capped.process_tree.omitted_images >= 1
    assert any(
        isinstance(event, InstrumentationError)
        and event.phase == "process_coverage"
        for event in capped.events
    )
    analysis = analyze_run(capped)
    rules = evaluate_rules(analysis, RuleConfig(fail_vm_steps=1_000_000))
    assert "PROCESS_COVERAGE_LOSS" in rules.incomplete_reasons
    assert resolve_outcome(capped, rules).exit_code == 70
    assert capped.exit_code == 0

    fast = _run("fast-child")
    assert fast.target_exit_code == 0
    assert not fast.instrumentation_failed
    assert len(fast.process_tree.processes) >= 2


@pytest.mark.integration
def test_fork_inherited_statement_is_explicit_data_loss(native_tools_available):
    subprocess.run(["make", "-C", str(C_FIXTURE_DIR), "clean", "all"], check=True)
    result = ProcessController().run(
        [str(C_FIXTURE_DIR / "fixture-fork-inherited")]
    )
    inherited = [
        event
        for event in result.events
        if isinstance(event, InstrumentationError)
        and event.phase == "fork_inherited_statement"
    ]
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    assert inherited
    assert all(event.data_loss and not event.fatal for event in inherited)
    assert len({(event.process_instance, event.message) for event in inherited}) == len(
        inherited
    )
    assert "INSTRUMENTATION_DATA_LOSS" in analyze_run(result).incomplete_reasons


@pytest.mark.integration
def test_root_exit_does_not_kill_lingering_child(native_tools_available, tmp_path):
    pid_file = tmp_path / "lingering.json"
    result = _run("lingering", pid_file)
    pid = json.loads(pid_file.read_text(encoding="utf-8"))["pid"]
    try:
        assert result.target_exit_code == 0
        assert not result.instrumentation_failed
        process = next(item for item in result.process_tree.processes if item.pid == pid)
        assert process.active_at_root_exit
        assert os.path.exists(f"/proc/{pid}")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        assert _wait_gone(pid)


@pytest.mark.integration
def test_ctrl_c_kills_adversarial_tree_without_stopped_children(
    native_tools_available, tmp_path,
):
    pid_file = tmp_path / "interrupt-tree.json"
    controller = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "sqlitewatch",
            "--",
            sys.executable,
            str(PYTHON_FIXTURE),
            "adversarial-tree",
            str(pid_file),
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pids = None
    deadline = time.monotonic() + 10.0
    try:
        while time.monotonic() < deadline:
            if controller.poll() is not None:
                raise AssertionError(
                    f"SQLiteWatch exited before interrupt setup: {controller.returncode}"
                )
            try:
                candidate = json.loads(pid_file.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.02)
                continue
            if {"root", "child", "grandchild"} <= candidate.keys():
                pids = candidate
                break
            time.sleep(0.02)
        assert pids is not None, "adversarial process tree did not become ready"
        controller.send_signal(signal.SIGINT)
        assert controller.wait(timeout=10.0) != 0
        assert all(_wait_gone(pid) for pid in pids.values())
    finally:
        if controller.poll() is None:
            controller.kill()
            controller.wait(timeout=5.0)
        if pids is not None:
            for pid in pids.values():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.mark.integration
def test_fatal_timeout_kills_adversarial_tree_deepest_first(
    native_tools_available, tmp_path,
):
    pid_file = tmp_path / "adversarial.json"
    result = _run(
        "adversarial-tree",
        pid_file,
        config=ControllerConfig(completion_timeout=2.0, cleanup_timeout=0.4),
    )
    pids = json.loads(pid_file.read_text(encoding="utf-8"))
    assert result.instrumentation_failed
    assert "timed out" in (result.instrumentation_error or "")
    assert {process.depth for process in result.process_tree.processes} >= {0, 1, 2}
    assert all(_wait_gone(pid) for pid in pids.values())
