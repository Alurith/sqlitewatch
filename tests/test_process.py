import json
import socket

import pytest

from sqlitewatch.events import (
    BackendReady,
    InstrumentationStatus,
    LauncherReady,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)
from sqlitewatch.process import ControllerConfig, ProcessController


class Child:
    pid = 5678
    parent_pid = 1234


class FakeBackend:
    def __init__(self, *, completion=None, child=Child(), fail_load=False, emit_child=True):
        self.calls = []
        self.launcher_callback = None
        self.target_callback = None
        self.child_callback = None
        self.completion = {"pid": 5678, "exit_code": 0, "signal": None} if completion is None else completion
        self.child = child
        self.fail_load = fail_load
        self.emit_child = emit_child
        self.socket_path = None

    def get_local_device(self): self.calls.append("device")

    def spawn(self, argv):
        self.calls.append(("spawn", argv))
        self.socket_path = argv[argv.index("--socket") + 1]
        return 1234

    def attach_launcher(self, pid): self.calls.append(("attach_launcher", pid))
    def enable_child_gating(self): self.calls.append("child_gating")
    def register_child_handler(self, callback): self.calls.append("register_child"); self.child_callback = callback
    def create_launcher_script(self, config): self.calls.append(("create_launcher_script", config.max_sql_length))
    def register_launcher_message_handler(self, callback): self.calls.append("register_launcher"); self.launcher_callback = callback

    def load_launcher(self):
        self.calls.append("load_launcher")
        if self.fail_load: raise RuntimeError("intentional load error")
        self.launcher_callback(LauncherReady(pid=1234))

    def attach_target(self, pid): self.calls.append(("attach_target", pid))
    def create_target_script(self, config): self.calls.append(("create_target_script", config.max_sql_length))
    def register_target_message_handler(self, callback): self.calls.append("register_target"); self.target_callback = callback

    def load_target(self):
        self.calls.append("load_target")
        self.target_callback(InstrumentationStatus(pid=5678, status="ACTIVE", hooks=5))
        self.target_callback(BackendReady(pid=5678))
        self.target_callback(StatementPrepared(5678, 7, "sqlite", "0x1", "0x2", "SELECT 1"))
        self.target_callback(StatementExecuted(5678, 7, "sqlite", "0x1", "0x2", 1, 101, "done", 1, 2, 0, 0))
        self.target_callback(StatementFinalized(5678, 7, "sqlite", "0x1", "0x2", 1, 0))

    def resume(self, pid):
        self.calls.append(("resume", pid))
        if pid == 1234:
            if self.emit_child:
                self.child_callback(self.child)
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.socket_path)
                if isinstance(self.completion, bytes):
                    client.sendall(self.completion)
                else:
                    client.sendall((json.dumps(self.completion) + "\n").encode())

    def terminate_launcher(self, pid): self.calls.append(("terminate_launcher", pid))
    def detach(self): self.calls.append("detach")


def test_launcher_gating_precedes_target_resume_and_socket_status():
    backend = FakeBackend()
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    names = [call[0] if isinstance(call, tuple) else call for call in backend.calls]
    assert names.index("child_gating") < names.index("load_launcher") < names.index("resume")
    assert names.index("attach_target") < names.index("load_target") < names.index("resume", names.index("resume") + 1)
    assert "waitpid" not in names
    assert result.pid == 5678
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    lifecycle = [event for event in result.events if isinstance(event, (StatementPrepared, StatementExecuted, StatementFinalized))]
    assert [type(event) for event in lifecycle] == [StatementPrepared, StatementExecuted, StatementFinalized]
    assert lifecycle[1].vm_steps == 2


@pytest.mark.parametrize("completion", [
    {"pid": 5678, "exit_code": 7, "signal": None},
    {"pid": 5678, "exit_code": None, "signal": 15},
])
def test_socket_completion_preserves_exit_or_signal(completion):
    result = ProcessController(FakeBackend(completion=completion)).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    assert result.target_exit_code == completion["exit_code"]
    assert result.signal == completion["signal"]
    assert not result.instrumentation_failed


@pytest.mark.parametrize("completion", [
    b"",
    b"not-json\n",
    b'{"pid":999,"exit_code":0,"signal":null}\n',
    b'{"pid":5678,"exit_code":0,"signal":null}\n{"pid":5678,"exit_code":0,"signal":null}\n',
])
def test_invalid_socket_completion_fails_instrumentation(completion):
    backend = FakeBackend(completion=completion)
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    assert result.instrumentation_failed
    assert result.instrumentation_status == "FAILED"
    assert ("terminate_launcher", 1234) in backend.calls


def test_unexpected_child_fails_instrumentation():
    child = type("UnexpectedChild", (), {"pid": 8888, "parent_pid": 99})()
    result = ProcessController(FakeBackend(child=child)).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    assert result.instrumentation_failed
    assert "child_gating" in (result.instrumentation_error or "")


def test_child_gating_timeout_fails_instrumentation():
    result = ProcessController(FakeBackend(emit_child=False)).run(
        ["target"], ControllerConfig(backend_ready_timeout=0.01, launcher_ready_timeout=0.1)
    )
    assert result.instrumentation_failed
    assert "child_gating" in (result.instrumentation_error or "")


def test_load_failure_is_instrumentation_failure_and_cleanup_runs():
    backend = FakeBackend(fail_load=True)
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.01, launcher_ready_timeout=0.01))
    assert result.instrumentation_failed
    assert result.instrumentation_status == "FAILED"
    assert "detach" in backend.calls
