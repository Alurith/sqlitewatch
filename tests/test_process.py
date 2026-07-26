import json
import os
import socket
import time

import pytest

from sqlitewatch.events import (
    BackendReady,
    InstrumentationStatus,
    LauncherReady,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)
from sqlitewatch.process import ControllerConfig, ProcessController as RealProcessController


class ProcessController(RealProcessController):
    @staticmethod
    def _peer_credentials(connection):
        return 1234, os.geteuid(), os.getegid()

    def _same_process_alive(self, pid):
        return pid in getattr(self.backend, "alive", set())


class Child:
    pid = 5678
    parent_pid = 1234


class FakeBackend:
    def __init__(self, *, completion=None, child=Child(), fail_load=False, emit_child=True, interrupt_target=False):
        self.calls = []
        self.alive = {1234}
        self.launcher_callback = None
        self.target_callback = None
        self.child_callback = None
        self.completion = {"pid": 5678, "exit_code": 0, "signal": None} if completion is None else completion
        self.child = child
        self.fail_load = fail_load
        self.emit_child = emit_child
        self.interrupt_target = interrupt_target
        self.socket_path = None

    def get_local_device(self): self.calls.append("device")

    def spawn(self, argv):
        self.calls.append(("spawn", argv))
        self.socket_path = argv[argv.index("--socket") + 1]
        return 1234

    def attach_launcher(self, pid): self.calls.append(("attach_launcher", pid))
    def enable_child_gating(self): self.calls.append("child_gating")
    def disable_child_gating(self): self.calls.append("disable_child_gating")
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
        instance = "p5678-i1"
        self.target_callback(InstrumentationStatus(
            pid=5678, status="ACTIVE", hooks=5, process_instance=instance,
        ))
        self.target_callback(BackendReady(pid=5678, process_instance=instance))
        self.target_callback(StatementPrepared(
            5678, 7, "sqlite", "0x1", "0x2", "SELECT 1",
            process_instance=instance,
        ))
        self.target_callback(StatementExecuted(
            5678, 7, "sqlite", "0x1", "0x2", 1, 101, "done", 1, 2, 0, 0,
            process_instance=instance,
        ))
        self.target_callback(StatementFinalized(
            5678, 7, "sqlite", "0x1", "0x2", 1, 0,
            process_instance=instance,
        ))

    def resume(self, pid):
        self.calls.append(("resume", pid))
        if pid == 1234:
            if self.emit_child:
                self.alive.add(5678)
                self.child_callback(self.child)
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(self.socket_path)
                if isinstance(self.completion, bytes):
                    client.sendall(self.completion)
                else:
                    client.sendall((json.dumps(self.completion) + "\n").encode())
            if self.interrupt_target:
                raise KeyboardInterrupt
            self.alive.discard(5678)
            self.alive.discard(1234)

    def terminate_launcher(self, pid, signum=None):
        self.calls.append(("terminate_launcher", pid, signum))
        self.alive.discard(pid)
        self.alive.discard(5678)
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


def test_controller_passes_stdout_redirection_only_when_requested_to_launcher():
    backend = FakeBackend()
    ProcessController(backend).run(
        ["target"],
        ControllerConfig(target_stdout_to_stderr=True, backend_ready_timeout=0.1, launcher_ready_timeout=0.1),
    )
    launcher_argv = next(call[1] for call in backend.calls if isinstance(call, tuple) and call[0] == "spawn")
    assert launcher_argv.index("--target-stdout-to-stderr") < launcher_argv.index("--")



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
    assert not backend.alive


def test_unexpected_child_fails_instrumentation():
    child = type("UnexpectedChild", (), {"pid": 8888, "parent_pid": 99})()
    result = ProcessController(FakeBackend(child=child)).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    assert result.instrumentation_failed
    assert "child_gating" in (result.instrumentation_error or "")


def test_ctrl_c_forwards_signal_and_reaps_launcher_target():
    backend = FakeBackend(
        completion={"pid": 5678, "exit_code": None, "signal": 2}, interrupt_target=True
    )
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.1, launcher_ready_timeout=0.1))
    assert result.signal == 2
    assert not result.instrumentation_failed
    assert ("terminate_launcher", 1234, 2) in backend.calls


def test_child_gating_timeout_fails_instrumentation():
    result = ProcessController(FakeBackend(emit_child=False)).run(
        ["target"], ControllerConfig(backend_ready_timeout=0.01, launcher_ready_timeout=0.1)
    )
    assert result.instrumentation_failed
    assert "child_gating" in (result.instrumentation_error or "")


def test_materialized_retention_limit_fails_clearly_but_streaming_drops_lifecycle():
    limited = ProcessController(FakeBackend()).run(
        ["target"],
        ControllerConfig(
            backend_ready_timeout=0.1,
            launcher_ready_timeout=0.1,
            max_retained_events=4,
        ),
    )
    assert limited.instrumentation_failed
    assert "event retention limit exceeded" in (limited.instrumentation_error or "")

    consumed = []
    streamed = ProcessController(FakeBackend()).run(
        ["target"],
        ControllerConfig(
            backend_ready_timeout=0.1,
            launcher_ready_timeout=0.1,
            max_retained_events=4,
        ),
        event_consumer=consumed.append,
        retain_events=False,
    )
    assert not streamed.instrumentation_failed
    assert any(isinstance(event, StatementExecuted) for event in consumed)
    assert not any(
        isinstance(event, (StatementPrepared, StatementExecuted, StatementFinalized))
        for event in streamed.events
    )


def test_linux_process_parent_identity_matches_proc():
    assert RealProcessController._process_parent_pid(os.getpid()) == os.getppid()


def test_completion_peer_must_be_launcher_and_same_uid(monkeypatch):
    controller = RealProcessController()
    monkeypatch.setattr(
        controller, "_peer_credentials", lambda connection: (999, os.geteuid(), os.getegid())
    )
    with pytest.raises(RuntimeError, match="not launcher"):
        controller._authenticate_peer(object(), 1234)
    monkeypatch.setattr(
        controller, "_peer_credentials", lambda connection: (1234, os.geteuid() + 1, os.getegid())
    )
    with pytest.raises(RuntimeError, match="does not match"):
        controller._authenticate_peer(object(), 1234)


def test_load_failure_is_instrumentation_failure_and_cleanup_runs():
    backend = FakeBackend(fail_load=True)
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.01, launcher_ready_timeout=0.01))
    assert result.instrumentation_failed
    assert result.instrumentation_status == "FAILED"
    assert "detach" in backend.calls


class TreeChild:
    def __init__(self, pid, parent_pid, origin="spawn", identifier=None):
        self.pid = pid
        self.parent_pid = parent_pid
        self.origin = origin
        self.identifier = identifier


class TreeBackend:
    def __init__(
        self,
        *,
        fail_pid=None,
        unknown_parent=False,
        exec_root=False,
        posix_spawn_child=False,
        lingering=False,
        emit_grandchild=True,
    ):
        self.calls = []
        self.alive = {50}
        self.fail_pid = fail_pid
        self.unknown_parent = unknown_parent
        self.exec_root = exec_root
        self.posix_spawn_child = posix_spawn_child
        self.lingering = lingering
        self.emit_grandchild = emit_grandchild
        self.socket_path = None
        self.child_callback = None
        self.callbacks = {}
        self.detached_callbacks = {}
        self.streams = set()
        self.resumed = []
        self._completion_sent = False
        self._root_resume_count = 0
        self.pending_ack_count = 0

    def begin_run(self):
        self.calls.append("begin_run")

    def get_local_device(self):
        self.calls.append("device")

    def spawn(self, argv):
        self.socket_path = argv[argv.index("--socket") + 1]
        self.calls.append(("spawn", tuple(argv)))
        return 50

    def attach_launcher(self, pid):
        self.calls.append(("attach_launcher", pid))

    def register_launcher_detached_handler(self, callback):
        self.launcher_detached = callback

    def enable_child_gating(self):
        self.calls.append(("launcher_gate", "enable"))

    def disable_child_gating(self):
        self.calls.append(("launcher_gate", "disable"))

    def register_child_handler(self, callback):
        self.child_callback = callback

    def register_child_removed_handler(self, callback):
        self.child_removed_callback = callback

    def create_launcher_script(self, config):
        self.calls.append("create_launcher")

    def register_launcher_message_handler(self, callback):
        self.launcher_callback = callback

    def load_launcher(self):
        self.calls.append("load_launcher")
        self.launcher_callback(LauncherReady(50))

    def attach_process(self, instance, pid):
        self.calls.append(("attach", instance, pid))
        if pid == self.fail_pid:
            raise RuntimeError("intentional descendant attach failure")
        self.streams.add(instance)

    def register_process_detached_handler(self, instance, callback):
        self.detached_callbacks[instance] = callback

    def enable_process_child_gating(self, instance):
        self.calls.append(("gate", instance))

    def disable_process_child_gating(self, instance):
        self.calls.append(("ungate", instance))

    def create_process_script(self, instance, config):
        self.calls.append(("create", instance))

    def register_process_message_handler(self, instance, callback):
        self.callbacks[instance] = callback

    def load_process(self, instance):
        self.calls.append(("load", instance))
        pid = int(instance.split("-", 1)[0][1:])
        callback = self.callbacks[instance]
        callback(InstrumentationStatus(
            "ACTIVE", pid, hooks=5, process_instance=instance,
        ))
        callback(BackendReady(pid, process_instance=instance))

    def process_instances(self):
        return tuple(sorted(self.streams))

    def detach_process(self, instance):
        self.calls.append(("detach_process", instance))
        self.streams.discard(instance)

    def release_pending_children(self):
        self.calls.append("release_pending")
        return ()

    def resume(self, pid):
        self.calls.append(("resume", pid))
        self.resumed.append(pid)
        if pid == 50:
            self.alive.add(100)
            self.child_callback(TreeChild(100, 50, "exec", "root"))
            return
        if pid == 100:
            self._root_resume_count += 1
            if self.exec_root and self._root_resume_count == 1:
                self.detached_callbacks["p100-i1"]("process-replaced")
                self.child_callback(TreeChild(100, 100, "exec", "root-exec"))
                return
            if self._root_resume_count == 1 and not self.exec_root:
                parent = 999 if self.unknown_parent else 100
                origin = "spawn"
                if self.posix_spawn_child:
                    parent = 101
                    origin = "exec"
                self.alive.add(101)
                self.child_callback(TreeChild(101, parent, origin, "child"))
                return
            self._send_completion()
            return
        if pid == 101:
            if self.fail_pid == 101 or not self.emit_grandchild or self.lingering:
                if not self.lingering:
                    self.alive.discard(101)
                self._send_completion()
            else:
                self.alive.add(102)
                self.child_callback(TreeChild(102, 101, "fork", "grandchild"))
            return
        if pid == 102:
            self.alive.discard(102)
            self.alive.discard(101)
            self._send_completion()

    def _send_completion(self):
        if self._completion_sent:
            return
        self._completion_sent = True
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(self.socket_path)
            client.sendall(b'{"pid":100,"exit_code":0,"signal":null}\n')
        self.alive.discard(100)
        self.alive.discard(50)

    def signal_process(self, pid, signum):
        self.calls.append(("signal", pid, signum))
        self.alive.discard(pid)

    def terminate_launcher(self, pid, signum=None):
        self.calls.append(("terminate_launcher", pid, signum))
        self.alive.discard(50)
        self.alive.discard(100)
        self._send_completion()

    def detach(self):
        self.calls.append("detach")
        self.streams.clear()


class TreeProcessController(ProcessController):
    @staticmethod
    def _peer_credentials(connection):
        return 50, os.geteuid(), os.getegid()

    def _same_process_alive(self, pid):
        return pid in self.backend.alive


def _tree_config(**changes):
    values = {
        "backend_ready_timeout": 0.1,
        "launcher_ready_timeout": 0.1,
        "cleanup_timeout": 0.15,
    }
    values.update(changes)
    return ControllerConfig(**values)


def test_child_queue_overflow_emergency_resumes_and_fails_without_attaching():
    backend = TreeBackend()
    controller = TreeProcessController(backend)
    config = _tree_config(max_pending_children=1)
    controller._reset_state(
        config=config,
        event_consumer=None,
        retain_events=True,
        max_retained_events=config.max_retained_events,
    )
    controller._on_child_added(TreeChild(201, 100))
    controller._on_child_added(TreeChild(202, 100))
    assert controller._instrumentation_failed
    assert "queue overflow" in (controller._error_message or "")
    assert 202 in backend.resumed
    assert not any(
        isinstance(call, tuple) and call[:2] == ("attach", "p202-i1")
        for call in backend.calls
    )


def test_recursive_follow_attaches_root_child_and_grandchild_before_each_resume():
    backend = TreeBackend()
    result = TreeProcessController(backend).run(["target"], _tree_config())
    assert not result.instrumentation_failed
    assert result.instrumentation_status == "ACTIVE"
    assert [process.pid for process in result.process_tree.processes] == [100, 101, 102]
    assert [process.depth for process in result.process_tree.processes] == [0, 1, 2]
    for pid in (100, 101, 102):
        instance = f"p{pid}-i1"
        assert backend.calls.index(("attach", instance, pid)) < backend.calls.index(("load", instance))
        assert backend.calls.index(("load", instance)) < backend.calls.index(("resume", pid))
        assert backend.calls.index(("gate", instance)) < backend.calls.index(("resume", pid))


def test_linux_posix_spawn_exec_only_child_recovers_parent_from_proc(monkeypatch):
    backend = TreeBackend(posix_spawn_child=True, emit_grandchild=False)
    monkeypatch.setattr(
        TreeProcessController,
        "_process_parent_pid",
        staticmethod(lambda pid: 100 if pid == 101 else None),
    )
    result = TreeProcessController(backend).run(["target"], _tree_config())
    assert not result.instrumentation_failed
    child = next(process for process in result.process_tree.processes if process.pid == 101)
    assert child.parent_pid == 100
    assert child.images[0].origin == "exec"
    assert backend.resumed.count(101) == 1


def test_descendant_attach_failure_and_process_cap_release_child_with_coverage_loss():
    failed_backend = TreeBackend(fail_pid=101, emit_grandchild=False)
    failed = TreeProcessController(failed_backend).run(["target"], _tree_config())
    assert not failed.instrumentation_failed
    assert failed.instrumentation_status == "PARTIAL"
    assert 101 in failed_backend.resumed
    assert any(
        getattr(event, "phase", None) == "process_coverage"
        for event in failed.events
    )

    capped_backend = TreeBackend(emit_grandchild=False)
    capped = TreeProcessController(capped_backend).run(
        ["target"], _tree_config(max_followed_processes=1)
    )
    assert not capped.instrumentation_failed
    assert capped.instrumentation_status == "PARTIAL"
    assert capped.process_tree.omitted_images == 1
    assert 101 in capped_backend.resumed


def test_unknown_ancestry_is_fatal_and_known_tree_is_cleaned():
    backend = TreeBackend(unknown_parent=True, emit_grandchild=False)
    result = TreeProcessController(backend).run(["target"], _tree_config())
    assert result.instrumentation_failed
    assert "not in scope" in (result.instrumentation_error or "")
    assert not backend.alive
    assert 101 in backend.resumed


def test_process_replaced_without_exec_child_is_bounded_and_fatal():
    backend = TreeBackend()
    controller = TreeProcessController(backend)
    config = _tree_config(exec_replacement_timeout=0.01)
    controller._reset_state(
        config=config,
        event_consumer=None,
        retain_events=True,
        max_retained_events=config.max_retained_events,
    )
    admission = controller._tree.admit_root(100, start_token="token")
    controller._tree.mark_instrumented(admission.instance)
    controller._on_stream_detached(admission.instance, 100, "process-replaced")
    controller._service_detach_notices(config)
    time.sleep(0.02)
    controller._check_exec_replacement_timeouts()
    assert controller._instrumentation_failed
    assert "exec replacement" in (controller._error_message or "")


def test_same_pid_exec_creates_new_stream_and_process_replaced_is_not_failure():
    backend = TreeBackend(exec_root=True, emit_grandchild=False)
    result = TreeProcessController(backend).run(["target"], _tree_config())
    assert not result.instrumentation_failed
    root = result.process_tree.processes[0]
    assert [image.instance for image in root.images] == ["p100-i1", "p100-i2"]
    assert root.images[0].detach_reason == "process-replaced"
    assert backend.resumed.count(100) == 2
    assert ("load", "p100-i2") in backend.calls


def test_explicit_root_only_releases_child_without_declaring_coverage_loss():
    backend = TreeBackend(emit_grandchild=False)
    result = TreeProcessController(backend).run(
        ["target"], _tree_config(follow_children=False)
    )
    assert not result.instrumentation_failed
    assert result.process_tree.follow_children is False
    assert result.process_tree.complete
    assert [process.pid for process in result.process_tree.processes] == [100]
    assert 101 in backend.resumed
    assert not any(
        getattr(event, "phase", None) == "process_coverage"
        for event in result.events
    )
    assert ("gate", "p100-i1") not in backend.calls


def test_root_completion_does_not_kill_lingering_child_and_marks_inventory():
    backend = TreeBackend(lingering=True, emit_grandchild=False)
    result = TreeProcessController(backend).run(["target"], _tree_config())
    assert not result.instrumentation_failed
    child = next(process for process in result.process_tree.processes if process.pid == 101)
    assert child.active_at_root_exit
    assert 101 in backend.alive
    assert not any(
        call[0] == "signal" and call[1] == 101
        for call in backend.calls if isinstance(call, tuple)
    )
