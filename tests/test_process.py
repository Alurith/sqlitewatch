import os

from sqlitewatch.events import (
    BackendReady,
    InstrumentationStatus,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)
from sqlitewatch.process import ControllerConfig, ProcessController


class FakeBackend:
    def __init__(self, fail_load=False):
        self.calls = []
        self.callback = None
        self.fail_load = fail_load

    def get_local_device(self):
        self.calls.append("device")

    def spawn(self, argv):
        self.calls.append(("spawn", argv))
        return 1234

    def attach(self, pid):
        self.calls.append(("attach", pid))

    def create_script(self, config):
        self.calls.append(("create_script", config.max_sql_length))

    def register_message_handler(self, callback):
        self.calls.append("register")
        self.callback = callback

    def load(self):
        self.calls.append("load")
        if self.fail_load:
            raise RuntimeError("intentional load error")
        self.callback(InstrumentationStatus(pid=1234, status="ACTIVE", hooks=5))
        self.callback(BackendReady(pid=1234))
        self.callback(StatementPrepared(1234, 7, "sqlite", "0x1", "0x2", "SELECT 1"))
        self.callback(StatementExecuted(1234, 7, "sqlite", "0x1", "0x2", 1, 101, "done"))
        self.callback(StatementFinalized(1234, 7, "sqlite", "0x1", "0x2", 1, 0))

    def resume(self, pid):
        self.calls.append(("resume", pid))

    def waitpid(self, pid):
        self.calls.append(("waitpid", pid))
        return os.waitstatus_to_exitcode(0)  # replaced below by a normal wait status

    def detach(self):
        self.calls.append("detach")


def test_resume_follows_load_and_backend_ready():
    backend = FakeBackend()
    # waitpid returns a raw wait status, not an exit code.
    backend.waitpid = lambda pid: (backend.calls.append(("waitpid", pid)) or 0)
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.1))
    names = [call[0] if isinstance(call, tuple) else call for call in backend.calls]
    assert names.index("load") < names.index("resume") < names.index("waitpid")
    assert result.target_exit_code == 0
    assert not result.instrumentation_failed
    lifecycle = [
        event for event in result.events
        if isinstance(event, (StatementPrepared, StatementExecuted, StatementFinalized))
    ]
    assert [type(event) for event in lifecycle] == [
        StatementPrepared, StatementExecuted, StatementFinalized,
    ]
    assert result.executions[0].boundary == "done"
    assert result.finalized_statements[0].executions == 1


def test_load_failure_is_instrumentation_failure_and_cleanup_runs():
    backend = FakeBackend(fail_load=True)
    result = ProcessController(backend).run(["target"], ControllerConfig(backend_ready_timeout=0.01))
    assert result.instrumentation_failed
    assert result.instrumentation_status == "FAILED"
    assert "detach" in backend.calls
