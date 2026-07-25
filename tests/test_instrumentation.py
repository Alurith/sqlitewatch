from pathlib import Path

from sqlitewatch.events import InstrumentationError, StatementPrepared
from sqlitewatch.instrumentation.frida_backend import FridaBackend
from sqlitewatch.instrumentation.protocol import ProtocolError, payload_to_events
from sqlitewatch.process import ControllerConfig


PREPARED = {
    "type": "statement_prepared", "protocol_version": 1, "pid": 1, "tid": 1,
    "module": "sqlite", "statement": "0x1", "database": "0x2", "sql": "SELECT 1",
}


def test_batch_expands_in_order_and_rejects_partial_or_non_lifecycle_members():
    payload = {"type": "lifecycle_batch", "protocol_version": 1, "sequence": 1, "events": [PREPARED]}
    events = payload_to_events(payload)
    assert isinstance(events[0], StatementPrepared)
    for invalid in (
        {**payload, "events": []},
        {**payload, "sequence": 0},
        {**payload, "events": [{"type": "backend_ready", "protocol_version": 1, "pid": 1}]},
        {**payload, "unexpected": True},
    ):
        try:
            payload_to_events(invalid)
        except ProtocolError:
            pass
        else:  # pragma: no cover - makes the assertion error useful
            raise AssertionError("invalid batch was accepted")


def test_backend_enforces_monotonic_batch_sequence():
    backend = object.__new__(FridaBackend)
    backend._next_lifecycle_sequence = 1
    received = []
    message = {"type": "send", "payload": {"type": "lifecycle_batch", "protocol_version": 1, "sequence": 1, "events": [PREPARED]}}
    backend._on_message(message, None, received.append)
    assert isinstance(received[0], StatementPrepared)
    backend._on_message(message, None, received.append)
    assert isinstance(received[-1], InstrumentationError)
    assert received[-1].fatal


def test_target_script_injects_private_doctor_flag(tmp_path):
    class ScriptSession:
        def create_script(self, source, name):
            self.source, self.name = source, name
            return object()

    backend = object.__new__(FridaBackend)
    backend.target_session = ScriptSession()
    backend.agent_path = Path(__file__).parents[1] / "src/sqlitewatch/agent/sqlitewatch_agent.js"
    backend.create_target_script(ControllerConfig(doctor=True))
    assert "doctor: true" in backend.target_session.source
    assert "max_sql_length: 65536" in backend.target_session.source
