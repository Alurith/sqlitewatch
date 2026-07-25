from pathlib import Path
from threading import Event

from sqlitewatch.events import InstrumentationError, StatementPrepared
from sqlitewatch.instrumentation.frida_backend import FridaBackend
from sqlitewatch.instrumentation.protocol import ProtocolError, payload_to_events
from sqlitewatch.process import ControllerConfig


PREPARED = {
    "type": "statement_prepared", "protocol_version": 2, "pid": 1, "tid": 1,
    "module": "sqlite", "module_path": "/tmp/sqlite", "module_base": "0x1000",
    "statement": "0x1", "database": "0x2", "sql": "SELECT 1",
    "sql_truncated": False, "captured_bytes": 8, "sql_capture_failed": False,
}


def test_batch_expands_in_order_and_rejects_partial_or_non_lifecycle_members():
    payload = {"type": "lifecycle_batch", "protocol_version": 2, "sequence": 1, "ack_required": False, "events": [PREPARED]}
    events = payload_to_events(payload)
    assert isinstance(events[0], StatementPrepared)
    for invalid in (
        {**payload, "events": []},
        {**payload, "sequence": 0},
        {**payload, "ack_required": 1},
        {**payload, "events": [{"type": "backend_ready", "protocol_version": 2, "pid": 1}]},
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
    message = {"type": "send", "payload": {"type": "lifecycle_batch", "protocol_version": 2, "sequence": 1, "ack_required": False, "events": [PREPARED]}}
    backend._on_message(message, None, received.append)
    assert isinstance(received[0], StatementPrepared)
    backend._on_message(message, None, received.append)
    assert isinstance(received[-1], InstrumentationError)
    assert received[-1].fatal


def test_acknowledged_batch_is_posted_back_only_after_validation():
    class Script:
        def __init__(self):
            self.messages = []

        def post(self, message):
            self.messages.append(message)

    backend = FridaBackend()
    generation = backend.begin_run()
    script = Script()
    received = []
    message = {
        "type": "send",
        "payload": {
            "type": "lifecycle_batch",
            "protocol_version": 2,
            "sequence": 1,
            "ack_required": True,
            "events": [PREPARED],
        },
    }
    backend._handle_script_message(script, message, None, received.append, generation)
    assert isinstance(received[0], StatementPrepared)
    assert script.messages == [{
        "type": "sqlitewatch_ack", "payload": {"sequence": 1}
    }]
    backend._on_message({
        "type": "send",
        "payload": {
            "type": "lifecycle_acknowledged",
            "protocol_version": 2,
            "sequence": 1,
        },
    }, None, received.append, generation)
    backend.detach()


def test_missing_agent_ack_confirmation_becomes_fatal_transport_error():
    class Script:
        def post(self, message):
            pass

    backend = FridaBackend()
    generation = backend.begin_run()
    backend._ack_timeout = 0.01
    failed = Event()
    received = []

    def callback(event):
        received.append(event)
        if isinstance(event, InstrumentationError) and event.fatal:
            failed.set()

    backend._handle_script_message(
        Script(),
        {
            "type": "send",
            "payload": {
                "type": "lifecycle_batch",
                "protocol_version": 2,
                "sequence": 1,
                "ack_required": True,
                "events": [PREPARED],
            },
        },
        None,
        callback,
        generation,
    )
    assert failed.wait(0.5)
    assert "acknowledgement timed out" in received[-1].message
    backend.detach()


def test_backend_resets_sequence_and_ignores_stale_generation_messages():
    backend = FridaBackend()
    first_generation = backend.begin_run()
    first = []
    batch = {
        "type": "send",
        "payload": {
            "type": "lifecycle_batch",
            "protocol_version": 2,
            "sequence": 1,
            "ack_required": False,
            "events": [PREPARED],
        },
    }
    backend._on_message(batch, None, first.append, first_generation)
    assert isinstance(first[0], StatementPrepared)
    backend.detach()

    second_generation = backend.begin_run()
    second = []
    backend._on_message(batch, None, second.append, first_generation)
    assert second == []
    backend._on_message(batch, None, second.append, second_generation)
    assert isinstance(second[0], StatementPrepared)
    backend.detach()


def test_child_added_listener_is_registered_once_across_runs():
    class Device:
        def __init__(self):
            self.listeners = []

        def on(self, name, callback):
            assert name == "child-added"
            self.listeners.append(callback)

    backend = FridaBackend()
    backend.device = Device()
    backend.begin_run()
    backend.register_child_handler(lambda child: None)
    backend.detach()
    backend.begin_run()
    backend.register_child_handler(lambda child: None)
    assert len(backend.device.listeners) == 1
    backend.detach()


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
