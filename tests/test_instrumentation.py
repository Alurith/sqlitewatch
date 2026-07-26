from pathlib import Path
from threading import Event

from sqlitewatch.events import InstrumentationError, StatementPrepared
from sqlitewatch.instrumentation.frida_backend import FridaBackend
from sqlitewatch.instrumentation.protocol import ProtocolError, payload_to_events
from sqlitewatch.process import ControllerConfig


def prepared(instance="p1-i1", pid=1):
    return {
        "type": "statement_prepared", "protocol_version": 3,
        "process_instance": instance, "pid": pid, "tid": 1,
        "module": "sqlite", "module_path": "/tmp/sqlite", "module_base": "0x1000",
        "statement": "0x1", "database": "0x2", "sql": "SELECT 1",
        "sql_truncated": False, "captured_bytes": 8, "sql_capture_failed": False,
    }


def batch(instance="p1-i1", pid=1, sequence=1, ack=False):
    return {
        "type": "send",
        "payload": {
            "type": "lifecycle_batch", "protocol_version": 3,
            "process_instance": instance, "sequence": sequence,
            "ack_required": ack, "events": [prepared(instance, pid)],
        },
    }


class Script:
    def __init__(self, source="", name=""):
        self.source = source
        self.name = name
        self.handlers = {}
        self.messages = []
        self.loaded = False

    def on(self, name, callback):
        self.handlers[name] = callback

    def post(self, message):
        self.messages.append(message)

    def load(self):
        self.loaded = True

    def emit(self, message):
        self.handlers["message"](message, None)


class Session:
    def __init__(self):
        self.handlers = {}
        self.scripts = []
        self.gating = False
        self.detached = False

    def on(self, name, callback):
        self.handlers[name] = callback

    def create_script(self, source, name):
        script = Script(source, name)
        self.scripts.append(script)
        return script

    def enable_child_gating(self):
        self.gating = True

    def disable_child_gating(self):
        self.gating = False

    def detach(self):
        self.detached = True


class Device:
    def __init__(self):
        self.listeners = {}
        self.sessions = {}
        self.resumed = []
        self.pending = []

    def on(self, name, callback):
        self.listeners.setdefault(name, []).append(callback)

    def attach(self, pid):
        session = Session()
        self.sessions[pid] = session
        return session

    def resume(self, pid):
        self.resumed.append(pid)

    def enumerate_pending_children(self):
        return self.pending


def configured_backend():
    backend = FridaBackend()
    backend.device = Device()
    backend.begin_run()
    return backend


def setup_stream(backend, instance, pid, callback):
    backend.attach_process(instance, pid)
    backend.create_process_script(instance, ControllerConfig())
    backend.register_process_message_handler(instance, callback)
    return backend._streams[instance].script


def test_batch_expands_in_order_and_rejects_partial_or_non_lifecycle_members():
    payload = batch()["payload"]
    events = payload_to_events(payload)
    assert isinstance(events[0], StatementPrepared)
    for invalid in (
        {**payload, "events": []},
        {**payload, "sequence": 0},
        {**payload, "ack_required": 1},
        {
            **payload,
            "events": [{
                "type": "backend_ready", "protocol_version": 3,
                "process_instance": "p1-i1", "pid": 1,
            }],
        },
        {**payload, "unexpected": True},
    ):
        try:
            payload_to_events(invalid)
        except ProtocolError:
            pass
        else:  # pragma: no cover
            raise AssertionError("invalid batch was accepted")


def test_two_streams_accept_sequence_one_and_ack_only_their_own_script():
    backend = configured_backend()
    first, second = [], []
    script_one = setup_stream(backend, "p1-i1", 1, first.append)
    script_two = setup_stream(backend, "p2-i1", 2, second.append)

    script_one.emit(batch("p1-i1", 1, ack=True))
    script_two.emit(batch("p2-i1", 2, ack=True))
    assert isinstance(first[0], StatementPrepared)
    assert isinstance(second[0], StatementPrepared)
    assert script_one.messages[0]["payload"]["process_instance"] == "p1-i1"
    assert script_two.messages[0]["payload"]["process_instance"] == "p2-i1"
    assert backend.pending_ack_count == 2

    script_one.emit({
        "type": "send",
        "payload": {
            "type": "lifecycle_acknowledged", "protocol_version": 3,
            "process_instance": "p1-i1", "sequence": 1,
        },
    })
    assert backend.pending_ack_count == 1
    script_two.emit({
        "type": "send",
        "payload": {
            "type": "lifecycle_acknowledged", "protocol_version": 3,
            "process_instance": "p2-i1", "sequence": 1,
        },
    })
    assert backend.pending_ack_count == 0
    backend.detach()


def test_sequence_pid_and_process_instance_are_stream_scoped_and_strict():
    backend = configured_backend()
    received = []
    script = setup_stream(backend, "p1-i1", 1, received.append)
    script.emit(batch("p1-i1", 1))
    assert isinstance(received[-1], StatementPrepared)
    script.emit(batch("p1-i1", 1))
    assert isinstance(received[-1], InstrumentationError)
    assert received[-1].fatal

    other = setup_stream(backend, "p2-i1", 2, received.append)
    other.emit(batch("p2-i1", 99))
    assert isinstance(received[-1], InstrumentationError)
    assert "pid" in received[-1].message
    other.emit(batch("p1-i1", 2))
    assert isinstance(received[-1], InstrumentationError)
    assert "process_instance" in received[-1].message
    backend.detach()


def test_timeout_and_detach_of_one_stream_do_not_remove_another_ack():
    backend = configured_backend()
    backend._ack_timeout = 0.02
    failed = Event()
    first, second = [], []

    def first_callback(event):
        first.append(event)
        if isinstance(event, InstrumentationError):
            failed.set()

    script_one = setup_stream(backend, "p1-i1", 1, first_callback)
    script_two = setup_stream(backend, "p2-i1", 2, second.append)
    # create_process_script resets the configured timeout, so set it afterwards.
    backend._ack_timeout = 0.02
    script_one.emit(batch("p1-i1", 1, ack=True))
    script_two.emit(batch("p2-i1", 2, ack=True))
    backend.detach_process("p2-i1")
    assert backend.pending_ack_count == 1
    assert failed.wait(0.5)
    assert "p1-i1" in first[-1].message
    assert not any(isinstance(event, InstrumentationError) for event in second)
    backend.detach()


def test_stale_callback_after_stream_detach_or_new_generation_is_ignored():
    backend = configured_backend()
    first = []
    script = setup_stream(backend, "p1-i1", 1, first.append)
    stale_handler = script.handlers["message"]
    backend.detach_process("p1-i1")
    stale_handler(batch("p1-i1", 1), None)
    assert first == []
    backend.detach()

    backend.begin_run()
    second = []
    new_script = setup_stream(backend, "p1-i1", 1, second.append)
    stale_handler(batch("p1-i1", 1), None)
    assert second == []
    new_script.emit(batch("p1-i1", 1))
    assert isinstance(second[0], StatementPrepared)
    backend.detach()


def test_child_listeners_are_registered_once_and_callbacks_change_per_run():
    backend = FridaBackend()
    backend.device = Device()
    observed = []
    backend.begin_run()
    backend.register_child_handler(lambda child: observed.append(("first", child)))
    backend.register_child_removed_handler(lambda child: observed.append(("removed", child)))
    backend.detach()
    backend.begin_run()
    backend.register_child_handler(lambda child: observed.append(("second", child)))
    backend.register_child_removed_handler(lambda child: observed.append(("removed2", child)))
    assert len(backend.device.listeners["child-added"]) == 1
    assert len(backend.device.listeners["child-removed"]) == 1
    backend.device.listeners["child-added"][0](123)
    backend.device.listeners["child-removed"][0](123)
    assert observed == [("second", 123), ("removed2", 123)]
    backend.detach()


def test_detach_releases_pending_children_and_registry_is_reusable():
    backend = configured_backend()
    child = type("Child", (), {"pid": 33})()
    backend.device.pending = [child]
    setup_stream(backend, "p1-i1", 1, lambda event: None)
    backend.enable_process_child_gating("p1-i1")
    backend.detach()
    assert backend.device.resumed == [33]
    assert backend.process_instances() == ()
    backend.begin_run()
    setup_stream(backend, "p2-i1", 2, lambda event: None)
    backend.detach()


def test_process_script_injects_private_doctor_and_stream_identity():
    backend = configured_backend()
    backend.attach_process("p42-i2", 42)
    script = backend.create_process_script(
        "p42-i2", ControllerConfig(doctor=True)
    )
    assert '"doctor":true' in script.source
    assert '"max_sql_length":65536' in script.source
    assert '"process_instance":"p42-i2"' in script.source
    backend.detach()
