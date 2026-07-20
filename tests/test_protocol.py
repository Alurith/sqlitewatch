import pytest

from sqlitewatch.events import InstrumentationError, LauncherReady, ProcessExited
from sqlitewatch.instrumentation.protocol import ProtocolError, event_to_payload, frida_message_to_event, payload_to_event


BASE_EXECUTION = {
    "type": "statement_executed", "protocol_version": 1, "pid": 1, "tid": 1,
    "module": "x", "statement": "0x1", "database": "0x2", "execution_number": 1,
    "sqlite_rc": 101, "boundary": "done",
    "fullscan_steps": 1, "vm_steps": 2, "sorts": 0, "autoindex": 0,
}


def test_process_exit_code_and_signal_are_distinct():
    exited = payload_to_event({"type": "process_exited", "protocol_version": 1, "pid": 9, "exit_code": 7})
    assert isinstance(exited, ProcessExited)
    assert exited.exit_code == 7
    assert exited.signal is None
    signaled = payload_to_event({"type": "process_exited", "protocol_version": 1, "pid": 9, "signal": 15})
    assert signaled.signal == 15


def test_launcher_ready_round_trip():
    event = payload_to_event({"type": "launcher_ready", "protocol_version": 1, "pid": 9})
    assert isinstance(event, LauncherReady)
    assert payload_to_event(event_to_payload(event)) == event


def test_frida_error_is_not_no_activity():
    event = frida_message_to_event({"type": "error", "description": "load failed"})
    assert isinstance(event, InstrumentationError)
    assert event.fatal is True
    assert "load failed" in event.message


def test_protocol_version_and_ids_are_validated():
    with pytest.raises(ProtocolError):
        payload_to_event({"type": "backend_ready", "protocol_version": 2, "pid": 1})
    with pytest.raises(ProtocolError):
        payload_to_event({"type": "backend_ready", "protocol_version": 1, "pid": 0})


@pytest.mark.parametrize("payload, message", [
    ({"type": "statement_executed", "protocol_version": 1}, "missing required fields"),
    ({**BASE_EXECUTION, "execution_number": 0}, "execution_number"),
    ({**BASE_EXECUTION, "boundary": "unknown"}, "boundary"),
    ({
        "type": "statement_finalized", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "1", "database": "0x2", "executions": 0,
        "sqlite_rc": 0,
    }, "statement"),
])
def test_invalid_lifecycle_payloads_are_rejected(payload, message):
    with pytest.raises(ProtocolError, match=message):
        payload_to_event(payload)


@pytest.mark.parametrize("metrics", [
    {"fullscan_steps": None, "vm_steps": 1, "sorts": None, "autoindex": None},
    {"fullscan_steps": -1, "vm_steps": 1, "sorts": 0, "autoindex": 0},
    {"fullscan_steps": True, "vm_steps": 1, "sorts": 0, "autoindex": 0},
    {"fullscan_steps": 1.5, "vm_steps": 1, "sorts": 0, "autoindex": 0},
])
def test_partial_or_invalid_metrics_are_rejected(metrics):
    with pytest.raises(ProtocolError):
        payload_to_event({**BASE_EXECUTION, **metrics})


def test_all_null_metrics_are_valid_but_remain_explicit():
    event = payload_to_event({
        **BASE_EXECUTION,
        "fullscan_steps": None, "vm_steps": None, "sorts": None, "autoindex": None,
    })
    assert event.fullscan_steps is None
    assert event_to_payload(event)["autoindex"] is None


def test_lifecycle_rejects_unknown_fields():
    payload = {
        "type": "statement_finalized", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "0x1", "database": "0x2", "executions": 0,
        "sqlite_rc": 0, "unexpected": True,
    }
    with pytest.raises(ProtocolError, match="unknown fields"):
        payload_to_event(payload)
