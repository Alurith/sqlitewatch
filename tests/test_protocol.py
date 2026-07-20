import pytest

from sqlitewatch.events import InstrumentationError, ProcessExited
from sqlitewatch.instrumentation.protocol import ProtocolError, frida_message_to_event, payload_to_event


def test_process_exit_code_and_signal_are_distinct():
    exited = payload_to_event({"type": "process_exited", "protocol_version": 1, "pid": 9, "exit_code": 7})
    assert isinstance(exited, ProcessExited)
    assert exited.exit_code == 7
    assert exited.signal is None
    signaled = payload_to_event({"type": "process_exited", "protocol_version": 1, "pid": 9, "signal": 15})
    assert signaled.signal == 15


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
    ({
        "type": "statement_executed", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "0x1", "database": "0x2", "execution_number": 0,
        "sqlite_rc": 101, "boundary": "done",
    }, "execution_number"),
    ({
        "type": "statement_executed", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "0x1", "database": "0x2", "execution_number": 1,
        "sqlite_rc": 101, "boundary": "unknown",
    }, "boundary"),
    ({
        "type": "statement_finalized", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "1", "database": "0x2", "executions": 0,
        "sqlite_rc": 0,
    }, "statement"),
])
def test_invalid_lifecycle_payloads_are_rejected(payload, message):
    with pytest.raises(ProtocolError, match=message):
        payload_to_event(payload)


def test_lifecycle_rejects_unknown_fields():
    payload = {
        "type": "statement_finalized", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "0x1", "database": "0x2", "executions": 0,
        "sqlite_rc": 0, "unexpected": True,
    }
    with pytest.raises(ProtocolError, match="unknown fields"):
        payload_to_event(payload)
