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
    payload = {"type": "backend_ready", "protocol_version": 2, "pid": 1}
    try:
        payload_to_event(payload)
    except ProtocolError:
        pass
    else:
        raise AssertionError("unsupported protocol version accepted")
    try:
        payload_to_event({"type": "backend_ready", "protocol_version": 1, "pid": 0})
    except ProtocolError:
        pass
    else:
        raise AssertionError("invalid pid accepted")
