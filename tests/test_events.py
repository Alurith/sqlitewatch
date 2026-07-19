from sqlitewatch.events import StatementPrepared
from sqlitewatch.instrumentation.protocol import ProtocolError, event_to_payload, payload_to_event


def test_statement_round_trip_unicode_and_pointer_strings():
    event = StatementPrepared(
        pid=123,
        tid=456,
        module="libsqlite3.so.0",
        statement="0x123456",
        database="0x987654",
        sql="SELECT café FROM users WHERE id = ?",
    )
    assert payload_to_event(event_to_payload(event)) == event


def test_truncated_sql_metadata_round_trip():
    event = StatementPrepared(
        pid=1,
        tid=1,
        module="x",
        statement="0x1",
        database="0x2",
        sql="SELECT",
        sql_truncated=True,
        captured_bytes=6,
    )
    assert payload_to_event(event_to_payload(event)).sql_truncated


def test_invalid_payloads_are_rejected():
    base = {
        "type": "statement_prepared",
        "protocol_version": 1,
        "pid": 1,
        "tid": 1,
        "module": "x",
        "statement": "1234",
        "database": "0x2",
        "sql": "SELECT 1",
    }
    try:
        payload_to_event(base)
    except ProtocolError as exc:
        assert "statement" in str(exc)
    else:
        raise AssertionError("invalid pointer was accepted")

    try:
        payload_to_event({"type": "unknown", "protocol_version": 1})
    except ProtocolError:
        pass
    else:
        raise AssertionError("unknown type was accepted")
