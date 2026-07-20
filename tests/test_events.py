import pytest

from sqlitewatch.events import (
    RunResult,
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
)
from sqlitewatch.instrumentation.protocol import ProtocolError, event_to_payload, payload_to_event


def test_statement_round_trip_unicode_and_pointer_strings():
    event = StatementPrepared(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", sql="SELECT café FROM users WHERE id = ?",
    )
    assert payload_to_event(event_to_payload(event)) == event


def test_truncated_sql_metadata_round_trip():
    event = StatementPrepared(
        pid=1, tid=1, module="x", statement="0x1", database="0x2", sql="SELECT",
        sql_truncated=True, captured_bytes=6,
    )
    assert payload_to_event(event_to_payload(event)).sql_truncated


@pytest.mark.parametrize("event", [
    StatementExecuted(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", execution_number=2, sqlite_rc=101, boundary="done",
    ),
    StatementFinalized(
        pid=123, tid=456, module="libsqlite3.so.0", statement="0x123456",
        database="0x987654", executions=2, sqlite_rc=0,
    ),
])
def test_lifecycle_events_round_trip(event):
    payload = event_to_payload(event)
    assert payload["protocol_version"] == 1
    assert payload_to_event(payload) == event


def test_run_result_exposes_lifecycle_collections_without_changing_prepared_alias():
    prepared = StatementPrepared(1, 1, "x", "0x1", "0x2", "SELECT 1")
    executed = StatementExecuted(1, 1, "x", "0x1", "0x2", 1, 101, "done")
    finalized = StatementFinalized(1, 1, "x", "0x1", "0x2", 1, 0)
    result = RunResult(1, 0, None, events=(prepared, executed, finalized))
    assert result.statements == (prepared,)
    assert result.executions == (executed,)
    assert result.finalized_statements == (finalized,)


def test_invalid_payloads_are_rejected():
    base = {
        "type": "statement_prepared", "protocol_version": 1, "pid": 1, "tid": 1,
        "module": "x", "statement": "1234", "database": "0x2", "sql": "SELECT 1",
    }
    with pytest.raises(ProtocolError, match="statement"):
        payload_to_event(base)
    with pytest.raises(ProtocolError):
        payload_to_event({"type": "unknown", "protocol_version": 1})
