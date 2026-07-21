from sqlitewatch import cli
from sqlitewatch.events import InstrumentationError, RunResult, StatementExecuted, StatementFinalized, StatementPrepared


def _result():
    events = (
        StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1"),
        StatementExecuted(1, 1, "sqlite", "0x1", "0x2", 1, 101, "done", 0, 2, 0, 0),
        StatementFinalized(1, 1, "sqlite", "0x1", "0x2", 1, 0),
        InstrumentationError("stmt_status", "transient", fatal=False),
    )
    return RunResult(1, 7, None, events, "ACTIVE")


def test_cli_renders_analysis_not_raw_lifecycle_and_preserves_status(monkeypatch, capsys):
    class Controller:
        def run(self, target, config):
            assert target == ["target"]
            assert config.max_sql_length == 16
            return _result()

    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    assert cli.main(["--max-sql-length", "16", "--", "target"]) == 7
    captured = capsys.readouterr()
    assert "SQLiteWatch analysis" in captured.out
    assert "Target exited with code 7" in captured.out
    assert "statement_prepared" not in captured.out
    assert "statement_executed" not in captured.out
    assert "statement_finalized" not in captured.out
    assert "[instrumentation_error] stmt_status: transient" in captured.err


def test_cli_parser_does_not_accept_future_output_options(capsys):
    assert cli.main(["--format", "json", "--", "target"]) == 2
    assert "unknown SQLiteWatch option" in capsys.readouterr().err
