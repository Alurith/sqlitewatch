import json
from pathlib import Path

import pytest

from sqlitewatch import cli
from sqlitewatch.events import InstrumentationError, RunResult, StatementExecuted, StatementFinalized, StatementPrepared


def _result(*, exit_code=0, status="ACTIVE", instrumentation_failed=False):
    events = (
        StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1"),
        StatementExecuted(1, 1, "sqlite", "0x1", "0x2", 1, 101, "done", 2, 9, 0, 0),
        StatementFinalized(1, 1, "sqlite", "0x1", "0x2", 1, 0),
        InstrumentationError("stmt_status", "transient", fatal=False),
    )
    return RunResult(1, exit_code, None, events, status, instrumentation_failed)


def test_parser_accepts_ci_options_before_delimiter_and_preserves_target_arguments():
    config, target = cli._parse([
        "--max-sql-length=16", "--fail-fullscan-steps", "0", "--fail-vm-steps=4",
        "--fail-on-autoindex", "--format=json", "--output", "report.json", "--",
        "target", "--format", "json",
    ])
    assert config.controller.max_sql_length == 16
    assert config.rules.fail_fullscan_steps == 0
    assert config.rules.fail_vm_steps == 4
    assert config.rules.fail_on_autoindex is True
    assert config.format == "json"
    assert config.output == Path("report.json")
    assert config.controller.target_stdout_to_stderr is False
    assert target == ["target", "--format", "json"]


def test_parser_defaults_and_json_stdout_redirection():
    config, target = cli._parse(["--format", "json", "--", "target"])
    assert config.output is None
    assert config.controller.target_stdout_to_stderr is True
    assert target == ["target"]


@pytest.mark.parametrize("args", [
    ["--max-sql-length", "0", "--", "target"],
    ["--fail-fullscan-steps", "-1", "--", "target"],
    ["--fail-vm-steps=bad", "--", "target"],
    ["--format", "yaml", "--", "target"],
    ["--output=", "--", "target"],
    ["--fail-vm-steps", "--", "target"],
])
def test_parser_rejects_invalid_ci_option_values(args, capsys):
    assert cli.main(args) == 2
    assert "usage: sqlitewatch" in capsys.readouterr().err


def test_cli_renders_complete_json_and_preserves_nonfatal_diagnostics(monkeypatch, capsys):
    class Controller:
        def run(self, target, config):
            assert target == ["target"]
            assert config.max_sql_length == 16
            assert config.target_stdout_to_stderr is True
            return _result()

    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    assert cli.main(["--max-sql-length", "16", "--format", "json", "--", "target"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == 1
    assert payload["outcome"]["exit_code"] == 0
    assert "Target exited" not in captured.out
    assert "SQLiteWatch analysis" not in captured.out
    assert "[instrumentation_error] stmt_status: transient" in captured.err


def test_cli_writes_report_to_file_without_duplication_or_target_redirection(monkeypatch, capsys, tmp_path):
    destination = tmp_path / "report.json"

    class Controller:
        def run(self, target, config):
            assert config.target_stdout_to_stderr is False
            return _result(exit_code=7)

    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    assert cli.main(["--format=json", "--output", str(destination), "--", "target"]) == 7
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(destination.read_text(encoding="utf-8"))["outcome"]["exit_code"] == 7


def test_cli_classifies_internal_and_output_errors(monkeypatch, capsys, tmp_path):
    class BrokenController:
        def run(self, target, config):
            raise RuntimeError("broken controller")

    monkeypatch.setattr(cli, "ProcessController", lambda: BrokenController())
    assert cli.main(["--", "target"]) == 70
    assert "instrumentation failure" in capsys.readouterr().err

    class Controller:
        def run(self, target, config):
            return _result(exit_code=7)

    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    monkeypatch.setattr(cli, "write_report", lambda path, content: (_ for _ in ()).throw(OSError("disk full")))
    assert cli.main(["--output", str(tmp_path / "report.txt"), "--", "target"]) == 74
    assert "previous outcome exit code: 7" in capsys.readouterr().err
