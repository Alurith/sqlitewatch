import json

from sqlitewatch import cli
from sqlitewatch.events import ModuleCapability, RunResult, StatementPrepared


MODULE = ModuleCapability(
    1, "libsqlite3.so", "/usr/lib/libsqlite3.so", "dynamic", True, True,
    ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step", "sqlite3_stmt_status"),
    ("sqlite3_libversion", "sqlite3_prepare_v3"), True,
    ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step"),
    ("sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step"), (), (), "3.45",
)


def test_doctor_parser_is_separate_and_json_stdout_is_clean(monkeypatch, capsys):
    class Controller:
        def run(self, target, config):
            assert target == ["target"]
            assert config.doctor and config.target_stdout_to_stderr
            return RunResult(1, 0, None, (MODULE, StatementPrepared(1, 1, "sqlite", "0x1", "0x2", "SELECT 1")), "ACTIVE")
    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    assert cli.main(["doctor", "--format", "json", "--", "target"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report_type"] == "sqlitewatch_doctor"
    assert payload["status"] == "ACTIVE"


def test_doctor_rejects_normal_mode_options(capsys):
    assert cli.main(["doctor", "--max-sql-length", "3", "--", "target"]) == 2
    assert "usage: sqlitewatch doctor" in capsys.readouterr().err
