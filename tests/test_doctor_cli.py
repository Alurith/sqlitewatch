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
            assert config.follow_children is True
            return RunResult(1, 0, None, (
                MODULE,
                StatementPrepared(
                    1, 1, "libsqlite3.so", "0x1", "0x2", "SELECT 1",
                    module_path="/usr/lib/libsqlite3.so", module_base="0x0",
                ),
            ), "ACTIVE")
    monkeypatch.setattr(cli, "ProcessController", lambda: Controller())
    assert cli.main(["doctor", "--format", "json", "--", "target"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 3
    assert payload["report_type"] == "sqlitewatch_doctor"
    assert payload["status"] == "ACTIVE"
    assert payload["modules"][0]["pid"] == 1
    assert payload["modules"][0]["process_instance"] == "legacy"
    assert payload["process_tree"]["root_pid"] == 1


def test_doctor_parser_supports_explicit_root_only_without_consuming_target_flag():
    config, target = cli._parse_doctor([
        "--no-follow-children", "--", "target", "--no-follow-children",
    ])
    assert config.controller.follow_children is False
    assert target == ["target", "--no-follow-children"]


def test_doctor_rejects_normal_mode_options(capsys):
    assert cli.main(["doctor", "--max-sql-length", "3", "--", "target"]) == 2
    assert "usage: sqlitewatch doctor" in capsys.readouterr().err
