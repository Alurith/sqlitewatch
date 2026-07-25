import os

from sqlitewatch import launcher


def test_launcher_parser_keeps_target_arguments_after_delimiter():
    socket_path, target, redirected = launcher._parse([
        "--socket", "/tmp/sqlitewatch.sock", "--target-stdout-to-stderr", "--",
        "target", "--target-stdout-to-stderr",
    ])
    assert socket_path == "/tmp/sqlitewatch.sock"
    assert target == ["target", "--target-stdout-to-stderr"]
    assert redirected is True


def test_launcher_uses_dup2_only_when_target_stdout_redirect_is_requested(monkeypatch):
    calls = []
    statuses = []

    def spawn(path, argv, env, **kwargs):
        calls.append(kwargs.get("file_actions"))
        return 123

    monkeypatch.setattr(launcher.os, "posix_spawnp", spawn)
    monkeypatch.setattr(launcher.os, "waitpid", lambda pid, flags: (pid, 0))
    monkeypatch.setattr(launcher, "_send_status", lambda path, record: statuses.append(record))

    assert launcher.run(["--socket", "/tmp/sqlitewatch.sock", "--", "target"]) == 0
    assert launcher.run([
        "--socket", "/tmp/sqlitewatch.sock", "--target-stdout-to-stderr", "--", "target",
    ]) == 0
    assert calls == [None, [(os.POSIX_SPAWN_DUP2, 2, 1)]]
    assert statuses == [
        {"pid": 123, "exit_code": 0, "signal": None},
        {"pid": 123, "exit_code": 0, "signal": None},
    ]
