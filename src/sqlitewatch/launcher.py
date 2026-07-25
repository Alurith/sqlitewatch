"""Private launcher that owns the target's wait status for SQLiteWatch."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sys
from typing import Sequence


def _parse(argv: Sequence[str]) -> tuple[str, list[str], bool]:
    parser = argparse.ArgumentParser(prog="sqlitewatch.launcher", add_help=False)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--target-stdout-to-stderr", action="store_true")
    parsed, remainder = parser.parse_known_args(argv)
    if not remainder or remainder[0] != "--" or len(remainder) == 1:
        raise ValueError("expected -- followed by a target command")
    socket_path = Path(parsed.socket)
    if not socket_path.is_absolute() or len(os.fsencode(socket_path)) >= 108:
        raise ValueError("socket path must be an absolute AF_UNIX path shorter than 108 bytes")
    return str(socket_path), list(remainder[1:]), parsed.target_stdout_to_stderr


def _decode_status(pid: int, status: int) -> dict[str, int | None]:
    if os.WIFEXITED(status):
        return {"pid": pid, "exit_code": os.WEXITSTATUS(status), "signal": None}
    if os.WIFSIGNALED(status):
        return {"pid": pid, "exit_code": None, "signal": os.WTERMSIG(status)}
    # waitpid(..., 0) should only return terminal statuses. Treat any platform
    # anomaly as an ordinary launcher-side failure rather than inventing a signal.
    return {"pid": pid, "exit_code": 127, "signal": None}


def _send_status(socket_path: str, record: dict[str, int | str | None]) -> None:
    payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5.0)
        client.connect(socket_path)
        client.sendall(payload)


def run(argv: Sequence[str]) -> int:
    socket_path, target, target_stdout_to_stderr = _parse(argv)
    # posix_spawnp performs the fork/exec transition atomically from Frida's
    # perspective.  With a Python-level os.fork(), child gating observes the
    # launcher interpreter before exec and any script loaded into that session
    # is discarded by exec.  The launcher is still the target's direct parent
    # and exclusively owns its waitpid status.
    try:
        file_actions = (
            [(os.POSIX_SPAWN_DUP2, 2, 1)] if target_stdout_to_stderr else None
        )
        child_pid = os.posix_spawnp(target[0], target, os.environ, file_actions=file_actions)
    except OSError:
        # Preserve the conventional exec failure status through the same IPC
        # contract even though posix_spawn reports the failure in the parent.
        _send_status(socket_path, {"kind": "launch_failure", "exit_code": 127})
        return 127

    forwarded_signal: int | None = None

    def forward(signum: int, _frame: object) -> None:
        nonlocal forwarded_signal
        forwarded_signal = signum
        try:
            # A gated child may be stopped by Frida. Continue it before delivery
            # so the launcher can always reap it during controller cleanup.
            os.kill(child_pid, signal.SIGCONT)
            os.kill(child_pid, signum)
        except ProcessLookupError:
            pass

    previous_term = signal.signal(signal.SIGTERM, forward)
    previous_int = signal.signal(signal.SIGINT, forward)
    try:
        while True:
            try:
                waited_pid, status = os.waitpid(child_pid, 0)
                break
            except InterruptedError:
                continue
        record = _decode_status(waited_pid, status)
        _send_status(socket_path, record)
        return 0 if forwarded_signal is None else 128 + forwarded_signal
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except (OSError, ValueError) as exc:
        print(f"sqlitewatch launcher: {exc}", file=sys.stderr)
        return 127


if __name__ == "__main__":  # pragma: no cover - exercised as a spawned module
    raise SystemExit(main())
