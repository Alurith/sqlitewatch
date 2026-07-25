"""Targets used to exercise authenticated completion and forced shutdown."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import sys
import time


def _record(path: str) -> None:
    Path(path).write_text(
        json.dumps({"target": os.getpid(), "launcher": os.getppid()}),
        encoding="utf-8",
    )


def _ignore(_signum: int, _frame: object) -> None:
    return


def _socket_from_launcher() -> str:
    arguments = Path(f"/proc/{os.getppid()}/cmdline").read_bytes().split(b"\0")
    decoded = [argument.decode("utf-8") for argument in arguments if argument]
    return decoded[decoded.index("--socket") + 1]


def main() -> int:
    mode, pid_file = sys.argv[1:3]
    signal.signal(signal.SIGTERM, _ignore)
    signal.signal(signal.SIGINT, _ignore)
    _record(pid_file)
    if mode == "forge":
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(_socket_from_launcher())
            client.sendall(
                (json.dumps({
                    "pid": os.getpid(), "exit_code": 0, "signal": None,
                }) + "\n").encode("utf-8")
            )
    while True:
        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(main())
