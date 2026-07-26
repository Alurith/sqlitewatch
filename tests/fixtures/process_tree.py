"""Deterministic subprocess shapes for recursive child-gating integration tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def _sqlite_work(marker: str) -> None:
    import sqlite3

    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE process_tree_marker (value TEXT)")
    connection.execute("INSERT INTO process_tree_marker VALUES (?)", (marker,))
    value = connection.execute(
        "SELECT value FROM process_tree_marker WHERE value = ?", (marker,)
    ).fetchone()[0]
    print(f"sql-marker={value}", flush=True)
    connection.close()


def _command(*args: str) -> list[str]:
    return [sys.executable, str(Path(__file__).resolve()), *args]


def _ignore(_signum: int, _frame: object) -> None:
    return


def main() -> int:
    mode = sys.argv[1]
    if mode == "worker":
        _sqlite_work(sys.argv[2])
        return 0
    if mode == "child-sql":
        return subprocess.run(_command("worker", "child-only"), check=False).returncode
    if mode == "fast-child":
        return subprocess.run(["/bin/true"], check=False).returncode
    if mode == "grandchild-sql":
        return subprocess.run(_command("spawn-grandchild"), check=False).returncode
    if mode == "spawn-grandchild":
        return subprocess.run(
            _command("worker", "grandchild-only"), check=False
        ).returncode
    if mode == "autoreload":
        for marker in ("reload-image-one", "reload-image-two"):
            completed = subprocess.run(_command("worker", marker), check=False)
            if completed.returncode != 0:
                return completed.returncode
        return 0
    if mode == "exec-same-pid":
        os.execv(sys.executable, _command("worker", "exec-same-pid"))
    if mode == "fork-exec":
        child = os.fork()
        if child == 0:
            os.execv(sys.executable, _command("worker", "fork-exec-child"))
        waited, status = os.waitpid(child, 0)
        if waited != child:
            return 3
        return os.waitstatus_to_exitcode(status)
    if mode == "lingering":
        pid_path = Path(sys.argv[2])
        child = subprocess.Popen(
            _command("linger-worker", str(pid_path)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 2.0
        while not pid_path.exists() and time.monotonic() < deadline:
            if child.poll() is not None:
                return 4
            time.sleep(0.01)
        return 0 if pid_path.exists() else 5
    if mode == "linger-worker":
        pid_path = Path(sys.argv[2])
        pid_path.write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
        time.sleep(2.0)
        return 0
    if mode == "adversarial-tree":
        pid_path = Path(sys.argv[2])
        signal.signal(signal.SIGTERM, _ignore)
        signal.signal(signal.SIGINT, _ignore)
        child = subprocess.Popen(_command("adversarial-child", str(pid_path)))
        while True:
            if child.poll() is not None:
                return 6
            try:
                root_record = json.loads(pid_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.01)
                continue
            if "child" in root_record and "grandchild" in root_record:
                break
            time.sleep(0.01)
        root_record["root"] = os.getpid()
        pid_path.write_text(json.dumps(root_record), encoding="utf-8")
        while True:
            time.sleep(0.1)
    if mode == "adversarial-child":
        pid_path = Path(sys.argv[2])
        signal.signal(signal.SIGTERM, _ignore)
        signal.signal(signal.SIGINT, _ignore)
        grandchild = subprocess.Popen(_command("adversarial-grandchild", str(pid_path)))
        while True:
            if grandchild.poll() is not None:
                return 7
            try:
                record = json.loads(pid_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.01)
                continue
            if "grandchild" in record:
                break
            time.sleep(0.01)
        record["child"] = os.getpid()
        pid_path.write_text(json.dumps(record), encoding="utf-8")
        while True:
            time.sleep(0.1)
    if mode == "adversarial-grandchild":
        pid_path = Path(sys.argv[2])
        signal.signal(signal.SIGTERM, _ignore)
        signal.signal(signal.SIGINT, _ignore)
        pid_path.write_text(json.dumps({"grandchild": os.getpid()}), encoding="utf-8")
        while True:
            time.sleep(0.1)
    raise ValueError(f"unknown mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
