"""Target lifecycle orchestration, deliberately independent of SQLite ABI details."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from queue import Empty, Queue
import socket
import signal as signal_module
import sys
from tempfile import TemporaryDirectory
import time
from typing import Any, Callable

from .events import (
    BackendReady,
    Event,
    InstrumentationError,
    InstrumentationStatus,
    LauncherReady,
    ProcessExited,
    RunResult,
)


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    max_sql_length: int = 65536
    backend_ready_timeout: float = 10.0
    launcher_ready_timeout: float = 10.0
    completion_timeout: float = 30.0


class ProcessController:
    """Instrument a gated target while its package-local launcher owns waitpid."""

    def __init__(self, backend: Any = None):
        self.backend = backend
        self._events: list[Event] = []
        self._queue: Queue[Event] = Queue()
        self._children: Queue[Any] = Queue()
        self._launcher_ready = False
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message: str | None = None

    def run(self, argv: list[str], config: ControllerConfig | None = None) -> RunResult:
        if not argv:
            raise ValueError("target command cannot be empty")
        config = config or ControllerConfig()
        if config.max_sql_length <= 0:
            raise ValueError("max_sql_length must be positive")
        if min(config.backend_ready_timeout, config.launcher_ready_timeout, config.completion_timeout) <= 0:
            raise ValueError("controller timeouts must be positive")

        backend = self._backend()
        self._reset_state()
        launcher_pid: int | None = None
        target_pid: int | None = None
        target_exit: int | None = None
        target_signal: int | None = None

        with TemporaryDirectory(prefix="sqlitewatch-") as temporary_directory:
            socket_path = os.path.join(temporary_directory, "completion.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(socket_path)
                os.chmod(socket_path, 0o600)
                listener.listen(1)
                try:
                    backend.get_local_device()
                    launcher_argv = [
                        sys.executable,
                        "-m",
                        "sqlitewatch.launcher",
                        "--socket",
                        socket_path,
                        "--",
                        *argv,
                    ]
                    launcher_pid = int(backend.spawn(launcher_argv))
                    backend.attach_launcher(launcher_pid)
                    backend.enable_child_gating()
                    backend.register_child_handler(self._on_child_added)
                    backend.create_launcher_script(config)
                    backend.register_launcher_message_handler(self._on_event)
                    backend.load_launcher()
                    if not self._wait_for(
                        lambda event: isinstance(event, LauncherReady) and event.pid == launcher_pid,
                        config.launcher_ready_timeout,
                    ):
                        self._fail("launcher_ready", "launcher bootstrap did not become ready before timeout")
                        raise RuntimeError(self._error_message)
                    if self._instrumentation_failed:
                        raise RuntimeError(self._error_message or "launcher instrumentation failed")

                    backend.resume(launcher_pid)
                    target_pid = self._wait_for_direct_child(launcher_pid, config.backend_ready_timeout)
                    if target_pid is None:
                        raise RuntimeError(self._error_message or "expected launcher child was not gated")
                    backend.attach_target(target_pid)
                    backend.create_target_script(config)
                    backend.register_target_message_handler(self._on_event)
                    backend.load_target()
                    if not self._wait_for(
                        lambda event: isinstance(event, BackendReady) and event.pid == target_pid,
                        config.backend_ready_timeout,
                    ):
                        self._fail("backend_ready", "target agent did not emit backend_ready before timeout")
                        raise RuntimeError(self._error_message)
                    if self._instrumentation_failed:
                        raise RuntimeError(self._error_message or "target instrumentation failed")

                    backend.resume(target_pid)
                    target_exit, target_signal = self._receive_completion(
                        listener, target_pid, config.completion_timeout
                    )
                    self._drain_queue_until_quiet()
                except KeyboardInterrupt:
                    # Ctrl-C is a normal target interruption, not an excuse to
                    # detach and orphan the launcher-owned Django process.
                    if launcher_pid is not None:
                        self._abort_launcher(launcher_pid, signal_module.SIGINT)
                    if target_pid is not None:
                        try:
                            target_exit, target_signal = self._receive_completion(
                                listener, target_pid, min(config.completion_timeout, 5.0)
                            )
                        except Exception as exc:
                            self._fail("interrupt_cleanup", str(exc))
                    else:
                        self._fail("interrupt_cleanup", "target was not started")
                except Exception as exc:
                    if not self._instrumentation_failed:
                        self._fail("controller", str(exc))
                    if launcher_pid is not None:
                        self._abort_launcher(launcher_pid)
                finally:
                    self._drain_queue()
                    if target_pid is not None and (target_exit is not None or target_signal is not None):
                        self._events.append(
                            ProcessExited(pid=target_pid, exit_code=target_exit, signal=target_signal)
                        )
                    try:
                        if hasattr(backend, "detach"):
                            backend.detach()
                        elif hasattr(backend, "close"):
                            backend.close()
                    except Exception as exc:
                        self._fail("cleanup", str(exc))

        status = self._instrumentation_status()
        return RunResult(
            pid=target_pid,
            target_exit_code=target_exit,
            signal=target_signal,
            events=tuple(self._events),
            instrumentation_status=status,
            instrumentation_failed=self._instrumentation_failed,
            instrumentation_error=self._error_message,
        )

    def _backend(self) -> Any:
        if self.backend is None:
            from .instrumentation.frida_backend import FridaBackend

            self.backend = FridaBackend()
        return self.backend

    def _reset_state(self) -> None:
        self._events = []
        self._queue = Queue()
        self._children = Queue()
        self._launcher_ready = False
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message = None

    def _on_event(self, event: Event) -> None:
        self._queue.put(event)

    def _on_child_added(self, child: Any) -> None:
        self._children.put(child)

    def _record_event(self, event: Event) -> None:
        self._events.append(event)
        if isinstance(event, LauncherReady):
            self._launcher_ready = True
        elif isinstance(event, BackendReady):
            self._backend_ready = True
        elif isinstance(event, InstrumentationError) and event.fatal:
            self._fail(event.phase, event.message)
        elif isinstance(event, InstrumentationStatus) and event.status == "FAILED":
            self._fail("instrumentation", event.reason or "agent reported FAILED")

    def _drain_queue(self) -> None:
        while True:
            try:
                event = self._queue.get_nowait()
            except Empty:
                return
            self._record_event(event)

    def _drain_queue_until_quiet(self, timeout: float = 0.25) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = self._queue.get(timeout=min(0.02, deadline - time.monotonic()))
            except Empty:
                continue
            self._record_event(event)

    def _wait_for(self, predicate: Callable[[Event], bool], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self._instrumentation_failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                event = self._queue.get(timeout=min(remaining, 0.1))
            except Empty:
                continue
            self._record_event(event)
            if predicate(event):
                return True
        return False

    def _wait_for_direct_child(self, launcher_pid: int, timeout: float) -> int | None:
        deadline = time.monotonic() + timeout
        while not self._instrumentation_failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail("child_gating", "launcher did not create a gated child before timeout")
                return None
            try:
                child = self._children.get(timeout=min(remaining, 0.1))
            except Empty:
                self._drain_queue()
                continue
            pid = int(getattr(child, "pid", child))
            parent_pid = getattr(child, "parent_pid", launcher_pid)
            # Linux posix_spawn may report an exec-origin child with parent_pid
            # equal to its own PID. The first gated child is still the sole
            # target; reject every other reported parent relationship.
            if parent_pid != launcher_pid and parent_pid != pid:
                self._fail("child_gating", f"unexpected child {pid} from parent {parent_pid}")
                return None
            if not isinstance(pid, int) or pid <= 0:
                self._fail("child_gating", "child-added did not contain a valid pid")
                return None
            return pid
        return None

    def _receive_completion(
        self, listener: socket.socket, expected_pid: int, timeout: float
    ) -> tuple[int | None, int | None]:
        deadline = time.monotonic() + timeout
        connection: socket.socket | None = None
        try:
            while connection is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("launcher completion socket timed out")
                listener.settimeout(min(remaining, 0.1))
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    self._drain_queue()
                    if self._instrumentation_failed:
                        raise RuntimeError(self._error_message or "instrumentation failed")
            data = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("launcher completion socket closed or timed out")
                connection.settimeout(min(remaining, 0.1))
                try:
                    chunk = connection.recv(4096)
                except TimeoutError:
                    self._drain_queue()
                    continue
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 8192:
                    raise RuntimeError("launcher completion record is too large")
            return self._validate_completion(bytes(data), expected_pid)
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate_completion(data: bytes, expected_pid: int) -> tuple[int | None, int | None]:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("launcher completion record is not UTF-8") from exc
        if not text.endswith("\n") or text.count("\n") != 1:
            raise RuntimeError("launcher must send exactly one newline-delimited completion record")
        try:
            record = json.loads(text[:-1])
        except json.JSONDecodeError as exc:
            raise RuntimeError("launcher completion record is not valid JSON") from exc
        if not isinstance(record, dict) or set(record) != {"pid", "exit_code", "signal"}:
            raise RuntimeError("launcher completion record has invalid fields")
        pid, exit_code, signal = record["pid"], record["exit_code"], record["signal"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid != expected_pid:
            raise RuntimeError("launcher completion record has an unexpected target pid")
        valid_exit = exit_code is None or (isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code >= 0)
        valid_signal = signal is None or (isinstance(signal, int) and not isinstance(signal, bool) and signal > 0)
        if not valid_exit or not valid_signal or (exit_code is None) == (signal is None):
            raise RuntimeError("launcher completion record must contain exactly one valid exit status")
        return exit_code, signal

    def _abort_launcher(self, pid: int, signum: int = signal_module.SIGTERM) -> None:
        try:
            if hasattr(self.backend, "terminate_launcher"):
                self.backend.terminate_launcher(pid, signum)
        except Exception:
            # Cleanup must not mask the original protocol or instrumentation error.
            pass

    def _fail(self, phase: str, message: str) -> None:
        self._instrumentation_failed = True
        self._error_message = f"{phase}: {message}"

    def _instrumentation_status(self) -> str:
        statuses = [event.status for event in self._events if isinstance(event, InstrumentationStatus)]
        if self._instrumentation_failed:
            return "FAILED"
        return statuses[-1] if statuses else "NOT_DETECTED"
