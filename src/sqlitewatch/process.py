"""Target lifecycle orchestration, independent of SQLite ABI details."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from queue import Empty, Queue
import signal as signal_module
import socket
import struct
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
    StatementExecuted,
    StatementFinalized,
    StatementPrepared,
    StatementStarted,
)

_MAX_SQL_LENGTH = 1_048_576
_LIFECYCLE_EVENTS = (
    StatementPrepared, StatementStarted, StatementExecuted, StatementFinalized
)
_PEERCRED_SIZE = struct.calcsize("3i")


class _TargetLaunchFailure(RuntimeError):
    """Expected launcher outcome for an unexecutable command."""


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    max_sql_length: int = 65536
    backend_ready_timeout: float = 10.0
    launcher_ready_timeout: float = 10.0
    # Completion is deliberately unbounded by default: this is target runtime,
    # not a controller handshake. Set a value only for a caller runtime deadline.
    completion_timeout: float | None = None
    cleanup_timeout: float = 1.0
    lifecycle_ack_timeout: float = 2.0
    max_retained_events: int = 1_000_000
    target_stdout_to_stderr: bool = False
    doctor: bool = False


class ProcessController:
    """Instrument a gated target while its package-local launcher owns waitpid."""

    def __init__(self, backend: Any = None):
        self.backend = backend
        self._events: list[Event] = []
        self._queue: Queue[Event] = Queue()
        self._children: Queue[Any] = Queue()
        self._process_tokens: dict[int, str | None] = {}
        self._event_consumer: Callable[[Event], None] | None = None
        self._retain_events = True
        self._max_retained_events = 1_000_000
        self._retention_limit_hit = False
        self._launcher_ready = False
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message: str | None = None

    def run(
        self,
        argv: list[str],
        config: ControllerConfig | None = None,
        *,
        event_consumer: Callable[[Event], None] | None = None,
        retain_events: bool = True,
    ) -> RunResult:
        if not argv:
            raise ValueError("target command cannot be empty")
        config = config or ControllerConfig()
        self._validate_config(config, retain_events)

        backend = self._backend()
        self._reset_state(
            event_consumer=event_consumer,
            retain_events=retain_events,
            max_retained_events=config.max_retained_events,
        )
        launcher_pid: int | None = None
        target_pid: int | None = None
        target_exit: int | None = None
        target_signal: int | None = None
        processes_cleaned = False

        with TemporaryDirectory(prefix="sqlitewatch-") as temporary_directory:
            socket_path = os.path.join(temporary_directory, "completion.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(socket_path)
                os.chmod(socket_path, 0o600)
                listener.listen(4)
                try:
                    if hasattr(backend, "begin_run"):
                        backend.begin_run()
                    backend.get_local_device()
                    launcher_argv = [
                        sys.executable,
                        "-m",
                        "sqlitewatch.launcher",
                        "--socket",
                        socket_path,
                        *(
                            ["--target-stdout-to-stderr"]
                            if config.target_stdout_to_stderr
                            else []
                        ),
                        "--",
                        *argv,
                    ]
                    launcher_pid = int(backend.spawn(launcher_argv))
                    self._remember_process(launcher_pid)
                    backend.attach_launcher(launcher_pid)
                    if hasattr(backend, "register_launcher_detached_handler"):
                        backend.register_launcher_detached_handler(
                            lambda reason: self._on_detached("launcher", reason)
                        )
                    backend.enable_child_gating()
                    backend.register_child_handler(self._on_child_added)
                    backend.create_launcher_script(config)
                    backend.register_launcher_message_handler(self._on_event)
                    backend.load_launcher()
                    if not self._wait_for(
                        lambda event: isinstance(event, LauncherReady)
                        and event.pid == launcher_pid,
                        config.launcher_ready_timeout,
                    ):
                        self._fail(
                            "launcher_ready",
                            "launcher bootstrap did not become ready before timeout",
                        )
                        raise RuntimeError(self._error_message)
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message or "launcher instrumentation failed"
                        )

                    backend.resume(launcher_pid)
                    target_pid = self._wait_for_direct_child(
                        launcher_pid,
                        config.backend_ready_timeout,
                        listener,
                    )
                    if target_pid is None:
                        if self._launch_failed:
                            target_exit, target_signal = 127, None
                            raise _TargetLaunchFailure("target launch failed")
                        raise RuntimeError(
                            self._error_message or "expected launcher child was not gated"
                        )
                    self._remember_process(target_pid)
                    backend.attach_target(target_pid)
                    if hasattr(backend, "register_target_detached_handler"):
                        backend.register_target_detached_handler(
                            lambda reason: self._on_detached("target", reason)
                        )
                    backend.create_target_script(config)
                    backend.register_target_message_handler(self._on_event)
                    backend.load_target()
                    if not self._wait_for(
                        lambda event: isinstance(event, BackendReady)
                        and event.pid == target_pid,
                        config.backend_ready_timeout,
                    ):
                        self._fail(
                            "backend_ready",
                            "target agent did not emit backend_ready before timeout",
                        )
                        raise RuntimeError(self._error_message)
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message or "target instrumentation failed"
                        )

                    # Release later children before the primary target. They are
                    # intentionally not instrumented by this PoC.
                    if hasattr(backend, "disable_child_gating"):
                        backend.disable_child_gating()
                    backend.resume(target_pid)
                    target_exit, target_signal = self._receive_completion(
                        listener,
                        expected_target_pid=target_pid,
                        expected_launcher_pid=launcher_pid,
                        timeout=config.completion_timeout,
                    )
                    self._drain_queue_until_quiet()
                    cleanup_errors = self._verify_completed_processes(
                        launcher_pid, target_pid, config.cleanup_timeout
                    )
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                except _TargetLaunchFailure:
                    # posix_spawnp could not execute the command. This is the
                    # target's conventional 127 outcome, not instrumentation.
                    cleanup_errors = self._finish_launcher_only(
                        launcher_pid, config.cleanup_timeout
                    )
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                except KeyboardInterrupt:
                    target_exit, target_signal, cleanup_errors = self._shutdown_processes(
                        listener,
                        launcher_pid,
                        target_pid,
                        initial_signal=signal_module.SIGINT,
                        timeout=config.cleanup_timeout,
                    )
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("interrupt_cleanup", error)
                    if target_pid is None:
                        self._fail("interrupt_cleanup", "target was not started")
                except Exception as exc:
                    if not self._instrumentation_failed:
                        self._fail("controller", str(exc))
                    (
                        cleanup_exit,
                        cleanup_signal,
                        cleanup_errors,
                    ) = self._shutdown_processes(
                        listener,
                        launcher_pid,
                        target_pid,
                        initial_signal=signal_module.SIGTERM,
                        timeout=config.cleanup_timeout,
                    )
                    if target_exit is None and target_signal is None:
                        target_exit, target_signal = cleanup_exit, cleanup_signal
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                finally:
                    if not processes_cleaned and (launcher_pid is not None or target_pid is not None):
                        (
                            cleanup_exit,
                            cleanup_signal,
                            cleanup_errors,
                        ) = self._shutdown_processes(
                            listener,
                            launcher_pid,
                            target_pid,
                            initial_signal=signal_module.SIGTERM,
                            timeout=config.cleanup_timeout,
                        )
                        if target_exit is None and target_signal is None:
                            target_exit, target_signal = cleanup_exit, cleanup_signal
                        for error in cleanup_errors:
                            self._fail("cleanup", error)
                    self._drain_queue()
                    if target_pid is not None and (
                        target_exit is not None or target_signal is not None
                    ):
                        self._record_event(
                            ProcessExited(
                                pid=target_pid,
                                exit_code=target_exit,
                                signal=target_signal,
                            )
                        )
                    try:
                        self._detaching = True
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
            sql_capture_limit=config.max_sql_length,
            events_retained=retain_events,
        )

    @staticmethod
    def _validate_config(config: ControllerConfig, retain_events: bool) -> None:
        if (
            isinstance(config.max_sql_length, bool)
            or not isinstance(config.max_sql_length, int)
            or not 0 < config.max_sql_length <= _MAX_SQL_LENGTH
        ):
            raise ValueError("max_sql_length must be between 1 and 1048576")
        if not isinstance(config.target_stdout_to_stderr, bool) or not isinstance(
            config.doctor, bool
        ):
            raise ValueError("controller boolean options must be booleans")
        if not isinstance(retain_events, bool):
            raise ValueError("retain_events must be a boolean")
        bounded_timeouts = (
            config.backend_ready_timeout,
            config.launcher_ready_timeout,
            config.cleanup_timeout,
            config.lifecycle_ack_timeout,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
            for value in bounded_timeouts
        ):
            raise ValueError(
                "controller handshake, acknowledgement, and cleanup timeouts must be finite and positive"
            )
        if config.completion_timeout is not None and (
            isinstance(config.completion_timeout, bool)
            or not isinstance(config.completion_timeout, (int, float))
            or not math.isfinite(config.completion_timeout)
            or config.completion_timeout <= 0
        ):
            raise ValueError(
                "completion_timeout must be finite and positive when configured"
            )
        if (
            isinstance(config.max_retained_events, bool)
            or not isinstance(config.max_retained_events, int)
            or config.max_retained_events <= 0
        ):
            raise ValueError("max_retained_events must be a positive integer")

    def _backend(self) -> Any:
        if self.backend is None:
            from .instrumentation.frida_backend import FridaBackend

            self.backend = FridaBackend()
        return self.backend

    def _reset_state(
        self,
        *,
        event_consumer: Callable[[Event], None] | None,
        retain_events: bool,
        max_retained_events: int,
    ) -> None:
        self._events = []
        self._queue = Queue()
        self._children = Queue()
        self._process_tokens = {}
        self._event_consumer = event_consumer
        self._retain_events = retain_events
        self._max_retained_events = max_retained_events
        self._retention_limit_hit = False
        self._launcher_ready = False
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message = None
        self._launch_failed = False
        self._detaching = False

    def _on_event(self, event: Event) -> None:
        self._queue.put(event)

    def _on_child_added(self, child: Any) -> None:
        self._children.put(child)

    def _record_event(self, event: Event) -> None:
        if self._event_consumer is not None:
            self._event_consumer(event)
        should_retain = self._retain_events or not isinstance(event, _LIFECYCLE_EVENTS)
        if should_retain and not self._retention_limit_hit:
            if len(self._events) >= self._max_retained_events:
                self._retention_limit_hit = True
                self._fail(
                    "event_retention",
                    f"event retention limit exceeded ({self._max_retained_events})",
                )
                raise RuntimeError(self._error_message)
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
                event = self._queue.get(
                    timeout=max(0.0, min(0.02, deadline - time.monotonic()))
                )
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

    def _wait_for_direct_child(
        self,
        launcher_pid: int,
        timeout: float,
        listener: socket.socket | None = None,
    ) -> int | None:
        deadline = time.monotonic() + timeout
        while not self._instrumentation_failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._fail(
                    "child_gating",
                    "launcher did not create a gated child before timeout",
                )
                return None
            try:
                child = self._children.get(timeout=min(remaining, 0.1))
            except Empty:
                self._drain_queue()
                if listener is not None and self._try_launch_failure(
                    listener, launcher_pid
                ):
                    return None
                continue
            pid = int(getattr(child, "pid", child))
            parent_pid = getattr(child, "parent_pid", launcher_pid)
            # Linux posix_spawn may report an exec-origin child with parent_pid
            # equal to its own PID. The first gated child is still the target.
            if parent_pid != launcher_pid and parent_pid != pid:
                self._fail(
                    "child_gating", f"unexpected child {pid} from parent {parent_pid}"
                )
                return None
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                self._fail("child_gating", "child-added did not contain a valid pid")
                return None
            return pid
        return None

    def _receive_completion(
        self,
        listener: socket.socket,
        *,
        expected_target_pid: int,
        expected_launcher_pid: int,
        timeout: float | None,
    ) -> tuple[int | None, int | None]:
        deadline = None if timeout is None else time.monotonic() + timeout
        connection: socket.socket | None = None
        try:
            while connection is None:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise RuntimeError("launcher completion socket timed out")
                listener.settimeout(
                    0.1 if remaining is None else min(remaining, 0.1)
                )
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    self._drain_queue()
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message or "instrumentation failed"
                        )
            self._authenticate_peer(connection, expected_launcher_pid)
            data = self._read_connection(connection, deadline)
            return self._validate_completion(data, expected_target_pid)
        finally:
            if connection is not None:
                connection.close()

    def _read_connection(
        self, connection: socket.socket, deadline: float | None
    ) -> bytes:
        data = bytearray()
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise RuntimeError("launcher completion socket closed or timed out")
            connection.settimeout(0.1 if remaining is None else min(remaining, 0.1))
            try:
                chunk = connection.recv(4096)
            except TimeoutError:
                self._drain_queue()
                continue
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > 8192:
                raise RuntimeError("launcher completion record is too large")

    @staticmethod
    def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError("SO_PEERCRED is required on the supported Linux platform")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED_SIZE)
        if len(raw) != _PEERCRED_SIZE:
            raise RuntimeError("launcher peer credentials have an invalid size")
        return struct.unpack("3i", raw)

    def _authenticate_peer(
        self, connection: socket.socket, expected_launcher_pid: int
    ) -> None:
        peer_pid, peer_uid, _peer_gid = self._peer_credentials(connection)
        if peer_pid != expected_launcher_pid:
            raise RuntimeError(
                f"completion peer pid {peer_pid} is not launcher {expected_launcher_pid}"
            )
        if peer_uid != os.geteuid():
            raise RuntimeError(
                f"completion peer uid {peer_uid} does not match controller uid {os.geteuid()}"
            )

    def _try_launch_failure(
        self, listener: socket.socket, expected_launcher_pid: int
    ) -> bool:
        """Recognize a launcher-side exec failure while no gated child exists."""
        try:
            listener.setblocking(False)
            connection, _ = listener.accept()
        except (BlockingIOError, TimeoutError):
            return False
        finally:
            listener.setblocking(True)
        try:
            self._authenticate_peer(connection, expected_launcher_pid)
            data = bytearray()
            connection.settimeout(0.1)
            while chunk := connection.recv(4096):
                data.extend(chunk)
                if len(data) > 8192:
                    raise RuntimeError("launcher completion record is too large")
            try:
                record = json.loads(bytes(data).decode("utf-8").rstrip("\n"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("launcher launch-failure record is invalid") from exc
            if record == {"kind": "launch_failure", "exit_code": 127}:
                self._launch_failed = True
                return True
            raise RuntimeError("unexpected completion before target child")
        finally:
            connection.close()

    @staticmethod
    def _validate_completion(
        data: bytes, expected_pid: int
    ) -> tuple[int | None, int | None]:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("launcher completion record is not UTF-8") from exc
        if not text.endswith("\n") or text.count("\n") != 1:
            raise RuntimeError(
                "launcher must send exactly one newline-delimited completion record"
            )
        try:
            record = json.loads(text[:-1])
        except json.JSONDecodeError as exc:
            raise RuntimeError("launcher completion record is not valid JSON") from exc
        if not isinstance(record, dict) or set(record) != {
            "pid",
            "exit_code",
            "signal",
        }:
            raise RuntimeError("launcher completion record has invalid fields")
        pid, exit_code, signal = (
            record["pid"],
            record["exit_code"],
            record["signal"],
        )
        if isinstance(pid, bool) or not isinstance(pid, int) or pid != expected_pid:
            raise RuntimeError(
                "launcher completion record has an unexpected target pid"
            )
        valid_exit = exit_code is None or (
            isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and exit_code >= 0
        )
        valid_signal = signal is None or (
            isinstance(signal, int)
            and not isinstance(signal, bool)
            and signal > 0
        )
        if (
            not valid_exit
            or not valid_signal
            or (exit_code is None) == (signal is None)
        ):
            raise RuntimeError(
                "launcher completion record must contain exactly one valid exit status"
            )
        return exit_code, signal

    def _shutdown_processes(
        self,
        listener: socket.socket,
        launcher_pid: int | None,
        target_pid: int | None,
        *,
        initial_signal: int,
        timeout: float,
    ) -> tuple[int | None, int | None, list[str]]:
        """Bounded TERM/INT → target KILL → launcher KILL escalation."""
        errors: list[str] = []
        target_exit: int | None = None
        target_signal: int | None = None

        if launcher_pid is not None and self._same_process_alive(launcher_pid):
            self._send_signal(launcher_pid, initial_signal, launcher=True, errors=errors)

        if target_pid is not None and launcher_pid is not None:
            try:
                target_exit, target_signal = self._receive_completion(
                    listener,
                    expected_target_pid=target_pid,
                    expected_launcher_pid=launcher_pid,
                    timeout=timeout,
                )
            except Exception:
                # Escalation below is authoritative; preserve the original run
                # error rather than replacing it with this grace-period timeout.
                pass

        if target_pid is not None and self._same_process_alive(target_pid):
            self._send_signal(
                target_pid,
                signal_module.SIGKILL,
                launcher=False,
                errors=errors,
            )
            if launcher_pid is not None:
                try:
                    target_exit, target_signal = self._receive_completion(
                        listener,
                        expected_target_pid=target_pid,
                        expected_launcher_pid=launcher_pid,
                        timeout=timeout,
                    )
                except Exception as exc:
                    errors.append(f"launcher did not report killed target: {exc}")

        if launcher_pid is not None and not self._wait_process_gone(
            launcher_pid, timeout
        ):
            self._send_signal(
                launcher_pid,
                signal_module.SIGKILL,
                launcher=True,
                errors=errors,
            )
            if not self._wait_process_gone(launcher_pid, timeout):
                errors.append(f"launcher {launcher_pid} remained alive after SIGKILL")

        if target_pid is not None and not self._wait_process_gone(target_pid, timeout):
            self._send_signal(
                target_pid,
                signal_module.SIGKILL,
                launcher=False,
                errors=errors,
            )
            if not self._wait_process_gone(target_pid, timeout):
                errors.append(f"target {target_pid} remained alive after SIGKILL")

        return target_exit, target_signal, errors

    def _verify_completed_processes(
        self, launcher_pid: int, target_pid: int, timeout: float
    ) -> list[str]:
        errors: list[str] = []
        if not self._wait_process_gone(target_pid, timeout):
            errors.append(f"completed target {target_pid} remained alive")
        if not self._wait_process_gone(launcher_pid, timeout):
            self._send_signal(
                launcher_pid,
                signal_module.SIGKILL,
                launcher=True,
                errors=errors,
            )
            if not self._wait_process_gone(launcher_pid, timeout):
                errors.append(f"completed launcher {launcher_pid} remained alive")
        return errors

    def _finish_launcher_only(
        self, launcher_pid: int | None, timeout: float
    ) -> list[str]:
        if launcher_pid is None or self._wait_process_gone(launcher_pid, timeout):
            return []
        errors: list[str] = []
        self._send_signal(
            launcher_pid,
            signal_module.SIGKILL,
            launcher=True,
            errors=errors,
        )
        if not self._wait_process_gone(launcher_pid, timeout):
            errors.append(f"launcher {launcher_pid} remained alive after launch failure")
        return errors

    def _send_signal(
        self,
        pid: int,
        signum: int,
        *,
        launcher: bool,
        errors: list[str],
    ) -> None:
        try:
            if launcher and hasattr(self.backend, "terminate_launcher"):
                self.backend.terminate_launcher(pid, signum)
            elif hasattr(self.backend, "signal_process"):
                self.backend.signal_process(pid, signum)
            else:
                if signum != signal_module.SIGKILL:
                    try:
                        os.kill(pid, signal_module.SIGCONT)
                    except ProcessLookupError:
                        return
                os.kill(pid, signum)
        except ProcessLookupError:
            return
        except Exception as exc:
            errors.append(f"could not signal process {pid} with {signum}: {exc}")

    def _remember_process(self, pid: int) -> None:
        self._process_tokens[pid] = self._process_start_token(pid)

    @staticmethod
    def _process_start_token(pid: int) -> str | None:
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
                stat = stat_file.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        closing = stat.rfind(")")
        fields = stat[closing + 2 :].split() if closing >= 0 else []
        return fields[19] if len(fields) > 19 else None

    def _same_process_alive(self, pid: int) -> bool:
        expected = self._process_tokens.get(pid)
        current = self._process_start_token(pid)
        if current is None or expected is None:
            return False
        return current == expected

    def _wait_process_gone(self, pid: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self._same_process_alive(pid):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def _on_detached(self, session: str, reason: str) -> None:
        # A target naturally detaches when it terminates; anything else before
        # controller cleanup means the event stream can no longer be trusted.
        if not self._detaching and reason not in {
            "process-terminated",
            "application-requested",
        }:
            self._fail("detach", f"{session} session detached: {reason}")

    def _fail(self, phase: str, message: str) -> None:
        self._instrumentation_failed = True
        detail = f"{phase}: {message}"
        if self._error_message is None:
            self._error_message = detail
        elif detail not in self._error_message:
            self._error_message += f"; secondary {detail}"

    def _instrumentation_status(self) -> str:
        statuses = [
            event.status
            for event in self._events
            if isinstance(event, InstrumentationStatus)
        ]
        if self._instrumentation_failed:
            return "FAILED"
        return statuses[-1] if statuses else "NOT_DETECTED"
