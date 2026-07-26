"""Recursive target process-tree orchestration independent of SQLite ABI details."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from queue import Empty, Full, Queue
import signal as signal_module
import socket
import struct
import sys
from tempfile import TemporaryDirectory
from threading import Lock
import time
from typing import Any, Callable

from .events import (
    LEGACY_PROCESS_INSTANCE,
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
from .process_tree import (
    DuplicateProcessImage,
    ImageAdmission,
    ProcessTreeError,
    ProcessTreeLimitExceeded,
    ProcessTreeRegistry,
    UnknownProcessParent,
    aggregate_instrumentation_status,
)

_MAX_SQL_LENGTH = 1_048_576
_LIFECYCLE_EVENTS = (
    StatementPrepared,
    StatementStarted,
    StatementExecuted,
    StatementFinalized,
)
_PEERCRED_SIZE = struct.calcsize("3i")
_NORMAL_DETACH_REASONS = {"process-terminated", "application-requested"}


class _TargetLaunchFailure(RuntimeError):
    """Expected launcher outcome for an unexecutable command."""


@dataclass(frozen=True, slots=True)
class _DetachNotice:
    instance: str
    pid: int
    reason: str


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
    follow_children: bool = True
    max_followed_processes: int = 256
    max_process_images: int = 1024
    max_pending_children: int = 256
    exec_replacement_timeout: float | None = None


class ProcessController:
    """Instrument a gated root and recursively follow all admitted descendants."""

    def __init__(self, backend: Any = None):
        self.backend = backend
        self._events: list[Event] = []
        self._queue: Queue[Event] = Queue()
        self._children: Queue[Any] = Queue()
        self._removed_children: Queue[Any] = Queue()
        self._detach_notices: Queue[_DetachNotice] = Queue()
        self._process_tokens: dict[int, str | None] = {}
        self._event_consumer: Callable[[Event], None] | None = None
        self._retain_events = True
        self._max_retained_events = 1_000_000
        self._retention_limit_hit = False
        self._launcher_ready = False
        self._instrumentation_failed = False
        self._error_message: str | None = None
        self._failure_lock = Lock()
        self._child_lock = Lock()
        self._queued_child_keys: set[tuple[object, ...]] = set()
        self._released_child_keys: set[tuple[object, ...]] = set()
        self._tree: ProcessTreeRegistry | None = None
        self._resumed_instances: set[str] = set()
        self._pending_exec: dict[int, tuple[str, float]] = {}
        self._terminal_streams: set[str] = set()
        self._untracked_failure_pids: set[int] = set()
        self._untracked_failure_depths: dict[int, int] = {}
        self._root_completion_received = False
        self._launch_failed = False
        self._detaching = False

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
            config=config,
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
                            lambda reason: self._on_launcher_detached(reason)
                        )
                    backend.enable_child_gating()
                    backend.register_child_handler(self._on_child_added)
                    if hasattr(backend, "register_child_removed_handler"):
                        backend.register_child_removed_handler(
                            self._on_child_removed
                        )
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
                    root_child = self._wait_for_root_child(
                        launcher_pid,
                        config.backend_ready_timeout,
                        listener,
                    )
                    if root_child is None:
                        if self._launch_failed:
                            target_exit, target_signal = 127, None
                            raise _TargetLaunchFailure("target launch failed")
                        raise RuntimeError(
                            self._error_message
                            or "expected launcher child was not gated"
                        )
                    pid, _parent_pid, origin, identifier = self._child_identity(
                        root_child, launcher_pid
                    )
                    target_pid = pid
                    assert self._tree is not None
                    root = self._tree.admit_root(
                        target_pid,
                        origin=origin,
                        identifier=identifier,
                        start_token=self._process_start_token(target_pid),
                    )
                    self._remember_admission(root)
                    self._instrument_stream(root, config, root=True)

                    # The private launcher is infrastructure. Once the root has
                    # its own gate (or root-only policy is explicit), release it.
                    backend.disable_child_gating()
                    self._resume_admission(root)

                    target_exit, target_signal = self._receive_completion(
                        listener,
                        expected_target_pid=target_pid,
                        expected_launcher_pid=launcher_pid,
                        timeout=config.completion_timeout,
                        service=lambda: self._service_runtime(config),
                    )
                    self._root_completion_received = True
                    self._mark_active_at_root_exit()
                    self._drain_after_root_completion(config)
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message
                            or "instrumentation failed during completion drain"
                        )
                    self._mark_active_at_root_exit()
                    self._release_successful_tree()
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message
                            or "failed to release process-tree instrumentation"
                        )
                    cleanup_errors = self._verify_completed_processes(
                        launcher_pid, target_pid, config.cleanup_timeout
                    )
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                except _TargetLaunchFailure:
                    cleanup_errors = self._finish_launcher_only(
                        launcher_pid, config.cleanup_timeout
                    )
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                except KeyboardInterrupt:
                    cleanup_exit, cleanup_signal, cleanup_errors = (
                        self._shutdown_processes(
                            listener,
                            launcher_pid,
                            target_pid,
                            initial_signal=signal_module.SIGINT,
                            timeout=config.cleanup_timeout,
                        )
                    )
                    if target_exit is None and target_signal is None:
                        target_exit, target_signal = cleanup_exit, cleanup_signal
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("interrupt_cleanup", error)
                    if target_pid is None:
                        self._fail("interrupt_cleanup", "target was not started")
                except Exception as exc:
                    if not self._instrumentation_failed:
                        self._fail("controller", str(exc))
                    cleanup_exit, cleanup_signal, cleanup_errors = (
                        self._shutdown_processes(
                            listener,
                            launcher_pid,
                            target_pid,
                            initial_signal=signal_module.SIGTERM,
                            timeout=config.cleanup_timeout,
                        )
                    )
                    if target_exit is None and target_signal is None:
                        target_exit, target_signal = cleanup_exit, cleanup_signal
                    processes_cleaned = not cleanup_errors
                    for error in cleanup_errors:
                        self._fail("cleanup", error)
                finally:
                    if not processes_cleaned and (
                        launcher_pid is not None or target_pid is not None
                    ):
                        cleanup_exit, cleanup_signal, cleanup_errors = (
                            self._shutdown_processes(
                                listener,
                                launcher_pid,
                                target_pid,
                                initial_signal=signal_module.SIGTERM,
                                timeout=config.cleanup_timeout,
                            )
                        )
                        if target_exit is None and target_signal is None:
                            target_exit, target_signal = cleanup_exit, cleanup_signal
                        for error in cleanup_errors:
                            self._fail("cleanup", error)
                    self._drain_queue()
                    self._service_detach_notices(config)
                    if target_pid is not None and (
                        target_exit is not None or target_signal is not None
                    ):
                        instance = (
                            self._tree.current_instance(target_pid)
                            if self._tree is not None
                            else None
                        ) or LEGACY_PROCESS_INSTANCE
                        self._record_event(
                            ProcessExited(
                                pid=target_pid,
                                exit_code=target_exit,
                                signal=target_signal,
                                process_instance=instance,
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

        assert self._tree is not None
        tree = self._tree.freeze(fatal_failure=self._instrumentation_failed)
        status = aggregate_instrumentation_status(
            tree, fatal_failure=self._instrumentation_failed
        )
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
            process_tree=tree,
        )

    @staticmethod
    def _validate_config(config: ControllerConfig, retain_events: bool) -> None:
        if (
            isinstance(config.max_sql_length, bool)
            or not isinstance(config.max_sql_length, int)
            or not 0 < config.max_sql_length <= _MAX_SQL_LENGTH
        ):
            raise ValueError("max_sql_length must be between 1 and 1048576")
        booleans = (
            config.target_stdout_to_stderr,
            config.doctor,
            config.follow_children,
        )
        if any(not isinstance(value, bool) for value in booleans):
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
                "controller handshake, acknowledgement, and cleanup timeouts "
                "must be finite and positive"
            )
        for name, value in (
            ("completion_timeout", config.completion_timeout),
            ("exec_replacement_timeout", config.exec_replacement_timeout),
        ):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be finite and positive when configured")
        for name, value in (
            ("max_retained_events", config.max_retained_events),
            ("max_followed_processes", config.max_followed_processes),
            ("max_process_images", config.max_process_images),
            ("max_pending_children", config.max_pending_children),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def _backend(self) -> Any:
        if self.backend is None:
            from .instrumentation.frida_backend import FridaBackend

            self.backend = FridaBackend()
        return self.backend

    def _reset_state(
        self,
        *,
        config: ControllerConfig,
        event_consumer: Callable[[Event], None] | None,
        retain_events: bool,
        max_retained_events: int,
    ) -> None:
        self._events = []
        self._queue = Queue()
        self._children = Queue(maxsize=config.max_pending_children)
        self._removed_children = Queue()
        self._detach_notices = Queue()
        self._process_tokens = {}
        self._event_consumer = event_consumer
        self._retain_events = retain_events
        self._max_retained_events = max_retained_events
        self._retention_limit_hit = False
        self._launcher_ready = False
        self._instrumentation_failed = False
        self._error_message = None
        self._queued_child_keys = set()
        self._released_child_keys = set()
        self._tree = ProcessTreeRegistry(
            follow_children=config.follow_children,
            max_followed_processes=config.max_followed_processes,
            max_process_images=config.max_process_images,
        )
        self._resumed_instances = set()
        self._pending_exec = {}
        self._terminal_streams = set()
        self._untracked_failure_pids = set()
        self._untracked_failure_depths = {}
        self._root_completion_received = False
        self._launch_failed = False
        self._detaching = False

    # Callback boundary --------------------------------------------------

    def _on_event(self, event: Event) -> None:
        self._queue.put(event)

    def _on_child_added(self, child: Any) -> None:
        key = self._child_key(child)
        with self._child_lock:
            if key in self._queued_child_keys or key in self._released_child_keys:
                return
            try:
                self._children.put_nowait(child)
            except Full:
                self._released_child_keys.add(key)
                queued = False
            else:
                self._queued_child_keys.add(key)
                queued = True
        if not queued:
            pid = self._best_effort_child_pid(child)
            resume_error: str | None = None
            if pid is not None:
                self._remember_untracked_child(child, pid)
                try:
                    self.backend.resume(pid)
                except Exception as exc:  # emergency callback path
                    resume_error = str(exc)
            detail = "pending child queue overflow"
            if resume_error is not None:
                detail += f"; emergency resume failed: {resume_error}"
            self._fail("child_queue", detail)

    def _on_child_removed(self, child: Any) -> None:
        self._removed_children.put(child)

    def _on_stream_detached(self, instance: str, pid: int, reason: str) -> None:
        self._detach_notices.put(_DetachNotice(instance, pid, reason))

    def _on_launcher_detached(self, reason: str) -> None:
        if (
            not self._detaching
            and not self._root_completion_received
            and reason not in _NORMAL_DETACH_REASONS
        ):
            self._fail("detach", f"launcher session detached: {reason}")

    # Event / child service ---------------------------------------------

    def _record_event(self, event: Event) -> None:
        if self._event_consumer is not None:
            self._event_consumer(event)
        should_retain = self._retain_events or not isinstance(
            event, _LIFECYCLE_EVENTS
        )
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
        elif isinstance(event, InstrumentationStatus):
            if self._tree is not None and self._tree.has_instance(
                event.process_instance
            ):
                self._tree.mark_status(event.process_instance, event.status)
            if event.status == "FAILED":
                root = False
                if self._tree is not None and self._tree.has_instance(
                    event.process_instance
                ):
                    root = self._tree.admission(event.process_instance).root
                if root:
                    self._fail(
                        "instrumentation", event.reason or "root agent reported FAILED"
                    )
        elif isinstance(event, InstrumentationError) and event.fatal:
            self._fail(event.phase, event.message)

    def _drain_queue(self) -> int:
        count = 0
        while True:
            try:
                event = self._queue.get_nowait()
            except Empty:
                return count
            self._record_event(event)
            count += 1

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

    def _wait_for_root_child(
        self,
        launcher_pid: int,
        timeout: float,
        listener: socket.socket | None = None,
    ) -> Any | None:
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
                self._reconcile_pending_children()
                self._drain_queue()
                if listener is not None and self._try_launch_failure(
                    listener, launcher_pid
                ):
                    return None
                continue
            self._mark_child_dequeued(child)
            try:
                pid, parent_pid, _origin, _identifier = self._child_identity(
                    child, launcher_pid
                )
            except ProcessTreeError as exc:
                self._emergency_resume(child)
                self._fail("child_gating", str(exc))
                return None
            # Linux posix_spawn may report an exec-origin child with parent_pid
            # equal to its own PID. This exception is bootstrap-root-only.
            if parent_pid not in {launcher_pid, pid}:
                self._emergency_resume(child)
                self._fail(
                    "child_gating",
                    f"unexpected root child {pid} from parent {parent_pid}",
                )
                return None
            return child
        return None

    def _service_runtime(self, config: ControllerConfig) -> int:
        serviced = self._drain_queue()
        serviced += self._service_detach_notices(config)
        self._discard_removed_children()
        self._check_exec_replacement_timeouts()
        while not self._instrumentation_failed:
            try:
                child = self._children.get_nowait()
            except Empty:
                break
            self._mark_child_dequeued(child)
            serviced += 1
            self._handle_runtime_child(child, config)
            serviced += self._drain_queue()
            serviced += self._service_detach_notices(config)
            self._check_exec_replacement_timeouts()
        return serviced

    def _handle_runtime_child(self, child: Any, config: ControllerConfig) -> None:
        try:
            pid, parent_pid, origin, identifier = self._child_identity(child)
        except ProcessTreeError as exc:
            self._emergency_resume(child)
            self._fail("child_gating", str(exc))
            return
        if not config.follow_children:
            self._mark_child_released(child)
            self._resume_pid_best_effort(pid, phase="root_only_release")
            return

        assert self._tree is not None
        try:
            parent_pid = self._resolve_runtime_parent(pid, parent_pid, origin)
        except ProcessTreeError as exc:
            self._emergency_resume(child)
            self._fail("child_gating", str(exc))
            return
        previous_instance = self._tree.current_instance(pid)
        if previous_instance is not None and origin == "exec":
            try:
                self._tree.mark_detached(previous_instance, "process-replaced")
            except ProcessTreeError:
                pass
            self._detach_process_stream(previous_instance)
            self._pending_exec.pop(pid, None)
        try:
            admission = self._tree.admit_child(
                pid,
                parent_pid,
                origin=origin,
                identifier=identifier,
                start_token=self._process_start_token(pid),
            )
        except ProcessTreeLimitExceeded as exc:
            self._coverage_loss(
                pid,
                LEGACY_PROCESS_INSTANCE,
                str(exc),
                admitted=False,
            )
            self._mark_child_released(child)
            self._resume_pid_best_effort(pid, phase="process_cap_release")
            return
        except (UnknownProcessParent, DuplicateProcessImage, ProcessTreeError) as exc:
            self._remember_untracked_child(child, pid)
            self._mark_child_released(child)
            self._resume_pid_best_effort(pid, phase="invalid_child_release")
            self._record_event(
                InstrumentationError(
                    "child_gating",
                    str(exc),
                    pid=pid,
                    fatal=True,
                    data_loss=True,
                    process_instance=LEGACY_PROCESS_INSTANCE,
                )
            )
            return

        self._remember_admission(admission)
        try:
            self._instrument_stream(admission, config, root=False)
        except Exception as exc:
            if self._instrumentation_failed:
                self._resume_pid_best_effort(
                    pid, phase="fatal_child_instrumentation_release"
                )
                return
            self._detach_process_stream(admission.instance)
            self._coverage_loss(
                pid, admission.instance, str(exc), admitted=True
            )
            self._resume_admission(admission, best_effort=True)
            return
        self._resume_admission(admission)

    def _instrument_stream(
        self, admission: ImageAdmission, config: ControllerConfig, *, root: bool
    ) -> None:
        backend = self.backend
        instance, pid = admission.instance, admission.pid
        try:
            if hasattr(backend, "attach_process"):
                backend.attach_process(instance, pid)
            else:
                backend.attach_target(pid)
            if hasattr(backend, "register_process_detached_handler"):
                backend.register_process_detached_handler(
                    instance,
                    lambda reason, i=instance, p=pid: self._on_stream_detached(
                        i, p, reason
                    ),
                )
            elif hasattr(backend, "register_target_detached_handler"):
                backend.register_target_detached_handler(
                    lambda reason, i=instance, p=pid: self._on_stream_detached(
                        i, p, reason
                    )
                )
            if config.follow_children and hasattr(
                backend, "enable_process_child_gating"
            ):
                backend.enable_process_child_gating(instance)
            if hasattr(backend, "create_process_script"):
                backend.create_process_script(instance, config)
                backend.register_process_message_handler(instance, self._on_event)
                backend.load_process(instance)
            else:
                backend.create_target_script(config)
                backend.register_target_message_handler(self._on_event)
                backend.load_target()
            ready, failure = self._wait_for_stream_ready(
                instance, pid, config.backend_ready_timeout, config
            )
            if not ready:
                message = failure or (
                    "root target agent did not emit backend_ready before timeout"
                    if root
                    else "descendant agent did not emit backend_ready before timeout"
                )
                raise RuntimeError(message)
            assert self._tree is not None
            self._tree.mark_instrumented(instance)
        except Exception as exc:
            if root:
                self._detach_process_stream(instance)
                if not self._instrumentation_failed:
                    self._fail("backend_ready", str(exc))
                raise RuntimeError(self._error_message or str(exc)) from exc
            raise

    def _wait_for_stream_ready(
        self,
        instance: str,
        pid: int,
        timeout: float,
        config: ControllerConfig,
    ) -> tuple[bool, str | None]:
        deadline = time.monotonic() + timeout
        while not self._instrumentation_failed:
            self._service_detach_notices(config)
            if instance in self._terminal_streams:
                return False, "process terminated before backend_ready"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, None
            try:
                event = self._queue.get(timeout=min(remaining, 0.05))
            except Empty:
                continue
            self._record_event(event)
            if (
                isinstance(event, BackendReady)
                and event.pid == pid
                and event.process_instance == instance
            ):
                return True, None
            if (
                isinstance(event, InstrumentationStatus)
                and event.pid == pid
                and event.process_instance == instance
                and event.status == "FAILED"
            ):
                return False, event.reason or "agent reported FAILED"
        return False, self._error_message

    def _resume_admission(
        self, admission: ImageAdmission, *, best_effort: bool = False
    ) -> None:
        if admission.instance in self._resumed_instances:
            return
        self._resumed_instances.add(admission.instance)
        try:
            self.backend.resume(admission.pid)
        except Exception:
            if not best_effort:
                raise

    def _resume_pid_best_effort(self, pid: int, *, phase: str) -> None:
        try:
            self.backend.resume(pid)
        except Exception as exc:
            # A fast-exited child is harmless; a still-present stopped child is
            # caught by pending-child release and bounded cleanup.
            if self._same_process_alive(pid):
                self._fail(phase, f"could not resume child {pid}: {exc}")

    def _emergency_resume(self, child: Any) -> None:
        self._mark_child_released(child)
        pid = self._best_effort_child_pid(child)
        if pid is not None:
            self._resume_pid_best_effort(pid, phase="emergency_resume")

    def _coverage_loss(
        self,
        pid: int,
        instance: str,
        message: str,
        *,
        admitted: bool,
    ) -> None:
        assert self._tree is not None
        if admitted and self._tree.has_instance(instance):
            self._tree.mark_coverage_loss(instance, message)
        self._record_event(
            InstrumentationError(
                phase="process_coverage",
                message=message,
                pid=pid,
                fatal=False,
                data_loss=True,
                process_instance=instance,
            )
        )

    def _service_detach_notices(self, config: ControllerConfig) -> int:
        count = 0
        while True:
            try:
                notice = self._detach_notices.get_nowait()
            except Empty:
                return count
            count += 1
            self._terminal_streams.add(notice.instance)
            if self._tree is not None and self._tree.has_instance(notice.instance):
                self._tree.mark_detached(notice.instance, notice.reason)
            if self._detaching:
                continue
            if notice.reason == "process-replaced":
                timeout = (
                    config.exec_replacement_timeout
                    if config.exec_replacement_timeout is not None
                    else config.backend_ready_timeout
                )
                self._pending_exec[notice.pid] = (
                    notice.instance,
                    time.monotonic() + timeout,
                )
                self._detach_process_stream(notice.instance)
            elif notice.reason not in _NORMAL_DETACH_REASONS:
                self._fail(
                    "detach",
                    f"process stream {notice.instance} detached: {notice.reason}",
                )

    def _check_exec_replacement_timeouts(self) -> None:
        if self._tree is None:
            return
        now = time.monotonic()
        for pid, (old_instance, deadline) in tuple(self._pending_exec.items()):
            current = self._tree.current_instance(pid)
            if current != old_instance:
                del self._pending_exec[pid]
            elif now >= deadline:
                del self._pending_exec[pid]
                self._fail(
                    "exec_replacement",
                    f"exec replacement child-added timed out for PID {pid}",
                )

    def _discard_removed_children(self) -> None:
        while True:
            try:
                self._removed_children.get_nowait()
            except Empty:
                return

    def _drain_after_root_completion(self, config: ControllerConfig) -> None:
        deadline = time.monotonic() + config.cleanup_timeout
        quiet_since: float | None = None
        while time.monotonic() < deadline:
            if config.follow_children:
                self._reconcile_pending_children()
            serviced = self._service_runtime(config)
            pending_acks = int(getattr(self.backend, "pending_ack_count", 0))
            queues_empty = self._children.empty() and self._queue.empty()
            if serviced == 0 and pending_acks == 0 and queues_empty:
                if quiet_since is None:
                    quiet_since = time.monotonic()
                elif time.monotonic() - quiet_since >= 0.05:
                    return
            else:
                quiet_since = None
            if self._instrumentation_failed:
                return
            time.sleep(0.005)
        self._service_runtime(config)
        pending_acks = int(getattr(self.backend, "pending_ack_count", 0))
        if pending_acks:
            self._fail(
                "transport",
                f"{pending_acks} lifecycle acknowledgement(s) remained in flight at root exit",
            )

    def _release_successful_tree(self) -> None:
        backend = self.backend
        # Resume the current pending snapshot before disabling gates. Frida's
        # disable is itself asynchronous and also releases children; reversing
        # this order could issue a non-idempotent duplicate resume(pid).
        if hasattr(backend, "release_pending_children"):
            for error in backend.release_pending_children():
                self._fail("pending_child_release", error)
        if hasattr(backend, "process_instances"):
            for instance in backend.process_instances():
                if hasattr(backend, "disable_process_child_gating"):
                    try:
                        backend.disable_process_child_gating(instance)
                    except Exception:
                        pass
        if hasattr(backend, "process_instances") and hasattr(
            backend, "detach_process"
        ):
            self._detaching = True
            for instance in backend.process_instances():
                backend.detach_process(instance)
            self._detaching = False

    def _detach_process_stream(self, instance: str) -> None:
        if hasattr(self.backend, "detach_process"):
            self.backend.detach_process(instance)

    # Completion socket --------------------------------------------------

    def _receive_completion(
        self,
        listener: socket.socket,
        *,
        expected_target_pid: int,
        expected_launcher_pid: int,
        timeout: float | None,
        service: Callable[[], Any] | None = None,
    ) -> tuple[int | None, int | None]:
        deadline = None if timeout is None else time.monotonic() + timeout
        connection: socket.socket | None = None
        try:
            while connection is None:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise RuntimeError("launcher completion socket timed out")
                listener.settimeout(
                    0.05 if remaining is None else min(remaining, 0.05)
                )
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    if service is not None:
                        service()
                    else:
                        self._drain_queue()
                    if self._instrumentation_failed:
                        raise RuntimeError(
                            self._error_message or "instrumentation failed"
                        )
            self._authenticate_peer(connection, expected_launcher_pid)
            data = self._read_connection(connection, deadline, service)
            return self._validate_completion(data, expected_target_pid)
        finally:
            if connection is not None:
                connection.close()

    def _read_connection(
        self,
        connection: socket.socket,
        deadline: float | None,
        service: Callable[[], Any] | None = None,
    ) -> bytes:
        data = bytearray()
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise RuntimeError("launcher completion socket closed or timed out")
            connection.settimeout(
                0.05 if remaining is None else min(remaining, 0.05)
            )
            try:
                chunk = connection.recv(4096)
            except TimeoutError:
                if service is not None:
                    service()
                else:
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
            raise RuntimeError(
                "SO_PEERCRED is required on the supported Linux platform"
            )
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED_SIZE
        )
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

    # Bounded cleanup ----------------------------------------------------

    def _release_unhandled_children_for_failure(
        self, errors: list[str], timeout: float
    ) -> None:
        """Resume the pending snapshot, then close every gate before signals."""
        pending: dict[int, Any] = {}
        if hasattr(self.backend, "enumerate_pending_children"):
            try:
                for child in self.backend.enumerate_pending_children():
                    pid = self._best_effort_child_pid(child)
                    if pid is not None:
                        pending[pid] = child
            except Exception as exc:
                errors.append(f"could not enumerate pending children: {exc}")
        while True:
            try:
                child = self._children.get_nowait()
            except Empty:
                break
            self._mark_child_dequeued(child)
            pid = self._best_effort_child_pid(child)
            if pid is not None:
                pending.setdefault(pid, child)
        for pid in sorted(pending, reverse=True):
            child = pending[pid]
            with self._child_lock:
                already_released = self._child_key(child) in self._released_child_keys
            self._remember_untracked_child(child, pid)
            if already_released:
                continue
            self._mark_child_released(child)
            try:
                self.backend.resume(pid)
            except Exception as exc:
                if self._same_process_alive(pid):
                    errors.append(
                        f"could not release pending child {pid} before cleanup: {exc}"
                    )

        if hasattr(self.backend, "disable_all_child_gating"):
            for error in self.backend.disable_all_child_gating():
                errors.append(error)
        else:
            if hasattr(self.backend, "process_instances") and hasattr(
                self.backend, "disable_process_child_gating"
            ):
                for instance in self.backend.process_instances():
                    try:
                        self.backend.disable_process_child_gating(instance)
                    except Exception as exc:
                        errors.append(
                            f"could not disable child gating for {instance}: {exc}"
                        )
            if hasattr(self.backend, "disable_child_gating"):
                try:
                    self.backend.disable_child_gating()
                except Exception:
                    # The launcher may already have terminated or been released.
                    pass

        # Child callbacks racing with the snapshot are auto-released by the
        # gate disable above. Briefly collect their PIDs for deepest-first kill.
        deadline = time.monotonic() + min(timeout, 0.1)
        quiet_since: float | None = None
        while time.monotonic() < deadline:
            observed = False
            while True:
                try:
                    child = self._children.get_nowait()
                except Empty:
                    break
                observed = True
                pid = self._best_effort_child_pid(child)
                if pid is not None:
                    self._remember_untracked_child(child, pid)
            if observed:
                quiet_since = None
            elif quiet_since is None:
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= 0.02:
                break
            time.sleep(0.002)

    def _shutdown_processes(
        self,
        listener: socket.socket,
        launcher_pid: int | None,
        target_pid: int | None,
        *,
        initial_signal: int,
        timeout: float,
    ) -> tuple[int | None, int | None, list[str]]:
        """Signal and, if needed, kill the known tree deepest-first."""
        errors: list[str] = []
        target_exit: int | None = None
        target_signal: int | None = None
        self._release_unhandled_children_for_failure(errors, timeout)
        admissions = self._tree.deepest_first() if self._tree is not None else ()
        depth_by_pid = {
            admission.pid: admission.depth for admission in admissions
        }
        admitted_pids = set(depth_by_pid)
        untracked_pids = self._untracked_failure_pids - admitted_pids
        depth_by_pid.update(
            {
                pid: self._untracked_failure_depths.get(pid, -1)
                for pid in untracked_pids
            }
        )
        ordered_application_pids = sorted(
            depth_by_pid,
            key=lambda pid: (-depth_by_pid[pid], -pid),
        )
        ordered_descendant_pids = [
            pid for pid in ordered_application_pids if pid != target_pid
        ]

        for pid in ordered_descendant_pids:
            if self._same_process_alive(pid):
                self._send_signal(
                    pid,
                    initial_signal,
                    launcher=False,
                    errors=errors,
                )
        if launcher_pid is not None and self._same_process_alive(launcher_pid):
            self._send_signal(
                launcher_pid,
                initial_signal,
                launcher=True,
                errors=errors,
            )
        elif target_pid is not None and self._same_process_alive(target_pid):
            self._send_signal(
                target_pid,
                initial_signal,
                launcher=False,
                errors=errors,
            )

        if (
            not self._root_completion_received
            and target_pid is not None
            and launcher_pid is not None
        ):
            try:
                target_exit, target_signal = self._receive_completion(
                    listener,
                    expected_target_pid=target_pid,
                    expected_launcher_pid=launcher_pid,
                    timeout=timeout,
                    service=self._drain_queue,
                )
                self._root_completion_received = True
            except Exception:
                pass

        self._wait_processes_gone(ordered_application_pids, timeout)
        for pid in ordered_application_pids:
            if self._same_process_alive(pid):
                self._send_signal(
                    pid,
                    signal_module.SIGKILL,
                    launcher=False,
                    errors=errors,
                )

        if (
            not self._root_completion_received
            and target_pid is not None
            and launcher_pid is not None
        ):
            try:
                target_exit, target_signal = self._receive_completion(
                    listener,
                    expected_target_pid=target_pid,
                    expected_launcher_pid=launcher_pid,
                    timeout=timeout,
                    service=self._drain_queue,
                )
                self._root_completion_received = True
            except Exception as exc:
                errors.append(f"launcher did not report killed root target: {exc}")

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
                errors.append(
                    f"launcher {launcher_pid} remained alive after SIGKILL"
                )

        for pid in ordered_application_pids:
            if not self._wait_process_gone(pid, timeout):
                errors.append(f"process {pid} remained alive after SIGKILL")
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
            errors.append(
                f"launcher {launcher_pid} remained alive after launch failure"
            )
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

    # Process identity ---------------------------------------------------

    def _remember_admission(self, admission: ImageAdmission) -> None:
        if admission.pid not in self._process_tokens:
            self._process_tokens[admission.pid] = admission.start_token

    def _remember_untracked_child(self, child: Any, pid: int) -> None:
        self._remember_process(pid)
        self._untracked_failure_pids.add(pid)
        parent_value = getattr(child, "parent_pid", None)
        try:
            parent_pid = int(parent_value) if parent_value is not None else None
        except (TypeError, ValueError):
            parent_pid = None
        depth = -1
        if parent_pid is not None and self._tree is not None and self._tree.has_pid(parent_pid):
            current = self._tree.current_instance(parent_pid)
            if current is not None:
                depth = self._tree.admission(current).depth + 1
        elif parent_pid in self._untracked_failure_depths:
            depth = self._untracked_failure_depths[parent_pid] + 1
        self._untracked_failure_depths[pid] = max(
            depth, self._untracked_failure_depths.get(pid, -1)
        )

    def _remember_process(self, pid: int) -> None:
        if pid not in self._process_tokens:
            self._process_tokens[pid] = self._process_start_token(pid)

    def _resolve_runtime_parent(
        self, pid: int, parent_pid: int | None, origin: str
    ) -> int | None:
        """Recover ancestry lost by Linux posix_spawn's exec-only event."""
        assert self._tree is not None
        if origin != "exec" or parent_pid != pid or self._tree.has_pid(pid):
            return parent_pid

        actual_parent = self._process_parent_pid(pid)
        if actual_parent is None:
            raise ProcessTreeError(
                f"fresh exec-origin child {pid} is self-parented and its OS parent "
                "could not be determined"
            )
        if not self._tree.has_pid(actual_parent):
            raise UnknownProcessParent(
                f"fresh exec-origin child {pid} has OS parent {actual_parent}, "
                "which is not in scope"
            )
        expected_token = self._process_tokens.get(actual_parent)
        if expected_token is not None:
            current_token = self._process_start_token(actual_parent)
            if current_token != expected_token:
                raise UnknownProcessParent(
                    f"fresh exec-origin child {pid} has a reused OS parent "
                    f"PID {actual_parent}"
                )
        return actual_parent

    @staticmethod
    def _process_parent_pid(pid: int) -> int | None:
        try:
            with open(f"/proc/{pid}/stat", encoding="ascii") as stat_file:
                stat = stat_file.read()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return None
        closing = stat.rfind(")")
        fields = stat[closing + 2 :].split() if closing >= 0 else []
        if len(fields) < 2:
            return None
        try:
            parent_pid = int(fields[1])
        except ValueError:
            return None
        return parent_pid if parent_pid > 0 else None

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

    def _wait_processes_gone(self, pids: list[int], timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while any(self._same_process_alive(pid) for pid in pids):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def _mark_active_at_root_exit(self) -> None:
        if self._tree is None:
            return
        for admission in self._tree.deepest_first():
            if not admission.root and self._same_process_alive(admission.pid):
                self._tree.mark_active_at_root_exit(admission.pid)

    def _reconcile_pending_children(self) -> None:
        if not hasattr(self.backend, "enumerate_pending_children"):
            return
        try:
            pending = self.backend.enumerate_pending_children()
        except Exception as exc:
            self._fail(
                "child_gating",
                f"could not reconcile pending children: {exc}",
            )
            return
        for child in pending:
            self._on_child_added(child)

    @staticmethod
    def _child_key(child: Any) -> tuple[object, ...]:
        return (
            repr(getattr(child, "pid", child)),
            repr(getattr(child, "parent_pid", None)),
            str(getattr(child, "origin", "spawn")),
            repr(
                getattr(child, "identifier", None)
                or getattr(child, "path", None)
            ),
        )

    def _mark_child_dequeued(self, child: Any) -> None:
        with self._child_lock:
            self._queued_child_keys.discard(self._child_key(child))

    def _mark_child_released(self, child: Any) -> None:
        key = self._child_key(child)
        with self._child_lock:
            self._queued_child_keys.discard(key)
            self._released_child_keys.add(key)

    @staticmethod
    def _best_effort_child_pid(child: Any) -> int | None:
        value = getattr(child, "pid", child)
        if isinstance(value, bool):
            return None
        try:
            pid = int(value)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    def _child_identity(
        self, child: Any, default_parent: int | None = None
    ) -> tuple[int, int | None, str, str | None]:
        pid = self._best_effort_child_pid(child)
        if pid is None:
            raise ProcessTreeError("child-added did not contain a valid pid")
        parent_value = getattr(child, "parent_pid", default_parent)
        if parent_value is None:
            parent_pid = None
        elif isinstance(parent_value, bool):
            raise ProcessTreeError("child-added contained an invalid parent pid")
        else:
            try:
                parent_pid = int(parent_value)
            except (TypeError, ValueError) as exc:
                raise ProcessTreeError(
                    "child-added contained an invalid parent pid"
                ) from exc
            if parent_pid <= 0:
                raise ProcessTreeError(
                    "child-added contained an invalid parent pid"
                )
        origin_value = getattr(child, "origin", "spawn")
        origin = str(origin_value) if origin_value is not None else "spawn"
        if not origin:
            origin = "spawn"
        identifier_value = getattr(child, "identifier", None)
        if not isinstance(identifier_value, str):
            identifier_value = getattr(child, "path", None)
        identifier = (
            identifier_value if isinstance(identifier_value, str) else None
        )
        return pid, parent_pid, origin, identifier

    # Failure bookkeeping ------------------------------------------------

    def _fail(self, phase: str, message: str) -> None:
        detail = f"{phase}: {message}"
        with self._failure_lock:
            self._instrumentation_failed = True
            if self._error_message is None:
                self._error_message = detail
            elif detail not in self._error_message:
                self._error_message += f"; secondary {detail}"
