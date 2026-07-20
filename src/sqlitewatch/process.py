"""Target lifecycle orchestration, deliberately independent of SQLite ABI details."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
from queue import Empty, Queue
import signal as signal_module
import time
from threading import Event as ThreadEvent, Thread
from typing import Any

from .events import (
    BackendReady,
    Event,
    InstrumentationError,
    InstrumentationStatus,
    ProcessExited,
    RunResult,
)


@dataclass(frozen=True, slots=True)
class ControllerConfig:
    max_sql_length: int = 65536
    backend_ready_timeout: float = 10.0


class ProcessController:
    """Run one primary process through spawn, instrumentation, resume and waitpid."""

    def __init__(self, backend: Any = None):
        self.backend = backend
        self._events: list[Event] = []
        self._queue: Queue[Event] = Queue()
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message: str | None = None

    def run(self, argv: list[str], config: ControllerConfig | None = None) -> RunResult:
        if not argv:
            raise ValueError("target command cannot be empty")
        config = config or ControllerConfig()
        if config.max_sql_length <= 0:
            raise ValueError("max_sql_length must be positive")

        backend = self.backend
        if backend is None:
            from .instrumentation.frida_backend import FridaBackend

            backend = FridaBackend()
            self.backend = backend
        self._reset_state()
        pid: int | None = None
        resumed = False
        target_exit: int | None = None
        target_signal: int | None = None
        wait_gate: ThreadEvent | None = None
        waiter: Thread | None = None

        try:
            backend.get_local_device()
            executable = shutil.which(argv[0]) or argv[0]
            pid = int(backend.spawn([executable, *argv[1:]]))
            backend.attach(pid)
            if hasattr(backend, "register_detached_handler"):
                backend.register_detached_handler(lambda _reason: None)
            backend.create_script(config)
            backend.register_message_handler(self._on_event)
            backend.load()
            ready = self._wait_for_backend_ready(config.backend_ready_timeout)
            if not ready:
                self._fail("bootstrap", "agent did not emit backend_ready before timeout")
                self._abort_target(pid, resumed)
            elif self._instrumentation_failed:
                self._abort_target(pid, resumed)
            else:
                # Start the wait operation before resume, but gate the actual
                # waitpid call until resume has returned. This prevents a fast
                # target from being reaped by Frida before the controller waits.
                wait_gate = ThreadEvent()
                wait_started = ThreadEvent()
                wait_result: Queue[Any] = Queue(maxsize=1)

                def wait_worker() -> None:
                    wait_gate.wait()
                    wait_started.set()
                    try:
                        wait_result.put(("ok", self._wait_for_target(pid)))
                    except Exception as exc:
                        wait_result.put(("error", exc))

                waiter = Thread(target=wait_worker, name="sqlitewatch-waitpid", daemon=True)
                waiter.start()
                if getattr(backend, "prearm_wait", False):
                    wait_gate.set()
                    # Ensure the OS wait is actually armed before Frida can
                    # resume and reap a short-lived target.  The worker sets
                    # its marker immediately before entering the syscall, so
                    # leave a small scheduling window for that syscall.
                    wait_started.wait()
                    time.sleep(1.0)
                backend.resume(pid)
                resumed = True
                if not getattr(backend, "prearm_wait", False):
                    wait_gate.set()
                outcome, value = wait_result.get()
                if outcome == "error":
                    raise value
                target_exit, target_signal = value
                # Frida delivers send() messages asynchronously. Keep the
                # script attached briefly after waitpid so short-lived
                # targets cannot lose tail events.
                self._drain_queue_until_quiet()
        except Exception as exc:
            self._fail("controller", str(exc))
            if wait_gate is not None:
                wait_gate.set()
            if waiter is not None:
                waiter.join(timeout=0.5)
            if pid is not None:
                self._abort_target(pid, resumed)
        finally:
            self._drain_queue()
            if pid is not None and (target_exit is not None or target_signal is not None):
                self._events.append(
                    ProcessExited(pid=pid, exit_code=target_exit, signal=target_signal)
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
            pid=pid,
            target_exit_code=target_exit,
            signal=target_signal,
            events=tuple(self._events),
            instrumentation_status=status,
            instrumentation_failed=self._instrumentation_failed,
            instrumentation_error=self._error_message,
        )

    def _reset_state(self) -> None:
        self._events = []
        self._queue = Queue()
        self._backend_ready = False
        self._instrumentation_failed = False
        self._error_message = None

    def _on_event(self, event: Event) -> None:
        self._queue.put(event)

    def _record_event(self, event: Event) -> None:
        self._events.append(event)
        if isinstance(event, BackendReady):
            self._backend_ready = True
        elif isinstance(event, InstrumentationError):
            if event.fatal:
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

    def _wait_for_backend_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self._backend_ready and not self._instrumentation_failed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                event = self._queue.get(timeout=min(remaining, 0.1))
            except Empty:
                continue
            self._record_event(event)
        return self._backend_ready

    def _wait_for_target(self, pid: int) -> tuple[int | None, int | None]:
        if hasattr(self.backend, "waitpid"):
            status = self.backend.waitpid(pid)
            return self._decode_wait_status(status)

        _, status = os.waitpid(pid, 0)
        return self._decode_wait_status(status)

    def _decode_wait_status(self, status: int) -> tuple[int | None, int | None]:
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status), None
        if os.WIFSIGNALED(status):
            return None, os.WTERMSIG(status)
        self._fail("waitpid", f"unsupported wait status {status}")
        return None, None

    def _abort_target(self, pid: int, resumed: bool) -> None:
        try:
            if hasattr(self.backend, "kill"):
                self.backend.kill(pid)
            elif resumed:
                os.kill(pid, signal_module.SIGKILL)
            # A real spawned process must be reaped; fake backends need not emulate this.
            if not hasattr(self.backend, "waitpid"):
                os.waitpid(pid, 0)
        except Exception:
            # Cleanup must not mask the original instrumentation or wait error.
            pass

    def _fail(self, phase: str, message: str) -> None:
        self._instrumentation_failed = True
        self._error_message = f"{phase}: {message}"

    def _instrumentation_status(self) -> str:
        statuses = [event.status for event in self._events if isinstance(event, InstrumentationStatus)]
        if self._instrumentation_failed:
            return "FAILED"
        return statuses[-1] if statuses else "NOT_DETECTED"
