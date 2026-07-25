"""Frida adapter for the launcher/child-gating process lifecycle."""

from __future__ import annotations

import math
import os
import signal
from pathlib import Path
from threading import Condition, Lock, Thread, current_thread
import time
from typing import Any, Callable

from .protocol import ProtocolError, frida_message_to_events
from ..events import PROTOCOL_VERSION, Event, InstrumentationError


class FridaUnavailable(RuntimeError):
    """Raised when the optional Frida runtime cannot be imported."""


class FridaBackend:
    """Keep launcher and gated-target Frida resources alive for one run."""

    def __init__(self, *, agent_path: Path | None = None, bootstrap_path: Path | None = None):
        try:
            import frida  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on the host
            raise FridaUnavailable(
                "Frida is required for native instrumentation; run `uv sync` first"
            ) from exc
        self.frida = frida
        self.device: Any = None
        self.launcher_session: Any = None
        self.target_session: Any = None
        self.launcher_script: Any = None
        self.target_script: Any = None
        self._launcher_callback: Callable[[Event], None] | None = None
        self._target_callback: Callable[[Event], None] | None = None
        self._child_callback: Callable[[Any], None] | None = None
        self._child_listener: Callable[[Any], None] | None = None
        self._lock = Lock()
        self._next_lifecycle_sequence = 1
        self._generation = 0
        self._run_active = False
        self._ack_timeout = 2.0
        self._ack_condition = Condition()
        self._pending_acks: dict[int, tuple[float, Callable[[Event], None], int]] = {}
        self._ack_thread: Thread | None = None
        self.agent_path = agent_path or self._find_agent()
        self.bootstrap_path = bootstrap_path or self._find_bootstrap()

    @staticmethod
    def _find_agent() -> Path:
        agent = Path(__file__).resolve().parent.parent / "agent" / "sqlitewatch_agent.js"
        if agent.is_file():
            return agent
        raise FileNotFoundError(f"package-local sqlitewatch agent not found: {agent}")

    @staticmethod
    def _find_bootstrap() -> Path:
        bootstrap = Path(__file__).resolve().parent.parent / "agent" / "launcher_bootstrap.js"
        if bootstrap.is_file():
            return bootstrap
        raise FileNotFoundError(f"package-local launcher bootstrap not found: {bootstrap}")

    def begin_run(self) -> int:
        """Reset all per-run protocol state and return a callback generation."""
        with self._lock:
            if self._run_active:
                raise RuntimeError("Frida backend already has an active run")
            self._generation += 1
            self._run_active = True
            self._next_lifecycle_sequence = 1
            self._launcher_callback = None
            self._target_callback = None
            self._child_callback = None
            self.launcher_session = None
            self.target_session = None
            self.launcher_script = None
            self.target_script = None
        with self._ack_condition:
            self._pending_acks.clear()
            self._ack_condition.notify_all()
        return self._generation

    def get_local_device(self) -> Any:
        if self.device is None:
            self.device = self.frida.get_local_device()
        return self.device

    def spawn(self, argv: list[str]) -> int:
        if self.device is None:
            self.get_local_device()
        return int(self.device.spawn(argv))

    def attach_launcher(self, pid: int) -> Any:
        if self.device is None:
            self.get_local_device()
        self.launcher_session = self.device.attach(pid)
        return self.launcher_session

    def enable_child_gating(self) -> None:
        if self.launcher_session is None:
            raise RuntimeError("attach_launcher must happen before child gating")
        self.launcher_session.enable_child_gating()

    def disable_child_gating(self) -> None:
        """Release later launcher children before resuming the instrumented target."""
        if self.launcher_session is None:
            raise RuntimeError("attach_launcher must happen before child-gate release")
        self.launcher_session.disable_child_gating()

    def register_child_handler(self, callback: Callable[[Any], None]) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self._child_callback = callback
        if self._child_listener is None:
            def on_child_added(child: Any) -> None:
                handler = self._child_callback
                if self._run_active and handler is not None:
                    handler(child)

            self._child_listener = on_child_added
            self.device.on("child-added", on_child_added)

    def attach_target(self, pid: int) -> Any:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self.target_session = self.device.attach(pid)
        return self.target_session

    def register_launcher_detached_handler(self, callback: Callable[[str], None]) -> None:
        self._register_detached(self.launcher_session, callback)

    def register_target_detached_handler(self, callback: Callable[[str], None]) -> None:
        self._register_detached(self.target_session, callback)

    def _register_detached(self, session: Any, callback: Callable[[str], None]) -> None:
        if session is None:
            raise RuntimeError("attach must happen before registering detached handler")
        generation = self._generation

        def detached(reason: Any, *_details: Any) -> None:
            if self._run_active and generation == self._generation:
                callback(str(reason))

        session.on("detached", detached)

    def create_launcher_script(self, _config: Any = None) -> Any:
        if self.launcher_session is None:
            raise RuntimeError("attach_launcher must happen before create_launcher_script")
        self.launcher_script = self.launcher_session.create_script(
            self.bootstrap_path.read_text(encoding="utf-8"), name="launcher_bootstrap.js"
        )
        return self.launcher_script

    def create_target_script(self, config: Any = None) -> Any:
        if self.target_session is None:
            raise RuntimeError("attach_target must happen before create_target_script")
        max_sql_length = int(getattr(config, "max_sql_length", 65536))
        if max_sql_length <= 0:
            raise ValueError("max_sql_length must be positive")
        doctor = bool(getattr(config, "doctor", False))
        self._ack_timeout = float(getattr(config, "lifecycle_ack_timeout", 2.0))
        if not math.isfinite(self._ack_timeout) or self._ack_timeout <= 0:
            raise ValueError("lifecycle_ack_timeout must be finite and positive")
        prefix = f"var SQLITEWATCH_CONFIG = {{ max_sql_length: {max_sql_length}, doctor: {str(doctor).lower()} }};\n"
        self.target_script = self.target_session.create_script(
            prefix + self.agent_path.read_text(encoding="utf-8"), name="sqlitewatch_agent.js"
        )
        return self.target_script

    def register_launcher_message_handler(self, callback: Callable[[Event], None]) -> None:
        self._launcher_callback = callback
        if self.launcher_script is None:
            raise RuntimeError("create_launcher_script must happen before registering a callback")
        generation = self._generation
        script = self.launcher_script
        script.on(
            "message",
            lambda message, data: self._handle_script_message(
                script, message, data, callback, generation
            ),
        )

    def register_target_message_handler(self, callback: Callable[[Event], None]) -> None:
        self._target_callback = callback
        if self.target_script is None:
            raise RuntimeError("create_target_script must happen before registering a callback")
        generation = self._generation
        script = self.target_script
        script.on(
            "message",
            lambda message, data: self._handle_script_message(
                script, message, data, callback, generation
            ),
        )

    def _handle_script_message(
        self,
        script: Any,
        message: dict[str, Any],
        data: Any,
        callback: Callable[[Event], None],
        generation: int,
    ) -> None:
        accepted = self._on_message(message, data, callback, generation)
        payload = message.get("payload") if message.get("type") == "send" else None
        if (
            accepted
            and isinstance(payload, dict)
            and payload.get("type") == "lifecycle_batch"
            and payload.get("ack_required") is True
        ):
            sequence = payload["sequence"]
            self._register_pending_ack(sequence, callback, generation)
            try:
                script.post({
                    "type": "sqlitewatch_ack",
                    "payload": {"sequence": sequence},
                })
            except Exception as exc:
                self._cancel_pending_ack(sequence)
                callback(InstrumentationError(
                    phase="transport",
                    message=f"could not acknowledge lifecycle batch: {exc}",
                    fatal=True,
                ))

    def _on_message(
        self,
        message: dict[str, Any],
        _data: Any,
        callback: Callable[[Event], None],
        generation: int | None = None,
    ) -> bool:
        if generation is not None and (
            not self._run_active or generation != self._generation
        ):
            return False
        accepted = True
        try:
            payload = message.get("payload") if message.get("type") == "send" else None
            if isinstance(payload, dict) and payload.get("type") == "lifecycle_acknowledged":
                if (
                    payload.get("protocol_version") != PROTOCOL_VERSION
                    or set(payload) != {"type", "protocol_version", "sequence"}
                    or isinstance(payload.get("sequence"), bool)
                    or not isinstance(payload.get("sequence"), int)
                    or payload["sequence"] <= 0
                    or not self._confirm_pending_ack(payload["sequence"], generation)
                ):
                    raise ProtocolError("invalid or unexpected lifecycle acknowledgement")
                return True
            if isinstance(payload, dict) and payload.get("type") == "lifecycle_batch":
                sequence = payload.get("sequence")
                if sequence != self._next_lifecycle_sequence:
                    raise ProtocolError(f"invalid lifecycle batch sequence: expected {self._next_lifecycle_sequence}")
                events = frida_message_to_events(message)
                self._next_lifecycle_sequence += 1
            else:
                events = frida_message_to_events(message)
        except ProtocolError as exc:
            accepted = False
            events = (InstrumentationError(phase="protocol", message=str(exc), fatal=True),)
        for event in events:
            callback(event)
        return accepted

    def _register_pending_ack(
        self,
        sequence: int,
        callback: Callable[[Event], None],
        generation: int,
    ) -> None:
        with self._ack_condition:
            self._pending_acks[sequence] = (
                time.monotonic() + self._ack_timeout,
                callback,
                generation,
            )
            if self._ack_thread is None or not self._ack_thread.is_alive():
                self._ack_thread = Thread(
                    target=self._watch_acknowledgements,
                    name="sqlitewatch-ack-watchdog",
                    daemon=True,
                )
                self._ack_thread.start()
            self._ack_condition.notify_all()

    def _cancel_pending_ack(self, sequence: int) -> None:
        with self._ack_condition:
            self._pending_acks.pop(sequence, None)
            self._ack_condition.notify_all()

    def _confirm_pending_ack(
        self, sequence: int, generation: int | None
    ) -> bool:
        with self._ack_condition:
            pending = self._pending_acks.get(sequence)
            if pending is None:
                return False
            if generation is not None and pending[2] != generation:
                return False
            del self._pending_acks[sequence]
            self._ack_condition.notify_all()
            return True

    def _watch_acknowledgements(self) -> None:
        while True:
            expired: list[tuple[int, Callable[[Event], None], int]] = []
            with self._ack_condition:
                if not self._run_active:
                    return
                if not self._pending_acks:
                    self._ack_condition.wait()
                    continue
                now = time.monotonic()
                next_deadline = min(item[0] for item in self._pending_acks.values())
                if next_deadline > now:
                    self._ack_condition.wait(next_deadline - now)
                    continue
                for sequence, (deadline, callback, generation) in tuple(
                    self._pending_acks.items()
                ):
                    if deadline <= now:
                        del self._pending_acks[sequence]
                        expired.append((sequence, callback, generation))
            for sequence, callback, generation in expired:
                if self._run_active and generation == self._generation:
                    callback(InstrumentationError(
                        phase="transport",
                        message=(
                            "lifecycle acknowledgement timed out for batch "
                            f"{sequence}"
                        ),
                        fatal=True,
                    ))

    def load_launcher(self) -> None:
        if self.launcher_script is None:
            raise RuntimeError("create_launcher_script must happen before load_launcher")
        self.launcher_script.load()

    def load_target(self) -> None:
        if self.target_script is None:
            raise RuntimeError("create_target_script must happen before load_target")
        self.target_script.load()

    def resume(self, pid: int) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self.device.resume(pid)

    def terminate_launcher(self, pid: int, signum: int = signal.SIGTERM) -> None:
        """Request graceful launcher cleanup without claiming its wait status."""
        self.signal_process(pid, signum)

    @staticmethod
    def signal_process(pid: int, signum: int) -> None:
        try:
            if signum != signal.SIGKILL:
                os.kill(pid, signal.SIGCONT)
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    def detach(self) -> None:
        with self._lock:
            self._run_active = False
            target_session, self.target_session = self.target_session, None
            launcher_session, self.launcher_session = self.launcher_session, None
            self.target_script = None
            self.launcher_script = None
            self._target_callback = None
            self._launcher_callback = None
            self._child_callback = None
        with self._ack_condition:
            self._pending_acks.clear()
            ack_thread = self._ack_thread
            self._ack_condition.notify_all()
        if (
            ack_thread is not None
            and ack_thread is not current_thread()
            and ack_thread.is_alive()
        ):
            ack_thread.join(timeout=0.2)
        with self._ack_condition:
            if self._ack_thread is ack_thread:
                self._ack_thread = None
        for session in (target_session, launcher_session):
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

    close = detach
