"""Frida adapter for the launcher/child-gating process lifecycle."""

from __future__ import annotations

import os
import signal
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from .protocol import ProtocolError, frida_message_to_events
from ..events import Event, InstrumentationError


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
        self._lock = Lock()
        self._next_lifecycle_sequence = 1
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

    def get_local_device(self) -> Any:
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

        def on_child_added(child: Any) -> None:
            handler = self._child_callback
            if handler is not None:
                handler(child)

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

    @staticmethod
    def _register_detached(session: Any, callback: Callable[[str], None]) -> None:
        if session is None:
            raise RuntimeError("attach must happen before registering detached handler")
        # Frida versions may include a second crash argument.
        session.on("detached", lambda reason, *_details: callback(str(reason)))

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
        prefix = f"var SQLITEWATCH_CONFIG = {{ max_sql_length: {max_sql_length}, doctor: {str(doctor).lower()} }};\n"
        self.target_script = self.target_session.create_script(
            prefix + self.agent_path.read_text(encoding="utf-8"), name="sqlitewatch_agent.js"
        )
        return self.target_script

    def register_launcher_message_handler(self, callback: Callable[[Event], None]) -> None:
        self._launcher_callback = callback
        if self.launcher_script is None:
            raise RuntimeError("create_launcher_script must happen before registering a callback")
        self.launcher_script.on("message", lambda message, data: self._on_message(message, data, callback))

    def register_target_message_handler(self, callback: Callable[[Event], None]) -> None:
        self._target_callback = callback
        if self.target_script is None:
            raise RuntimeError("create_target_script must happen before registering a callback")
        self.target_script.on("message", lambda message, data: self._on_message(message, data, callback))

    def _on_message(self, message: dict[str, Any], _data: Any, callback: Callable[[Event], None]) -> None:
        try:
            payload = message.get("payload") if message.get("type") == "send" else None
            if isinstance(payload, dict) and payload.get("type") == "lifecycle_batch":
                sequence = payload.get("sequence")
                if sequence != self._next_lifecycle_sequence:
                    raise ProtocolError(f"invalid lifecycle batch sequence: expected {self._next_lifecycle_sequence}")
                events = frida_message_to_events(message)
                self._next_lifecycle_sequence += 1
            else:
                events = frida_message_to_events(message)
        except ProtocolError as exc:
            events = (InstrumentationError(phase="protocol", message=str(exc), fatal=True),)
        for event in events:
            callback(event)

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
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    def detach(self) -> None:
        with self._lock:
            target_session, self.target_session = self.target_session, None
            launcher_session, self.launcher_session = self.launcher_session, None
        for session in (target_session, launcher_session):
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

    close = detach
