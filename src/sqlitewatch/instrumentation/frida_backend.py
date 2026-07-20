"""Thin Frida adapter; SQLite-specific semantics stay in the agent."""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any, Callable

from .protocol import ProtocolError, frida_message_to_event
from ..events import Event, InstrumentationError


class FridaUnavailable(RuntimeError):
    """Raised when the optional Frida runtime cannot be imported."""


class FridaBackend:
    """A small lifecycle adapter around Frida's local device API."""

    # Frida may reap a very fast spawned process while device.resume() is
    # delivering script messages. Arm waitpid concurrently on local Linux.
    prearm_wait = True

    def __init__(self, *, agent_path: Path | None = None):
        try:
            import frida  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on the host
            raise FridaUnavailable(
                "Frida is required for native instrumentation; run `uv sync` first"
            ) from exc
        self.frida = frida
        self.device: Any = None
        self.session: Any = None
        self.script: Any = None
        self._callback: Callable[[Event], None] | None = None
        self._lock = Lock()
        self.detached_reason: str | None = None
        self.agent_path = agent_path or self._find_agent()

    @staticmethod
    def _find_agent() -> Path:
        agent = Path(__file__).resolve().parent.parent / "agent" / "sqlitewatch_agent.js"
        if agent.is_file():
            return agent
        raise FileNotFoundError(f"package-local sqlitewatch agent not found: {agent}")

    def get_local_device(self) -> Any:
        self.device = self.frida.get_local_device()
        return self.device

    def spawn(self, argv: list[str]) -> int:
        if self.device is None:
            self.get_local_device()
        return int(self.device.spawn(argv))

    def attach(self, pid: int) -> Any:
        if self.device is None:
            self.get_local_device()
        self.session = self.device.attach(pid)
        return self.session

    def register_detached_handler(self, callback: Callable[[str], None]) -> None:
        if self.session is None:
            raise RuntimeError("attach must happen before registering detached handler")

        def on_detached(reason: str) -> None:
            self.detached_reason = reason
            callback(reason)

        self.session.on("detached", on_detached)

    def create_script(self, config: Any = None) -> Any:
        if self.session is None:
            raise RuntimeError("attach must happen before create_script")
        source = self.agent_path.read_text(encoding="utf-8")
        max_sql_length = int(getattr(config, "max_sql_length", 65536))
        if max_sql_length <= 0:
            raise ValueError("max_sql_length must be positive")
        prefix = f"var SQLITEWATCH_CONFIG = {{ max_sql_length: {max_sql_length} }};\n"
        self.script = self.session.create_script(prefix + source, name="sqlitewatch_agent.js")
        return self.script

    def register_message_handler(self, callback: Callable[[Event], None]) -> None:
        self._callback = callback
        if self.script is None:
            raise RuntimeError("create_script must happen before registering a callback")
        self.script.on("message", self._on_message)

    def _on_message(self, message: dict[str, Any], _data: Any) -> None:
        try:
            event = frida_message_to_event(message)
        except ProtocolError as exc:
            event = InstrumentationError(phase="protocol", message=str(exc), fatal=True)
        callback = self._callback
        if callback is not None:
            callback(event)

    def load(self) -> None:
        if self.script is None:
            raise RuntimeError("create_script must happen before load")
        self.script.load()

    def resume(self, pid: int) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self.device.resume(pid)

    def kill(self, pid: int) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self.device.kill(pid)

    def detach(self) -> None:
        with self._lock:
            session, self.session = self.session, None
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    def close(self) -> None:
        self.detach()
