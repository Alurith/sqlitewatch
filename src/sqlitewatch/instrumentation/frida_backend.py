"""Frida adapter with one isolated stream per followed process image."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
import signal
from pathlib import Path
from threading import Condition, Lock, Thread, current_thread
import time
from typing import Any, Callable

from .protocol import (
    ProtocolError,
    frida_message_to_events,
    validate_lifecycle_acknowledged,
)
from ..events import (
    LEGACY_PROCESS_INSTANCE,
    PROTOCOL_VERSION,
    Event,
    InstrumentationError,
)


class FridaUnavailable(RuntimeError):
    """Raised when the optional Frida runtime cannot be imported."""


@dataclass(slots=True)
class _TargetStream:
    instance: str
    pid: int
    session: Any
    generation: int
    script: Any | None = None
    callback: Callable[[Event], None] | None = None
    next_sequence: int = 1
    expected_detach: bool = False


class FridaBackend:
    """Keep launcher resources and process-scoped target streams for one run."""

    def __init__(
        self,
        *,
        agent_path: Path | None = None,
        bootstrap_path: Path | None = None,
    ) -> None:
        try:
            import frida  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on the host
            raise FridaUnavailable(
                "Frida is required for native instrumentation; run `uv sync` first"
            ) from exc
        self.frida = frida
        self.device: Any = None
        self.launcher_session: Any = None
        self.launcher_script: Any = None
        self._launcher_callback: Callable[[Event], None] | None = None
        self._child_callback: Callable[[Any], None] | None = None
        self._child_removed_callback: Callable[[Any], None] | None = None
        self._child_listener: Callable[[Any], None] | None = None
        self._child_removed_listener: Callable[[Any], None] | None = None
        self._streams: dict[str, _TargetStream] = {}
        self._compat_target_instance = LEGACY_PROCESS_INSTANCE
        self._lock = Lock()
        self._generation = 0
        self._run_active = False
        self._ack_timeout = 2.0
        self._ack_condition = Condition()
        self._pending_acks: dict[
            tuple[int, str, int],
            tuple[float, Callable[[Event], None], int, int],
        ] = {}
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
        bootstrap = (
            Path(__file__).resolve().parent.parent / "agent" / "launcher_bootstrap.js"
        )
        if bootstrap.is_file():
            return bootstrap
        raise FileNotFoundError(
            f"package-local launcher bootstrap not found: {bootstrap}"
        )

    def begin_run(self) -> int:
        """Reset all per-run protocol state and return a callback generation."""
        with self._lock:
            if self._run_active:
                raise RuntimeError("Frida backend already has an active run")
            if self._streams or self.launcher_session is not None:
                raise RuntimeError("Frida backend resources were not detached")
            self._generation += 1
            self._run_active = True
            self._launcher_callback = None
            self._child_callback = None
            self._child_removed_callback = None
            self.launcher_script = None
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

    # Launcher lifecycle -------------------------------------------------

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

    def register_child_removed_handler(self, callback: Callable[[Any], None]) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self._child_removed_callback = callback
        if self._child_removed_listener is None:

            def on_child_removed(child: Any) -> None:
                handler = self._child_removed_callback
                if self._run_active and handler is not None:
                    handler(child)

            self._child_removed_listener = on_child_removed
            self.device.on("child-removed", on_child_removed)

    def register_launcher_detached_handler(
        self, callback: Callable[[str], None]
    ) -> None:
        self._register_detached(self.launcher_session, callback)

    def create_launcher_script(self, _config: Any = None) -> Any:
        if self.launcher_session is None:
            raise RuntimeError(
                "attach_launcher must happen before create_launcher_script"
            )
        self.launcher_script = self.launcher_session.create_script(
            self.bootstrap_path.read_text(encoding="utf-8"),
            name="launcher_bootstrap.js",
        )
        return self.launcher_script

    def register_launcher_message_handler(
        self, callback: Callable[[Event], None]
    ) -> None:
        self._launcher_callback = callback
        if self.launcher_script is None:
            raise RuntimeError(
                "create_launcher_script must happen before registering a callback"
            )
        generation = self._generation
        self.launcher_script.on(
            "message",
            lambda message, data: self._handle_launcher_message(
                message, data, callback, generation
            ),
        )

    def _handle_launcher_message(
        self,
        message: dict[str, Any],
        _data: Any,
        callback: Callable[[Event], None],
        generation: int,
    ) -> None:
        if not self._generation_is_active(generation):
            return
        try:
            events = frida_message_to_events(message)
        except ProtocolError as exc:
            events = (
                InstrumentationError(
                    phase="protocol",
                    message=str(exc),
                    fatal=True,
                    data_loss=True,
                ),
            )
        for event in events:
            callback(event)

    def load_launcher(self) -> None:
        if self.launcher_script is None:
            raise RuntimeError(
                "create_launcher_script must happen before load_launcher"
            )
        self.launcher_script.load()

    # Process-scoped streams --------------------------------------------

    def attach_process(self, instance: str, pid: int) -> Any:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        with self._lock:
            if not self._run_active:
                raise RuntimeError("begin_run must happen before attach_process")
            if instance in self._streams:
                raise RuntimeError(f"process stream already exists: {instance}")
            generation = self._generation
        session = self.device.attach(pid)
        stream = _TargetStream(instance, int(pid), session, generation)
        with self._lock:
            if not self._run_active or generation != self._generation:
                try:
                    session.detach()
                finally:
                    raise RuntimeError("run ended while attaching process")
            if instance in self._streams:
                try:
                    session.detach()
                finally:
                    raise RuntimeError(f"process stream already exists: {instance}")
            self._streams[instance] = stream
        return session

    def register_process_detached_handler(
        self, instance: str, callback: Callable[[str], None]
    ) -> None:
        stream = self._stream(instance)
        generation = stream.generation

        def detached(reason: Any, *_details: Any) -> None:
            if not self._stream_is_current(stream, generation):
                return
            self._cancel_stream_acks(stream.instance, generation)
            callback(str(reason))

        stream.session.on("detached", detached)

    def expect_process_detach(self, instance: str) -> None:
        self._stream(instance).expected_detach = True

    def enable_process_child_gating(self, instance: str) -> None:
        self._stream(instance).session.enable_child_gating()

    def disable_process_child_gating(self, instance: str) -> None:
        self._stream(instance).session.disable_child_gating()

    def create_process_script(self, instance: str, config: Any = None) -> Any:
        stream = self._stream(instance)
        max_sql_length = int(getattr(config, "max_sql_length", 65536))
        if max_sql_length <= 0:
            raise ValueError("max_sql_length must be positive")
        doctor = bool(getattr(config, "doctor", False))
        self._ack_timeout = float(getattr(config, "lifecycle_ack_timeout", 2.0))
        if not math.isfinite(self._ack_timeout) or self._ack_timeout <= 0:
            raise ValueError("lifecycle_ack_timeout must be finite and positive")
        injected = {
            "max_sql_length": max_sql_length,
            "doctor": doctor,
            "process_instance": stream.instance,
        }
        prefix = "var SQLITEWATCH_CONFIG = " + json.dumps(
            injected, ensure_ascii=True, separators=(",", ":")
        ) + ";\n"
        stream.script = stream.session.create_script(
            prefix + self.agent_path.read_text(encoding="utf-8"),
            name=f"sqlitewatch_agent_{stream.instance}.js",
        )
        return stream.script

    def register_process_message_handler(
        self, instance: str, callback: Callable[[Event], None]
    ) -> None:
        stream = self._stream(instance)
        if stream.script is None:
            raise RuntimeError(
                "create_process_script must happen before registering a callback"
            )
        stream.callback = callback
        generation = stream.generation
        script = stream.script
        script.on(
            "message",
            lambda message, data: self._handle_stream_message(
                stream, script, message, data, callback, generation
            ),
        )

    def _handle_stream_message(
        self,
        stream: _TargetStream,
        script: Any,
        message: dict[str, Any],
        data: Any,
        callback: Callable[[Event], None],
        generation: int,
    ) -> None:
        if not self._stream_is_current(stream, generation):
            return
        accepted = self._on_stream_message(
            stream, message, data, callback, generation
        )
        payload = message.get("payload") if message.get("type") == "send" else None
        if (
            accepted
            and isinstance(payload, dict)
            and payload.get("type") == "lifecycle_batch"
            and payload.get("ack_required") is True
        ):
            sequence = payload["sequence"]
            key = (generation, stream.instance, sequence)
            self._register_pending_ack(
                key, callback, generation, stream.pid
            )
            try:
                script.post(
                    {
                        "type": "sqlitewatch_ack",
                        "payload": {
                            "protocol_version": PROTOCOL_VERSION,
                            "process_instance": stream.instance,
                            "sequence": sequence,
                        },
                    }
                )
            except Exception as exc:
                self._cancel_pending_ack(key)
                callback(
                    InstrumentationError(
                        phase="transport",
                        message=f"could not acknowledge lifecycle batch: {exc}",
                        pid=stream.pid,
                        fatal=True,
                        data_loss=True,
                        process_instance=stream.instance,
                    )
                )

    def _on_stream_message(
        self,
        stream: _TargetStream,
        message: dict[str, Any],
        _data: Any,
        callback: Callable[[Event], None],
        generation: int | None = None,
    ) -> bool:
        if generation is not None and not self._stream_is_current(stream, generation):
            return False
        accepted = True
        try:
            payload = message.get("payload") if message.get("type") == "send" else None
            if isinstance(payload, dict) and payload.get("type") == "lifecycle_acknowledged":
                sequence = validate_lifecycle_acknowledged(
                    payload, expected_process_instance=stream.instance
                )
                if not self._confirm_pending_ack(
                    (generation or stream.generation, stream.instance, sequence),
                    generation,
                ):
                    raise ProtocolError(
                        "invalid or unexpected lifecycle acknowledgement"
                    )
                return True
            if isinstance(payload, dict) and payload.get("type") == "lifecycle_batch":
                sequence = payload.get("sequence")
                with self._lock:
                    if not self._stream_is_current_unlocked(stream, generation):
                        return False
                    if sequence != stream.next_sequence:
                        raise ProtocolError(
                            "invalid lifecycle batch sequence: expected "
                            f"{stream.next_sequence}"
                        )
                    events = frida_message_to_events(
                        message,
                        expected_pid=stream.pid,
                        expected_process_instance=stream.instance,
                    )
                    stream.next_sequence += 1
            else:
                events = frida_message_to_events(
                    message,
                    expected_pid=stream.pid,
                    expected_process_instance=stream.instance,
                )
        except ProtocolError as exc:
            accepted = False
            events = (
                InstrumentationError(
                    phase="protocol",
                    message=str(exc),
                    pid=stream.pid,
                    fatal=True,
                    data_loss=True,
                    process_instance=stream.instance,
                ),
            )
        for event in events:
            callback(event)
        return accepted

    def load_process(self, instance: str) -> None:
        stream = self._stream(instance)
        if stream.script is None:
            raise RuntimeError("create_process_script must happen before load_process")
        stream.script.load()

    def detach_process(self, instance: str) -> None:
        with self._lock:
            stream = self._streams.pop(instance, None)
            if stream is None:
                return
            stream.expected_detach = True
            stream.callback = None
        self._cancel_stream_acks(instance, stream.generation)
        try:
            stream.session.disable_child_gating()
        except Exception:
            pass
        try:
            stream.session.detach()
        except Exception:
            pass

    def process_instances(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._streams))

    # Pending children / transport drain --------------------------------

    def enumerate_pending_children(self) -> tuple[Any, ...]:
        if self.device is None:
            return ()
        return tuple(self.device.enumerate_pending_children())

    def disable_all_child_gating(self) -> tuple[str, ...]:
        """Stop creating new pending children; existing ones auto-resume."""
        errors: list[str] = []
        with self._lock:
            sessions = tuple(stream.session for stream in self._streams.values())
            launcher = self.launcher_session
        for session in sessions:
            try:
                session.disable_child_gating()
            except Exception as exc:
                errors.append(f"could not disable process child gating: {exc}")
        if launcher is not None:
            try:
                launcher.disable_child_gating()
            except Exception as exc:
                errors.append(f"could not disable launcher child gating: {exc}")
        return tuple(errors)

    def release_pending_children(self) -> tuple[str, ...]:
        errors: list[str] = []
        try:
            children = self.enumerate_pending_children()
        except Exception as exc:
            return (f"could not enumerate pending children: {exc}",)
        for child in children:
            try:
                self.resume(int(getattr(child, "pid", child)))
            except Exception as exc:
                errors.append(
                    f"could not resume pending child {getattr(child, 'pid', child)}: {exc}"
                )
        return tuple(errors)

    @property
    def pending_ack_count(self) -> int:
        with self._ack_condition:
            return len(self._pending_acks)

    def wait_for_pending_acks(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._ack_condition:
            while self._pending_acks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._ack_condition.wait(remaining)
            return True

    def _register_pending_ack(
        self,
        key: tuple[int, str, int],
        callback: Callable[[Event], None],
        generation: int,
        pid: int,
    ) -> None:
        with self._ack_condition:
            if key in self._pending_acks:
                raise RuntimeError(f"duplicate pending lifecycle acknowledgement: {key}")
            self._pending_acks[key] = (
                time.monotonic() + self._ack_timeout,
                callback,
                generation,
                pid,
            )
            if self._ack_thread is None or not self._ack_thread.is_alive():
                self._ack_thread = Thread(
                    target=self._watch_acknowledgements,
                    name="sqlitewatch-ack-watchdog",
                    daemon=True,
                )
                self._ack_thread.start()
            self._ack_condition.notify_all()

    def _cancel_pending_ack(self, key: tuple[int, str, int]) -> None:
        with self._ack_condition:
            self._pending_acks.pop(key, None)
            self._ack_condition.notify_all()

    def _cancel_stream_acks(self, instance: str, generation: int) -> None:
        with self._ack_condition:
            for key, pending in tuple(self._pending_acks.items()):
                if key[1] == instance and pending[2] == generation:
                    del self._pending_acks[key]
            self._ack_condition.notify_all()

    def _confirm_pending_ack(
        self, key: tuple[int, str, int], generation: int | None
    ) -> bool:
        with self._ack_condition:
            pending = self._pending_acks.get(key)
            if pending is None:
                return False
            if generation is not None and pending[2] != generation:
                return False
            del self._pending_acks[key]
            self._ack_condition.notify_all()
            return True

    def _watch_acknowledgements(self) -> None:
        while True:
            expired: list[
                tuple[tuple[int, str, int], Callable[[Event], None], int, int]
            ] = []
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
                for key, (deadline, callback, generation, pid) in tuple(
                    self._pending_acks.items()
                ):
                    if deadline <= now:
                        del self._pending_acks[key]
                        expired.append((key, callback, generation, pid))
                self._ack_condition.notify_all()
            for (_run_generation, instance, sequence), callback, generation, pid in expired:
                if self._generation_is_active(generation):
                    callback(
                        InstrumentationError(
                            phase="transport",
                            message=(
                                "lifecycle acknowledgement timed out for stream "
                                f"{instance} batch {sequence}"
                            ),
                            pid=pid,
                            fatal=True,
                            data_loss=True,
                            process_instance=instance,
                        )
                    )

    # Compatibility wrappers for small programmatic/fake backends --------

    @property
    def target_session(self) -> Any | None:
        stream = self._streams.get(self._compat_target_instance)
        return None if stream is None else stream.session

    @property
    def target_script(self) -> Any | None:
        stream = self._streams.get(self._compat_target_instance)
        return None if stream is None else stream.script

    def attach_target(self, pid: int) -> Any:
        return self.attach_process(self._compat_target_instance, pid)

    def register_target_detached_handler(
        self, callback: Callable[[str], None]
    ) -> None:
        self.register_process_detached_handler(self._compat_target_instance, callback)

    def create_target_script(self, config: Any = None) -> Any:
        return self.create_process_script(self._compat_target_instance, config)

    def register_target_message_handler(
        self, callback: Callable[[Event], None]
    ) -> None:
        self.register_process_message_handler(self._compat_target_instance, callback)

    def load_target(self) -> None:
        self.load_process(self._compat_target_instance)

    # Generic process lifecycle / teardown -------------------------------

    def resume(self, pid: int) -> None:
        if self.device is None:
            raise RuntimeError("device is not initialized")
        self.device.resume(pid)

    def terminate_launcher(
        self, pid: int, signum: int = signal.SIGTERM
    ) -> None:
        self.signal_process(pid, signum)

    @staticmethod
    def signal_process(pid: int, signum: int) -> None:
        try:
            if signum != signal.SIGKILL:
                os.kill(pid, signal.SIGCONT)
            os.kill(pid, signum)
        except ProcessLookupError:
            pass

    def _register_detached(
        self, session: Any, callback: Callable[[str], None]
    ) -> None:
        if session is None:
            raise RuntimeError("attach must happen before registering detached handler")
        generation = self._generation

        def detached(reason: Any, *_details: Any) -> None:
            if self._generation_is_active(generation):
                callback(str(reason))

        session.on("detached", detached)

    def _stream(self, instance: str) -> _TargetStream:
        with self._lock:
            try:
                return self._streams[instance]
            except KeyError as exc:
                raise RuntimeError(f"unknown process stream: {instance}") from exc

    def _generation_is_active(self, generation: int) -> bool:
        with self._lock:
            return self._run_active and generation == self._generation

    def _stream_is_current(
        self, stream: _TargetStream, generation: int | None
    ) -> bool:
        with self._lock:
            return self._stream_is_current_unlocked(stream, generation)

    def _stream_is_current_unlocked(
        self, stream: _TargetStream, generation: int | None
    ) -> bool:
        return (
            self._run_active
            and (generation is None or generation == self._generation)
            and self._streams.get(stream.instance) is stream
        )

    def detach(self) -> None:
        with self._lock:
            self._run_active = False
            streams = tuple(self._streams.values())
            self._streams.clear()
            launcher_session, self.launcher_session = self.launcher_session, None
            self.launcher_script = None
            self._launcher_callback = None
            self._child_callback = None
            self._child_removed_callback = None
        with self._ack_condition:
            self._pending_acks.clear()
            ack_thread = self._ack_thread
            self._ack_condition.notify_all()

        # Device.resume(pid) is not idempotent for pending children. Consume
        # the pending snapshot before disable_child_gating() asynchronously
        # releases anything that raced with the snapshot.
        self.release_pending_children()
        for stream in streams:
            try:
                stream.session.disable_child_gating()
            except Exception:
                pass
        for stream in streams:
            try:
                stream.session.detach()
            except Exception:
                pass
        if launcher_session is not None:
            try:
                launcher_session.disable_child_gating()
            except Exception:
                pass
            try:
                launcher_session.detach()
            except Exception:
                pass

        if (
            ack_thread is not None
            and ack_thread is not current_thread()
            and ack_thread.is_alive()
        ):
            ack_thread.join(timeout=0.2)
        with self._ack_condition:
            if self._ack_thread is ack_thread:
                self._ack_thread = None

    close = detach


__all__ = ["FridaBackend", "FridaUnavailable"]
