"""Instrumentation contracts and the optional Frida implementation."""

from .protocol import (
    ProtocolError,
    event_to_payload,
    frida_message_to_event,
    frida_message_to_events,
    payload_to_event,
    payload_to_events,
)

__all__ = [
    "ProtocolError",
    "event_to_payload",
    "frida_message_to_event",
    "frida_message_to_events",
    "payload_to_event",
    "payload_to_events",
]
