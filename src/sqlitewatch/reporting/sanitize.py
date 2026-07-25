"""Terminal-safe rendering for target-controlled text fields."""

from __future__ import annotations

import unicodedata


def terminal_safe(value: object) -> str:
    """Escape controls and invisible formatting characters deterministically."""
    text = str(value)
    escaped: list[str] = []
    named = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    for character in text:
        codepoint = ord(character)
        if character in named:
            escaped.append(named[character])
        elif codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F:
            escaped.append(f"\\x{codepoint:02x}")
        elif unicodedata.category(character) in {"Cf", "Cs"}:
            escaped.append(
                f"\\u{codepoint:04x}"
                if codepoint <= 0xFFFF
                else f"\\U{codepoint:08x}"
            )
        else:
            escaped.append(character)
    return "".join(escaped)


__all__ = ["terminal_safe"]
