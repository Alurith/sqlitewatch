"""Conservative SQL whitespace normalization and fingerprints."""

from __future__ import annotations

import hashlib


def normalize_sql(sql: str) -> str:
    """Normalize only whitespace outside SQL literals, identifiers, and comments.

    This deliberately is not a SQL parser: malformed input remains intact and
    protected regions are copied verbatim.
    """
    if not isinstance(sql, str):
        raise TypeError("sql must be a string")

    output: list[str] = []
    index = 0
    pending_space = False
    state = "normal"

    def emit(character: str) -> None:
        nonlocal pending_space
        if pending_space and output:
            output.append(" ")
        pending_space = False
        output.append(character)

    while index < len(sql):
        character = sql[index]
        next_character = sql[index + 1] if index + 1 < len(sql) else ""

        if state == "normal":
            if character.isspace():
                pending_space = bool(output)
                index += 1
                continue
            if character == "'":
                emit(character)
                state = "single_quote"
            elif character == '"':
                emit(character)
                state = "double_quote"
            elif character == "`":
                emit(character)
                state = "backtick"
            elif character == "[":
                emit(character)
                state = "bracket"
            elif character == "-" and next_character == "-":
                emit("-")
                emit("-")
                index += 1
                state = "line_comment"
            elif character == "/" and next_character == "*":
                emit("/")
                emit("*")
                index += 1
                state = "block_comment"
            else:
                emit(character)
        elif state == "single_quote":
            output.append(character)
            if character == "'":
                if next_character == "'":
                    output.append(next_character)
                    index += 1
                else:
                    state = "normal"
        elif state == "double_quote":
            output.append(character)
            if character == '"':
                if next_character == '"':
                    output.append(next_character)
                    index += 1
                else:
                    state = "normal"
        elif state == "backtick":
            output.append(character)
            if character == "`":
                state = "normal"
        elif state == "bracket":
            output.append(character)
            if character == "]":
                state = "normal"
        elif state == "line_comment":
            output.append(character)
            if character in "\r\n":
                state = "normal"
        else:  # block_comment
            output.append(character)
            if character == "*" and next_character == "/":
                output.append(next_character)
                index += 1
                state = "normal"
        index += 1

    return "".join(output).strip()


def fingerprint_sql(sql: str) -> str:
    """Return the SHA-256 hex digest of conservatively normalized SQL."""
    normalized = normalize_sql(sql)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
