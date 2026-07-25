"""Safe persistent report emission."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


def write_utf8_stream(stream: Any, content: str) -> None:
    """Write UTF-8 regardless of a stdio text wrapper's ambient encoding."""
    data = content.encode("utf-8")
    binary = getattr(stream, "buffer", None)
    if binary is not None and hasattr(binary, "write"):
        binary.write(data)
        binary.flush()
        return
    try:
        stream.write(content)
        stream.flush()
        return
    except UnicodeEncodeError:
        # Embedded callers may expose a text wrapper without ``buffer`` but
        # still provide a real descriptor.
        descriptor = stream.fileno()
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]


def write_report(path: Path, content: str) -> None:
    """Atomically replace *path* with UTF-8 report content.

    The parent directory is deliberately not created: a missing or inaccessible
    destination is an output failure and leaves any existing destination intact.
    """
    temporary_path: str | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
