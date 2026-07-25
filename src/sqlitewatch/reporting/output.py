"""Safe persistent report emission."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import NamedTemporaryFile


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
