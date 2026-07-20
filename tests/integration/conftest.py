from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
from typing import Iterable

import pytest


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    """Tool versions used to explain scenario-local prerequisite skips."""

    versions: dict[str, str | None]

    def missing(self, tools: Iterable[str]) -> tuple[str, ...]:
        return tuple(tool for tool in tools if self.versions.get(tool) is None)

    def describe(self, tools: Iterable[str]) -> str:
        return "; ".join(
            f"{tool}={self.versions.get(tool) or 'unavailable'}" for tool in tools
        )


def _tool_version(tool: str) -> str | None:
    executable = shutil.which(tool)
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "available (version query failed)"
    output = (completed.stdout or completed.stderr).splitlines()
    return output[0].strip() if output else "available"


@pytest.fixture(scope="session")
def tool_availability() -> ToolAvailability:
    tools = ("gcc", "ldd", "nm", "strip", "pkg-config", "node", "npm")
    versions = {tool: _tool_version(tool) for tool in tools}
    try:
        import frida
    except Exception:
        versions["frida"] = None
    else:
        versions["frida"] = getattr(frida, "__version__", "available")
    return ToolAvailability(versions)


@pytest.fixture(scope="session")
def native_tools_available(tool_availability: ToolAvailability):
    required = ("gcc", "ldd", "pkg-config")
    missing = tool_availability.missing(required)
    if missing:
        pytest.skip(
            "native prerequisites unavailable: "
            f"{', '.join(missing)} ({tool_availability.describe(required)})"
        )
    if tool_availability.versions.get("frida") is None:
        pytest.skip(
            "Frida is required for integration tests "
            f"({tool_availability.describe((*required, 'frida'))})"
        )
    return True


@pytest.fixture(scope="session")
def embedded_tools_available(
    native_tools_available, tool_availability: ToolAvailability
):
    required = ("gcc", "ldd", "nm", "strip")
    missing = tool_availability.missing(required)
    if missing:
        pytest.skip(
            "embedded prerequisites unavailable: "
            f"{', '.join(missing)} ({tool_availability.describe(required)})"
        )
    return True


@pytest.fixture(scope="session")
def node_tools_available(tool_availability: ToolAvailability):
    required = ("node", "npm")
    missing = tool_availability.missing(required)
    if missing:
        pytest.skip(
            "Node prerequisites unavailable: "
            f"{', '.join(missing)} ({tool_availability.describe(required)})"
        )
    return True
