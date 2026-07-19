import shutil

import pytest


@pytest.fixture(scope="session")
def native_tools_available():
    required = ["gcc", "ldd", "pkg-config"]
    if any(shutil.which(tool) is None for tool in required):
        pytest.skip("GCC, ldd and pkg-config are required")
    try:
        import frida  # noqa: F401
    except Exception:
        pytest.skip("Frida is required for integration tests")
    return True
