"""Target used to verify that application status survives instrumentation."""

from __future__ import annotations

import sys
import time


if __name__ == "__main__":
    code = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    # Keep the target alive long enough for local Frida's waitpid path to arm.
    time.sleep(0.1)
    raise SystemExit(code)
