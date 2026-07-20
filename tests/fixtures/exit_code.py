"""Target used to verify that application status survives instrumentation."""

from __future__ import annotations

import os
import signal
import sys
import time


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "0"
    # Keep the target alive long enough for the launcher/Frida handshake.
    time.sleep(0.1)
    if mode == "signal":
        os.kill(os.getpid(), signal.SIGTERM)
    raise SystemExit(int(mode))
