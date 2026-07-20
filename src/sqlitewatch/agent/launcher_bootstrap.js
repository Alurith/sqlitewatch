"use strict";

// The launcher has no SQLite hooks. Its only purpose is to confirm that the
// controller attached and enabled child gating before it is resumed.
send({
  type: "launcher_ready",
  protocol_version: 1,
  pid: Process.id,
  arch: Process.arch,
  platform: Process.platform
});
