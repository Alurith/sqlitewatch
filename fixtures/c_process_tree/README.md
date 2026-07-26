# C process-tree fixture

`fixture-fork-inherited` prepares a SQLite statement before `fork()` and steps
that inherited pointer only in the child. The child stream therefore has no
local prepare event and must emit explicit, deduplicated data-loss diagnostics
instead of silently accepting lifecycle events.
