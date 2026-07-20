from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]
AGENT = ROOT / "src" / "sqlitewatch" / "agent" / "sqlitewatch_agent.js"
LEGACY_AGENT = ROOT / "agent" / "sqlitewatch_agent.js"


def test_agent_source_has_lifecycle_registry_and_modern_frida_api():
    source = AGENT.read_text()
    assert "Process.attachModuleObserver" in source
    assert "Process.enumerateModules" in source
    assert "findExportByName" in source
    assert "findSymbolByName" in source
    assert "Interceptor.attach" in source
    assert "findSymbol(module, name)" in source
    assert "const HOOKS" in source
    assert "inspectModule(module, false)" in source
    assert "inspectModule(modules[i], true)" in source
    assert "hookedAddresses" in source
    assert "hookedSymbolNames" in source
    for symbol in (
        "sqlite3_prepare_v2",
        "sqlite3_prepare_v3",
        "sqlite3_step",
        "sqlite3_reset",
        "sqlite3_finalize",
        "sqlite3_stmt_status",
    ):
        assert symbol in source
    assert "new NativeFunction" in source
    assert "SQLITE_STMTSTATUS_RESET_FLAG = 0" in source
    assert "resetFlag=1" not in source
    assert 'installHook(module, "sqlite3_stmt_status"' not in source
    assert "embedded_or_unknown" in source
    assert "Module.findExportByName" not in source
    assert "Module.enumerateExports" not in source


def test_agent_has_one_canonical_source():
    assert not LEGACY_AGENT.exists()


def test_backend_uses_only_the_controller_buffer():
    source = (ROOT / "src" / "sqlitewatch" / "instrumentation" / "frida_backend.py").read_text()
    assert "self._events" not in source
    assert "from queue import Queue" not in source


def test_agent_source_parses_with_node():
    completed = subprocess.run(["node", "--check", str(AGENT)], cwd=ROOT)
    assert completed.returncode == 0
    bootstrap = ROOT / "src" / "sqlitewatch" / "agent" / "launcher_bootstrap.js"
    assert subprocess.run(["node", "--check", str(bootstrap)], cwd=ROOT).returncode == 0
