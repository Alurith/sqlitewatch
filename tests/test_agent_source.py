from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]
AGENT = ROOT / "agent" / "sqlitewatch_agent.js"
FALLBACK_AGENT = ROOT / "src" / "sqlitewatch" / "agent" / "sqlitewatch_agent.js"


def test_agent_source_has_required_frida_api_and_linkage_classification():
    source = AGENT.read_text()
    assert "Process.attachModuleObserver" in source
    assert "Process.enumerateModules" in source
    assert "findExportByName" in source
    assert "findSymbolByName" in source
    assert "Interceptor.attach" in source
    assert "sqlite3_prepare_v2" in source
    assert "embedded_or_unknown" in source
    assert "libsqlite3" in source
    assert "Module.findExportByName" not in source
    assert "Module.enumerateExports" not in source


def test_agent_copies_are_synchronized():
    assert AGENT.read_bytes() == FALLBACK_AGENT.read_bytes()


def test_agent_source_parses_with_node():
    completed = subprocess.run(["node", "--check", str(AGENT)], cwd=ROOT)
    assert completed.returncode == 0
