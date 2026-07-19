from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]


def test_agent_source_has_required_frida_api():
    source = (ROOT / "agent" / "sqlitewatch_agent.js").read_text()
    assert "Process.attachModuleObserver" in source
    assert "Process.enumerateModules" in source
    assert "findExportByName" in source
    assert "findSymbolByName" in source
    assert "Interceptor.attach" in source
    assert "sqlite3_prepare_v2" in source


def test_agent_source_parses_with_node():
    completed = subprocess.run(["node", "--check", "agent/sqlitewatch_agent.js"], cwd=ROOT)
    assert completed.returncode == 0
