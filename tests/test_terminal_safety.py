from io import BytesIO

from sqlitewatch.analysis import RuleConfig, analyze_run, evaluate_rules
from sqlitewatch.doctor import reduce_events, resolve_doctor_outcome
from sqlitewatch.events import (
    ModuleCapability,
    ObservedProcess,
    ProcessImage,
    ProcessTreeResult,
    RunResult,
    StatementExecuted,
    StatementPrepared,
)
from sqlitewatch.outcome import resolve_outcome
from sqlitewatch.reporting import ReportData, render_doctor_terminal, render_run_terminal
from sqlitewatch.reporting.output import write_utf8_stream


DANGER = "line\n\x1b]52;c;Y2xpcGJvYXJk\x07\u202e"


def test_run_terminal_escapes_controls_newlines_and_bidi_text():
    sql = f"SELECT '{DANGER}'"
    events = (
        StatementPrepared(
            1, 1, f"sqlite-{DANGER}", "0x1", f"0x2", sql,
            module_path=f"/tmp/{DANGER}", module_base="0x1000",
            process_instance=f"instance-{DANGER}",
        ),
        StatementExecuted(
            1, 1, f"sqlite-{DANGER}", "0x1", "0x2", 1, 101, "done",
            1, 1, 0, 0, module_path=f"/tmp/{DANGER}", module_base="0x1000",
            process_instance=f"instance-{DANGER}",
        ),
    )
    image = ProcessImage(
        f"instance-{DANGER}", 1, f"exec-{DANGER}", f"/tmp/{DANGER}",
        "ACTIVE", True, True,
    )
    tree = ProcessTreeResult(
        True, 1, True, (ObservedProcess(1, None, 0, True, (image,)),), 256, 1024,
    )
    run = RunResult(1, 0, None, events, "ACTIVE", process_tree=tree)
    analysis = analyze_run(run)
    rules = evaluate_rules(analysis, RuleConfig())
    text = render_run_terminal(ReportData(analysis, rules, resolve_outcome(run, rules)))
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "\u202e" not in text
    assert r"\x1b" in text and r"\x07" in text and r"\u202e" in text
    assert r"line\n" in text


def test_doctor_terminal_escapes_module_paths_and_reasons():
    symbols = (
        "sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset",
        "sqlite3_step", "sqlite3_stmt_status",
    )
    hooks = (
        "sqlite3_finalize", "sqlite3_prepare_v2", "sqlite3_reset", "sqlite3_step",
    )
    path = f"/tmp/{DANGER}"
    module = ModuleCapability(
        1, f"sqlite-{DANGER}", path, "embedded_or_unknown", True, True,
        symbols, ("sqlite3_libversion", "sqlite3_prepare_v3"), True,
        hooks, hooks, (), (DANGER,), "3.45", "0x1000",
    )
    prepared = StatementPrepared(
        1, 1, f"sqlite-{DANGER}", "0x1", "0x2", "SELECT 1",
        module_path=path, module_base="0x1000",
    )
    result = reduce_events(RunResult(1, 0, None, (module, prepared), "ACTIVE"))
    text = render_doctor_terminal(result, resolve_doctor_outcome(result))
    assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text
    assert r"\x1b" in text and r"\x07" in text and r"\u202e" in text


def test_utf8_stream_bypasses_ascii_text_wrapper_encoding():
    class AsciiStream:
        def __init__(self):
            self.buffer = BytesIO()

        def write(self, _content):  # pragma: no cover - binary path must win
            raise UnicodeEncodeError("ascii", "café", 3, 4, "ordinal")

        def flush(self):
            pass

    stream = AsciiStream()
    write_utf8_stream(stream, "café\n")
    assert stream.buffer.getvalue() == "café\n".encode("utf-8")
