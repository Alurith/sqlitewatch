"""Deterministic renderers for the Doctor-specific report schema."""

from __future__ import annotations

import json

from ..doctor import DoctorOutcome, DoctorResult
from .sanitize import terminal_safe


def doctor_to_dict(result: DoctorResult, outcome: DoctorOutcome) -> dict[str, object]:
    return {
        "schema_version": 2,
        "report_type": "sqlitewatch_doctor",
        "status": result.status,
        "target": {
            "pid": result.pid,
            "exit_code": result.target_exit_code,
            "signal": result.signal,
            "failed": outcome.application_failed,
        },
        "modules": [
            {
                "name": module.module,
                "path": module.path,
                "base": module.base,
                "linkage": module.linkage,
                "candidate": module.candidate,
                "scanned": module.scanned,
                "sqlite_version": module.sqlite_version,
                "symbols": {
                    "present": list(module.symbols_present),
                    "missing": list(module.symbols_missing),
                },
                "metric_reader": module.metric_reader,
                "hooks": {
                    "attempted": list(module.hooks_attempted),
                    "installed": list(module.hooks_installed),
                    "failed": list(module.hooks_failed),
                },
                "supported": module.complete,
                "reasons": list(module.reasons),
            }
            for module in result.modules
        ],
        "activity": {
            "statement_prepared": result.activity_count,
            "complete_modules": result.complete_activity_count,
            "incomplete_modules": result.incomplete_activity_count,
        },
        "reasons": list(result.reasons),
        "limitations": list(result.limitations),
        "outcome": {
            "application_failure": outcome.application_failed,
            "doctor_failure": outcome.doctor_failed,
            "exit_code": outcome.exit_code,
        },
    }


def render_doctor_json(result: DoctorResult, outcome: DoctorOutcome) -> str:
    return json.dumps(
        doctor_to_dict(result, outcome), ensure_ascii=False, sort_keys=True
    ) + "\n"


def render_doctor_terminal(result: DoctorResult, outcome: DoctorOutcome) -> str:
    lines = [
        "SQLiteWatch Doctor",
        "",
        f"Status: {result.status}",
        f"Target: pid={result.pid} exit={result.target_exit_code} signal={result.signal}",
        f"Activity: complete={result.complete_activity_count} incomplete={result.incomplete_activity_count}",
        "",
        "Modules",
    ]
    if not result.modules:
        lines.append("  none")
    for module in result.modules:
        lines.extend([
            f"  {terminal_safe(module.module)} ({terminal_safe(module.linkage)})",
            f"    Path: {terminal_safe(module.path)}",
            f"    Base: {terminal_safe(module.base)}",
            f"    Candidate/scanned: {module.candidate}/{module.scanned}",
            f"    SQLite version: {terminal_safe(module.sqlite_version or 'unavailable')}",
            "    Symbols present: "
            + terminal_safe(", ".join(module.symbols_present) or "none"),
            "    Symbols missing: "
            + terminal_safe(", ".join(module.symbols_missing) or "none"),
            f"    Metric reader: {module.metric_reader}; hooks: "
            + terminal_safe(", ".join(module.hooks_installed) or "none"),
            f"    Supported: {module.complete}",
        ])
        for reason in module.reasons:
            lines.append(f"    Reason: {terminal_safe(reason)}")
    if result.reasons:
        lines.extend([
            "",
            "Reasons",
            *[f"  {terminal_safe(reason)}" for reason in result.reasons],
        ])
    lines.extend([
        "",
        "Limitations",
        *[f"  {terminal_safe(item)}" for item in result.limitations],
        "",
        "Outcome",
        f"  Application failure: {outcome.application_failed}",
        f"  Doctor failure: {outcome.doctor_failed}",
        f"  Final exit code: {outcome.exit_code}",
    ])
    return "\n".join(lines) + "\n"
