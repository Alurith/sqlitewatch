"""Deterministic renderers for the Doctor-specific report schema."""

from __future__ import annotations

import json

from ..doctor import DoctorOutcome, DoctorResult
from .process_tree import process_tree_to_dict
from .sanitize import terminal_safe


def doctor_to_dict(result: DoctorResult, outcome: DoctorOutcome) -> dict[str, object]:
    return {
        "schema_version": 3,
        "report_type": "sqlitewatch_doctor",
        "status": result.status,
        "target": {
            "pid": result.pid,
            "exit_code": result.target_exit_code,
            "signal": result.signal,
            "failed": outcome.application_failed,
        },
        "process_tree": (
            process_tree_to_dict(result.process_tree)
            if result.process_tree is not None
            else None
        ),
        "modules": [
            {
                "process_instance": module.process_instance,
                "pid": module.pid,
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


def _doctor_verdict(result: DoctorResult) -> str:
    return {
        "ACTIVE": "HEALTHY",
        "NO_ACTIVITY": "NO SQLITE ACTIVITY",
        "NOT_DETECTED": "SQLITE NOT DETECTED",
        "DETECTED_UNSUPPORTED": "SQLITE DETECTED BUT UNSUPPORTED",
        "PARTIAL": "PROBLEMS FOUND",
        "FAILED": "FAILED",
    }.get(result.status, str(result.status))


def _relevant_module_groups(result: DoctorResult) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], dict[str, object]] = {}
    for module in result.modules:
        relevant = (
            module.complete
            or module.candidate
            or module.sqlite_version is not None
            or bool(module.symbols_present)
            or bool(module.hooks_installed)
            or bool(module.hooks_failed)
        )
        if not relevant:
            continue
        key = (
            module.path,
            module.module,
            module.sqlite_version,
            module.complete,
            module.reasons,
            module.hooks_failed,
        )
        group = groups.setdefault(
            key,
            {
                "module": module.module,
                "path": module.path,
                "version": module.sqlite_version,
                "complete": module.complete,
                "reasons": module.reasons,
                "hooks_failed": module.hooks_failed,
                "pids": set(),
                "instances": set(),
            },
        )
        group["pids"].add(module.pid)  # type: ignore[union-attr]
        group["instances"].add(module.process_instance)  # type: ignore[union-attr]
    return sorted(
        groups.values(),
        key=lambda item: (
            not bool(item["complete"]),
            str(item["module"]),
            str(item["path"]),
        ),
    )


def render_doctor_terminal(result: DoctorResult, outcome: DoctorOutcome) -> str:
    """Render compatibility conclusions, hiding irrelevant native modules."""
    lines = [
        f"SQLiteWatch Doctor: {_doctor_verdict(result)}",
        "",
        f"SQLite activity: {result.complete_activity_count} complete, "
        f"{result.incomplete_activity_count} incomplete",
    ]
    if result.process_tree is not None:
        tree = result.process_tree
        coverage = "COMPLETE" if tree.complete else "INCOMPLETE"
        scope = "recursive" if tree.follow_children else "root only"
        lines.append(
            f"Process coverage: {coverage} "
            f"({tree.process_count} processes, {tree.image_count} images, {scope})"
        )

    groups = _relevant_module_groups(result)
    lines.extend(["", f"SQLite-capable modules: {len(groups)}"])
    if not groups:
        lines.append("  None detected.")
    for index, group in enumerate(groups, start=1):
        pids = ", ".join(str(pid) for pid in sorted(group["pids"]))
        support = "supported" if group["complete"] else "not fully supported"
        version = terminal_safe(str(group["version"] or "version unavailable"))
        lines.extend([
            f"  [{index}] {terminal_safe(str(group['module']))}, SQLite {version}, "
            f"{support} in {len(group['pids'])} process(es)",
            f"    PIDs: {pids}",
        ])
        if not group["complete"]:
            lines.append(f"    Path: {terminal_safe(str(group['path']))}")
            for reason in group["reasons"]:
                lines.append(f"    Problem: {terminal_safe(str(reason))}")
            if group["hooks_failed"]:
                lines.append(
                    "    Failed hooks: "
                    + terminal_safe(", ".join(group["hooks_failed"]))
                )

    problems = list(result.reasons)
    if result.process_tree is not None and not result.process_tree.complete:
        problems.append("process-tree coverage is incomplete")
    if outcome.application_failed:
        problems.append("the target application failed")
    incomplete_modules = sum(1 for group in groups if not group["complete"])
    lines.extend(["", f"Compatibility problems: {len(problems) + incomplete_modules}"])
    if not problems and not incomplete_modules:
        lines.append("  None detected.")
    else:
        lines.extend(f"  {terminal_safe(problem)}" for problem in problems)
        if incomplete_modules:
            lines.append(
                f"  {incomplete_modules} SQLite-capable module group(s) are not fully supported."
            )

    lines.extend([
        "",
        f"Exit code: {outcome.exit_code}",
        "Doctor checks compatibility; use the normal command for query analysis.",
        "Full details: rerun Doctor with --format json.",
    ])
    return "\n".join(lines) + "\n"
