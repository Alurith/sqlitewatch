"""Deterministic, terminal-safe rendering of derived analysis."""

from __future__ import annotations

from ..analysis import AnalysisResult
from .model import ReportData
from .process_tree import render_process_tree_terminal
from .sanitize import terminal_safe


def render_terminal(analysis: AnalysisResult) -> str:
    """Render analysis only; process execution and I/O remain with the caller."""
    quality = analysis.data_quality
    lines = [
        "SQLiteWatch analysis",
        "",
        "Summary",
        f"  Observed executions: {quality.observed_executions}",
        f"  Metric-bearing executions: {quality.metric_bearing_executions}",
        f"  Unique scoped queries: {len(analysis.aggregates)}",
        f"  Instrumentation: {terminal_safe(analysis.instrumentation_status)}"
        + (" (failed)" if analysis.instrumentation_failed else ""),
        f"  SQL capture limit: {analysis.sql_capture_limit if analysis.sql_capture_limit is not None else 'unknown'} bytes",
        f"  Evaluation complete: {analysis.evaluation_complete}",
    ]

    nonzero_quality = (
        ("Null-metric executions", quality.null_metric_executions),
        ("Unmatched executions", quality.unmatched_executions),
        ("Truncated-SQL executions", quality.truncated_sql_executions),
        ("SQL-capture-failed executions", quality.sql_capture_failed_executions),
        ("Duplicate executions", quality.duplicate_executions),
        ("Conflicted executions", quality.conflicted_executions),
        ("Unfinished executions", quality.unfinished_executions),
        ("Instrumentation data-loss errors", quality.instrumentation_data_loss_events),
        ("Process coverage-loss errors", quality.process_coverage_loss_events),
    )
    if any(value for _, value in nonzero_quality):
        lines.extend(["", "Data quality"])
        lines.extend(
            f"  {name}: {value}" for name, value in nonzero_quality if value
        )
    if analysis.incomplete_reasons:
        lines.extend([
            "",
            "Evaluation warning",
            "  Some observed executions could not be evaluated: "
            + ", ".join(analysis.incomplete_reasons),
        ])

    if analysis.process_tree is not None:
        lines.extend(["", *render_process_tree_terminal(analysis.process_tree)])

    if quality.observed_executions and not quality.metric_bearing_executions:
        lines.extend([
            "",
            "No metric-bearing executions were observed; queries were not aggregated.",
        ])
    elif not analysis.aggregates:
        lines.extend([
            "",
            "No metric-bearing executions could be associated with complete SQL.",
        ])
    else:
        lines.extend(["", "Queries"])
        for index, aggregate in enumerate(analysis.aggregates, start=1):
            scope = aggregate.scope
            lines.extend([
                f"  [{index}] instance={terminal_safe(scope.process_instance)} "
                f"pid={scope.pid} module={terminal_safe(scope.module)} "
                f"database={terminal_safe(scope.database)} path={terminal_safe(scope.module_path)} "
                f"base={terminal_safe(scope.module_base)}",
                f"    SQL: {terminal_safe(aggregate.normalized_sql)}",
                f"    Fingerprint: {aggregate.fingerprint}",
                f"    Executions: {aggregate.executions}",
                f"    Fullscan steps: total={aggregate.total_fullscan_steps} max={aggregate.max_fullscan_steps}",
                f"    VM steps: total={aggregate.total_vm_steps} max={aggregate.max_vm_steps}",
                f"    Sorts: {aggregate.total_sorts}",
                f"    Autoindex: {aggregate.total_autoindex}",
                f"    Signals: {', '.join(aggregate.signals) if aggregate.signals else 'none'}",
            ])
    return "\n".join(lines) + "\n"


_MAX_TERMINAL_PROBLEMS = 10


def _operational_verdict(report: ReportData) -> str:
    analysis = report.analysis
    outcome = report.outcome
    if outcome.instrumentation_failed or analysis.instrumentation_status == "FAILED":
        return "FAILED"
    if analysis.instrumentation_status == "ACTIVE":
        if outcome.evaluation_incomplete or outcome.application_failed:
            return "WORKING WITH WARNINGS"
        return "WORKING"
    if analysis.instrumentation_status == "PARTIAL":
        return "PARTIAL"
    if analysis.instrumentation_status == "DETECTED_UNSUPPORTED":
        return "SQLITE DETECTED BUT UNSUPPORTED"
    return "SQLITE NOT DETECTED"


def _problem_groups(report: ReportData) -> list[dict[str, object]]:
    violated = {violation.query.fingerprint for violation in report.rules.violations}
    groups: dict[str, dict[str, object]] = {}
    for query in report.analysis.aggregates:
        if not query.signals and query.fingerprint not in violated:
            continue
        group = groups.setdefault(
            query.fingerprint,
            {
                "sql": query.normalized_sql,
                "executions": 0,
                "fullscan_total": 0,
                "fullscan_max": 0,
                "vm_total": 0,
                "vm_max": 0,
                "sorts": 0,
                "autoindex": 0,
                "signals": set(),
                "scopes": set(),
                "rules": {},
            },
        )
        group["executions"] = int(group["executions"]) + query.executions
        group["fullscan_total"] = int(group["fullscan_total"]) + query.total_fullscan_steps
        group["fullscan_max"] = max(int(group["fullscan_max"]), query.max_fullscan_steps)
        group["vm_total"] = int(group["vm_total"]) + query.total_vm_steps
        group["vm_max"] = max(int(group["vm_max"]), query.max_vm_steps)
        group["sorts"] = int(group["sorts"]) + query.total_sorts
        group["autoindex"] = int(group["autoindex"]) + query.total_autoindex
        group["signals"].update(query.signals)  # type: ignore[union-attr]
        group["scopes"].add(
            (query.scope.process_instance, query.scope.pid, query.scope.database)
        )  # type: ignore[union-attr]
    for violation in report.rules.violations:
        group = groups.get(violation.query.fingerprint)
        if group is not None:
            group["rules"][violation.rule] = violation.threshold  # type: ignore[index]
    return sorted(
        groups.values(),
        key=lambda item: (
            -int(item["autoindex"]),
            -int(item["fullscan_max"]),
            -int(item["sorts"]),
            -int(item["vm_max"]),
            str(item["sql"]),
        ),
    )


def render_run_terminal(report: ReportData) -> str:
    """Render a concise human verdict; JSON retains the complete report."""
    analysis = report.analysis
    quality = analysis.data_quality
    rules = report.rules
    outcome = report.outcome
    tree = analysis.process_tree
    lines = [
        f"SQLiteWatch: {_operational_verdict(report)}",
        "",
        f"Analysis: {quality.metric_bearing_executions} measured SQL executions "
        f"across {len(analysis.aggregates)} scoped query aggregates",
    ]
    if tree is not None:
        coverage = "COMPLETE" if tree.complete else "INCOMPLETE"
        lines.append(
            f"Process coverage: {coverage} "
            f"({tree.process_count} processes, {tree.image_count} images)"
        )
    if outcome.application_failed:
        target_result = (
            f"signal {outcome.signal}"
            if outcome.signal is not None
            else f"exit {outcome.target_exit_code}"
        )
        lines.append(f"Application: FAILED ({target_result})")
    else:
        lines.append(f"Application: EXITED NORMALLY ({outcome.target_exit_code or 0})")

    if rules.config.enabled:
        if rules.failed:
            lines.append(
                f"Rules: FAILED ({len(rules.violations)} violations)"
            )
        elif rules.inconclusive:
            lines.append("Rules: INCONCLUSIVE (some activity could not be evaluated)")
        else:
            lines.append("Rules: PASSED")

    quality_items = (
        (quality.null_metric_executions, "executions had no usable metrics"),
        (quality.unmatched_executions, "executions had no matching prepare event"),
        (quality.truncated_sql_executions, "executions had truncated SQL"),
        (quality.sql_capture_failed_executions, "executions had failed SQL capture"),
        (quality.duplicate_executions, "duplicate executions were ignored"),
        (quality.conflicted_executions, "conflicting executions were ignored"),
        (quality.unfinished_executions, "executions were unfinished"),
        (
            quality.instrumentation_data_loss_events,
            "instrumentation data-loss events made evaluation partial",
        ),
        (
            quality.process_coverage_loss_events,
            "process coverage-loss events made evaluation partial",
        ),
    )
    warnings = [(count, label) for count, label in quality_items if count]
    if warnings or analysis.instrumentation_failed:
        lines.extend(["", "Warnings"])
        lines.extend(f"  {count} {label}" for count, label in warnings)
        if analysis.instrumentation_failed and analysis.instrumentation_error:
            lines.append(
                "  Instrumentation failed: "
                + terminal_safe(analysis.instrumentation_error)
            )

    problems = _problem_groups(report)
    lines.extend(["", f"Potential query problems: {len(problems)}"])
    if not problems:
        lines.append("  None detected from full scans, sorts, autoindexes, or configured rules.")
    else:
        for index, problem in enumerate(
            problems[:_MAX_TERMINAL_PROBLEMS], start=1
        ):
            labels = set(problem["signals"])
            labels.update(
                rule if threshold is None else f"{rule}>{threshold}"
                for rule, threshold in problem["rules"].items()
            )
            lines.extend([
                f"  [{index}] {', '.join(sorted(labels))}",
                f"    SQL: {terminal_safe(str(problem['sql']))}",
                "    "
                f"executions={problem['executions']} scopes={len(problem['scopes'])} "
                f"fullscan(total/max)={problem['fullscan_total']}/{problem['fullscan_max']} "
                f"vm(total/max)={problem['vm_total']}/{problem['vm_max']} "
                f"sorts={problem['sorts']} autoindex={problem['autoindex']}",
            ])
        omitted = len(problems) - _MAX_TERMINAL_PROBLEMS
        if omitted > 0:
            lines.append(
                f"  {omitted} additional problem query patterns omitted from terminal output."
            )

    lines.extend([
        "",
        f"Exit code: {outcome.exit_code}",
        "Full details: rerun with --format json.",
    ])
    return "\n".join(lines) + "\n"
