"""Deterministic, terminal-safe rendering of derived analysis."""

from __future__ import annotations

from ..analysis import AnalysisResult
from .model import ReportData
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
                f"  [{index}] pid={scope.pid} module={terminal_safe(scope.module)} "
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


def render_run_terminal(report: ReportData) -> str:
    """Render the complete run envelope without target-controlled controls."""
    analysis = report.analysis
    rules = report.rules
    outcome = report.outcome
    lines = render_terminal(analysis).rstrip("\n").split("\n")
    lines.extend([
        "",
        "Outcome",
        f"  Application failure: {outcome.application_failed}",
        f"  Instrumentation failure: {outcome.instrumentation_failed}",
        f"  Performance rule failure: {outcome.performance_rule_failed}",
        f"  Evaluation incomplete: {outcome.evaluation_incomplete}",
        f"  Final exit code: {outcome.exit_code}",
    ])

    if rules.config.enabled:
        lines.extend([
            "",
            "Configured rules",
            f"  Fullscan steps: {rules.config.fail_fullscan_steps}",
            f"  VM steps: {rules.config.fail_vm_steps}",
            f"  Fail on autoindex: {rules.config.fail_on_autoindex}",
            f"  Conclusive: {rules.evaluation_complete}",
        ])
        if rules.incomplete_reasons:
            lines.append(
                "  Incomplete reasons: " + ", ".join(rules.incomplete_reasons)
            )
        lines.extend(["", "Rule violations"])
        if rules.violations:
            for index, violation in enumerate(rules.violations, start=1):
                query = violation.query
                scope = query.scope
                lines.extend([
                    f"  [{index}] {violation.rule}",
                    f"    SQL: {terminal_safe(query.normalized_sql)}",
                    f"    Scope: pid={scope.pid} module={terminal_safe(scope.module)} "
                    f"database={terminal_safe(scope.database)} path={terminal_safe(scope.module_path)} "
                    f"base={terminal_safe(scope.module_base)}",
                    f"    Observed: {violation.observed}",
                    f"    Threshold: {violation.threshold}",
                ])
        else:
            lines.append("  none")

    return "\n".join(lines) + "\n"
