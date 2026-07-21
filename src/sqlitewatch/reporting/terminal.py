"""Deterministic human-readable rendering of derived analysis."""

from __future__ import annotations

from ..analysis import AnalysisResult


def render_terminal(analysis: AnalysisResult) -> str:
    """Render analysis only; process execution and I/O remain the caller's job."""
    quality = analysis.data_quality
    lines = [
        "SQLiteWatch analysis",
        "",
        "Summary",
        f"  Observed executions: {quality.observed_executions}",
        f"  Metric-bearing executions: {quality.metric_bearing_executions}",
        f"  Unique scoped queries: {len(analysis.aggregates)}",
        f"  Instrumentation: {analysis.instrumentation_status}"
        + (" (failed)" if analysis.instrumentation_failed else ""),
    ]

    nonzero_quality = (
        ("Null-metric executions", quality.null_metric_executions),
        ("Unmatched executions", quality.unmatched_executions),
        ("Truncated-SQL executions", quality.truncated_sql_executions),
        ("Duplicate executions", quality.duplicate_executions),
        ("Conflicted executions", quality.conflicted_executions),
    )
    if any(value for _, value in nonzero_quality):
        lines.extend(["", "Data quality"])
        lines.extend(f"  {name}: {value}" for name, value in nonzero_quality if value)

    if quality.observed_executions and not quality.metric_bearing_executions:
        lines.extend(["", "No metric-bearing executions were observed; queries were not aggregated."])
    elif not analysis.aggregates:
        lines.extend(["", "No metric-bearing executions could be associated with complete SQL."])
    else:
        lines.extend(["", "Queries"])
        for index, aggregate in enumerate(analysis.aggregates, start=1):
            lines.extend([
                f"  [{index}] pid={aggregate.scope.pid} module={aggregate.scope.module} database={aggregate.scope.database}",
                f"    SQL: {aggregate.normalized_sql}",
                f"    Fingerprint: {aggregate.fingerprint}",
                f"    Executions: {aggregate.executions}",
                f"    Fullscan steps: total={aggregate.total_fullscan_steps} max={aggregate.max_fullscan_steps}",
                f"    VM steps: total={aggregate.total_vm_steps} max={aggregate.max_vm_steps}",
                f"    Sorts: {aggregate.total_sorts}",
                f"    Autoindex: {aggregate.total_autoindex}",
                f"    Signals: {', '.join(aggregate.signals) if aggregate.signals else 'none'}",
            ])
    return "\n".join(lines) + "\n"
