"""Stable JSON serialization for derived analysis results."""

from __future__ import annotations

import json

from ..analysis import AnalysisResult


def analysis_to_dict(analysis: AnalysisResult) -> dict[str, object]:
    """Convert derived analysis to the public, raw-event-free JSON shape."""
    quality = analysis.data_quality
    return {
        "summary": {
            "observed_executions": quality.observed_executions,
            "metric_bearing_executions": quality.metric_bearing_executions,
            "unique_scoped_queries": len(analysis.aggregates),
        },
        "data_quality": {
            "null_metric_executions": quality.null_metric_executions,
            "unmatched_executions": quality.unmatched_executions,
            "truncated_sql_executions": quality.truncated_sql_executions,
            "duplicate_executions": quality.duplicate_executions,
            "conflicted_executions": quality.conflicted_executions,
        },
        "instrumentation": {
            "status": analysis.instrumentation_status,
            "failed": analysis.instrumentation_failed,
        },
        "queries": [
            {
                "scope": {
                    "pid": aggregate.scope.pid,
                    "module": aggregate.scope.module,
                    "database": aggregate.scope.database,
                },
                "fingerprint": aggregate.fingerprint,
                "sql": aggregate.normalized_sql,
                "executions": aggregate.executions,
                "fullscan_steps": {
                    "total": aggregate.total_fullscan_steps,
                    "max": aggregate.max_fullscan_steps,
                },
                "vm_steps": {
                    "total": aggregate.total_vm_steps,
                    "max": aggregate.max_vm_steps,
                },
                "sorts": aggregate.total_sorts,
                "autoindex": aggregate.total_autoindex,
                "signals": list(aggregate.signals),
            }
            for aggregate in analysis.aggregates
        ],
    }


def render_json(analysis: AnalysisResult) -> str:
    return json.dumps(analysis_to_dict(analysis), sort_keys=True, ensure_ascii=False) + "\n"
