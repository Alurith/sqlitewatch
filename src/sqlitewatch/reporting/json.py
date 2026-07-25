"""Stable JSON serialization for derived analysis results."""

from __future__ import annotations

import json

from ..analysis import AnalysisResult
from .model import ReportData


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


def run_report_to_dict(report: ReportData) -> dict[str, object]:
    """Convert a full run report to the versioned CLI JSON envelope."""
    derived = analysis_to_dict(report.analysis)
    rules = report.rules
    outcome = report.outcome
    return {
        "schema_version": 1,
        "summary": derived["summary"],
        "data_quality": derived["data_quality"],
        "target": {
            "exit_code": outcome.target_exit_code,
            "signal": outcome.signal,
            "failed": outcome.application_failed,
        },
        "instrumentation": {
            "status": outcome.instrumentation_status,
            "failed": outcome.instrumentation_failed,
        },
        "rules": {
            "enabled": rules.config.enabled,
            "passed": not rules.failed,
            "configuration": {
                "fail_fullscan_steps": rules.config.fail_fullscan_steps,
                "fail_vm_steps": rules.config.fail_vm_steps,
                "fail_on_autoindex": rules.config.fail_on_autoindex,
            },
            "violations": [
                {
                    "rule": violation.rule,
                    "scope": {
                        "pid": violation.query.scope.pid,
                        "module": violation.query.scope.module,
                        "database": violation.query.scope.database,
                    },
                    "fingerprint": violation.query.fingerprint,
                    "sql": violation.query.normalized_sql,
                    "observed": violation.observed,
                    "threshold": violation.threshold,
                }
                for violation in rules.violations
            ],
        },
        "outcome": {
            "application_failure": outcome.application_failed,
            "instrumentation_failure": outcome.instrumentation_failed,
            "performance_rule_failure": outcome.performance_rule_failed,
            "exit_code": outcome.exit_code,
        },
        "queries": derived["queries"],
    }


def render_run_json(report: ReportData) -> str:
    return json.dumps(run_report_to_dict(report), sort_keys=True, ensure_ascii=False) + "\n"
