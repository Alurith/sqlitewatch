"""Pure post-processing for SQLiteWatch lifecycle events."""

from .aggregation import AnalysisReducer, AnalysisResult, DataQuality, QueryAggregate, QueryScope, analyze_run
from .rules import RuleConfig, RuleEvaluation, RuleName, RuleViolation, evaluate_rules

__all__ = [
    "AnalysisReducer",
    "AnalysisResult",
    "DataQuality",
    "QueryAggregate",
    "QueryScope",
    "RuleConfig",
    "RuleEvaluation",
    "RuleName",
    "RuleViolation",
    "analyze_run",
    "evaluate_rules",
]
