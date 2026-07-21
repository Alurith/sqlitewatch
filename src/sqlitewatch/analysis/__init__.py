"""Pure post-processing for SQLiteWatch lifecycle events."""

from .aggregation import AnalysisResult, DataQuality, QueryAggregate, QueryScope, analyze_run

__all__ = ["AnalysisResult", "DataQuality", "QueryAggregate", "QueryScope", "analyze_run"]
