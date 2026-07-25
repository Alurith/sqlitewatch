"""Structured input for complete SQLiteWatch run reports."""

from __future__ import annotations

from dataclasses import dataclass

from ..analysis import AnalysisResult, RuleEvaluation
from ..outcome import RunOutcome


@dataclass(frozen=True, slots=True)
class ReportData:
    """The derived analysis, configured rules, and resolved final outcome."""

    analysis: AnalysisResult
    rules: RuleEvaluation
    outcome: RunOutcome

    def __post_init__(self) -> None:
        if self.analysis.instrumentation_status != self.outcome.instrumentation_status:
            raise ValueError("analysis and outcome instrumentation statuses must match")
        if self.analysis.instrumentation_failed and not self.outcome.instrumentation_failed:
            raise ValueError("an instrumentation-failed analysis requires a failed outcome")
        if self.rules.failed != self.outcome.performance_rule_failed:
            raise ValueError("rule evaluation and outcome performance status must match")
