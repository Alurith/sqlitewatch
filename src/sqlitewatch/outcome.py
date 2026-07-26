"""Final result policy combining target, instrumentation, and rule outcomes."""

from __future__ import annotations

from dataclasses import dataclass

from .analysis.rules import RuleEvaluation
from .events import RunResult


@dataclass(frozen=True, slots=True)
class RunOutcome:
    target_exit_code: int | None
    signal: int | None
    instrumentation_status: str
    application_failed: bool
    instrumentation_failed: bool
    performance_rule_failed: bool
    evaluation_incomplete: bool
    exit_code: int
    pid: int | None = None


def resolve_outcome(run: RunResult, rules: RuleEvaluation) -> RunOutcome:
    """Resolve the approved exit-code precedence for a completed run."""
    application_failed = run.signal is not None or (
        run.target_exit_code is not None and run.target_exit_code != 0
    )
    instrumentation_failed = (
        run.instrumentation_failed
        or run.instrumentation_status == "FAILED"
        or (rules.config.enabled and run.instrumentation_status != "ACTIVE")
        or (rules.config.enabled and rules.inconclusive)
    )
    performance_rule_failed = rules.failed
    evaluation_incomplete = rules.inconclusive

    if instrumentation_failed:
        exit_code = 70
    elif run.signal is not None:
        exit_code = 128 + run.signal
    elif run.target_exit_code is not None and run.target_exit_code != 0:
        exit_code = run.target_exit_code
    elif performance_rule_failed:
        exit_code = 1
    else:
        exit_code = 0

    return RunOutcome(
        target_exit_code=run.target_exit_code,
        signal=run.signal,
        instrumentation_status=run.instrumentation_status,
        application_failed=application_failed,
        instrumentation_failed=instrumentation_failed,
        performance_rule_failed=performance_rule_failed,
        evaluation_incomplete=evaluation_incomplete,
        exit_code=exit_code,
        pid=run.pid,
    )
