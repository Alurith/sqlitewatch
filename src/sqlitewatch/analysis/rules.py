"""Pure CI rule evaluation over completed query aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .aggregation import AnalysisResult, QueryAggregate

RuleName = Literal["FULLSCAN_STEPS", "VM_STEPS", "AUTOINDEX"]


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Optional performance checks configured for one completed run."""

    fail_fullscan_steps: int | None = None
    fail_vm_steps: int | None = None
    fail_on_autoindex: bool = False

    def __post_init__(self) -> None:
        _validate_threshold("fail_fullscan_steps", self.fail_fullscan_steps)
        _validate_threshold("fail_vm_steps", self.fail_vm_steps)
        if not isinstance(self.fail_on_autoindex, bool):
            raise TypeError("fail_on_autoindex must be a boolean")

    @property
    def enabled(self) -> bool:
        return (
            self.fail_fullscan_steps is not None
            or self.fail_vm_steps is not None
            or self.fail_on_autoindex
        )


@dataclass(frozen=True, slots=True)
class RuleViolation:
    rule: RuleName
    query: QueryAggregate
    observed: int
    threshold: int | None


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    config: RuleConfig
    violations: tuple[RuleViolation, ...]

    @property
    def failed(self) -> bool:
        return bool(self.violations)


def evaluate_rules(analysis: AnalysisResult, config: RuleConfig) -> RuleEvaluation:
    """Evaluate enabled rules in aggregate and fixed-rule order."""
    violations: list[RuleViolation] = []
    for aggregate in analysis.aggregates:
        if config.fail_on_autoindex and aggregate.total_autoindex > 0:
            violations.append(RuleViolation("AUTOINDEX", aggregate, aggregate.total_autoindex, None))
        if (
            config.fail_fullscan_steps is not None
            and aggregate.max_fullscan_steps > config.fail_fullscan_steps
        ):
            violations.append(
                RuleViolation(
                    "FULLSCAN_STEPS",
                    aggregate,
                    aggregate.max_fullscan_steps,
                    config.fail_fullscan_steps,
                )
            )
        if config.fail_vm_steps is not None and aggregate.max_vm_steps > config.fail_vm_steps:
            violations.append(
                RuleViolation("VM_STEPS", aggregate, aggregate.max_vm_steps, config.fail_vm_steps)
            )
    return RuleEvaluation(config, tuple(violations))


def _validate_threshold(name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be a non-negative integer or None")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer or None")
