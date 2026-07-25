"""Command-line interface for analysis, CI policy, and report emission."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Literal, Sequence

from .analysis import RuleConfig, analyze_run, evaluate_rules
from .doctor import reduce_events, resolve_doctor_outcome
from .events import InstrumentationError
from .outcome import resolve_outcome
from .process import ControllerConfig, ProcessController
from .reporting import (
    ReportData, render_doctor_json, render_doctor_terminal, render_run_json,
    render_run_terminal,
)
from .reporting.output import write_report

_DOCTOR_USAGE = "usage: sqlitewatch doctor [--format terminal|json] [--output FILE] -- <command> [args...]"

_USAGE = (
    "usage: sqlitewatch [--max-sql-length N] [--fail-fullscan-steps N] "
    "[--fail-vm-steps N] [--fail-on-autoindex] [--format terminal|json] "
    "[--output FILE] -- <command> [args...]"
)


class CliError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CliConfig:
    controller: ControllerConfig
    rules: RuleConfig
    format: Literal["terminal", "json"] = "terminal"
    output: Path | None = None


@dataclass(frozen=True, slots=True)
class DoctorCliConfig:
    controller: ControllerConfig
    format: Literal["terminal", "json"] = "terminal"
    output: Path | None = None


def _parse_nonnegative(option: str, value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise CliError(f"{option} requires a non-negative integer") from exc
    if parsed < 0:
        raise CliError(f"{option} requires a non-negative integer")
    return parsed


def _parse(argv: Sequence[str]) -> tuple[CliConfig, list[str]]:
    args = list(argv)
    try:
        separator = args.index("--")
    except ValueError as exc:
        raise CliError("missing required delimiter '--'") from exc
    options, target = args[:separator], args[separator + 1 :]
    if not target:
        raise CliError("missing target command after '--'")

    max_sql_length = 65536
    fail_fullscan_steps: int | None = None
    fail_vm_steps: int | None = None
    fail_on_autoindex = False
    report_format: Literal["terminal", "json"] = "terminal"
    output: Path | None = None
    index = 0
    value_options = {
        "--max-sql-length",
        "--fail-fullscan-steps",
        "--fail-vm-steps",
        "--format",
        "--output",
    }

    while index < len(options):
        option = options[index]
        if option == "--fail-on-autoindex":
            fail_on_autoindex = True
            index += 1
            continue

        name: str | None = None
        value: str | None = None
        if option in value_options:
            if index + 1 >= len(options):
                raise CliError(f"{option} requires a value")
            name, value = option, options[index + 1]
            index += 2
        else:
            for candidate in value_options:
                if option.startswith(candidate + "="):
                    name, value = candidate, option.partition("=")[2]
                    index += 1
                    break
        if name is None or value is None:
            raise CliError(f"unknown SQLiteWatch option: {option}")

        if name == "--max-sql-length":
            max_sql_length = _parse_nonnegative(name, value)
            if max_sql_length == 0:
                raise CliError("--max-sql-length requires a positive integer")
        elif name == "--fail-fullscan-steps":
            fail_fullscan_steps = _parse_nonnegative(name, value)
        elif name == "--fail-vm-steps":
            fail_vm_steps = _parse_nonnegative(name, value)
        elif name == "--format":
            if value not in {"terminal", "json"}:
                raise CliError("--format must be 'terminal' or 'json'")
            report_format = value  # type: ignore[assignment]
        else:  # --output
            if not value:
                raise CliError("--output requires a non-empty path")
            output = Path(value)

    rules = RuleConfig(
        fail_fullscan_steps=fail_fullscan_steps,
        fail_vm_steps=fail_vm_steps,
        fail_on_autoindex=fail_on_autoindex,
    )
    controller = ControllerConfig(
        max_sql_length=max_sql_length,
        target_stdout_to_stderr=report_format == "json" and output is None,
    )
    return CliConfig(controller, rules, report_format, output), target


def _parse_doctor(argv: Sequence[str]) -> tuple[DoctorCliConfig, list[str]]:
    args = list(argv)
    try:
        separator = args.index("--")
    except ValueError as exc:
        raise CliError("missing required delimiter '--'") from exc
    options, target = args[:separator], args[separator + 1 :]
    if not target:
        raise CliError("missing target command after '--'")
    report_format: Literal["terminal", "json"] = "terminal"
    output: Path | None = None
    index = 0
    while index < len(options):
        option = options[index]
        if option.startswith("--format="):
            value = option.partition("=")[2]
            index += 1
        elif option.startswith("--output="):
            value = option.partition("=")[2]
            option = "--output"
            index += 1
        elif option in {"--format", "--output"}:
            if index + 1 >= len(options):
                raise CliError(f"{option} requires a value")
            value = options[index + 1]
            index += 2
        else:
            raise CliError(f"Doctor does not support option: {option}")
        if option.startswith("--format"):
            if value not in {"terminal", "json"}:
                raise CliError("--format must be 'terminal' or 'json'")
            report_format = value  # type: ignore[assignment]
        else:
            if not value:
                raise CliError("--output requires a non-empty path")
            output = Path(value)
    return DoctorCliConfig(ControllerConfig(doctor=True, target_stdout_to_stderr=report_format == "json" and output is None), report_format, output), target


def _print_instrumentation_diagnostics(result: object) -> None:
    events = getattr(result, "events", ())
    for event in events:
        if isinstance(event, InstrumentationError):
            print(f"[instrumentation_error] {event.phase}: {event.message}", file=sys.stderr)
    if getattr(result, "instrumentation_failed", False):
        message = getattr(result, "instrumentation_error", None) or "unknown error"
        print(f"Instrumentation failed: {message}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    doctor_mode = bool(args and args[0] == "doctor")
    try:
        config, target = _parse_doctor(args[1:]) if doctor_mode else _parse(args)
    except CliError as exc:
        print(f"sqlitewatch: {exc}", file=sys.stderr)
        print(_DOCTOR_USAGE if doctor_mode else _USAGE, file=sys.stderr)
        return 2

    try:
        result = ProcessController().run(target, config.controller)
        if doctor_mode:
            doctor_result = reduce_events(result)
            outcome = resolve_doctor_outcome(doctor_result)
            content = render_doctor_json(doctor_result, outcome) if config.format == "json" else render_doctor_terminal(doctor_result, outcome)
        else:
            analysis = analyze_run(result)
            rules = evaluate_rules(analysis, config.rules)
            outcome = resolve_outcome(result, rules)
            report = ReportData(analysis, rules, outcome)
            content = render_run_json(report) if config.format == "json" else render_run_terminal(report)
    except Exception as exc:
        print(f"SQLiteWatch instrumentation failure: {exc}", file=sys.stderr)
        return 70

    _print_instrumentation_diagnostics(result)
    try:
        if config.output is None:
            sys.stdout.write(content)
            sys.stdout.flush()
        else:
            write_report(config.output, content)
    except (BrokenPipeError, OSError) as exc:
        print(
            "SQLiteWatch report output failure: "
            f"{exc} (previous outcome exit code: {outcome.exit_code})",
            file=sys.stderr,
        )
        return 74
    return outcome.exit_code


__all__ = ["CliConfig", "main"]
