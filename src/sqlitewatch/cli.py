"""Command-line interface for analysis, CI policy, and report emission."""

from __future__ import annotations

from dataclasses import dataclass
import inspect
from pathlib import Path
import sys
from typing import Literal, Sequence

from .analysis import AnalysisReducer, RuleConfig, analyze_run, evaluate_rules
from .doctor import reduce_events, resolve_doctor_outcome
from .events import InstrumentationError
from .outcome import resolve_outcome
from .process import ControllerConfig, ProcessController
from .reporting import (
    ReportData, render_doctor_json, render_doctor_terminal, render_run_json,
    render_run_terminal,
)
from .reporting.output import write_report, write_utf8_stream
from .reporting.sanitize import terminal_safe

_CHECK_USAGE = (
    "usage: sqlitewatch check [--format terminal|json] [--output FILE] "
    "[--no-follow-children] -- <command> [args...]"
)

_USAGE = (
    "usage: sqlitewatch [--max-sql-length N] [--fail-fullscan-steps N] "
    "[--fail-vm-steps N] [--fail-on-autoindex] [--format terminal|json] "
    "[--output FILE] [--no-follow-children] -- <command> [args...]"
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
class CheckCliConfig:
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
    follow_children = True
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
        if option == "--no-follow-children":
            follow_children = False
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
            if max_sql_length == 0 or max_sql_length > 1_048_576:
                raise CliError(
                    "--max-sql-length requires an integer between 1 and 1048576"
                )
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
        follow_children=follow_children,
    )
    return CliConfig(controller, rules, report_format, output), target


def _parse_check(argv: Sequence[str]) -> tuple[CheckCliConfig, list[str]]:
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
    follow_children = True
    index = 0
    while index < len(options):
        option = options[index]
        if option == "--no-follow-children":
            follow_children = False
            index += 1
            continue
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
            raise CliError(f"Check does not support option: {option}")
        if option.startswith("--format"):
            if value not in {"terminal", "json"}:
                raise CliError("--format must be 'terminal' or 'json'")
            report_format = value  # type: ignore[assignment]
        else:
            if not value:
                raise CliError("--output requires a non-empty path")
            output = Path(value)
    return CheckCliConfig(
        ControllerConfig(
            doctor=True,
            target_stdout_to_stderr=report_format == "json" and output is None,
            follow_children=follow_children,
        ),
        report_format,
        output,
    ), target


def _stderr_line(message: str) -> None:
    write_utf8_stream(sys.stderr, message + "\n")


def _print_instrumentation_diagnostics(
    result: object, *, check: bool = False
) -> None:
    events = getattr(result, "events", ())
    grouped: dict[tuple[str, bool], list[InstrumentationError]] = {}
    for event in events:
        if not isinstance(event, InstrumentationError):
            continue
        if check and not event.fatal and event.phase == "fork_inherited_statement":
            continue
        if event.fatal:
            _stderr_line(
                "[instrumentation_error] "
                f"{terminal_safe(event.phase)}: {terminal_safe(event.message)}"
            )
            continue
        grouped.setdefault((event.phase, event.data_loss), []).append(event)
    for (phase, data_loss), diagnostics in grouped.items():
        prefix = "data_quality_warning" if data_loss else "instrumentation_warning"
        if phase == "fork_inherited_statement":
            message = (
                f"{len(diagnostics)} SQLite operation(s) used statements whose "
                "prepare was not observed; evaluation is partial"
            )
        elif len(diagnostics) == 1:
            message = diagnostics[0].message
        else:
            message = f"{len(diagnostics)} occurrences; {diagnostics[0].message}"
        _stderr_line(
            f"[{prefix}] {terminal_safe(phase)}: {terminal_safe(message)}"
        )
    if getattr(result, "instrumentation_failed", False):
        message = getattr(result, "instrumentation_error", None) or "unknown error"
        _stderr_line(f"Instrumentation failed: {terminal_safe(message)}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    check_mode = bool(args and args[0] == "check")
    try:
        config, target = _parse_check(args[1:]) if check_mode else _parse(args)
    except CliError as exc:
        _stderr_line(f"sqlitewatch: {terminal_safe(exc)}")
        _stderr_line(_CHECK_USAGE if check_mode else _USAGE)
        return 2

    try:
        controller = ProcessController()
        if check_mode:
            result = controller.run(target, config.controller)
            check_result = reduce_events(result)
            outcome = resolve_doctor_outcome(check_result)
            content = (
                render_doctor_json(check_result, outcome)
                if config.format == "json"
                else render_doctor_terminal(check_result, outcome)
            )
        else:
            reducer = AnalysisReducer()
            run_parameters = inspect.signature(controller.run).parameters
            if "event_consumer" in run_parameters:
                result = controller.run(
                    target,
                    config.controller,
                    event_consumer=reducer.consume,
                    retain_events=False,
                )
                analysis = reducer.finish(result)
            else:  # compatibility for small embedded/fake controllers
                result = controller.run(target, config.controller)
                analysis = analyze_run(result)
            rules = evaluate_rules(analysis, config.rules)
            outcome = resolve_outcome(result, rules)
            report = ReportData(analysis, rules, outcome)
            content = (
                render_run_json(report)
                if config.format == "json"
                else render_run_terminal(report)
            )
    except Exception as exc:
        _stderr_line(
            f"SQLiteWatch instrumentation failure: {terminal_safe(exc)}"
        )
        return 70

    _print_instrumentation_diagnostics(result, check=check_mode)
    try:
        if config.output is None:
            write_utf8_stream(sys.stdout, content)
        else:
            write_report(config.output, content)
    except (BrokenPipeError, OSError, UnicodeError) as exc:
        try:
            _stderr_line(
                "SQLiteWatch report output failure: "
                f"{terminal_safe(exc)} (previous outcome exit code: {outcome.exit_code})"
            )
        except (BrokenPipeError, OSError, UnicodeError):
            pass
        return 74
    return outcome.exit_code


__all__ = ["CliConfig", "main"]
