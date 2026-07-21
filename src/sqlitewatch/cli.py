"""Minimal command-line interface for the instrumentation proof of concept."""

from __future__ import annotations

import sys
from typing import Sequence

from .analysis import analyze_run
from .events import InstrumentationError
from .process import ControllerConfig, ProcessController
from .reporting import render_terminal

_USAGE = "usage: sqlitewatch [--max-sql-length N] -- <command> [args...]"


class CliError(ValueError):
    pass


def _parse(argv: Sequence[str]) -> tuple[ControllerConfig, list[str]]:
    args = list(argv)
    try:
        separator = args.index("--")
    except ValueError as exc:
        raise CliError("missing required delimiter '--'") from exc
    options, target = args[:separator], args[separator + 1 :]
    if not target:
        raise CliError("missing target command after '--'")

    max_sql_length = 65536
    index = 0
    while index < len(options):
        option = options[index]
        if option == "--max-sql-length":
            if index + 1 >= len(options):
                raise CliError("--max-sql-length requires a positive integer")
            value = options[index + 1]
            index += 2
        elif option.startswith("--max-sql-length="):
            value = option.partition("=")[2]
            index += 1
        else:
            raise CliError(f"unknown SQLiteWatch option: {option}")
        try:
            max_sql_length = int(value)
        except ValueError as exc:
            raise CliError("--max-sql-length requires a positive integer") from exc
        if max_sql_length <= 0:
            raise CliError("--max-sql-length requires a positive integer")
    return ControllerConfig(max_sql_length=max_sql_length), target


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        config, target = _parse(args)
        result = ProcessController().run(target, config)
    except CliError as exc:
        print(f"sqlitewatch: {exc}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"SQLiteWatch instrumentation failure: {exc}", file=sys.stderr)
        return 70

    print(render_terminal(analyze_run(result)), end="")
    for event in result.events:
        if isinstance(event, InstrumentationError):
            print(f"[instrumentation_error] {event.phase}: {event.message}", file=sys.stderr)
    if result.target_exit_code is not None:
        print(f"Target exited with code {result.target_exit_code}")
    elif result.signal is not None:
        print(f"Target terminated by signal {result.signal}")
    if result.instrumentation_failed:
        print(f"Instrumentation failed: {result.instrumentation_error or 'unknown error'}", file=sys.stderr)
    return result.exit_code


__all__ = ["main"]
