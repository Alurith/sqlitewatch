"""Presentation helpers for derived analysis and complete run reports."""

from .doctor import doctor_to_dict, render_doctor_json, render_doctor_terminal
from .json import analysis_to_dict, render_json, render_run_json, run_report_to_dict
from .model import ReportData
from .process_tree import process_tree_to_dict, render_process_tree_terminal
from .terminal import render_run_terminal, render_terminal

__all__ = [
    "ReportData",
    "analysis_to_dict",
    "doctor_to_dict",
    "render_doctor_json",
    "render_doctor_terminal",
    "process_tree_to_dict",
    "render_json",
    "render_run_json",
    "render_process_tree_terminal",
    "render_run_terminal",
    "render_terminal",
    "run_report_to_dict",
]
