from pathlib import Path

import pytest

from sqlitewatch.reporting import output
from sqlitewatch.reporting.output import write_report


def test_write_report_is_utf8_atomic_and_replaces_existing_file(tmp_path):
    destination = tmp_path / "report.json"
    destination.write_text("old report", encoding="utf-8")
    write_report(destination, "café\n")
    assert destination.read_text(encoding="utf-8") == "café\n"
    assert not list(tmp_path.glob(".report.json.*.tmp"))


@pytest.mark.parametrize("failure", ["fsync", "replace"])
def test_write_report_preserves_existing_destination_and_cleans_up_on_failure(monkeypatch, tmp_path, failure):
    destination = tmp_path / "report.json"
    destination.write_text("old report", encoding="utf-8")

    def fail(*args, **kwargs):
        raise OSError(f"{failure} failed")

    monkeypatch.setattr(output.os, failure, fail)
    with pytest.raises(OSError, match=failure):
        write_report(destination, "new report\n")
    assert destination.read_text(encoding="utf-8") == "old report"
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_write_report_does_not_create_missing_parent(tmp_path):
    destination = tmp_path / "missing" / "report.json"
    with pytest.raises(OSError):
        write_report(destination, "report\n")
    assert not destination.parent.exists()
