"""The recurrence preview is an operator-facing calculation, not a scheduler."""

from __future__ import annotations

import json
import socket
import subprocess

import pytest

from megalodon import cli


@pytest.fixture(autouse=True)
def no_effects(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("automation preview crossed an effect boundary")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(cli, "Store", denied)
    monkeypatch.setattr(cli, "_load", denied)


def _run(arguments: list[str], capsys) -> tuple[int, str, str]:
    with pytest.raises(SystemExit) as caught:
        cli.main(["automation-preview", *arguments])
    output = capsys.readouterr()
    return caught.value.code, output.out, output.err


def test_preview_prints_bounded_utc_instants_without_effects(capsys) -> None:
    code, output, error = _run([
        "--dtstart", "2026-09-28T09:00:00", "--timezone", "America/Chicago",
        "--rrule", "FREQ=WEEKLY;BYDAY=MO,WE", "--limit", "2",
    ], capsys)
    assert code == 0 and error == ""
    result = json.loads(output)
    assert result == {
        "schema_version": "megalodon-automation-preview-v1",
        "status": "preview_only",
        "occurrences": [
            {"occurrence_at": "2026-09-28T14:00:00Z", "local_time": "2026-09-28T09:00:00", "dst_status": "normal"},
            {"occurrence_at": "2026-09-30T14:00:00Z", "local_time": "2026-09-30T09:00:00", "dst_status": "normal"},
        ],
    }


def test_preview_exposes_explicit_gap_policy(capsys) -> None:
    code, output, error = _run([
        "--dtstart", "2027-03-14T02:30:00", "--timezone", "America/Chicago",
        "--rrule", "FREQ=DAILY;COUNT=1", "--dst-policy", "shift_forward",
    ], capsys)
    assert code == 0 and error == ""
    assert json.loads(output)["occurrences"] == [{
        "occurrence_at": "2027-03-14T08:30:00Z",
        "local_time": "2027-03-14T02:30:00",
        "dst_status": "gap",
    }]


def test_invalid_rule_refuses_without_partial_preview(capsys) -> None:
    code, output, error = _run([
        "--dtstart", "2026-09-28T09:00:00", "--timezone", "UTC",
        "--rrule", "FREQ=SECONDLY;COUNT=2",
    ], capsys)
    assert code == 2 and output == ""
    assert error == "megalodon automation-preview: PATTERN\n"


def test_traversal_shaped_zone_refuses_without_echoing_input(capsys) -> None:
    code, output, error = _run([
        "--dtstart", "2026-09-28T09:00:00", "--timezone", "America/../../etc/passwd",
        "--rrule", "FREQ=DAILY;COUNT=1",
    ], capsys)
    assert code == 2 and output == ""
    assert error == "megalodon automation-preview: TIMEZONE_VALUE\n"


def test_limit_is_bounded_before_generation(capsys) -> None:
    code, output, error = _run([
        "--dtstart", "2026-09-28T09:00:00", "--timezone", "UTC",
        "--rrule", "FREQ=DAILY", "--limit", "367",
    ], capsys)
    assert code == 2 and output == ""
    assert "limit must be between 1 and 366" in error
