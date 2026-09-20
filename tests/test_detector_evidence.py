"""Evaluation evidence is explicit about identity, coverage and unavailable labels."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from megalodon import evaluation
from megalodon.config import DetectionSettings
from megalodon.detector_registry import DETECTORS, registry_document, registry_sha256
from megalodon.reference import (
    ReferenceDataError, corpus_evidence_report, evaluate_corpus, load_corpus,
)
from megalodon.reference import loader


SOURCE = {"source_commit": "a" * 40, "source_tree": "b" * 40}
SCENARIO = "dns-protocol-gates-v1"
REPORT_ARGS = ["corpus-report", "--source-commit", "a" * 40, "--source-tree", "b" * 40]


def test_unregistered_detection_cannot_disappear_from_passing_evaluation(monkeypatch):
    original = loader.Detector.analyze

    def analyze_with_unknown(self, event):
        return [*original(self, event), SimpleNamespace(rule_id="UNREGISTERED")]

    monkeypatch.setattr(loader.Detector, "analyze", analyze_with_unknown)
    with pytest.raises(ReferenceDataError, match="^REFERENCE_DATA:UNKNOWN_DETECTOR$"):
        evaluate_corpus("dns-protocol-gates-v1")


def test_registry_round_trip_is_closed_detached_and_bound_to_existing_fixtures():
    document = registry_document()
    assert json.loads(json.dumps(document)) == document
    assert document["registry_version"] == "1.0.1"
    assert [(rule["rule_id"], rule["version"], rule["severity"]) for rule in document["rules"]] == [
        ("DNS_TUNNELING", "1.0.0", "CRITICAL"),
        ("PORT_SCAN", "1.0.0", "MEDIUM"),
        ("SYN_FLOOD", "1.0.0", "HIGH"),
    ]
    assert document["default_settings"] == asdict(DetectionSettings())
    fixtures = {item.scenario_id for item in load_corpus().scenarios}
    for rule in document["rules"]:
        assert set(rule["fixtures"]) <= fixtures
        assert rule["threshold_setting"] in document["default_settings"]
        assert rule["cooldown_setting"] in document["default_settings"]
        assert rule["window_setting"] is None or rule["window_setting"] in document["default_settings"]
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    assert registry_sha256() == hashlib.sha256(encoded).hexdigest()
    digest = registry_sha256()
    document["rules"][0]["fixtures"].clear()
    document["rules"][0]["required_fields"].append("payload")
    document["default_settings"]["dns_query_length"] = 0
    assert registry_sha256() == digest
    assert "payload" not in DETECTORS[0].required_fields


def test_source_capacity_fixture_is_bound_only_to_the_rule_it_exercises():
    document = registry_document()
    fixture_rules = {
        rule["rule_id"]
        for rule in document["rules"]
        if "source-cap-pressure-v1" in rule["fixtures"]
    }
    scenario = next(
        item for item in load_corpus().scenarios
        if item.scenario_id == "source-cap-pressure-v1"
    )

    assert fixture_rules == {"SYN_FLOOD"}
    assert dict(scenario.expected) == {
        "DNS_TUNNELING": 0,
        "PORT_SCAN": 0,
        "SYN_FLOOD": 2,
    }


def test_report_preserves_legacy_results_and_never_invents_classification_metrics():
    report = corpus_evidence_report(**SOURCE)
    assert report["evaluation"] == evaluate_corpus()
    assert report["all_match"] is True
    assert report["effective_settings"] == asdict(DetectionSettings())
    assert report["source_identity"] == {
        "commit": SOURCE["source_commit"], "tree": SOURCE["source_tree"],
        "status": "caller_declared_unverified", "registry_sha256": registry_sha256(),
    }
    assert report["labels"]["identity"] == report["evaluation"]["manifest_sha256"]
    assert report["labels"]["event_class_labels"] == "unavailable"
    assert report["denominators"] == {
        "selected_scenarios": 12, "validated_scenarios": 12,
        "selected_events": 6492, "validated_events": 6492, "binary_labeled_units": None,
    }
    metrics = report["classification_metrics"]
    assert metrics["status"] == "unavailable"
    assert metrics["reason"] == "EVENT_LABELS_AND_DENOMINATOR_UNAVAILABLE"
    assert all(metrics[name] is None for name in (
        "tp", "fp", "fn", "tn", "precision", "recall", "false_positive_rate", "accuracy",
    ))
    assert report["quality"] == {
        "source": "synthetic-only", "calibration": "uncalibrated",
        "bundle_integrity": "verified", "selected_replay": "complete",
        "corpus_selection": "all_bundled_scenarios", "operational_source_quality": "unavailable",
        "capture_loss": "unknown", "operational_coverage": "unknown",
        "clean_interpretation": "unavailable",
    }
    assert report["exclusions"]["scenario_ids"] == []
    assert report["exclusions"]["events"] == 0
    assert len(json.dumps(report, allow_nan=False).encode()) < 32 * 1024


def test_console_corpus_totals_match_the_unfiltered_evaluator_report():
    report = corpus_evidence_report(**SOURCE)
    site_source = (
        Path(__file__).resolve().parents[1] / "site" / "dist" / "index.html"
    )
    if not site_source.is_file():
        pytest.skip("repository-only Site source is not included in the sdist")
    html = site_source.read_text(encoding="utf-8")
    displayed = re.search(
        r"<strong>([\d,]+) synthetic scenarios · ([\d,]+) metadata events</strong>",
        html,
    )

    assert displayed is not None
    assert tuple(int(value.replace(",", "")) for value in displayed.groups()) == (
        report["denominators"]["selected_scenarios"],
        report["denominators"]["selected_events"],
    )


def test_selected_report_accounts_for_exclusions_and_uses_selected_event_times():
    report = corpus_evidence_report(**SOURCE, scenario_id=SCENARIO)
    bundle = load_corpus()
    selected = next(item for item in bundle.scenarios if item.scenario_id == SCENARIO)
    assert report["denominators"]["selected_events"] == len(selected.records)
    assert report["denominators"]["selected_scenarios"] == 1
    assert report["exclusions"]["events"] + len(selected.records) == 6492
    assert len(report["exclusions"]["scenario_ids"]) == 11
    assert SCENARIO not in report["exclusions"]["scenario_ids"]
    assert report["quality"]["corpus_selection"] == "subset"
    times = [event.observed_at for event in selected.records]
    for key, expected in (("start", min(times)), ("end", max(times))):
        assert report["replay"]["time_window"][key] == expected.isoformat(
            timespec="microseconds",
        ).replace("+00:00", "Z")


@pytest.mark.parametrize("field", ("source_commit", "source_tree"))
@pytest.mark.parametrize("value", (None, 1, "", "a" * 39, "a" * 41, "A" * 40, "é" * 40, "../private"))
def test_invalid_source_identity_fails_before_resource_access(monkeypatch, field, value):
    def unexpected_read():
        pytest.fail("invalid source identity reached corpus loading")

    monkeypatch.setattr(loader, "load_corpus", unexpected_read)
    with pytest.raises(ReferenceDataError, match="^REFERENCE_DATA:INVALID_SOURCE_IDENTITY$"):
        corpus_evidence_report(**{**SOURCE, field: value})


def test_unselected_corrupt_resource_blocks_report_without_partial_results(monkeypatch, capsys):
    original = loader._read_resource

    def corrupt(parts, maximum):
        data = original(parts, maximum)
        if parts == ("corpus-v1", "source-cap-pressure-v1.part-001.jsonl"):
            return b"!" + data[1:]
        return data

    monkeypatch.setattr(loader, "_read_resource", corrupt)
    assert evaluation.main([*REPORT_ARGS, "--scenario", SCENARIO]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "REFERENCE_DATA:ARTIFACT_INTEGRITY"
    assert "evaluation" not in result and "all_match" not in result


@pytest.mark.parametrize("extra", (
    ["--source-commit", "c" * 40], ["--source-tree", "d" * 40],
    ["--scenario", SCENARIO, "--scenario", SCENARIO], ["--source-c", "c" * 40],
))
def test_report_cli_rejects_duplicate_or_abbreviated_arguments(extra, capsys):
    with pytest.raises(SystemExit) as caught:
        evaluation.main([*REPORT_ARGS, *extra])
    assert caught.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"] == "INVALID_ARGUMENTS"


@pytest.mark.parametrize("arguments", (["corpus-report"], REPORT_ARGS[:3]))
def test_report_cli_requires_both_source_references(arguments, capsys):
    with pytest.raises(SystemExit) as caught:
        evaluation.main(arguments)
    assert caught.value.code == 2
    assert json.loads(capsys.readouterr().err)["error"] == "INVALID_ARGUMENTS"


def test_report_cli_unknown_detector_is_fixed_error_without_rule_text(monkeypatch, capsys):
    monkeypatch.setattr(loader.Detector, "analyze", lambda *_: [SimpleNamespace(rule_id="private-marker")])
    assert evaluation.main([*REPORT_ARGS, "--scenario", SCENARIO]) == 2
    output = capsys.readouterr().out
    assert "private-marker" not in output
    assert json.loads(output)["error"] == "REFERENCE_DATA:UNKNOWN_DETECTOR"


def test_report_cli_count_mismatch_is_failure_with_evidence(monkeypatch, capsys):
    monkeypatch.setattr(loader.Detector, "analyze", lambda *_: [])
    assert evaluation.main([*REPORT_ARGS, "--scenario", SCENARIO]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["all_match"] is False
    assert result["classification_metrics"]["accuracy"] is None


@pytest.mark.parametrize("arguments", (["detectors"], REPORT_ARGS))
def test_new_commands_have_no_network_database_or_process_effects(monkeypatch, capsys, arguments):
    def forbidden(*args, **kwargs):
        pytest.fail("effectful operation attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert evaluation.main(arguments) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["network_access_performed"] is False
    assert result["persistence_status"] == result["action_status"] == "not_attempted"
