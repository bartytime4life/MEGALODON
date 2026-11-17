from __future__ import annotations

import hashlib
import json
import os

import pytest

from megalodon import cli, threat_context
from megalodon.capture import iter_sample
from megalodon.detector import Detector
from megalodon.config import DetectionSettings
from megalodon.threat_detector import ThreatDetector


def run(argv, capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(argv)
    out, err = capsys.readouterr()
    return raised.value.code, out, err


def private(path, text):
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_detectors_prints_both_registries(capsys):
    code, out, _ = run(["detectors"], capsys)
    document = json.loads(out)
    assert code == 0
    assert [rule["rule_id"] for rule in document["core"]["rules"]] == [
        "DNS_TUNNELING", "PORT_SCAN", "SYN_FLOOD"]
    assert document["threat_signals"]["auth_services"]["3389"] == "rdp"


def test_watchlist_check_and_match(tmp_path, capsys):
    path = private(tmp_path / "w.txt", "203.0.113.0/24 # range\n2001:db8::1\n")
    code, out, _ = run(["watchlist", "check", "--path", str(path)], capsys)
    assert code == 0 and json.loads(out)["indicators"] == 2
    code, out, _ = run(["watchlist", "match", "--path", str(path), "--address", "203.0.113.9"], capsys)
    assert json.loads(out) == {"schema": "megalodon-watchlist-match-v1", "address": "203.0.113.9",
                               "matched": True, "indicator": "203.0.113.0/24", "label": "range"}
    code, out, _ = run(["watchlist", "match", "--path", str(path), "--address", "8.8.8.8"], capsys)
    assert json.loads(out)["matched"] is False


def test_watchlist_errors_are_reported_without_traceback(tmp_path, capsys):
    bad = private(tmp_path / "bad.txt", "0.0.0.0/0\n")
    code, _, err = run(["watchlist", "check", "--path", str(bad)], capsys)
    assert code == 2 and "line 1" in err and "Traceback" not in err
    code, _, err = run(["watchlist", "match", "--path", str(bad), "--address", "nope"], capsys)
    assert code == 2


def test_import_stix_writes_private_watchlist(tmp_path, capsys, monkeypatch):
    # The reader refuses root; this container may run as root.
    monkeypatch.setattr(threat_context, "require_unprivileged_linux", lambda: None)
    bundle = {
        "type": "bundle", "id": "bundle--0f7a2bc5-6f1d-4b0f-9d6e-1a2b3c4d5e6f",
        "objects": [
            {"type": "indicator", "spec_version": "2.1",
             "id": "indicator--11111111-1111-4111-8111-111111111111",
             "created": "2030-01-01T00:00:00Z", "modified": "2030-01-01T00:00:00Z",
             "name": "lab c2", "pattern_type": "stix", "valid_from": "2030-01-01T00:00:00Z",
             "pattern": "[ipv4-addr:value = '203.0.113.5']"},
            {"type": "indicator", "spec_version": "2.1",
             "id": "indicator--22222222-2222-4222-8222-222222222222",
             "created": "2030-01-01T00:00:00Z", "modified": "2030-01-01T00:00:00Z",
             "pattern_type": "stix", "valid_from": "2030-01-01T00:00:00Z",
             "pattern": "[domain-name:value = 'example.com']"},
        ],
    }
    raw = json.dumps(bundle).encode()
    source = tmp_path / "bundle.json"
    source.write_bytes(raw)
    os.chmod(source, 0o600)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    output = tmp_path / "watch.txt"
    argv = ["watchlist", "import-stix", "--bundle", str(source), "--digest", digest,
            "--output", str(output)]
    code, out, err = run(argv, capsys)
    assert code == 0, err
    receipt = json.loads(out)
    assert receipt["converted"] == 1 and receipt["skipped_pattern"] == 1
    assert receipt["indicators_written"] == 1
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert "203.0.113.5  # lab c2" in output.read_text()
    code, _, err = run(argv, capsys)
    assert code == 2 and "--replace" in err
    code, _, err = run(argv[:-1] + [str(output), "--replace"], capsys)
    assert code == 0
    wrong = argv.copy()
    wrong[wrong.index(digest)] = "sha256:" + "0" * 64
    code, _, err = run(wrong, capsys)
    assert code == 2 and "DIGEST" in err


def test_demo_sample_exercises_every_behavioral_threat_rule():
    detector, threat = Detector(DetectionSettings()), ThreatDetector()
    seen = set()
    for event in iter_sample(include_demo_threat=True):
        seen.update(item.rule_id for item in detector.analyze(event))
        seen.update(item.rule_id for item in threat.analyze(event))
    assert {"SYN_FLOOD", "DNS_TUNNELING", "BRUTE_FORCE", "HOST_SWEEP", "DATA_EXFILTRATION",
            "BEACONING"} <= seen
    plain, quiet = set(), ThreatDetector()
    for event in iter_sample():
        plain.update(item.rule_id for item in quiet.analyze(event))
    assert plain == set()
