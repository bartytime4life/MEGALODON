from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import urllib.request

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("repository_currentness", ROOT / "tools/repository_currentness.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
CONTRACT = ROOT / "contracts/repository-currentness/v1"
SCHEMA = json.loads((CONTRACT / "schema.json").read_text())
CAPTURE = json.loads((CONTRACT / "fixtures/accepted/synthetic-capture.json").read_text())
VIOLATIONS = json.loads((CONTRACT / "fixtures/rejected/violations.json").read_text())


def validator(name):
    return Draft202012Validator({"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]},
                                format_checker=FormatChecker())


@pytest.fixture
def checkout(tmp_path):
    for entry in CAPTURE["readbacks"]["tree"]["excerpt"]["files"]:
        path = tmp_path / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic " + entry["path"] + "\n")
    return tmp_path


def generate(capture, checkout):
    return tool.generate(tool.canonical(capture), checkout)


def assert_blocked(result, reason):
    validator("failure").validate(result)
    assert result == {"schema_version": "megalodon-currentness-manifest-v1",
                      "status": "blocked", "reason": reason}


def test_schema_and_fixture_are_closed_and_valid(checkout):
    Draft202012Validator.check_schema(SCHEMA)
    validator("capture").validate(CAPTURE)
    result = generate(CAPTURE, checkout)
    validator("manifest").validate(result)
    assert result["status"] == "validated"
    assert result["capture"]["basis"] == "synthetic"
    assert result["capture"] == CAPTURE
    assert result["capture_sha256"] == tool.digest(CAPTURE)
    assert result["excerpt_sha256"]["checks"] == tool.digest(CAPTURE["readbacks"]["checks"]["excerpt"])
    # Reformatting object keys/whitespace cannot change the digest or output.
    assert tool.generate(json.dumps(CAPTURE, indent=4, sort_keys=True).encode(), checkout) == result


@pytest.mark.parametrize("case", VIOLATIONS, ids=lambda case: case["id"])
def test_rejected_semantic_fixture(case, checkout):
    capture = deepcopy(CAPTURE)
    for pointer, value in case["changes"].items():
        parts = pointer.lstrip("/").split("/")
        cursor = capture
        for key in parts[:-1]:
            cursor = cursor[int(key)] if isinstance(cursor, list) else cursor[key]
        cursor[int(parts[-1]) if isinstance(cursor, list) else parts[-1]] = value
    assert_blocked(generate(capture, checkout), case["reason"])


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                                  b'{"x":-Infinity}', b'\xff', b'{', b'null', b'[]',
                                  b'"forbidden-sentinel"', b'[] trailing'])
def test_malformed_input_never_echoes_content(raw, checkout):
    result = tool.generate(raw, checkout)
    assert_blocked(result, "INPUT_INVALID")
    assert b"forbidden-sentinel" not in tool.canonical(result)


def test_byte_depth_and_collection_limits(checkout):
    assert_blocked(tool.generate(b" " * (tool.MAX_INPUT_BYTES + 1), checkout), "INPUT_LIMIT")
    assert_blocked(tool.generate(b"[" * 14 + b"0" + b"]" * 14, checkout), "INPUT_LIMIT")
    capture = deepcopy(CAPTURE)
    capture["readbacks"]["pulls"]["excerpt"]["numbers"] = list(range(100))
    assert_blocked(generate(capture, checkout), "INPUT_INVALID")


def test_required_readback_cannot_disappear(checkout):
    capture = deepcopy(CAPTURE)
    del capture["readbacks"]["releases"]
    assert_blocked(generate(capture, checkout), "INPUT_INVALID")


def test_pr_inventory_race_is_not_silently_accepted(checkout):
    capture = deepcopy(CAPTURE)
    capture["readbacks"]["pulls"]["excerpt"]["numbers"] = [263]
    assert_blocked(generate(capture, checkout), "INCOMPLETE_READBACK")


def test_pending_and_failed_checks_are_observations_not_passes(checkout):
    capture = deepcopy(CAPTURE)
    row = capture["readbacks"]["checks"]["excerpt"]["items"][0]
    for status, conclusion in [("in_progress", None), ("completed", "failure")]:
        row.update(status=status, conclusion=conclusion)
        assert generate(capture, checkout)["status"] == "validated"
        capture["claims"][0]["check_run_ids"] = [row["id"]]
        assert_blocked(generate(capture, checkout), "CLAIM_REFERENCE")
        capture["claims"][0]["check_run_ids"] = []
    row.update(status="in_progress", conclusion="success")
    assert_blocked(generate(capture, checkout), "INCOMPLETE_READBACK")


@pytest.mark.parametrize("state", ["verified", "observed", "proposed", "blocked", "unknown", "stale"])
def test_claim_states_are_preserved_not_promoted(state, checkout):
    capture = deepcopy(CAPTURE)
    capture["claims"][0].update(state=state, check_run_ids=[123])
    result = generate(capture, checkout)
    assert result["capture"]["claims"][0]["state"] == state


def test_missing_duplicate_and_misassigned_references_refuse(checkout):
    for mutate in [
        lambda c: c["readbacks"]["tree"]["excerpt"]["files"].pop(),
        lambda c: c["claims"].__setitem__(1, {**c["claims"][0], "state": "unknown"}),
        lambda c: c["claims"][0].update(source_paths=["SECURITY_REVIEW.md"]),
    ]:
        capture = deepcopy(CAPTURE)
        mutate(capture)
        assert_blocked(generate(capture, checkout), "CLAIM_REFERENCE")


def test_source_bytes_must_match_and_paths_still_exist(checkout):
    for groups in tool.CLAIMS.values():
        for group in groups:
            for path in group:
                assert (ROOT / path).is_file()
    path = checkout / "megalodon/firewall.py"
    path.write_text("changed\n")
    assert_blocked(generate(CAPTURE, checkout), "LOCAL_IDENTITY")
    path.unlink()
    assert_blocked(generate(CAPTURE, checkout), "IO_UNAVAILABLE")


def test_symlink_and_special_file_refuse(checkout):
    path = checkout / "megalodon/firewall.py"
    path.unlink()
    path.symlink_to(checkout / "SECURITY_REVIEW.md")
    assert_blocked(generate(CAPTURE, checkout), "IO_UNAVAILABLE")
    path.unlink()
    if hasattr(os, "mkfifo"):
        os.mkfifo(path)
        assert_blocked(generate(CAPTURE, checkout), "IO_UNAVAILABLE")


def test_generation_has_no_network_process_database_or_write_calls(checkout, monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("prohibited side effect")
    for owner, name in [(socket, "socket"), (socket, "getaddrinfo"),
                        (urllib.request, "urlopen"), (subprocess, "Popen"),
                        (sqlite3, "connect"), (os, "system"), (os, "unlink"),
                        (Path, "write_text"), (Path, "write_bytes")]:
        monkeypatch.setattr(owner, name, deny)
    real_open = os.open
    def read_only(path, flags, *args, **kwargs):
        assert flags & os.O_ACCMODE == os.O_RDONLY
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", read_only)
    assert generate(CAPTURE, checkout)["status"] == "validated"
    capture = deepcopy(CAPTURE)
    capture["readbacks"]["checks"].update(status="unavailable", excerpt=None)
    assert_blocked(generate(capture, checkout), "READBACK_UNAVAILABLE")


def test_cli_failure_is_complete_json_without_traceback_or_input(tmp_path):
    capture = tmp_path / "bad.json"
    capture.write_text('{"forbidden-sentinel":')
    result = subprocess.run([sys.executable, str(ROOT / "tools/repository_currentness.py"), str(capture)],
                            capture_output=True, check=False)
    assert result.returncode == 3
    assert_blocked(json.loads(result.stdout), "INPUT_INVALID")
    assert result.stderr == b""
    assert b"forbidden-sentinel" not in result.stdout


def test_cli_success_preserves_synthetic_basis_and_emits_one_manifest(tmp_path):
    capture = deepcopy(CAPTURE)
    for row in capture["readbacks"]["tree"]["excerpt"]["files"]:
        raw = (ROOT / row["path"]).read_bytes()
        row["sha"] = tool.hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    source = tmp_path / "synthetic.json"
    source.write_bytes(tool.canonical(capture))
    result = subprocess.run([sys.executable, str(ROOT / "tools/repository_currentness.py"), str(source)],
                            capture_output=True, check=False)
    assert result.returncode == 0
    assert result.stderr == b""
    manifest = json.loads(result.stdout)
    validator("manifest").validate(manifest)
    assert manifest["capture"]["basis"] == "synthetic"


def test_cli_is_development_only_and_sdist_carries_the_contract():
    manifest = (ROOT / "MANIFEST.in").read_text()
    assert "recursive-include contracts *" in manifest
    assert "recursive-include tools *.py" in manifest
    # Runtime modules never import the development validator.
    assert not any("repository_currentness" in p.read_text() for p in (ROOT / "megalodon").rglob("*.py"))
