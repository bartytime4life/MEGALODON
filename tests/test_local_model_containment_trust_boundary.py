"""Packet validity is not authenticated provider evidence or owner approval.

All candidates here are hand-built, in-memory self-reports with synthetic
identities. No fixture is an operator binding, signed corpus, host observation,
or independent review. These tests document the v1 validator's trust boundary;
a future authenticated evidence-ingestion contract must be separately reviewed.
"""

from copy import deepcopy
from datetime import datetime, timezone
import builtins
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "containment_trust_boundary", ROOT / "tools/local_model_containment.py",
)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
        return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(TOOL, "datetime", FixedClock)


def self_report(status):
    """Construct claims, deliberately without obtaining real supporting evidence."""
    value = TOOL.collect()
    value["status"] = status
    if status != "unbound":
        value["model_binding"] = {
            "model_alias": "local:qwen-synthetic-trust-boundary",
            "artifact_sha256": "a" * 64,
            "registry_fingerprint_sha256": "b" * 64,
            "operator_approved": True,
        }
    if status == "candidate_evidence":
        value["wrapper_reachability"] = {
            "literal_loopback_only": "verified",
            "outbound_deny_test": "passed",
            "effective_no_cloud_configuration": "verified",
        }
        value["process_boundary"] = {
            "identity_verified": "verified",
            "lifecycle_observed": "observed",
            "concurrency_slot_rejection": "passed",
            "cancellation_timeout": "passed",
            "filesystem_mutation_absent": "verified",
            "host_wide_concurrency_absent": "verified",
        }
        value["adversarial_corpus"] = {
            "corpus_id": "synthetic-self-report-not-signed",
            "categories_covered": list(TOOL.ADVERSARIAL_CATEGORIES),
            "total_cases": 7, "cases_passed": 7, "cases_failed": 0,
        }
        value["gates"] = {
            "operator_model_selection": "met",
            "independent_security_review": "recorded",
        }
    value["limitations"] = [
        "Synthetic self-report, not authenticated collector output.",
        "No model, host, signature, or reviewer was inspected.",
        "Passing validation cannot authorize or attest any operation.",
    ]
    return value


@pytest.mark.parametrize("status", ["unbound", "incomplete", "candidate_evidence"])
def test_validating_claims_cannot_promote_fixed_collector(status):
    before = TOOL.collect()
    document = self_report(status)
    original = deepcopy(document)
    validated = TOOL.validate(document)
    assert validated == original
    assert document == original
    # Returned nested collections are owned, not aliases into caller input.
    validated["limitations"][0] = "changed copy"
    assert document == original
    assert TOOL.collect() == before
    assert before["model_binding"] is None
    assert before["gates"] == {
        "operator_model_selection": "blocked",
        "independent_security_review": "not_recorded",
    }
    assert all(effect is False for effect in before["effects"].values())


@pytest.mark.parametrize("status", ["unbound", "incomplete", "candidate_evidence"])
def test_in_memory_validation_and_collection_do_not_perform_claimed_checks(monkeypatch, status):
    document = self_report(status)
    expected = TOOL.validate(document)  # Warm standard-library date parsing.
    before = TOOL.collect()
    touched = []

    def forbidden(*args, **kwargs):
        touched.append("forbidden_effect")
        raise AssertionError("Unexpected external effect during packet validation")

    with monkeypatch.context() as guard:
        for owner, names in (
            (builtins, ("open",)),
            (Path, ("open", "read_bytes", "read_text", "write_bytes", "write_text")),
            (os, ("open", "stat", "lstat", "scandir", "listdir", "readlink", "system")),
            (socket, ("socket", "create_connection", "getaddrinfo")),
            (http.client, ("HTTPConnection", "HTTPSConnection")),
            (subprocess, ("Popen",)),
            (threading.Thread, ("start",)),
        ):
            for name in names:
                guard.setattr(owner, name, forbidden)
        result = TOOL.validate(document)
        collected = TOOL.collect()
    assert touched == []
    assert result == expected
    assert collected == before


def test_cli_validated_means_supplied_packet_consistency_not_attestation(tmp_path, capsys):
    source = tmp_path / "synthetic-self-report.json"
    document = self_report("candidate_evidence")
    original = json.dumps(document, indent=2).encode("utf-8")
    source.write_bytes(original)
    assert TOOL.main(["validate", str(source)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert captured.err == ""
    assert set(result) == {"schema_version", "status", "manifest_sha256", "manifest"}
    assert result["schema_version"] == "local-model-containment-acceptance-validation-v1"
    assert result["status"] == "validated"
    assert result["manifest"] == document
    assert result["manifest_sha256"] == TOOL.digest(document)
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == [source]
    assert TOOL.collect()["status"] == "unbound"


def test_explicit_synthetic_basis_still_cannot_claim_candidate_evidence():
    document = self_report("candidate_evidence")
    document["basis"] = "synthetic_contract_fixture"
    with pytest.raises(TOOL.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        TOOL.validate(document)


@pytest.mark.parametrize("field", ["artifact_sha256", "registry_fingerprint_sha256"])
@pytest.mark.parametrize("missing", [None, "PENDING", "a" * 63])
def test_incomplete_binding_requires_actual_shape_not_placeholder(field, missing):
    document = self_report("incomplete")
    document["model_binding"][field] = missing
    with pytest.raises(TOOL.ContainmentError, match="BINDING_REQUIRED"):
        TOOL.validate(document)


@pytest.mark.parametrize("alias", ["qwen2.5:7b-instruct-fp16", "qwen3.6:latest"])
def test_provider_tag_is_not_the_contract_alias(alias):
    document = self_report("incomplete")
    document["model_binding"]["model_alias"] = alias
    with pytest.raises(TOOL.ContainmentError, match="BINDING_REQUIRED"):
        TOOL.validate(document)


def test_profile_nomination_is_not_operator_approval():
    document = self_report("incomplete")
    document["model_binding"]["operator_approved"] = False
    with pytest.raises(TOOL.ContainmentError, match="BINDING_REQUIRED"):
        TOOL.validate(document)


def test_unrecorded_independent_review_keeps_candidate_incomplete():
    document = self_report("candidate_evidence")
    document["gates"]["independent_security_review"] = "not_recorded"
    with pytest.raises(TOOL.ContainmentError, match="CANDIDATE_INCOMPLETE"):
        TOOL.validate(document)


def test_help_discloses_validation_and_collection_limits(capsys):
    with pytest.raises(SystemExit) as caught:
        TOOL.main(["--help"])
    assert caught.value.code == 0
    captured = capsys.readouterr()
    normalized = " ".join(captured.out.split())
    assert captured.err == ""
    assert "not provider acceptance" in normalized
    assert "not an attestation" in normalized
    assert "fixed unbound state without host inspection" in normalized
