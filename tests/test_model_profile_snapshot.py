"""Synthetic regressions for owned, immutable model-profile validation snapshots."""

from __future__ import annotations

from hashlib import sha256
import json

import pytest

from megalodon.model_profile import (
    binding_candidate_packet,
    canonical_json,
    compare_profiles,
    validate_profile,
)


def _profile(profile_id: str = "qwen-snapshot-a") -> dict:
    # These repeated digests are synthetic identities, never real model evidence.
    return {
        "schema": "megalodon-local-model-profile-v1",
        "profile_id": profile_id,
        "status": "candidate",
        "evidence_class": "synthetic_fixture",
        "provider": "ollama",
        "endpoint": "http://127.0.0.1:11434",
        "model_alias": "qwen2.5:7b-instruct-fp16",
        "ollama_manifest_digest": "a" * 64,
        "artifact_sha256": "b" * 64,
        "provenance_sha256": "c" * 64,
        "containment_receipt_sha256": "d" * 64,
        "model_family": "qwen2.5",
        "quantization": "fp16",
        "context_window": 32768,
        "operational_context": 4096,
        "purpose": "advisory",
        "structured_output": True,
        "thinking_enabled": False,
        "license": "Apache-2.0",
        "source_reference": "synthetic snapshot regression only",
        "runner": {
            "name": "ollama", "version": "0.0.0-synthetic", "binary_sha256": "e" * 64,
        },
        "evaluation": {
            "corpus_sha256": "f" * 64,
            "sample_count": 12,
            "schema_valid_count": 12,
            "citation_valid_count": 12,
            "refusal_valid_count": 12,
            "p95_latency_ms": 900,
            "max_rss_mib": 8192,
        },
    }


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        (None, "evidence_class", "operator_observed"),
        (None, "purpose", "explanation"),
        (None, "artifact_sha256", "1" * 64),
        ("runner", "version", "0.0.1-synthetic"),
        ("runner", "binary_sha256", "1" * 64),
        ("evaluation", "corpus_sha256", "1" * 64),
        ("evaluation", "sample_count", 13),
        ("evaluation", "citation_valid_count", 0),
        ("evaluation", "p95_latency_ms", 1),
    ],
)
def test_mutating_returned_profile_cannot_change_validated_evidence(
    section, field, replacement,
):
    validated = validate_profile(_profile())
    other = validate_profile(_profile("qwen-snapshot-b"))
    before = binding_candidate_packet(validated)
    comparison = compare_profiles([validated, other])
    exposed = validated.value
    target = exposed if section is None else exposed[section]
    target[field] = replacement

    assert binding_candidate_packet(validated) == before
    assert compare_profiles([validated, other]) == comparison
    assert validated.evidence_class == "synthetic_fixture"
    assert before["state"] == "SYNTHETIC_ONLY"
    assert sha256(canonical_json(validated.value).encode("ascii")).hexdigest() == (
        validated.canonical_sha256
    )


def test_input_and_emitted_packet_mutations_do_not_change_snapshot():
    supplied = _profile()
    validated = validate_profile(supplied)
    before = binding_candidate_packet(validated)
    supplied["evaluation"]["corpus_sha256"] = "1" * 64
    emitted = binding_candidate_packet(validated)
    emitted["evaluation"]["sample_count"] = 999
    emitted["remaining_holds"].clear()
    assert binding_candidate_packet(validated) == before
    assert validated.value["evaluation"]["sample_count"] == 12


def test_snapshot_returns_owned_json_compatible_values():
    validated = validate_profile(_profile())
    first = validated.value
    second = validated.value
    assert first == second
    assert json.loads(canonical_json(first)) == first
    assert first is not second
    assert first["runner"] is not second["runner"]
    assert first["evaluation"] is not second["evaluation"]


def test_incomplete_snapshot_remains_hold_after_exposed_counts_are_changed():
    supplied = _profile()
    supplied["evidence_class"] = "operator_observed"
    supplied["evaluation"]["citation_valid_count"] = 11
    validated = validate_profile(supplied)
    before = binding_candidate_packet(validated)
    exposed = validated.value
    exposed["evaluation"]["citation_valid_count"] = 12
    assert binding_candidate_packet(validated) == before
    assert before["state"] == "EVALUATION_HOLD"
    assert validated.hard_gate_passed is False
