"""Static guardrails for the not-run Suricata engine research packet."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = (
    Path(__file__).parents[1]
    / "contracts"
    / "suricata-eve"
    / "v1"
    / "qualification"
)
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
PACKET = json.loads((ROOT / "research-packet.json").read_text(encoding="utf-8"))


def test_research_packet_validates_and_cannot_claim_execution() -> None:
    assert list(Draft202012Validator(SCHEMA).iter_errors(PACKET)) == []
    assert PACKET["disposition"] == "not_run_research_candidate"
    assert PACKET["producer"]["acceptance"] == "not_established"
    assert {case["execution_status"] for case in PACKET["cases"]} == {"not_run"}
    assert {case["fixture_status"] for case in PACKET["cases"]} == {"not_supplied"}
    assert set(PACKET["effects"].values()) == {False}


def test_packet_pins_the_two_reviewed_upstream_changes() -> None:
    cases = {case["id"]: case for case in PACKET["cases"]}
    assert cases["fragmented_tls_handshake_header"]["upstream_commit"] == (
        "bea218e7b1dd8ffb09f250e62c096c6b3da749b4"
    )
    assert cases["fragmented_tls_handshake_header"]["ticket"] == 9167
    assert cases["pcre_only_stream_progress"]["upstream_commit"] == (
        "f87b8e64a5fb80788897f7a9073c5407a2f5bc96"
    )
    assert cases["pcre_only_stream_progress"]["ticket"] == 8684
    for case in cases.values():
        assert case["upstream_url"].endswith(case["upstream_commit"])
        assert case["evidence_status"] == "research_only"


def test_schema_rejects_missing_hold_or_substituted_case_provenance() -> None:
    missing_hold = deepcopy(PACKET)
    missing_hold["remaining_holds"].remove("OWNER_AUTHORIZATION")
    assert list(Draft202012Validator(SCHEMA).iter_errors(missing_hold))

    duplicated_case = deepcopy(PACKET)
    duplicated_case["cases"][1] = deepcopy(duplicated_case["cases"][0])
    assert list(Draft202012Validator(SCHEMA).iter_errors(duplicated_case))

    substituted_commit = deepcopy(PACKET)
    substituted_commit["cases"][0]["upstream_commit"] = "0" * 40
    substituted_commit["cases"][0]["upstream_url"] = (
        "https://github.com/OISF/suricata/commit/" + "0" * 40
    )
    assert list(Draft202012Validator(SCHEMA).iter_errors(substituted_commit))

    fabricated_pass = deepcopy(PACKET)
    fabricated_pass["cases"][0]["verified_observation"] = (
        "Suricata was executed and passed production acceptance."
    )
    assert list(Draft202012Validator(SCHEMA).iter_errors(fabricated_pass))


def test_proposed_experiment_is_small_and_single_threaded() -> None:
    limits = PACKET["proposed_limits"]
    assert limits == {
        "max_fixture_bytes": 262144,
        "max_packets": 512,
        "max_output_bytes": 1048576,
        "max_wall_seconds_per_case": 10,
        "max_address_space_bytes": 536870912,
        "threads": 1,
    }


def test_research_packet_contains_no_executable_experiment_artifacts() -> None:
    allowed = {"README.md", "experiment", "research-packet.json", "schema.json"}
    assert {path.name for path in ROOT.iterdir()} == allowed
    assert (ROOT / "experiment").is_dir()
    serialized = json.dumps(PACKET, sort_keys=True).lower()
    for forbidden in (
        '"status": "passed"',
        '"suricata_executed": true',
        '"network_used": true',
        '"live_capture_used": true',
        '"host_changed": true',
        '"model_invoked": true',
    ):
        assert forbidden not in serialized
