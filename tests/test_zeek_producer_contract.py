"""Synthetic schema and parser checks for the declared Zeek 8.0.10 profile.

The owner selected this private-build candidate in PR #519. Admission pins its
recorded identities and declared configuration; fixtures do not authenticate a
native producer, loaded settings, capture completeness or owner acceptance.
The former placeholder remains in Git history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from megalodon.offline import zeek
from megalodon.offline.common import OfflineError

CONTRACT_ROOT = (
    Path(__file__).parents[1] / "contracts" / "zeek-conn-log" / "v1" / "producer"
)
SCHEMA = json.loads((CONTRACT_ROOT / "schema.json").read_text(encoding="utf-8"))
ACCEPTED = json.loads(
    (CONTRACT_ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8")
)
REJECTED = json.loads(
    (CONTRACT_ROOT / "fixtures" / "rejected.json").read_text(encoding="utf-8")
)


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]})


def _parse(value: dict) -> zeek.FlowRecord:
    """Round-trip through the real decoder, matching zeek.replay()'s own path."""
    text = json.dumps(value, separators=(",", ":"))
    return zeek.parse_flow(zeek.json_object(text))


def test_schema_names_the_exact_selected_candidate_without_native_qualification() -> None:
    admission = SCHEMA["$defs"]["admission"]["properties"]
    assert admission["producer_profile"]["const"] == "zeek-8.0.10-conn-json-tsv-v1"
    assert admission["declared_version"]["const"] == "8.0.10"
    assert "NOT QUALIFIED" in SCHEMA["title"]
    assert "does not attest" in SCHEMA["$comment"]


_ADMISSIONS = json.loads((CONTRACT_ROOT / "fixtures" / "admissions.json").read_text())


@pytest.mark.parametrize("case", _ADMISSIONS, ids=lambda item: item["format"])
def test_profile_admission_fixtures_validate(case) -> None:
    assert not list(_validator("admission").iter_errors(case))


def test_profile_json_positive_packet_matches_the_declared_record_shape() -> None:
    path = CONTRACT_ROOT.parent / "qualification" / "fixtures" / "accepted.jsonl"
    for raw in path.read_text().splitlines():
        assert not list(_validator("profileConnJsonRecord").iter_errors(json.loads(raw)))


@pytest.mark.parametrize("changes", [
    {"producer_profile": "unknown"}, {"declared_version": "9.0.0"},
    {"format": "csv"}, {"expected_digest": "sha256:" + "A" * 64},
    {"expected_digest": "sha256:" + "a" * 64 + "\n"},
    {"expected_records": 0}, {"source_id": "../escape"},
    {"source_id": "Synthetic\n"},
    {"binary_digest": "sha256:" + "0" * 64},
    {"configuration_digest": "sha256:" + "0" * 64}, {"extra": "field"},
])
def test_profile_admission_schema_refuses_drift(changes) -> None:
    assert list(_validator("admission").iter_errors({**_ADMISSIONS[0], **changes}))


@pytest.mark.parametrize("case", ACCEPTED, ids=lambda item: item["id"])
def test_accepted_contract_fixtures_validate(case) -> None:
    assert list(_validator("connJsonRecord").iter_errors(case["value"])) == []


_SCHEMA_INVALID_REJECTED = [c for c in REJECTED if not c.get("schema_valid")]
_SCHEMA_VALID_BUT_ADAPTER_REJECTED = [c for c in REJECTED if c.get("schema_valid")]


@pytest.mark.parametrize(
    "case", _SCHEMA_INVALID_REJECTED, ids=lambda item: item["id"]
)
def test_rejected_contract_fixtures_fail_schema(case) -> None:
    assert list(_validator("connJsonRecord").iter_errors(case["value"]))


@pytest.mark.parametrize(
    "case", _SCHEMA_VALID_BUT_ADAPTER_REJECTED, ids=lambda item: item["id"]
)
def test_schema_alone_cannot_catch_every_declared_rejection(case) -> None:
    """Named exception, not a silent gap: a per-field JSON Schema cannot express
    a cross-field consistency rule (declared transport protocol vs. the
    numeric ip_proto it must match), so this fixture is schema-valid by
    itself. The real adapter still refuses it — see the paired test below.
    A rejected fixture may only skip the schema-failure test by carrying an
    explicit "schema_valid": true and a "note" explaining why."""
    assert "note" in case
    assert list(_validator("connJsonRecord").iter_errors(case["value"])) == []


@pytest.mark.parametrize("case", ACCEPTED, ids=lambda item: item["id"])
def test_accepted_fixtures_parse_through_the_real_zeek_adapter(case) -> None:
    """A schema-valid record must also survive the actual parser, not only the schema."""
    record = _parse(case["value"])
    assert isinstance(record, zeek.FlowRecord)
    assert record.protocol in {"TCP", "UDP", "ICMP"}


@pytest.mark.parametrize("case", REJECTED, ids=lambda item: item["id"])
def test_rejected_fixtures_fail_the_real_zeek_adapter_with_named_code(case) -> None:
    """Schema drift must fail the actual parser with the specific declared code,
    not merely fail schema validation while still producing a record."""
    with pytest.raises(OfflineError, match=case["code"]):
        _parse(case["value"])


def test_duplicate_key_truncation_style_drift_is_not_representable_as_a_json_object_fixture() -> None:
    """A duplicate top-level key cannot survive Python's own JSON decoding as a
    dict fixture (the second value silently wins before this test ever sees
    it), so this case is exercised directly against raw text instead of the
    accepted/rejected fixture files.

    `zeek.json_object`'s own internal DUPLICATE_JSON_KEY code (raised by its
    object_pairs_hook while `json.loads` is still running) never reaches the
    caller: `json_object` catches every ValueError from that parse, including
    its own hook's, and re-raises the single collapsed INVALID_JSON code. That
    collapsing is real adapter behavior, not a test bug; a future producer
    qualification should decide whether losing that distinction is acceptable
    for operator diagnosis.
    """
    raw = (
        '{"ts":1758270930.123456,"id.orig_h":"192.0.2.10","id.orig_h":"203.0.113.5",'
        '"id.orig_p":54321,"id.resp_h":"198.51.100.20","id.resp_p":443,'
        '"proto":"tcp","conn_state":"SF","orig_pkts":12,"resp_pkts":9,'
        '"orig_ip_bytes":1440,"resp_ip_bytes":980}'
    )
    with pytest.raises(OfflineError, match="INVALID_JSON"):
        zeek.json_object(raw)


def test_accepted_and_rejected_ids_are_unique() -> None:
    accepted_ids = [case["id"] for case in ACCEPTED]
    rejected_ids = [case["id"] for case in REJECTED]
    assert len(accepted_ids) == len(set(accepted_ids))
    assert len(rejected_ids) == len(set(rejected_ids))
    assert set(accepted_ids).isdisjoint(rejected_ids)
