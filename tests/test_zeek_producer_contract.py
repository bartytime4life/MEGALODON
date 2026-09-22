"""Schema-drift scaffold for a PLACEHOLDER Zeek conn.log producer profile.

Issue #327 requires the owner to record an exact Zeek producer version,
build/package configuration, and field set before any profile here can be
called "supported." No such selection exists yet, so every fixture in
contracts/zeek-conn-log/v1/producer/ is a named stand-in
(``zeek-PLACEHOLDER-UNSELECTED-conn-json-v1``), not the qualified profile
that closes #327. These tests only prove that the placeholder fixtures are
internally consistent with the schema and with the already-implemented
`megalodon.offline.zeek` parser; they do not qualify an installed Zeek
producer, prove field-drift coverage against a real conn.log, or authorize
closing #327.
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


def test_schema_names_an_explicit_placeholder_profile() -> None:
    admission = SCHEMA["$defs"]["admission"]
    assert admission["properties"]["producer_profile"]["const"].startswith(
        "zeek-PLACEHOLDER-UNSELECTED-"
    )
    assert "$comment" in SCHEMA
    assert "PLACEHOLDER" in SCHEMA["title"]


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
