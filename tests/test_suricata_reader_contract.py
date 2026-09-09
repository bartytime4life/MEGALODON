"""Inert bounded-reader conformance oracle; not a production file reader."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
from types import MappingProxyType

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
READER_ROOT = ROOT / "reader"
RECORD_SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
READER_SCHEMA = json.loads((READER_ROOT / "schema.json").read_text(encoding="utf-8"))
RECORD_CASES = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
ACCEPTED = json.loads((READER_ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
REJECTED = json.loads((READER_ROOT / "fixtures" / "rejected.json").read_text(encoding="utf-8"))

LIMITS = ACCEPTED["policy"]["limits"]
MAX_TOTAL_BYTES = LIMITS["max_total_bytes"]
MAX_RECORDS = LIMITS["max_records"]
MAX_RECORD_BYTES = LIMITS["max_record_bytes"]
MAX_DEPTH = LIMITS["max_nesting_depth"]
MAX_INTEGER_DIGITS = LIMITS["max_integer_digits"]
MAX_OUTPUT_BYTES = LIMITS["max_normalized_batch_bytes"]
MAX_ELAPSED_MS = LIMITS["max_elapsed_ms"]
MAX_DIAGNOSTIC_BYTES = LIMITS["max_diagnostic_bytes"]
ERROR_CODES = frozenset(READER_SCHEMA["$defs"]["errorCode"]["enum"])
EXPECTED_ERROR_CODES = frozenset({
    "SOURCE_PATH", "SOURCE_SYMLINK", "SOURCE_TYPE", "SOURCE_OWNER",
    "SOURCE_MODE", "SOURCE_CHANGED", "TOTAL_BYTES", "RECORD_LIMIT",
    "RECORD_BYTES", "EMPTY_INPUT", "EMPTY_RECORD", "FRAMING", "UTF8",
    "DUPLICATE_KEY", "DEPTH", "JSON_NUMBER", "JSON", "SCHEMA",
    "SEMANTIC", "RUN_IDENTITY", "RECORD_SEQUENCE", "REPLAY",
    "COUNT_MISMATCH", "OUTPUT_LIMIT", "TIME_LIMIT",
})


class ReaderError(ValueError):
    """Fixed diagnostic only: never include data, paths, metadata or exceptions."""

    def __init__(self, code: str):
        assert code in ERROR_CODES
        super().__init__(f"SURICATA_READER_V1:{code}")


def _fail(code: str):
    raise ReaderError(code)


def _no_retrieval(uri: str):
    raise NoSuchResource(ref=uri)


CHECKER = FormatChecker(formats=["ipv4", "ipv6"])


@CHECKER.checks("date-time", raises=(ValueError, OverflowError))
def _calendar_time(value):
    if not isinstance(value, str):
        return True
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


def _record_validator(name: str):
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": RECORD_SCHEMA["$defs"]},
        format_checker=CHECKER,
        registry=Registry(retrieve=_no_retrieval),
    )


READER_VALIDATOR = Draft202012Validator(
    READER_SCHEMA, registry=Registry(retrieve=_no_retrieval)
)


def _enforce_total(value: int):
    if value > MAX_TOTAL_BYTES:
        _fail("TOTAL_BYTES")


def _enforce_count(value: int):
    if value > MAX_RECORDS:
        _fail("RECORD_LIMIT")


def _enforce_output(value: int):
    if value > MAX_OUTPUT_BYTES:
        _fail("OUTPUT_LIMIT")


def _enforce_elapsed(value: int):
    if value > MAX_ELAPSED_MS:
        _fail("TIME_LIMIT")


def _decode(raw: bytes):
    """Test-only logical-record oracle; it never opens a file."""
    if len(raw) > MAX_RECORD_BYTES:
        _fail("RECORD_BYTES")
    raw = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith(b"\n") else raw
    if not raw:
        _fail("EMPTY_RECORD")
    if b"\n" in raw or b"\r" in raw:
        _fail("FRAMING")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("UTF8")

    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _fail("UTF8")

    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _fail("DEPTH")
        elif char in "]}":
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("DUPLICATE_KEY")
            result[key] = value
        return result

    def integer(token):
        if len(token.lstrip("-")) > MAX_INTEGER_DIGITS:
            _fail("JSON_NUMBER")
        return int(token)

    def reject_number(token):
        _fail("JSON_NUMBER")

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except ReaderError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _fail("JSON")


def _utc(value: str) -> str:
    try:
        if value.endswith(("-0000", "-00:00")):
            raise ValueError
        match = re.search(r"([+-])([0-9]{2}):?([0-9]{2})$", value)
        if match:
            hours, minutes = int(match[2]), int(match[3])
            if minutes > 59 or hours > 14 or (hours == 14 and minutes):
                raise ValueError
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
        stamp = stamp.astimezone(timezone.utc)
        if stamp.year < 1970:
            raise ValueError
        return stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        _fail("SEMANTIC")


def _validate_input(value):
    if not _record_validator("inputEnvelope").is_valid(value):
        _fail("SCHEMA")
    event = value["event"]
    try:
        src = ipaddress.ip_address(event["src_ip"])
        dst = ipaddress.ip_address(event["dest_ip"])
    except ValueError:
        _fail("SEMANTIC")
    if src.version != dst.version:
        _fail("SEMANTIC")
    _utc(event["timestamp"])


def _normalize(value):
    event = value["event"]
    return {
        "schema_version": "external-alert-v1",
        "source": value["source"],
        "source_record_index": value["source_record_index"],
        "observed_at": _utc(event["timestamp"]),
        "src_ip": str(ipaddress.ip_address(event["src_ip"])),
        "src_port": event["src_port"],
        "dst_ip": str(ipaddress.ip_address(event["dest_ip"])),
        "dst_port": event["dest_port"],
        "protocol": event["proto"],
        "rule": {
            key: event["alert"][key]
            for key in ("gid", "signature_id", "rev", "severity")
        },
        "producer_reported_action": event["alert"]["action"],
        "evidence_kind": "signature_match",
        "count_unit": "alert",
        "action_status": "not_attempted",
    }


def _run_key(identity):
    return tuple(identity[key] for key in (
        "engine", "adapter_profile", "declared_version", "version_basis",
        "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
    ))


def _validate_reader_value(value):
    if not READER_VALIDATOR.is_valid(value):
        _fail("SCHEMA")


def _validate_receipt(value):
    _validate_reader_value(value)
    if (
        value["record_count"] != value["normalized_alert_count"]
        or value["producer_blocked_count"] > value["record_count"]
    ):
        _fail("COUNT_MISMATCH")


def _logical_records(raw: bytes):
    records, start = [], 0
    quoted = escaped = False
    for index, byte in enumerate(raw):
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        if byte == 10:
            if quoted:
                _fail("FRAMING")
            records.append(raw[start:index + 1])
            start = index + 1
    if start < len(raw):
        records.append(raw[start:])
    return records


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _read_in_memory(raw: bytes, *, completed_run_keys=frozenset(),
                    elapsed_ms=0, publish=None):
    """Model the publish boundary only; this is intentionally not runtime code."""
    _enforce_elapsed(elapsed_ms)
    _enforce_total(len(raw))
    if not raw:
        _fail("EMPTY_INPUT")
    logical = _logical_records(raw)
    _enforce_count(len(logical))

    normalized = []
    identity = None
    blocked = 0
    for expected_index, encoded in enumerate(logical, start=1):
        value = _decode(encoded)
        _validate_input(value)
        if value["source_record_index"] != expected_index:
            _fail("RECORD_SEQUENCE")
        if identity is None:
            identity = deepcopy(value["source"])
        elif value["source"] != identity:
            _fail("RUN_IDENTITY")
        item = _normalize(value)
        if item["producer_reported_action"] == "blocked":
            blocked += 1
        normalized.append(item)

    assert identity is not None
    if _run_key(identity) in completed_run_keys:
        _fail("REPLAY")

    output_bytes = sum(len(json.dumps(
        item, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")) for item in normalized)
    _enforce_output(output_bytes)
    _enforce_elapsed(elapsed_ms)

    receipt = {
        "schema_version": "suricata-eve-reader-receipt-v1",
        "reader_policy_version": "suricata-eve-reader-policy-v1",
        "status": "complete",
        "run_identity": identity,
        "record_count": len(normalized),
        "normalized_alert_count": len(normalized),
        "producer_blocked_count": blocked,
        "normalized_batch_bytes": output_bytes,
        "count_unit": "alert",
        "action_status": "not_attempted",
        "durable_write_status": "not_attempted",
        "source_snapshot_status": "metadata_unchanged_not_atomic",
        "replay_status": "fresh",
    }
    _validate_receipt(receipt)
    publication = (tuple(_freeze(item) for item in normalized), _freeze(receipt))
    if publish is not None:
        publish(publication)
    return publication


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Reader contract tests must not use network or processes")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


def test_schema_fixture_inventory_and_local_resolution():
    Draft202012Validator.check_schema(READER_SCHEMA)
    assert ACCEPTED["receipts"] and REJECTED
    assert len({case["id"] for case in ACCEPTED["receipts"]}) == len(ACCEPTED["receipts"])
    assert len({case["id"] for case in REJECTED}) == len(REJECTED)

    def walk(node):
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/$defs/")
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(READER_SCHEMA)
    assert ERROR_CODES == EXPECTED_ERROR_CODES
    assert len(ERROR_CODES) == len(READER_SCHEMA["$defs"]["errorCode"]["enum"])


def test_policy_is_exact_bounded_and_inert():
    policy = ACCEPTED["policy"]
    _validate_reader_value(policy)
    assert policy["limits"] == {
        "max_total_bytes": 67108864,
        "max_records": 10000,
        "max_record_bytes": 65536,
        "max_nesting_depth": 4,
        "max_integer_digits": 10,
        "max_buffered_input_bytes": 65536,
        "max_normalized_batch_bytes": 16777216,
        "max_elapsed_ms": 30000,
        "max_diagnostic_bytes": 64,
    }
    assert policy["source_file"] == {
        "explicit_single_path": True,
        "require_absolute_path": True,
        "require_regular_file": True,
        "require_effective_uid_owner": True,
        "forbid_group_other_permissions": True,
        "reject_symlink_components": True,
        "open_read_only": True,
        "verify_descriptor_identity": True,
        "verify_post_read_metadata": True,
        "atomic_snapshot_guaranteed": False,
    }
    assert set(policy["side_effects"].values()) == {False}
    assert policy["stream"]["retain_original_json"] is False


@pytest.mark.parametrize("case", ACCEPTED["receipts"], ids=lambda c: c["id"])
def test_accepted_completed_receipts(case):
    _validate_receipt(case["receipt"])


@pytest.mark.parametrize("case", REJECTED, ids=lambda c: c["id"])
def test_rejected_contract_mutations(case):
    seeds = {"policy": ACCEPTED["policy"]}
    seeds.update({item["id"]: item["receipt"] for item in ACCEPTED["receipts"]})
    value = deepcopy(seeds[case["seed"]])
    parent = value
    for part in case["path"][:-1]:
        parent = parent[part]
    assert case["operation"] == "set"
    parent[case["path"][-1]] = case["value"]
    if case["stage"] == "semantic":
        _validate_reader_value(value)
    with pytest.raises(ReaderError) as caught:
        if case["seed"] == "policy":
            _validate_reader_value(value)
        else:
            _validate_receipt(value)
    assert str(caught.value) == f"SURICATA_READER_V1:{case['code']}"


def test_two_record_batch_is_published_once_after_complete_validation():
    raw = b"\n".join(json.dumps(case["input"]).encode("utf-8") for case in RECORD_CASES[:2])
    publications = []
    batch, receipt = _read_in_memory(raw, publish=publications.append)
    assert publications == [(batch, receipt)]
    assert [item["source_record_index"] for item in batch] == [1, 2]
    assert receipt["record_count"] == receipt["normalized_alert_count"] == 2
    assert receipt["producer_blocked_count"] == 1
    assert receipt["action_status"] == "not_attempted"
    assert receipt["durable_write_status"] == "not_attempted"
    assert batch[1]["producer_reported_action"] == "blocked"
    assert batch[1]["action_status"] == "not_attempted"
    assert set(batch[0]["rule"]) == {"gid", "signature_id", "rev", "severity"}


def test_accepted_receipts_are_derived_from_oracle_outputs():
    raw = b"\n".join(json.dumps(case["input"]).encode("utf-8") for case in RECORD_CASES[:2])
    _, receipt = _read_in_memory(raw)
    assert receipt == ACCEPTED["receipts"][0]["receipt"]

    value = _largest_closed_record()
    encoded = json.dumps(_normalize(value), sort_keys=True, separators=(",", ":")).encode()
    expected = ACCEPTED["receipts"][1]["receipt"]
    assert expected["run_identity"] == value["source"]
    assert expected["normalized_batch_bytes"] == len(encoded) * MAX_RECORDS


def test_published_batch_and_receipt_are_deeply_immutable():
    raw = json.dumps(RECORD_CASES[0]["input"]).encode("utf-8")
    batch, receipt = _read_in_memory(raw)
    with pytest.raises(TypeError):
        batch[0]["rule"]["severity"] = 1
    with pytest.raises(TypeError):
        receipt["run_identity"]["run_id"] = "changed"


def test_late_failure_never_publishes_a_partial_batch():
    first = RECORD_CASES[0]["input"]
    second = deepcopy(RECORD_CASES[1]["input"])
    second["event"]["command"] = "SYNTHETIC"
    raw = b"\n".join(json.dumps(value).encode("utf-8") for value in (first, second))
    publications = []
    with pytest.raises(ReaderError, match="^SURICATA_READER_V1:SCHEMA$"):
        _read_in_memory(raw, publish=publications.append)
    assert publications == []


def test_record_sequence_and_run_identity_are_run_level_gates():
    first = RECORD_CASES[0]["input"]
    gap = deepcopy(RECORD_CASES[1]["input"])
    gap["source_record_index"] = 3
    with pytest.raises(ReaderError, match="RECORD_SEQUENCE$"):
        _read_in_memory(b"\n".join(json.dumps(v).encode() for v in (first, gap)))

    changed = deepcopy(RECORD_CASES[1]["input"])
    changed["source"]["run_id"] = "fixture-run-b"
    with pytest.raises(ReaderError, match="RUN_IDENTITY$"):
        _read_in_memory(b"\n".join(json.dumps(v).encode() for v in (first, changed)))


def test_replay_uses_completed_run_identity_without_content_hashes():
    first = RECORD_CASES[0]["input"]
    key = _run_key(first["source"])
    with pytest.raises(ReaderError, match="REPLAY$"):
        _read_in_memory(json.dumps(first).encode(), completed_run_keys={key})
    assert not any("hash" in field for field in first["source"])


def test_ordinal_bound_is_not_mistaken_for_stream_quota():
    boundary = RECORD_CASES[2]["input"]
    _validate_input(boundary)
    assert boundary["source_record_index"] == 10000
    with pytest.raises(ReaderError, match="RECORD_SEQUENCE$"):
        _read_in_memory(json.dumps(boundary).encode())


@pytest.mark.parametrize(("check", "value", "code"), [
    (_enforce_total, MAX_TOTAL_BYTES + 1, "TOTAL_BYTES"),
    (_enforce_count, MAX_RECORDS + 1, "RECORD_LIMIT"),
    (_enforce_output, MAX_OUTPUT_BYTES + 1, "OUTPUT_LIMIT"),
    (_enforce_elapsed, MAX_ELAPSED_MS + 1, "TIME_LIMIT"),
])
def test_numeric_resource_boundaries_fail_closed(check, value, code):
    check(value - 1)
    with pytest.raises(ReaderError) as caught:
        check(value)
    assert str(caught.value) == f"SURICATA_READER_V1:{code}"


@pytest.mark.parametrize(("raw", "code"), [
    (b"", "EMPTY_INPUT"),
    (b"\n", "EMPTY_RECORD"),
    (b"\xef\xbb\xbf{}", "UTF8"),
    (b'{"x":1,"x":2}', "DUPLICATE_KEY"),
    (b"[[[[[0]]]]]", "DEPTH"),
    (b'{"x":12345678901}', "JSON_NUMBER"),
    (b'{"x":1.0}', "JSON_NUMBER"),
    (b'{"x":"line\rbreak"}', "FRAMING"),
    (b'{"x":"line\nbreak"}', "FRAMING"),
    (b"\xff", "UTF8"),
])
def test_stream_failures_use_fixed_codes(raw, code):
    with pytest.raises(ReaderError) as caught:
        _read_in_memory(raw)
    assert str(caught.value) == f"SURICATA_READER_V1:{code}"


def test_logical_record_byte_boundary_includes_terminator():
    assert _decode(b" " * (MAX_RECORD_BYTES - 2) + b"{}") == {}
    with pytest.raises(ReaderError, match="RECORD_BYTES$"):
        _decode(b" " * (MAX_RECORD_BYTES - 1) + b"{}")


def _largest_closed_record():
    value = deepcopy(RECORD_CASES[0]["input"])
    value["source"] |= {
        "declared_version": "999.999.999",
        "sensor_id": "S" * 64,
        "run_id": "R" * 64,
        "ruleset_id": "T" * 64,
    }
    value["source_record_index"] = 10000
    value["event"] |= {
        "timestamp": "9999-12-31T23:59:59.999999Z",
        "src_ip": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
        "dest_ip": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "src_port": 65535,
        "dest_port": 65535,
    }
    value["event"]["alert"] |= {
        "gid": 4294967295,
        "signature_id": 4294967295,
        "rev": 4294967295,
        "severity": 255,
    }
    _validate_input(value)
    return value


def test_output_budget_can_hold_ten_thousand_largest_closed_records():
    value = _largest_closed_record()
    encoded = json.dumps(_normalize(value), sort_keys=True, separators=(",", ":")).encode()
    assert len(encoded) * MAX_RECORDS <= MAX_OUTPUT_BYTES


def test_diagnostics_are_bounded_and_never_echo_input():
    raw = b'{"path":"/synthetic/private/eve.json","label":"SYNTHETIC"}'
    with pytest.raises(ReaderError) as caught:
        _read_in_memory(raw)
    diagnostic = str(caught.value)
    assert diagnostic.encode("ascii")
    assert len(diagnostic.encode("ascii")) <= MAX_DIAGNOSTIC_BYTES
    for forbidden in ("path", "private", "eve.json", "label", "SYNTHETIC"):
        assert forbidden not in diagnostic
