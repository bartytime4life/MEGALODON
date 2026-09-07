"""Inert contract conformance examples; not a production parser or importer."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).parents[1] / "contracts" / "suricata-eve" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
ACCEPTED = json.loads((ROOT / "fixtures" / "accepted.json").read_text(encoding="utf-8"))
REJECTED = json.loads((ROOT / "fixtures" / "rejected.json").read_text(encoding="utf-8"))
FRAMING = json.loads((ROOT / "fixtures" / "rejected-framing.json").read_text(encoding="utf-8"))
MAX_LINE_BYTES = 65536
MAX_DEPTH = 4


class ContractError(ValueError):
    """Fixed diagnostic only: never include input, paths, labels or JSON errors."""


def _no_retrieval(uri: str):
    raise NoSuchResource(ref=uri)


CHECKER = FormatChecker(formats=["ipv4", "ipv6"])


@CHECKER.checks("date-time", raises=(ValueError, OverflowError))
def _calendar_time(value):
    if not isinstance(value, str):
        return True  # The schema's type constraint handles this.
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


def _validator(name):
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]},
        format_checker=CHECKER, registry=Registry(retrieve=_no_retrieval),
    )


def _decode(raw: bytes):
    """Test-only byte/framing oracle. No filesystem, stream or production API."""
    if len(raw) > MAX_LINE_BYTES:
        raise ContractError("LINE_LIMIT")
    raw = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith(b"\n") else raw
    if b"\n" in raw or b"\r" in raw:
        raise ContractError("FRAMING")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ContractError("DEPTH")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("DUPLICATE_KEY")
            result[key] = value
        return result

    def integer(token):
        if len(token.lstrip("-")) > 10:
            raise ContractError("JSON_NUMBER")
        return int(token)

    def reject_number(token):
        raise ContractError("JSON_NUMBER")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_int=integer, parse_float=reject_number,
                          parse_constant=reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ContractError("JSON") from None


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
        raise ContractError("TIMESTAMP") from None


def _validate(value, target, *, semantic=True):
    name = "inputEnvelope" if target == "input" else "externalAlert"
    if not _validator(name).is_valid(value):
        raise ContractError("SCHEMA")
    if not semantic:
        return
    record = value["event"] if target == "input" else value
    dst = "dest_ip" if target == "input" else "dst_ip"
    left, right = ipaddress.ip_address(record["src_ip"]), ipaddress.ip_address(record[dst])
    if left.version != right.version:
        raise ContractError("ADDRESS_FAMILY")
    _utc(record["timestamp"] if target == "input" else record["observed_at"])
    if target != "input" and (str(left) != record["src_ip"] or str(right) != record[dst]):
        raise ContractError("CANONICAL_IP")


def _expected(inp):
    """Executable mapping example only; absent from the runtime package."""
    event = inp["event"]
    return {
        "schema_version": "external-alert-v1", "source": inp["source"],
        "source_record_index": inp["source_record_index"],
        "observed_at": _utc(event["timestamp"]),
        "src_ip": str(ipaddress.ip_address(event["src_ip"])), "src_port": event["src_port"],
        "dst_ip": str(ipaddress.ip_address(event["dest_ip"])), "dst_port": event["dest_port"],
        "protocol": event["proto"],
        "rule": {key: event["alert"][key] for key in ("gid", "signature_id", "rev", "severity")},
        "producer_reported_action": event["alert"]["action"],
        "evidence_kind": "signature_match", "count_unit": "alert", "action_status": "not_attempted",
    }


def _validate_pair(inp, out):
    _validate(inp, "input")
    _validate(out, "normalized")
    if _expected(inp) != out:
        raise ContractError("PAIR")


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Contract tests must not open sockets or launch processes")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


def test_schema_and_fixture_inventory():
    Draft202012Validator.check_schema(SCHEMA)
    for cases in (ACCEPTED, REJECTED, FRAMING):
        assert cases
        assert len({case["id"] for case in cases}) == len(cases)
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
    walk(SCHEMA)


@pytest.mark.parametrize("case", ACCEPTED, ids=lambda c: c["id"])
def test_accepted_pairs(case):
    inp = _decode(json.dumps(case["input"]).encode("utf-8"))
    out = _decode(json.dumps(case["normalized"]).encode("utf-8"))
    _validate_pair(inp, out)


@pytest.mark.parametrize("case", REJECTED, ids=lambda c: c["id"])
def test_rejected_contract_cases(case):
    seeds = {seed["id"]: seed for seed in ACCEPTED}
    seed = deepcopy(seeds[case["seed"]])
    _validate_pair(seed["input"], seed["normalized"])
    parent = seed[case["target"]]
    for part in case["path"][:-1]:
        parent = parent[part]
    if case["operation"] == "remove":
        del parent[case["path"][-1]]
    else:
        assert case["operation"] == "set"
        parent[case["path"][-1]] = case["value"]
    value = _decode(json.dumps(seed[case["target"]]).encode("utf-8"))
    if case["stage"] in ("semantic", "pair"):
        _validate(value, case["target"], semantic=False)
    if case["stage"] == "pair":
        _validate(value, case["target"])
    with pytest.raises(ContractError) as caught:
        if case["stage"] == "pair":
            _validate_pair(seed["input"], seed["normalized"])
        else:
            _validate(value, case["target"])
    assert str(caught.value) == case["code"]


@pytest.mark.parametrize("case", FRAMING, ids=lambda c: c["id"])
def test_rejected_byte_framing(case):
    with pytest.raises(ContractError) as caught:
        _decode(case["text"].encode("utf-8"))
    assert str(caught.value) == case["code"]


def test_line_budget_and_invalid_encoding():
    assert _decode(b" " * (MAX_LINE_BYTES - 2) + b"{}") == {}
    for raw, code in ((b" " * (MAX_LINE_BYTES - 1) + b"{}", "LINE_LIMIT"),
                      (b"\xff", "JSON")):
        with pytest.raises(ContractError) as caught:
            _decode(raw)
        assert str(caught.value) == code


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_record_terminators_and_braces_inside_strings(ending):
    assert _decode(b'{"x":"[[[[[\\\""}' + ending) == {"x": '[[[[["'}


@pytest.mark.parametrize("number", [1.0, 1.5, float("nan"), float("inf")])
def test_numeric_tokens_are_not_coerced(number):
    value = deepcopy(ACCEPTED[0]["input"])
    value["event"]["src_port"] = number
    with pytest.raises(ContractError, match="^JSON_NUMBER$"):
        _decode(json.dumps(value).encode("utf-8"))


def test_no_action_upgrade_or_label_retention():
    out = ACCEPTED[1]["normalized"]
    assert out["producer_reported_action"] == "blocked"
    assert out["action_status"] == "not_attempted"
    props = SCHEMA["$defs"]["externalAlert"]["properties"]
    assert props["action_status"] == {"const": "not_attempted"}
    assert set(SCHEMA["$defs"]["rule"]["properties"]) == {"gid", "signature_id", "rev", "severity"}
    assert props["count_unit"] == {"const": "alert"}


def test_duplicate_alerts_are_not_claimed_independent_or_deduplicated():
    seed = ACCEPTED[0]
    _validate_pair(seed["input"], seed["normalized"])
    _validate_pair(deepcopy(seed["input"]), deepcopy(seed["normalized"]))
    # A record schema cannot establish run-level uniqueness or corroboration.
    assert seed["normalized"]["source_record_index"] == 1
