"""Consumer format assertions are mandatory; these are not runtime helpers."""
from __future__ import annotations

from copy import deepcopy
import socket
import subprocess

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry

import test_suricata_contract as contract


# These expectations are independent of the schema and configured checker.
FORMAT_PROBES = (
    ("ipv4", "192.0.2.1", "999.0.2.1"),
    ("ipv6", "2001:db8::1", "2001:db8::gg"),
    ("date-time", "2024-02-29T00:00:00.000000Z", "2023-02-29T00:00:00.000000Z"),
)


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Format tests must remain local and inert")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


def _assert_required_formats(validator):
    """Test-only consumer acceptance gate, never imported by runtime code."""
    checker = validator.format_checker
    assert checker is not None, "FORMAT_ASSERTIONS_REQUIRED"
    for name, valid, invalid in FORMAT_PROBES:
        assert name in checker.checkers, "FORMAT_ASSERTIONS_REQUIRED"
        assert checker.conforms(valid, name), "FORMAT_ASSERTIONS_REQUIRED"
        assert not checker.conforms(invalid, name), "FORMAT_ASSERTIONS_REQUIRED"


@pytest.mark.parametrize("entry", ("inputEnvelope", "externalAlert", "ip", "utcTime"))
def test_existing_consumer_has_required_working_formats(entry):
    _assert_required_formats(contract._validator(entry))


@pytest.mark.parametrize("missing", (None, "ipv4", "ipv6", "date-time"))
def test_acceptance_gate_detects_missing_assertions(missing):
    checker = deepcopy(contract.CHECKER)
    if missing is None:
        checker = None
    else:
        del checker.checkers[missing]
    consumer = Draft202012Validator({}, format_checker=checker)
    with pytest.raises(AssertionError, match="FORMAT_ASSERTIONS_REQUIRED"):
        _assert_required_formats(consumer)


@pytest.mark.parametrize("name, valid, invalid", FORMAT_PROBES)
def test_acceptance_gate_detects_a_noop_checker(name, valid, invalid):
    checker = deepcopy(contract.CHECKER)
    checker.checkers[name] = (lambda _: True, ())
    consumer = Draft202012Validator({}, format_checker=checker)
    with pytest.raises(AssertionError, match="FORMAT_ASSERTIONS_REQUIRED"):
        _assert_required_formats(consumer)


@pytest.mark.parametrize("address", ("192.0.2.1", "127.0.0.1", "2001:db8::1", "::1"))
def test_valid_addresses_require_a_conforming_consumer(address):
    assert contract._validator("ip").is_valid(address)
    annotation_only = Draft202012Validator(
        {"$ref": "#/$defs/ip", "$defs": contract.SCHEMA["$defs"]},
        registry=Registry(retrieve=contract._no_retrieval),
    )
    # Both format-only oneOf branches annotate successfully without checking.
    # This is a nonconforming consumer, not evidence the address is invalid.
    assert not annotation_only.is_valid(address)


@pytest.mark.parametrize("address", (
    "999.0.2.1", "192.0.2", "2001:db8::gg", ":::1", "::1%lo", "192.0.2.1\n",
))
def test_configured_consumer_rejects_invalid_addresses(address):
    assert not contract._validator("ip").is_valid(address)


def test_calendar_format_rejects_shape_valid_invalid_date():
    validator = contract._validator("utcTime")
    assert validator.is_valid("2024-02-29T00:00:00.000000Z")
    assert not validator.is_valid("2023-02-29T00:00:00.000000Z")


@pytest.mark.parametrize("case", contract.ACCEPTED, ids=lambda c: c["id"])
@pytest.mark.parametrize("target, entry", (("input", "inputEnvelope"), ("normalized", "externalAlert")))
def test_complete_positive_fixtures_use_explicit_assertions(case, target, entry):
    validator = contract._validator(entry)
    _assert_required_formats(validator)
    assert validator.is_valid(case[target])
