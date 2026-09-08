"""Persistent COUNT/UNTIL regression controls; no recurrence or execution."""
from __future__ import annotations

from copy import deepcopy
from itertools import permutations
import json
from pathlib import Path
import socket
import subprocess

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).parents[1] / "contracts" / "automation" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
# Independent expectations: do not derive coverage from the schema under test.
FREQUENCIES = ("MINUTELY", "HOURLY", "DAILY", "WEEKLY", "MONTHLY", "YEARLY")
BOUNDS = ("COUNT=24", "UNTIL=20260908T000000Z")


@pytest.fixture(autouse=True)
def no_network_or_process(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("RRULE tests must remain inert")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)


def _no_retrieval(uri):
    raise NoSuchResource(ref=uri)


def _validator(schema, entry):
    return Draft202012Validator(
        {"$ref": f"#/$defs/{entry}", "$defs": schema["$defs"]},
        format_checker=FormatChecker(), registry=Registry(retrieve=_no_retrieval),
    )


def _value(entry, rule):
    if entry == "canonicalRrule":
        return rule
    return {"name": "Bounded fixture", "prompt": "Synthetic metadata only.", "rrule": rule}


@pytest.mark.parametrize("entry", ("canonicalRrule", "draftCreate"))
@pytest.mark.parametrize("frequency", FREQUENCIES)
@pytest.mark.parametrize("bound", BOUNDS)
def test_single_bound_remains_accepted(entry, frequency, bound):
    assert _validator(SCHEMA, entry).is_valid(_value(entry, f"FREQ={frequency};{bound}"))


@pytest.mark.parametrize("entry", ("canonicalRrule", "draftCreate"))
@pytest.mark.parametrize("frequency", FREQUENCIES)
@pytest.mark.parametrize("parts", tuple(permutations((*BOUNDS, "INTERVAL=2"))))
def test_every_mixed_order_is_rejected_by_the_exclusion(entry, frequency, parts):
    value = _value(entry, ";".join((f"FREQ={frequency}", *parts)))
    assert not _validator(SCHEMA, entry).is_valid(value)
    weakened = deepcopy(SCHEMA)
    del weakened["$defs"]["canonicalRrule"]["not"]
    # Prove another invalid field is not accidentally causing this rejection.
    assert _validator(weakened, entry).is_valid(value)


@pytest.mark.parametrize("name", ("draft-count-bounded", "draft-until-bounded"))
def test_named_positive_fixtures_are_retained(name):
    case = json.loads((ROOT / "fixtures" / "accepted" / f"{name}.json").read_text())
    assert case["schema"] == "draftCreate"
    assert _validator(SCHEMA, case["schema"]).is_valid(case["value"])


@pytest.mark.parametrize("name", ("count-before-until", "until-before-count"))
def test_named_negative_fixtures_detect_exclusion_removal(name):
    case = json.loads((ROOT / "fixtures" / "rejected" / f"{name}.json").read_text())
    assert case["schema"] == "draftCreate"
    assert not _validator(SCHEMA, case["schema"]).is_valid(case["value"])
    weakened = deepcopy(SCHEMA)
    del weakened["$defs"]["canonicalRrule"]["not"]
    assert _validator(weakened, case["schema"]).is_valid(case["value"])
