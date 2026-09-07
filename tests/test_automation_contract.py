from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parents[1] / "contracts" / "automation" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
FORMAT_CHECKER = FormatChecker()


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]},
        format_checker=FORMAT_CHECKER,
    )


def fixtures(kind: str) -> list[Path]:
    return sorted((ROOT / "fixtures" / kind).glob("*.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("path", fixtures("accepted"), ids=lambda path: path.name)
def test_accepted_contract_fixtures(path: Path) -> None:
    case = load(path)
    validator(case["schema"]).validate(case["value"])


@pytest.mark.parametrize("path", fixtures("rejected"), ids=lambda path: path.name)
def test_rejected_contract_fixtures(path: Path) -> None:
    case = load(path)
    with pytest.raises(Exception) as caught:
        validator(case["schema"]).validate(case["value"])
    assert caught.type.__module__.startswith("jsonschema")


def test_contract_keeps_execution_authority_closed() -> None:
    policy = SCHEMA["$defs"]["executionPolicy"]["properties"]
    assert policy["network_access"] == {"const": False}
    assert policy["firewall_access"] == {"const": False}
    assert policy["capabilities"]["items"]["enum"] == [
        "observe_metadata",
        "read_local_fixture",
        "write_local_report",
    ]
    assert SCHEMA["$defs"]["runSnapshot"]["properties"]["requested_actions"]["maxItems"] == 0


def test_fixture_sets_are_nonempty() -> None:
    assert fixtures("accepted")
    assert fixtures("rejected")
