"""Static external-exchange contract tests; no parser, sender, or executor."""

from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).parents[1] / "contracts" / "external-exchange" / "v1"
SCHEMA = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
ACCEPTED = json.loads(
    (ROOT / "fixtures" / "accepted" / "static-plan.json").read_text(encoding="utf-8")
)


def rejected() -> list[Path]:
    return sorted((ROOT / "fixtures" / "rejected").glob("*.json"))


def lane(value: dict[str, object], lane_id: str) -> dict[str, object]:
    return next(item for item in value["lanes"] if item["lane"] == lane_id)


def test_schema_and_static_plan_are_valid() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    Draft202012Validator(SCHEMA).validate(ACCEPTED)
    assert [item["lane"] for item in ACCEPTED["lanes"]] == [
        "threat-context-import",
        "siem-export",
        "soar-handoff",
    ]


def test_schema_requires_exactly_one_object_per_lane() -> None:
    validator = Draft202012Validator(SCHEMA)

    for missing_index, digest_character in ((1, "2"), (2, "3")):
        candidate = deepcopy(ACCEPTED)
        duplicate = deepcopy(candidate["lanes"][0])
        duplicate["artifact_digest"] = "sha256:" + digest_character * 64
        candidate["lanes"][missing_index] = duplicate

        with pytest.raises(Exception) as caught:
            validator.validate(candidate)
        assert caught.type.__module__.startswith("jsonschema")


@pytest.mark.parametrize("path", rejected(), ids=lambda path: path.stem)
def test_rejected_capability_escalations_fail_closed(path: Path) -> None:
    case = json.loads(path.read_text(encoding="utf-8"))
    candidate = deepcopy(ACCEPTED)
    patch = case["patch"]
    lane(candidate, patch["lane"]).update({key: value for key, value in patch.items() if key != "lane"})
    with pytest.raises(Exception) as caught:
        Draft202012Validator(SCHEMA).validate(candidate)
    assert caught.type.__module__.startswith("jsonschema")


def test_threat_context_is_offline_bounded_and_non_authoritative() -> None:
    value = lane(ACCEPTED, "threat-context-import")
    assert value["input_mode"] == "operator_supplied_completed_file"
    assert value["max_bundle_bytes"] == 16 * 1024 * 1024
    assert value["max_objects"] == 4096
    assert value["runtime_fetch"] is value["taxii"] is False
    assert value["pattern_handling"] == "store_as_untrusted_text_never_execute"
    assert value["attribution_authority"] is False
    assert value["action_authority"] == "none"


def test_siem_and_soar_paths_cannot_deliver_or_act() -> None:
    siem = lane(ACCEPTED, "siem-export")
    assert siem["profiles"] == ["ecs-9.5.0", "ocsf-1.9.0"]
    assert siem["output_mode"] == "new_local_file_only"
    assert siem["include_event_original"] is siem["include_payload"] is False
    assert siem["network_delivery"] is siem["credentials"] is False
    soar = lane(ACCEPTED, "soar-handoff")
    assert soar["destination_class"] == "not_configured"
    assert soar["max_attempts"] == 0
    assert soar["status"] == "not_attempted"
    assert not any(soar[key] for key in ("endpoint", "credentials", "network_delivery", "host_action", "automation"))


def test_contract_test_has_no_runtime_import() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(name == "megalodon" or name.startswith("megalodon.") for name in imported)
