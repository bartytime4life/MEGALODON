"""Offline proof for Ollama identity observations. No provider is contacted."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from megalodon.ollama_identity import (
    OllamaIdentityError,
    canonical_json,
    identity_receipt,
    parse_observation_bytes,
    validate_observation,
)

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "contracts" / "ollama-model-identity" / "v1" / "fixtures" / "accepted-synthetic.json"
SCHEMA = ROOT / "contracts" / "ollama-model-identity" / "v1" / "schema.json"


def observation() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_synthetic_observation_stays_synthetic_and_non_authoritative():
    receipt = identity_receipt(validate_observation(observation()))
    assert receipt["state"] == "SYNTHETIC_ONLY"
    assert receipt["authority"] == {
        "contacts_provider": False,
        "starts_provider": False,
        "pulls_model": False,
        "changes_host": False,
        "attests_loaded_bytes": False,
        "approves_binding": False,
        "authorizes_release": False,
    }
    assert "LOADED_RUNTIME_BYTES_NOT_ATTESTED" in receipt["remaining_holds"]
    assert len(receipt["provider_identity_sha256"]) == 64


def test_operator_observation_is_validated_but_not_accepted():
    value = observation()
    value["evidence_class"] = "operator_observed"
    receipt = identity_receipt(validate_observation(value))
    assert receipt["state"] == "IDENTITY_OBSERVATION_VALIDATED"
    assert "OWNER_MODEL_BINDING" in receipt["remaining_holds"]
    assert receipt["authority"]["approves_binding"] is False


def test_capability_listing_can_record_tools_without_granting_tools():
    value = observation()
    value["show"]["capabilities"].append("tools")
    receipt = identity_receipt(validate_observation(value))
    assert receipt["capability_observation"] == {
        "listed": ["completion", "tools"],
        "tools_capability_present": True,
        "tools_used_or_authorized": False,
    }


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda value: value.__setitem__("endpoint", "http://localhost:11434"), "ENDPOINT"),
        (lambda value: value.__setitem__("binding_alias", "qwen2.5:7b"), "BINDING_ALIAS"),
        (lambda value: value["tags"].__setitem__("matched_name", "qwen2.5:14b"), "TAG_IDENTITY"),
        (lambda value: value["show"].__setitem__("request_model", "qwen2.5:14b"), "SHOW_MODEL"),
        (lambda value: value["show"]["details"].__setitem__("quantization_level", "Q4_K_M"), "DETAILS_MISMATCH"),
        (lambda value: value["show"].__setitem__("capabilities", ["tools"]), "COMPLETION_CAPABILITY_REQUIRED"),
        (lambda value: value["tags"]["details"].__setitem__("family", "llama"), "MODEL_FAMILY"),
        (lambda value: value["version"].__setitem__("extra", "x"), "VERSION_SHAPE"),
    ],
)
def test_identity_substitution_and_shape_refusals(mutator, code):
    value = observation()
    mutator(value)
    with pytest.raises(OllamaIdentityError, match=code):
        validate_observation(value)


def test_duplicate_key_and_nonfinite_number_refuse():
    with pytest.raises(OllamaIdentityError, match="DUPLICATE_JSON_KEY"):
        parse_observation_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(OllamaIdentityError, match="NON_FINITE_NUMBER"):
        parse_observation_bytes(b'{"value":NaN}')


def test_invalid_timestamp_refuses():
    value = observation()
    value["observed_at"] = "2026-02-30T00:00:00Z"
    with pytest.raises(OllamaIdentityError, match="OBSERVED_AT"):
        validate_observation(value)


def test_validation_owns_input_and_hash_is_order_independent():
    first = observation()
    original = deepcopy(first)
    reversed_value = dict(reversed(list(first.items())))
    one = validate_observation(first)
    two = validate_observation(reversed_value)
    assert first == original
    assert one["observation_sha256"] == two["observation_sha256"]
    one["value"]["model_tag"] = "changed"
    assert first == original


def test_manifest_or_binary_change_changes_provider_identity():
    first = observation()
    second = observation()
    second["tags"]["manifest_sha256"] = "c" * 64
    assert validate_observation(first)["provider_identity_sha256"] != validate_observation(second)["provider_identity_sha256"]


def test_cli_refusal_does_not_echo_path_or_input(tmp_path: Path):
    value = observation()
    value["endpoint"] = "https://example.invalid/private"
    path = tmp_path / "identity-private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    completed = subprocess.run([sys.executable, "tools/ollama_identity_lab.py", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["error_code"] == "ENDPOINT"
    assert str(path) not in completed.stdout
    assert "example.invalid" not in completed.stdout


def test_cli_success_projects_no_raw_template_or_license(tmp_path: Path):
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(observation()), encoding="utf-8")
    completed = subprocess.run([sys.executable, "tools/ollama_identity_lab.py", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["state"] == "SYNTHETIC_ONLY"
    rendered = completed.stdout.lower()
    assert "template_sha256" not in rendered
    assert "license_sha256" not in rendered


def test_schema_accepts_fixture_and_runtime_validator_agrees():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    fixture = observation()
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(fixture)) == []
    validate_observation(fixture)


def test_module_has_no_network_or_process_dependencies():
    source = (ROOT / "megalodon" / "ollama_identity.py").read_text(encoding="utf-8")
    for forbidden in ("import socket", "import subprocess", "urllib", "requests", "http.client", "os.system", "Popen"):
        assert forbidden not in source


def test_canonical_output_has_no_incidental_whitespace():
    rendered = canonical_json(identity_receipt(validate_observation(observation())))
    assert "\n" not in rendered and ": " not in rendered
