"""Offline proof for deterministic Ollama generate-request construction."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from megalodon.ollama_generate_contract import (
    FIXED_OPTIONS,
    GenerateContractError,
    MAX_REQUEST_BYTES,
    anomaly_format_schema,
    build_generate_request,
    canonical_json,
    parse_input_bytes,
    request_receipt,
)


ROOT = Path(__file__).parents[1]
FIXTURE = (
    ROOT
    / "contracts"
    / "ollama-generate-request"
    / "v1"
    / "fixtures"
    / "anomaly-synthetic.json"
)
SCHEMA = ROOT / "contracts" / "ollama-generate-request" / "v1" / "schema.json"


def anomaly_input() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def generic_input() -> dict:
    value = anomaly_input()
    value["mode"] = "generic_advisory"
    value["candidate_ids"] = []
    return value


def test_generic_request_has_exact_fixed_controls_and_no_format_or_tools():
    built = build_generate_request(generic_input())
    assert built.request == {
        "keep_alive": 0,
        "model": "local:qwen-approved-v1",
        "options": {
            "num_ctx": 4096,
            "num_predict": 512,
            "seed": 0,
            "temperature": 0,
        },
        "prompt": generic_input()["prompt"],
        "raw": True,
        "stream": False,
        "think": False,
    }
    assert "format" not in built.request
    assert "tools" not in built.request
    assert built.format_schema_sha256 is None
    assert len(built.request_bytes) <= MAX_REQUEST_BYTES


def test_anomaly_request_enforces_exact_candidate_bound_json_schema():
    built = build_generate_request(anomaly_input())
    request = built.request
    assert set(request) == {
        "format",
        "keep_alive",
        "model",
        "options",
        "prompt",
        "raw",
        "stream",
        "think",
    }
    assert request["options"] == FIXED_OPTIONS
    schema = request["format"]
    assert schema["additionalProperties"] is False
    assert schema["required"] == [
        "candidate_ids",
        "summary",
        "benign_alternatives",
        "missing_evidence",
    ]
    candidate_schema = schema["properties"]["candidate_ids"]
    assert candidate_schema == {
        "type": "array",
        "prefixItems": [{"const": "a01"}, {"const": "a02"}],
        "items": False,
        "minItems": 2,
        "maxItems": 2,
    }
    assert schema["properties"]["summary"]["maxLength"] == 600
    assert schema["properties"]["benign_alternatives"]["uniqueItems"] is True
    assert schema["properties"]["missing_evidence"]["uniqueItems"] is True
    assert built.format_schema_sha256 is not None


def test_receipt_omits_prompt_and_preserves_all_separate_holds():
    built = build_generate_request(anomaly_input())
    receipt = request_receipt(built)
    assert receipt["prompt_retained_in_receipt"] is False
    assert "prompt" not in receipt
    assert receipt["network_performed"] is False
    assert receipt["request_controls"] == {
        "keep_alive": 0,
        "raw": True,
        "stream": False,
        "think": False,
        "tools_present": False,
    }
    assert receipt["authority"] == {
        "contacts_provider": False,
        "starts_provider": False,
        "pulls_model": False,
        "changes_host": False,
        "authorizes_tools": False,
        "accepts_model": False,
        "authorizes_release": False,
    }
    assert "RUNTIME_PROVIDER_WIRING" in receipt["remaining_holds"]


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda value: value.__setitem__("extra", True), "INPUT_SHAPE"),
        (lambda value: value.__setitem__("schema", "v2"), "SCHEMA_MISMATCH"),
        (lambda value: value.__setitem__("mode", "chat"), "MODE"),
        (lambda value: value.__setitem__("model_id", "qwen2.5:7b"), "MODEL_ID"),
        (lambda value: value.__setitem__("prompt", ""), "PROMPT"),
        (lambda value: value.__setitem__("prompt", "ok\u202epwn"), "PROMPT"),
        (
            lambda value: value.__setitem__(
                "candidate_ids", ["a01", "a01"]
            ),
            "CANDIDATE_IDS",
        ),
    ],
)
def test_closed_input_and_policy_refusals(mutator, code):
    value = anomaly_input()
    mutator(value)
    with pytest.raises(GenerateContractError, match=code):
        build_generate_request(value)


def test_generic_forbids_candidate_ids():
    value = generic_input()
    value["candidate_ids"] = ["a01"]
    with pytest.raises(GenerateContractError, match="CANDIDATE_IDS_FORBIDDEN"):
        build_generate_request(value)


def test_anomaly_requires_candidate_ids():
    value = anomaly_input()
    value["candidate_ids"] = []
    with pytest.raises(GenerateContractError, match="CANDIDATE_IDS_REQUIRED"):
        build_generate_request(value)


def test_more_than_eight_candidate_ids_refuse():
    value = anomaly_input()
    value["candidate_ids"] = [f"a{index:02d}" for index in range(9)]
    with pytest.raises(GenerateContractError, match="CANDIDATE_IDS"):
        build_generate_request(value)


def test_prompt_byte_limit_is_utf8_aware():
    value = generic_input()
    value["prompt"] = "é" * 500
    build_generate_request(value)
    value["prompt"] = "é" * 2049
    with pytest.raises(GenerateContractError, match="PROMPT"):
        build_generate_request(value)


def test_final_request_size_fails_closed_after_json_escaping():
    value = anomaly_input()
    value["prompt"] = "\U0001f600" * 1024
    with pytest.raises(GenerateContractError, match="REQUEST_SIZE"):
        build_generate_request(value)


def test_request_hash_is_order_independent_and_mutation_sensitive():
    first = anomaly_input()
    reversed_value = dict(reversed(list(first.items())))
    one = build_generate_request(first)
    two = build_generate_request(reversed_value)
    assert one.request_sha256 == two.request_sha256
    changed = deepcopy(first)
    changed["candidate_ids"] = ["a01", "a03"]
    assert build_generate_request(changed).request_sha256 != one.request_sha256


def test_builder_owns_input_and_request_output():
    value = anomaly_input()
    original = deepcopy(value)
    built = build_generate_request(value)
    built.request["model"] = "changed"
    assert value == original
    assert build_generate_request(value).model_id == original["model_id"]


def test_schema_rejects_extra_response_fields():
    schema = anomaly_format_schema(("a01",))
    validator = Draft202012Validator(schema)
    valid = {
        "candidate_ids": ["a01"],
        "summary": "Bounded explanation.",
        "benign_alternatives": ["Routine administration."],
        "missing_evidence": ["Host ownership context."],
    }
    assert list(validator.iter_errors(valid)) == []
    invalid = dict(valid, action="block")
    assert list(validator.iter_errors(invalid))


def test_schema_rejects_candidate_reordering_or_substitution():
    schema = anomaly_format_schema(("a01", "a02"))
    validator = Draft202012Validator(schema)
    base = {
        "summary": "Bounded explanation.",
        "benign_alternatives": ["Routine administration."],
        "missing_evidence": ["Host ownership context."],
    }
    assert list(
        validator.iter_errors(dict(base, candidate_ids=["a01", "a02"]))
    ) == []
    assert list(
        validator.iter_errors(dict(base, candidate_ids=["a02", "a01"]))
    )
    assert list(
        validator.iter_errors(dict(base, candidate_ids=["a01", "a03"]))
    )


def test_duplicate_key_and_nonfinite_number_refuse():
    with pytest.raises(GenerateContractError, match="DUPLICATE_JSON_KEY"):
        parse_input_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(GenerateContractError, match="NON_FINITE_NUMBER"):
        parse_input_bytes(b'{"value":NaN}')


def test_cli_refusal_does_not_echo_path_or_prompt(tmp_path: Path):
    value = anomaly_input()
    value["model_id"] = "private.invalid/model"
    value["prompt"] = "private prompt must not be echoed"
    path = tmp_path / "private-request.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "tools/ollama_generate_contract.py", str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["error_code"] == "MODEL_ID"
    assert str(path) not in completed.stdout
    assert "private prompt" not in completed.stdout


def test_cli_success_emits_receipt_not_prompt(tmp_path: Path):
    value = anomaly_input()
    value["prompt"] = "private aggregate prompt"
    path = tmp_path / "request.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "tools/ollama_generate_contract.py", str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["state"] == "REQUEST_CONTRACT_VALIDATED"
    assert result["prompt_retained_in_receipt"] is False
    assert "private aggregate prompt" not in completed.stdout


def test_checked_in_schema_accepts_both_fixtures_and_runtime_validator_agrees():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    for name in ("generic-synthetic.json", "anomaly-synthetic.json"):
        fixture = json.loads((FIXTURE.parent / name).read_text(encoding="utf-8"))
        assert list(Draft202012Validator(schema).iter_errors(fixture)) == []
        build_generate_request(fixture)


def test_module_has_no_network_process_or_host_control_dependencies():
    source = (
        ROOT / "megalodon" / "ollama_generate_contract.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "http.client",
        "import urllib",
        "import requests",
        "os.system",
        "Popen",
        "systemctl",
        "ollama pull",
    ):
        assert forbidden not in source


def test_canonical_receipt_has_no_incidental_whitespace():
    rendered = canonical_json(
        request_receipt(build_generate_request(anomaly_input()))
    )
    assert "\n" not in rendered and ": " not in rendered
