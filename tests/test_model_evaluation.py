"""Offline proof for signature-bound Qwen evaluation receipts."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from megalodon.model_evaluation import (
    CATEGORIES,
    EFFECT_IDS,
    ModelEvaluationError,
    canonical_json,
    evaluation_projection,
    parse_receipt_bytes,
    validate_evaluation_receipt,
)

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "contracts" / "local-model-evaluation" / "v1" / "fixtures" / "accepted-synthetic.json"
SCHEMA = ROOT / "contracts" / "local-model-evaluation" / "v1" / "schema.json"


def receipt() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def operator_receipt() -> dict:
    value = receipt()
    value["evidence_class"] = "operator_observed"
    value["corpus"]["signature"]["externally_verified"] = True
    return value


def test_synthetic_receipt_stays_synthetic_and_non_authoritative():
    projection = evaluation_projection(validate_evaluation_receipt(receipt()))
    assert projection["state"] == "SYNTHETIC_ONLY"
    assert projection["hard_gate_passed"] is True
    assert projection["raw_prompts_retained"] is False
    assert projection["raw_advisory_text_retained"] is False
    assert projection["authority"] == {
        "verifies_signature_cryptographically": False,
        "contacts_provider": False,
        "starts_provider": False,
        "pulls_model": False,
        "changes_host": False,
        "accepts_model": False,
        "authorizes_release": False,
    }


def test_complete_operator_receipt_is_validated_not_accepted():
    projection = evaluation_projection(validate_evaluation_receipt(operator_receipt()))
    assert projection["state"] == "EVALUATION_RECEIPT_VALIDATED"
    assert projection["hard_gate_passed"] is True
    assert "OWNER_MODEL_BINDING" in projection["remaining_holds"]
    assert projection["authority"]["accepts_model"] is False


def test_unverified_operator_signature_is_named_hold():
    value = operator_receipt()
    value["corpus"]["signature"]["externally_verified"] = False
    validated = validate_evaluation_receipt(value)
    assert validated["hard_gate_passed"] is False
    assert validated["gate_failures"] == ("CORPUS_SIGNATURE_NOT_EXTERNALLY_VERIFIED",)
    assert evaluation_projection(validated)["state"] == "EVALUATION_HOLD"


def test_partial_evaluation_is_named_hold():
    value = operator_receipt()
    value["execution"]["completed_cases"] = 6
    value["execution"]["outcome_counts"]["ANSWER"] = 1
    value["execution"]["category_results"][-1]["passed_cases"] = 0
    for accounting in value["execution"]["prohibited_effects"].values():
        accounting["total_cases"] = 6
    assert "EVALUATION_INCOMPLETE" in validate_evaluation_receipt(value)["gate_failures"]


def test_case_failure_is_named_hold():
    value = operator_receipt()
    first = value["execution"]["category_results"][0]
    first["passed_cases"] = 0
    first["failed_cases"] = 1
    assert "CASE_FAILURES_RECORDED" in validate_evaluation_receipt(value)["gate_failures"]


def test_unknown_evidence_id_rejection_is_hard_gate():
    value = operator_receipt()
    value["execution"]["unknown_evidence_id_rejected"] = 0
    assert "UNKNOWN_EVIDENCE_ID_REJECTION_INCOMPLETE" in validate_evaluation_receipt(value)["gate_failures"]


def test_outcome_distinction_is_hard_gate():
    value = operator_receipt()
    value["execution"]["answer_abstain_error_distinct"] = False
    assert "OUTCOME_DISTINCTION_NOT_PROVED" in validate_evaluation_receipt(value)["gate_failures"]


@pytest.mark.parametrize("effect", EFFECT_IDS)
def test_each_prohibited_effect_is_a_hard_gate(effect: str):
    value = operator_receipt()
    value["execution"]["prohibited_effects"][effect]["observed_count"] = 1
    assert "PROHIBITED_EFFECT_OBSERVED" in validate_evaluation_receipt(value)["gate_failures"]


def test_categories_are_exact_and_ordered():
    value = receipt()
    value["corpus"]["categories"] = list(reversed(CATEGORIES))
    with pytest.raises(ModelEvaluationError, match="CORPUS_CATEGORIES"):
        validate_evaluation_receipt(value)


def test_category_result_identity_is_exact_and_ordered():
    value = receipt()
    value["execution"]["category_results"][0]["category"] = "privacy"
    with pytest.raises(ModelEvaluationError, match="CATEGORY_RESULTS"):
        validate_evaluation_receipt(value)


def test_outcome_accounting_must_equal_completed_cases():
    value = receipt()
    value["execution"]["outcome_counts"]["ANSWER"] = 3
    with pytest.raises(ModelEvaluationError, match="OUTCOME_ACCOUNTING"):
        validate_evaluation_receipt(value)


def test_category_accounting_must_equal_total_and_completed():
    value = receipt()
    value["execution"]["category_results"][0]["total_cases"] = 2
    with pytest.raises(ModelEvaluationError, match="CATEGORY_ACCOUNTING"):
        validate_evaluation_receipt(value)


def test_effect_accounting_uses_every_completed_case():
    value = receipt()
    value["execution"]["prohibited_effects"][EFFECT_IDS[0]]["total_cases"] = 6
    with pytest.raises(ModelEvaluationError, match="EFFECT_ACCOUNTING"):
        validate_evaluation_receipt(value)


def test_raw_advisory_retention_refuses_structurally():
    value = receipt()
    value["execution"]["raw_advisory_text_retained"] = True
    with pytest.raises(ModelEvaluationError, match="RAW_TEXT_RETENTION"):
        validate_evaluation_receipt(value)


def test_duplicate_key_and_nonfinite_number_refuse():
    with pytest.raises(ModelEvaluationError, match="DUPLICATE_JSON_KEY"):
        parse_receipt_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ModelEvaluationError, match="NON_FINITE_NUMBER"):
        parse_receipt_bytes(b'{"value":NaN}')


def test_time_order_refuses():
    value = receipt()
    value["execution"]["completed_at"] = "2025-12-31T23:59:59Z"
    with pytest.raises(ModelEvaluationError, match="TIME_ORDER"):
        validate_evaluation_receipt(value)


def test_validation_owns_input_and_hash_is_order_independent():
    first = receipt()
    original = deepcopy(first)
    reversed_value = dict(reversed(list(first.items())))
    one = validate_evaluation_receipt(first)
    two = validate_evaluation_receipt(reversed_value)
    assert first == original
    assert one["receipt_sha256"] == two["receipt_sha256"]
    one["value"]["profile_sha256"] = "changed"
    assert first == original


def test_profile_or_corpus_change_changes_evaluation_boundary():
    first = receipt()
    second = receipt()
    second["corpus"]["corpus_sha256"] = "8" * 64
    assert validate_evaluation_receipt(first)["evaluation_boundary_sha256"] != validate_evaluation_receipt(second)["evaluation_boundary_sha256"]


def test_cli_refusal_does_not_echo_path_or_input(tmp_path: Path):
    value = receipt()
    value["corpus"]["categories"] = ["private-invalid-category"]
    path = tmp_path / "private-evaluation.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    completed = subprocess.run([sys.executable, "tools/qwen_evaluation_receipt.py", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["error_code"] == "CORPUS_CATEGORIES"
    assert str(path) not in completed.stdout
    assert "private-invalid-category" not in completed.stdout


def test_cli_projection_contains_no_raw_prompt_or_advisory_text(tmp_path: Path):
    path = tmp_path / "evaluation.json"
    path.write_text(json.dumps(receipt()), encoding="utf-8")
    completed = subprocess.run([sys.executable, "tools/qwen_evaluation_receipt.py", str(path)], cwd=ROOT, text=True, capture_output=True, check=False)
    assert completed.returncode == 0
    projection = json.loads(completed.stdout)
    assert projection["raw_prompts_retained"] is False
    assert projection["raw_advisory_text_retained"] is False
    assert '"prompt":' not in completed.stdout.lower()
    assert '"summary":' not in completed.stdout.lower()


def test_schema_accepts_fixture_and_runtime_validator_agrees():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    fixture = receipt()
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(fixture)) == []
    validate_evaluation_receipt(fixture)


def test_module_has_no_network_process_or_signature_dependencies():
    source = (ROOT / "megalodon" / "model_evaluation.py").read_text(encoding="utf-8")
    for forbidden in ("import socket", "import subprocess", "urllib", "requests", "http.client", "cryptography", "gnupg", "Popen"):
        assert forbidden not in source


def test_canonical_output_has_no_incidental_whitespace():
    rendered = canonical_json(evaluation_projection(validate_evaluation_receipt(receipt())))
    assert "\n" not in rendered and ": " not in rendered
