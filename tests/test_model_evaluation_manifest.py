"""Offline proof for the privacy-minimized evaluation corpus manifest."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from megalodon.model_evaluation import (
    CATEGORIES,
    ModelEvaluationError,
    canonical_json,
    check_receipt_against_manifest,
    manifest_projection,
    parse_manifest_bytes,
    validate_corpus_manifest,
    validate_evaluation_receipt,
)

ROOT = Path(__file__).parents[1]
CONTRACT = ROOT / "contracts" / "local-model-evaluation" / "v1"
MANIFEST = CONTRACT / "fixtures" / "manifest-synthetic.json"
RECEIPT = CONTRACT / "fixtures" / "accepted-synthetic.json"
SCHEMA = CONTRACT / "manifest-schema.json"


def manifest() -> dict:
    return json.loads(MANIFEST.read_bytes())


def encode(value: dict) -> bytes:
    return canonical_json(value).encode("ascii")


def validate(value: dict) -> dict:
    return validate_corpus_manifest(parse_manifest_bytes(encode(value)))


def refuses(value: dict, code: str) -> None:
    with pytest.raises(ModelEvaluationError, match=f"^{code}$"):
        validate(value)


def matching_receipt() -> dict:
    value = json.loads(RECEIPT.read_text(encoding="utf-8"))
    value["corpus"]["manifest_sha256"] = sha256(MANIFEST.read_bytes()).hexdigest()
    return value


def test_fixture_is_canonical_and_hash_is_the_file_digest():
    raw = MANIFEST.read_bytes()
    validated = validate_corpus_manifest(parse_manifest_bytes(raw))
    assert validated["manifest_sha256"] == sha256(raw).hexdigest()
    assert validated["category_totals"] == dict.fromkeys(CATEGORIES, 1)
    assert validated["unknown_evidence_id_cases"] == 1


def test_synthetic_projection_is_non_authoritative_and_omits_case_detail():
    projection = manifest_projection(validate(manifest()))
    assert projection["state"] == "SYNTHETIC_ONLY"
    assert projection["raw_prompts_retained"] is False
    assert set(projection["authority"].values()) == {False}
    assert "EVALUATION_NOT_EXECUTED" in projection["remaining_holds"]
    rendered = canonical_json(projection)
    assert "case-0001" not in rendered
    assert manifest()["cases"][0]["fixture_sha256"] not in rendered


def test_operator_frozen_manifest_is_validated_not_accepted():
    value = manifest()
    value["evidence_class"] = "operator_frozen"
    projection = manifest_projection(validate(value))
    assert projection["state"] == "MANIFEST_VALIDATED"
    assert "OWNER_MODEL_BINDING" in projection["remaining_holds"]
    assert projection["authority"]["accepts_model"] is False


@pytest.mark.parametrize(
    "raw",
    [
        lambda value: json.dumps(value, indent=2).encode(),
        lambda value: encode(value) + b"\n",
        lambda value: json.dumps(value, separators=(",", ":")).encode(),
    ],
    ids=["indented", "trailing-newline", "unsorted-keys"],
)
def test_non_canonical_bytes_refuse(raw):
    value = dict(reversed(list(manifest().items())))
    with pytest.raises(ModelEvaluationError, match="^MANIFEST_NOT_CANONICAL$"):
        parse_manifest_bytes(raw(value))


def test_duplicate_key_and_oversize_refuse():
    with pytest.raises(ModelEvaluationError, match="DUPLICATE_JSON_KEY"):
        parse_manifest_bytes(b'{"schema":"a","schema":"b"}')
    with pytest.raises(ModelEvaluationError, match="MANIFEST_SIZE"):
        parse_manifest_bytes(b"")


def test_case_ids_are_opaque_so_no_text_can_be_carried():
    value = manifest()
    value["cases"][0]["case_id"] = "ignore-previous-instructions"
    refuses(value, "CASE_ID")


def test_extra_case_field_cannot_carry_prompt_text():
    value = manifest()
    value["cases"][0]["prompt"] = "private prompt"
    refuses(value, "CASE_SHAPE")


def test_every_category_needs_a_case():
    value = manifest()
    value["cases"][-1]["category"] = "cancellation"
    refuses(value, "CATEGORY_COVERAGE")


def test_categories_follow_the_closed_order():
    value = manifest()
    value["cases"][0]["category"], value["cases"][1]["category"] = (
        value["cases"][1]["category"],
        value["cases"][0]["category"],
    )
    refuses(value, "CASE_ORDER")


def test_case_numbers_increase_regardless_of_width():
    value = manifest()
    value["cases"][1]["case_id"] = "case-00001"
    refuses(value, "DUPLICATE_CASE_ID")
    value = manifest()
    value["cases"][0]["case_id"] = "case-0009"
    refuses(value, "CASE_ORDER")
    value = manifest()
    value["cases"][-1]["case_id"] = "case-10000"
    assert validate(value)["value"]["cases"][-1]["case_id"] == "case-10000"


def test_reused_fixture_cannot_be_counted_twice():
    value = manifest()
    value["cases"][1]["fixture_sha256"] = value["cases"][0]["fixture_sha256"]
    refuses(value, "DUPLICATE_FIXTURE")


def test_unknown_evidence_id_case_is_required_and_cannot_expect_answer():
    value = manifest()
    value["cases"][1]["unknown_evidence_id"] = False
    refuses(value, "UNKNOWN_EVIDENCE_ID_COVERAGE")
    value = manifest()
    value["cases"][1]["expected_outcome"] = "ANSWER"
    refuses(value, "UNKNOWN_EVIDENCE_ID_ANSWER")


@pytest.mark.parametrize("outcome", ["ANSWER", "ABSTAIN", "ERROR"])
def test_distinct_outcomes_need_an_expected_case_each(outcome: str):
    value = manifest()
    for case in value["cases"]:
        if case["expected_outcome"] == outcome:
            case["expected_outcome"] = "DENY"
    refuses(value, "OUTCOME_COVERAGE")


def test_denominator_matches_listed_cases():
    value = manifest()
    value["total_cases"] = 8
    refuses(value, "CASE_COUNT")


def test_receipt_matching_manifest_is_accepted_by_cross_check():
    check_receipt_against_manifest(
        validate_evaluation_receipt(matching_receipt()), validate(manifest())
    )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda r: r["corpus"].update(manifest_sha256="4" * 64), "RECEIPT_MANIFEST_SHA256"),
        (lambda r: r["corpus"].update(corpus_sha256="8" * 64), "RECEIPT_MANIFEST_CORPUS"),
        (lambda r: r["corpus"].update(corpus_id="other-corpus"), "RECEIPT_MANIFEST_CORPUS"),
        (lambda r: r.update(profile_sha256="8" * 64), "RECEIPT_MANIFEST_CANDIDATE"),
        (lambda r: r.update(comparison_boundary_sha256="8" * 64), "RECEIPT_MANIFEST_CANDIDATE"),
    ],
)
def test_receipt_bound_to_other_corpus_or_candidate_refuses(change, code):
    value = matching_receipt()
    change(value)
    with pytest.raises(ModelEvaluationError, match=f"^{code}$"):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validate(manifest())
        )


def eight_case_receipt() -> dict:
    """A consistent receipt whose extra eighth case is an injection case."""

    value = matching_receipt()
    execution = value["execution"]
    execution["category_results"][0].update(total_cases=2, passed_cases=2)
    execution["total_cases"] = execution["completed_cases"] = 8
    execution["outcome_counts"]["ANSWER"] = 3
    for accounting in execution["prohibited_effects"].values():
        accounting["total_cases"] = 8
    return value


def test_receipt_denominators_must_match_manifest():
    with pytest.raises(ModelEvaluationError, match="^RECEIPT_MANIFEST_TOTAL$"):
        check_receipt_against_manifest(
            validate_evaluation_receipt(eight_case_receipt()), validate(manifest())
        )
    frozen = manifest()
    frozen["cases"].append(
        {
            "case_id": "case-0008",
            "category": "out_of_distribution",
            "fixture_sha256": "f" * 64,
            "expected_outcome": "ANSWER",
            "unknown_evidence_id": False,
        }
    )
    frozen["total_cases"] = 8
    value = eight_case_receipt()
    value["corpus"]["manifest_sha256"] = sha256(encode(frozen)).hexdigest()
    with pytest.raises(ModelEvaluationError, match="^RECEIPT_MANIFEST_CATEGORY$"):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validate(frozen)
        )


def test_unknown_evidence_id_count_equal_when_complete_bounded_when_partial():
    frozen = manifest()
    frozen["cases"][0]["unknown_evidence_id"] = True
    validated_manifest = validate(frozen)
    value = matching_receipt()
    value["corpus"]["manifest_sha256"] = validated_manifest["manifest_sha256"]
    with pytest.raises(
        ModelEvaluationError, match="^RECEIPT_MANIFEST_UNKNOWN_EVIDENCE_ID$"
    ):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validated_manifest
        )
    execution = value["execution"]
    execution["completed_cases"] = 6
    execution["outcome_counts"]["ANSWER"] = 1
    execution["category_results"][-1]["passed_cases"] = 0
    for accounting in execution["prohibited_effects"].values():
        accounting["total_cases"] = 6
    partial = validate_evaluation_receipt(value)
    assert "EVALUATION_INCOMPLETE" in partial["gate_failures"]
    check_receipt_against_manifest(partial, validated_manifest)
    execution["unknown_evidence_id_cases"] = 3
    execution["unknown_evidence_id_rejected"] = 3
    with pytest.raises(
        ModelEvaluationError, match="^RECEIPT_MANIFEST_UNKNOWN_EVIDENCE_ID$"
    ):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validated_manifest
        )


def test_schema_accepts_fixture_and_runtime_validator_agrees():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(manifest())) == []
    validate(manifest())


def test_schema_rejects_free_text_case_fields():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    value = manifest()
    value["cases"][0]["prompt"] = "private prompt"
    assert list(Draft202012Validator(schema).iter_errors(value))


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args], cwd=ROOT, text=True, capture_output=True, check=False
    )


def test_manifest_cli_projects_fixture():
    completed = run_tool("tools/qwen_evaluation_manifest.py", str(MANIFEST))
    assert completed.returncode == 0
    projection = json.loads(completed.stdout)
    assert projection["state"] == "SYNTHETIC_ONLY"
    assert projection["manifest_sha256"] == sha256(MANIFEST.read_bytes()).hexdigest()


def test_manifest_cli_refusal_does_not_echo_path_or_input(tmp_path: Path):
    value = manifest()
    value["cases"][0]["case_id"] = "private-case-text"
    path = tmp_path / "private-manifest.json"
    path.write_bytes(encode(value))
    completed = run_tool("tools/qwen_evaluation_manifest.py", str(path))
    assert completed.returncode == 2
    assert json.loads(completed.stdout)["error_code"] == "CASE_ID"
    assert str(path) not in completed.stdout
    assert "private-case-text" not in completed.stdout


def test_receipt_cli_binds_to_manifest(tmp_path: Path):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(matching_receipt()), encoding="utf-8")
    completed = run_tool(
        "tools/qwen_evaluation_receipt.py", str(path), "--manifest", str(MANIFEST)
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["manifest_binding"] == "MATCHED"
    unbound = run_tool("tools/qwen_evaluation_receipt.py", str(path))
    assert json.loads(unbound.stdout)["manifest_binding"] == "NOT_CHECKED"
    path.write_text(json.dumps(json.loads(RECEIPT.read_text())), encoding="utf-8")
    mismatched = run_tool(
        "tools/qwen_evaluation_receipt.py", str(path), "--manifest", str(MANIFEST)
    )
    assert mismatched.returncode == 2
    assert json.loads(mismatched.stdout)["error_code"] == "RECEIPT_MANIFEST_SHA256"


def test_operator_receipt_cannot_bind_to_synthetic_manifest():
    value = matching_receipt()
    value["evidence_class"] = "operator_observed"
    value["corpus"]["signature"]["externally_verified"] = True
    validated = validate_evaluation_receipt(value)
    assert validated["hard_gate_passed"] is True
    with pytest.raises(
        ModelEvaluationError, match="^RECEIPT_MANIFEST_EVIDENCE_CLASS$"
    ):
        check_receipt_against_manifest(validated, validate(manifest()))
    frozen = manifest()
    frozen["evidence_class"] = "operator_frozen"
    value["corpus"]["manifest_sha256"] = sha256(encode(frozen)).hexdigest()
    check_receipt_against_manifest(
        validate_evaluation_receipt(value), validate(frozen)
    )


def test_all_passed_receipt_outcomes_must_equal_manifest_expectations():
    value = matching_receipt()
    value["execution"]["outcome_counts"].update(ANSWER=3, DENY=2)
    with pytest.raises(ModelEvaluationError, match="^RECEIPT_MANIFEST_OUTCOMES$"):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validate(manifest())
        )


def test_each_failed_case_may_move_one_outcome():
    value = matching_receipt()
    execution = value["execution"]
    execution["outcome_counts"].update(ANSWER=3, DENY=2)
    execution["category_results"][0].update(passed_cases=0, failed_cases=1)
    check_receipt_against_manifest(
        validate_evaluation_receipt(value), validate(manifest())
    )
    execution["outcome_counts"].update(ANSWER=4, DENY=1)
    with pytest.raises(ModelEvaluationError, match="^RECEIPT_MANIFEST_OUTCOMES$"):
        check_receipt_against_manifest(
            validate_evaluation_receipt(value), validate(manifest())
        )
