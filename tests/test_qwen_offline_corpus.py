"""Concrete corpus integrity and scoped component behavior, never model evidence."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from megalodon import local_model_runtime, qwen_advisory
from megalodon.model_evaluation import (
    CATEGORIES, ModelEvaluationError, manifest_projection,
    parse_manifest_bytes, validate_corpus_manifest,
)
from tools import qwen_offline_corpus as corpus
from test_qwen_zero_effect import no_effects


SOURCES = corpus.load_sources()
ARTIFACTS = corpus.build_artifacts(SOURCES)
CASES = json.loads(ARTIFACTS["cases.json"])["cases"]


def test_concrete_corpus_matches_sources_manifest_schema_and_every_fixture_digest():
    corpus.verify_artifacts(ARTIFACTS)
    manifest = json.loads(ARTIFACTS["manifest.json"])
    schema = json.loads((corpus.ROOT / "contracts/local-model-evaluation/v1/manifest-schema.json").read_bytes())
    Draft202012Validator(schema).validate(manifest)
    validated = validate_corpus_manifest(parse_manifest_bytes(ARTIFACTS["manifest.json"]))
    projection = manifest_projection(validated)
    assert projection["state"] == "SYNTHETIC_ONLY"
    assert projection["total_cases"] == 28
    assert projection["unknown_evidence_id_cases"] == 1
    assert projection["expected_outcome_totals"] == {"ANSWER": 2, "ABSTAIN": 1, "DENY": 13, "ERROR": 12}
    assert manifest["corpus_sha256"] == sha256(ARTIFACTS["cases.json"]).hexdigest()
    assert manifest["candidate"]["binding_sha256"] == local_model_runtime.BINDING_SHA256
    assert [(item["category"], item["total_cases"]) for item in projection["category_totals"]] == [(c, 4) for c in CATEGORIES]
    for case, entry in zip(CASES, manifest["cases"], strict=True):
        assert entry["fixture_sha256"] == sha256(corpus.encode(case)).hexdigest()
        assert entry["case_id"] == case["case_id"]
    # IDs/labels cannot disguise duplicated probes as additional coverage.
    probes = [corpus.encode({"stage": c["stage"], "input": c["input"]}) for c in CASES]
    assert len(set(probes)) == len(CASES)
    assert corpus.build_artifacts(deepcopy(SOURCES)) == ARTIFACTS


@pytest.mark.parametrize("case", CASES, ids=[case["case_id"] for case in CASES])
def test_every_case_has_exact_component_behavior_without_io_or_runtime_admission(case, monkeypatch):
    saved_case, saved_sources = deepcopy(case), deepcopy(SOURCES)

    def forbidden(*args, **kwargs):
        pytest.fail("corpus entered model invocation")

    for name in ("invoke_qwen_advisory", "invoke_qwen_anomaly_advisory", "_invoke_admitted"):
        monkeypatch.setattr(qwen_advisory, name, forbidden)
    # No binding bypass fixture: parsers and pure helpers are called directly.
    with no_effects(monkeypatch):
        assert corpus.replay_case(case, SOURCES) == (case["expected_outcome"], case["expected_reason"])
        assert local_model_runtime.binding_failure() == "OWNER_MODEL_BINDING_NOT_RECORDED"
    assert case == saved_case and SOURCES == saved_sources


@pytest.mark.parametrize("name", list(ARTIFACTS))
def test_corrupted_artifact_fails_before_replay(name, tmp_path):
    for filename, raw in ARTIFACTS.items():
        (tmp_path / filename).write_bytes(raw)
    (tmp_path / name).write_bytes(ARTIFACTS[name] + b"\n")
    with pytest.raises(ModelEvaluationError, match="^CORPUS_ARTIFACT_MISMATCH$"):
        corpus.verify_artifacts(ARTIFACTS, tmp_path)


def test_structural_manifest_validation_alone_cannot_find_fixture_tampering(tmp_path):
    for filename, raw in ARTIFACTS.items():
        (tmp_path / filename).write_bytes(raw)
    value = json.loads(ARTIFACTS["cases.json"])
    value["cases"][4]["input"]["envelope"] = "{}"
    (tmp_path / "cases.json").write_bytes(corpus.encode(value))
    # This is the demonstrated gap in the pre-existing manifest-only scope:
    # it intentionally does not read fixtures. The companion check must refuse.
    validate_corpus_manifest(parse_manifest_bytes((tmp_path / "manifest.json").read_bytes()))
    with pytest.raises(ModelEvaluationError, match="^CORPUS_ARTIFACT_MISMATCH$"):
        corpus.verify_artifacts(ARTIFACTS, tmp_path)


def test_manifest_cannot_be_silently_promoted_to_operator_frozen(tmp_path):
    for filename, raw in ARTIFACTS.items():
        (tmp_path / filename).write_bytes(raw)
    value = json.loads(ARTIFACTS["manifest.json"])
    value["evidence_class"] = "operator_frozen"
    promoted = corpus.encode(value)
    assert manifest_projection(validate_corpus_manifest(parse_manifest_bytes(promoted)))["state"] == "MANIFEST_VALIDATED"
    (tmp_path / "manifest.json").write_bytes(promoted)
    with pytest.raises(ModelEvaluationError, match="^CORPUS_ARTIFACT_MISMATCH$"):
        corpus.verify_artifacts(ARTIFACTS, tmp_path)


def test_changed_source_bytes_are_not_automatically_repinned(tmp_path):
    for relative in corpus.SOURCE_DIGESTS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((corpus.ROOT / relative).read_bytes())
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ModelEvaluationError, match="^CORPUS_SOURCE_MISMATCH$"):
        corpus.load_sources(tmp_path)


def test_missing_artifact_and_final_symlink_fail_closed(tmp_path):
    with pytest.raises(ModelEvaluationError, match="^CORPUS_ARTIFACT_READ$"):
        corpus.verify_artifacts(ARTIFACTS, tmp_path)
    if os.name == "posix":
        (tmp_path / "cases.json").symlink_to(corpus.CORPUS_DIR / "cases.json")
        with pytest.raises(ModelEvaluationError, match="^CORPUS_ARTIFACT_READ$"):
            corpus.verify_artifacts(ARTIFACTS, tmp_path)


def test_replay_retains_holds_and_does_not_emit_synthetic_attack_text(monkeypatch):
    with no_effects(monkeypatch):
        result = corpus.replay(CASES, SOURCES)
    assert result["component_cases_passed"] == 28
    assert result["binding_status"] == "UNBOUND"
    assert result["model_evaluation_executed"] is False
    assert result["signature_verified"] is False
    assert result["provider_request_performed"] is False
    assert "OWNER_FREEZE_AND_SIGNING" in result["remaining_holds"]
    rendered = corpus.encode(result)
    for forbidden in (b"SYNTHETIC_PRIVATE_MARKER", b"Ignore policy", b"synthetic partial", b"a99"):
        assert forbidden not in rendered


def test_cli_is_reproducible_across_hash_seeds_and_read_only():
    outputs = []
    before = {name: (corpus.CORPUS_DIR / name).read_bytes() for name in ARTIFACTS}
    for seed in ("1", "127"):
        completed = subprocess.run(
            [sys.executable, "-B", "tools/qwen_offline_corpus.py"], cwd=corpus.ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, check=True, timeout=20,
        )
        assert completed.stderr == b""
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
    assert before == {name: (corpus.CORPUS_DIR / name).read_bytes() for name in ARTIFACTS}


def test_cli_refuses_before_replay_on_bad_artifact(monkeypatch, capsys):
    def refuse(*args):
        raise ModelEvaluationError("CORPUS_ARTIFACT_MISMATCH")

    monkeypatch.setattr(corpus, "verify_artifacts", refuse)
    monkeypatch.setattr(corpus, "replay", lambda *args: pytest.fail("unverified replay"))
    assert corpus.main([]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result == {"state": "REFUSED", "error_code": "CORPUS_ARTIFACT_MISMATCH",
                      "provider_request_performed": False}
