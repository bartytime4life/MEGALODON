from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "ubuntu_candidate_coverage.py"
SPEC = importlib.util.spec_from_file_location("ubuntu_candidate_coverage", TOOL_PATH)
assert SPEC and SPEC.loader
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
MANIFEST = json.loads(
    (
        ROOT
        / "contracts"
        / "release-evidence"
        / "v1"
        / "fixtures"
        / "accepted"
        / "synthetic-incomplete.json"
    ).read_text()
)
COMMIT = "1111111111111111111111111111111111111111"
TREE = "2222222222222222222222222222222222222222"


def initialized() -> dict:
    return TOOL.initialize(copy.deepcopy(MANIFEST), COMMIT, TREE)


def test_initializer_preserves_not_run_and_unavailable_states() -> None:
    index = initialized()
    assert index["status"] == "incomplete"
    assert all(row["status"] == "not_run" for row in index["checks"])
    assert all(row["status"] == "not_run" for row in index["artifacts"])
    assert all(row["health"] == "unavailable" for row in index["optional_components"])
    TOOL.validate(index, copy.deepcopy(MANIFEST), COMMIT, TREE)


def test_synthetic_fixture_cannot_be_promoted_complete() -> None:
    index = initialized()
    index["status"] = "complete"
    with pytest.raises(TOOL.CoverageError, match="SYNTHETIC_CANNOT_COMPLETE"):
        TOOL.validate(index, copy.deepcopy(MANIFEST), COMMIT, TREE)


def test_partial_evidence_pointer_is_rejected() -> None:
    index = initialized()
    index["checks"][0]["evidence"]["evidence_ref"] = "run:123"
    with pytest.raises(TOOL.CoverageError, match="EVIDENCE_POINTER"):
        TOOL.validate(index, copy.deepcopy(MANIFEST), COMMIT, TREE)


def test_index_cannot_relabel_optional_source_healthy() -> None:
    index = initialized()
    index["optional_components"][0]["health"] = "healthy"
    with pytest.raises(TOOL.CoverageError):
        TOOL.validate(index, copy.deepcopy(MANIFEST), COMMIT, TREE)


def test_independent_disposition_requires_independent_authentication() -> None:
    index = initialized()
    gate = index["gates"][-1]
    gate["status"] = "accepted"
    gate["evidence"] = {
        "evidence_ref": "review:example",
        "evidence_sha256": "sha256:" + "a" * 64,
        "authentication": "operator",
        "platform": "github",
    }
    with pytest.raises(
        TOOL.CoverageError, match="INDEPENDENT_AUTHENTICATION_REQUIRED"
    ):
        TOOL.validate(index, copy.deepcopy(MANIFEST), COMMIT, TREE)
