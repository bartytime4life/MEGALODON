from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "security_scan_receipt.py"
SPEC = importlib.util.spec_from_file_location("security_scan_receipt", TOOL_PATH)
assert SPEC and SPEC.loader
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)
FIXTURE = json.loads(
    (ROOT / "tests" / "fixtures" / "security_scan_receipt" / "valid.json").read_text()
)
COMMIT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TREE = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def test_valid_receipt_binds_exact_subject() -> None:
    assert TOOL.validate(copy.deepcopy(FIXTURE), expected_commit=COMMIT, expected_tree=TREE)


def test_other_commit_is_rejected() -> None:
    with pytest.raises(TOOL.ReceiptError, match="COMMIT_MISMATCH"):
        TOOL.validate(
            copy.deepcopy(FIXTURE),
            expected_commit="f" * 40,
            expected_tree=TREE,
        )


def test_summary_must_match_findings() -> None:
    candidate = copy.deepcopy(FIXTURE)
    candidate["summary"]["medium"] = 0
    with pytest.raises(TOOL.ReceiptError, match="SUMMARY_MISMATCH"):
        TOOL.validate(candidate)


def test_suppression_requires_reason_and_future_expiry() -> None:
    candidate = copy.deepcopy(FIXTURE)
    finding = candidate["findings"][0]
    finding["status"] = "suppressed"
    candidate["summary"]["suppressed"] = 1
    with pytest.raises(TOOL.ReceiptError, match="SUPPRESSION_INCOMPLETE"):
        TOOL.validate(candidate)


def test_scanner_cannot_grant_merge_authority() -> None:
    candidate = copy.deepcopy(FIXTURE)
    candidate["authority"]["merge_authority"] = True
    with pytest.raises(TOOL.ReceiptError, match="SCHEMA_INVALID"):
        TOOL.validate(candidate)
