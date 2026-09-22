#!/usr/bin/env python3
"""Validate imported scanner output without converting it into authority."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "security-scan-receipt" / "v1" / "schema.json"


class ReceiptError(ValueError):
    """A deterministic scan-receipt validation failure."""


def fail(code: str) -> None:
    raise ReceiptError(code) from None


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("INPUT_INVALID")


def parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (TypeError, ValueError):
        fail("TIMESTAMP_INVALID")


def validate(
    receipt: Any,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
) -> dict[str, Any]:
    schema = read_json(SCHEMA)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(receipt),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        fail("SCHEMA_INVALID")

    subject = receipt["subject"]
    if expected_commit is not None and subject["commit"] != expected_commit:
        fail("COMMIT_MISMATCH")
    if expected_tree is not None and subject["tree"] != expected_tree:
        fail("TREE_MISMATCH")

    started = parse_time(receipt["scan"]["started_at"])
    finished = parse_time(receipt["scan"]["finished_at"])
    if finished < started:
        fail("SCAN_TIME_REVERSED")

    identifiers: set[str] = set()
    severity_counts: Counter[str] = Counter()
    suppressed = 0
    for finding in receipt["findings"]:
        identifier = finding["finding_id"]
        if identifier in identifiers:
            fail("DUPLICATE_FINDING_ID")
        identifiers.add(identifier)
        severity_counts[finding["severity"]] += 1
        if finding["status"] == "suppressed":
            suppressed += 1
            if (
                finding["suppression_reason"] is None
                or finding["suppression_expires_at"] is None
            ):
                fail("SUPPRESSION_INCOMPLETE")
            if parse_time(finding["suppression_expires_at"]) <= finished:
                fail("SUPPRESSION_EXPIRED_AT_SCAN")
        elif (
            finding["suppression_reason"] is not None
            or finding["suppression_expires_at"] is not None
        ):
            fail("OPEN_FINDING_HAS_SUPPRESSION")

    summary = receipt["summary"]
    for severity in ("critical", "high", "medium", "low", "informational"):
        if summary[severity] != severity_counts[severity]:
            fail("SUMMARY_MISMATCH")
    if summary["suppressed"] != suppressed:
        fail("SUMMARY_MISMATCH")

    if receipt["scan"]["completeness"] == "failed" and receipt["findings"]:
        fail("FAILED_SCAN_CANNOT_ASSERT_FINDINGS")
    return receipt


def canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    args = parser.parse_args()
    try:
        result = validate(
            read_json(args.receipt),
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
        )
    except ReceiptError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "megalodon.security-scan-receipt-validation/v1",
                    "status": "blocked",
                    "reason": str(exc),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    print(
        canonical(
            {
                "schema_version": "megalodon.security-scan-receipt-validation/v1",
                "status": "validated",
                "receipt": result,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
