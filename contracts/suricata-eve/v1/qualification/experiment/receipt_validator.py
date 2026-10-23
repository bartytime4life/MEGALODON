"""Deterministic semantic validation for Suricata experiment receipts.

JSON Schema closes the receipt shape. This module additionally verifies the
arithmetic relationship between the nine recorded CPU measurements and the
two claimed median ratios. It has no network, process, or host-control path.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from statistics import median
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent
SCHEMA_SHA256 = "d12f999bc67a654b0950131aa89ee3ef119ff8ac12bb55eeba79edc99e4efa1f"


def _bound_schema() -> Mapping[str, Any]:
    raw = (ROOT / "receipt.schema.json").read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != SCHEMA_SHA256:
        raise ValueError(f"schema:digest mismatch:{observed}")
    return json.loads(raw)


def _schema_errors(receipt: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    return [
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '<root>'}:{error.message}"
        for error in sorted(validator.iter_errors(receipt), key=lambda item: list(item.absolute_path))
    ]


def validate_receipt(receipt: Mapping[str, Any]) -> list[str]:
    """Return deterministic validation errors; an empty list means valid."""

    errors = _schema_errors(receipt, _bound_schema())
    manifest_sha256 = hashlib.sha256((ROOT / "manifest.json").read_bytes()).hexdigest()
    if receipt.get("packet_sha256") != manifest_sha256:
        errors.append("packet_sha256:does not match manifest.json")
    if errors or receipt.get("status") != "pass":
        return errors

    oracle = receipt["oracle"]
    runs = oracle["pcre_runs"]
    medians = {
        segments: int(
            median(
                run["process_cpu_ns"]
                for run in runs
                if run["stream_segments"] == segments
            )
        )
        for segments in (32, 64, 128)
    }
    expected = (
        (32, 64, medians[64], medians[32]),
        (64, 128, medians[128], medians[64]),
    )
    claimed = oracle["pcre_ratios"]
    for index, (from_segments, to_segments, numerator, denominator) in enumerate(expected):
        ratio = claimed[index]
        if ratio["from_segments"] != from_segments or ratio["to_segments"] != to_segments:
            errors.append(f"oracle:pcre_ratios:{index}:unexpected segment pair")
        if ratio["numerator_ns"] != numerator or ratio["denominator_ns"] != denominator:
            errors.append(f"oracle:pcre_ratios:{index}:does not match recorded medians")
        if numerator > 3 * denominator:
            errors.append(f"oracle:pcre_ratios:{index}:exceeds 3.0 bound")
    return errors


def require_valid_receipt(receipt: Mapping[str, Any]) -> None:
    """Raise ValueError when structural or semantic receipt checks fail."""

    errors = validate_receipt(receipt)
    if errors:
        raise ValueError("; ".join(errors))
