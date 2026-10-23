"""Deterministic semantic validation for Suricata experiment receipts.

JSON Schema closes the receipt shape. This module additionally verifies the
arithmetic relationship between the nine recorded CPU measurements and the
two claimed median ratios. It has no network, process, or host-control path.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from statistics import median
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent


def _schema_errors(receipt: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    return [
        f"schema:{'/'.join(str(part) for part in error.absolute_path) or '<root>'}:{error.message}"
        for error in sorted(validator.iter_errors(receipt), key=lambda item: list(item.absolute_path))
    ]


def validate_receipt(
    receipt: Mapping[str, Any], schema: Mapping[str, Any] | None = None
) -> list[str]:
    """Return deterministic validation errors; an empty list means valid."""

    if schema is None:
        schema = json.loads((ROOT / "receipt.schema.json").read_text(encoding="utf-8"))

    errors = _schema_errors(receipt, schema)
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


def require_valid_receipt(
    receipt: Mapping[str, Any], schema: Mapping[str, Any] | None = None
) -> None:
    """Raise ValueError when structural or semantic receipt checks fail."""

    errors = validate_receipt(receipt, schema)
    if errors:
        raise ValueError("; ".join(errors))
