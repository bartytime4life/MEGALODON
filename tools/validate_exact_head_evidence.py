#!/usr/bin/env python3
"""Validate MEGALODON exact-head evidence without granting lifecycle authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "exact-head-evidence" / "v1" / "schema.json"


class ManifestError(ValueError):
    """A deterministic manifest validation failure."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path}: unreadable JSON: {exc}") from exc


def validate_manifest(document: Any, *, current_head: str | None = None) -> None:
    schema = load_json(SCHEMA_PATH)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        rendered = "; ".join(
            f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
            f"{error.message}"
            for error in errors
        )
        raise ManifestError(rendered)

    execution = document["execution"]
    if len(execution["commands"]) != len(execution["exit_codes"]):
        raise ManifestError("execution commands and exit_codes must have equal length")

    subject_sha = document["subject"]["commit"]
    supersession = document["supersession"]
    status = supersession["status"]
    successor = supersession["superseded_by"]

    if status == "current":
        if successor is not None:
            raise ManifestError("current evidence cannot name superseded_by")
        if current_head is None:
            raise ManifestError("current evidence requires --current-head")
        if subject_sha != current_head:
            raise ManifestError(
                f"STALE_HEAD: subject {subject_sha} != observed {current_head}"
            )
    elif status == "superseded" and successor is None:
        raise ManifestError("superseded evidence must name superseded_by")
    elif status == "historical" and successor == subject_sha:
        raise ManifestError("historical evidence cannot supersede itself")

    acceptance = document["disposition"]["independent_acceptance"]
    collector = document["authentication"]["collector"]
    if acceptance == "accepted" and collector != "independent":
        raise ManifestError(
            "independent acceptance requires authentication.collector=independent"
        )

    if collector == "github_actions":
        authentication = document["authentication"]
        if authentication["workflow_run_id"] is None:
            raise ManifestError("github_actions evidence requires workflow_run_id")
        if (
            authentication["artifact_id"] is not None
            and authentication["artifact_digest"] is None
        ):
            raise ManifestError("authenticated artifact_id requires artifact_digest")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--current-head",
        help="full observed 40-character head; required when status is current",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        document = load_json(args.manifest)
        validate_manifest(document, current_head=args.current_head)
    except ManifestError as exc:
        print(f"MEGALODON_EXACT_HEAD_EVIDENCE_INVALID: {exc}")
        return 2
    print("MEGALODON_EXACT_HEAD_EVIDENCE_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
