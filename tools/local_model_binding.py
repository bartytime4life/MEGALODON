#!/usr/bin/env python3
"""Validate or emit the fixed unbound MEGALODON local-model binding."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "local-model-binding" / "v1" / "schema.json"
TEMPLATE = ROOT / "config" / "model-bindings" / "qwen.unbound.json"


class BindingError(ValueError):
    """A deterministic binding validation failure."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BindingError(f"unreadable JSON: {path}") from exc


def _is_empty_identity(document: dict[str, Any]) -> bool:
    return (
        document["logical_alias"] is None
        and document["provider"]["version"] is None
        and document["provider"]["executable_sha256"] is None
        and document["provider"]["provenance_ref"] is None
        and document["artifact"]["installed_tag"] is None
        and document["artifact"]["manifest_sha256"] is None
        and document["artifact"]["model_weight_sha256"] is None
        and document["artifact"]["components"] == []
        and document["artifact"]["provenance_ref"] is None
        and document["artifact"]["license_refs"] == []
        and all(value is None for value in document["host_profile"].values())
        and document["registry"]["registry_id"] is None
        and document["registry"]["fingerprint_sha256"] is None
        and document["operator_decision"]
        == {
            "status": "NOT_RECORDED",
            "actor": None,
            "approved_at": None,
            "evidence_refs": [],
        }
    )


def validate(document: Any) -> dict[str, Any]:
    schema = load_json(SCHEMA)
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise BindingError(
            "; ".join(
                f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
                f"{error.message}"
                for error in errors
            )
        )

    if document["status"] == "UNBOUND":
        if not _is_empty_identity(document):
            raise BindingError("UNBOUND_IDENTITY_MUST_BE_EMPTY")
        return document

    provider = document["provider"]
    artifact = document["artifact"]
    host = document["host_profile"]
    registry = document["registry"]
    decision = document["operator_decision"]
    required = [
        document["logical_alias"],
        provider["version"],
        provider["executable_sha256"],
        provider["provenance_ref"],
        artifact["installed_tag"],
        artifact["manifest_sha256"],
        artifact["model_weight_sha256"],
        artifact["provenance_ref"],
        host["profile_id"],
        host["os"],
        host["architecture"],
        host["backend"],
        host["effective_config_sha256"],
        registry["registry_id"],
        registry["fingerprint_sha256"],
        decision["actor"],
        decision["approved_at"],
    ]
    if any(value is None for value in required):
        raise BindingError("BOUND_IDENTITY_INCOMPLETE")
    if artifact["installed_tag"].endswith(":latest"):
        raise BindingError("MUTABLE_TAG_FORBIDDEN")
    if not artifact["components"]:
        raise BindingError("COMPONENT_CLOSURE_REQUIRED")
    component_ids = [item["component_id"] for item in artifact["components"]]
    if len(component_ids) != len(set(component_ids)):
        raise BindingError("DUPLICATE_COMPONENT_ID")
    component_digests = [item["sha256"] for item in artifact["components"]]
    if len(component_digests) != len(set(component_digests)):
        raise BindingError("DUPLICATE_COMPONENT_DIGEST")
    weight_rows = [
        item for item in artifact["components"] if item["role"] == "weights"
    ]
    if len(weight_rows) != 1:
        raise BindingError("EXACTLY_ONE_WEIGHT_COMPONENT_REQUIRED")
    if weight_rows[0]["sha256"] != artifact["model_weight_sha256"]:
        raise BindingError("MODEL_WEIGHT_DIGEST_MISMATCH")
    if not artifact["license_refs"]:
        raise BindingError("LICENSE_REFERENCE_REQUIRED")
    if decision["status"] != "APPROVED" or not decision["evidence_refs"]:
        raise BindingError("OPERATOR_APPROVAL_REQUIRED")
    if document["generated_at"] < decision["approved_at"]:
        raise BindingError("BINDING_PRECEDES_APPROVAL")
    return document


def unbound() -> dict[str, Any]:
    document = load_json(TEMPLATE)
    document["generated_at"] = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return validate(document)


def canonical(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("validate", allow_abbrev=False)
    check.add_argument("manifest", type=Path)
    commands.add_parser("collect-unbound", allow_abbrev=False)
    args = parser.parse_args()
    try:
        document = (
            validate(load_json(args.manifest))
            if args.command == "validate"
            else unbound()
        )
    except BindingError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "megalodon.local-model-binding-validation/v1",
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
                "schema_version": "megalodon.local-model-binding-validation/v1",
                "status": "validated",
                "binding": document,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
