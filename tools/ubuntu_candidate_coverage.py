#!/usr/bin/env python3
"""Index retained Ubuntu candidate evidence without executing candidate checks."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "ubuntu-candidate-coverage" / "v1" / "schema.json"
IDENTITY_TOOL = ROOT / "tools" / "ubuntu_release_evidence.py"
GATE_IDS = (
    "artifact_notice_license",
    "sbom",
    "provenance",
    "operator_recovery",
    "optional_source_behavior",
    "owner_disposition",
    "independent_disposition",
)
AUTHENTICATION = {"not_performed", "github_actions", "operator", "independent"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _load_identity_tool():
    spec = importlib.util.spec_from_file_location(
        "_megalodon_ubuntu_release_evidence", IDENTITY_TOOL
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("ubuntu evidence verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity = _load_identity_tool()


class CoverageError(ValueError):
    """A deterministic candidate coverage failure."""


def _fail(code: str) -> None:
    raise CoverageError(code) from None


def read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError:
        _fail("INPUT_INVALID")
    try:
        value = identity.load(raw)
    except identity.EvidenceError:
        _fail("INPUT_INVALID")
    return value


def empty_pointer() -> dict[str, Any]:
    return {
        "evidence_ref": None,
        "evidence_sha256": None,
        "authentication": "not_performed",
        "platform": None,
    }


def _pointer_complete(pointer: dict[str, Any]) -> bool:
    return (
        pointer["evidence_ref"] is not None
        and pointer["evidence_sha256"] is not None
        and pointer["authentication"] != "not_performed"
        and pointer["platform"] is not None
    )


def _validate_pointer(pointer: dict[str, Any]) -> None:
    if set(pointer) != {
        "evidence_ref",
        "evidence_sha256",
        "authentication",
        "platform",
    }:
        _fail("EVIDENCE_POINTER")
    if pointer["authentication"] not in AUTHENTICATION:
        _fail("EVIDENCE_POINTER")
    values = (
        pointer["evidence_ref"],
        pointer["evidence_sha256"],
        pointer["platform"],
    )
    if all(value is None for value in values):
        if pointer["authentication"] != "not_performed":
            _fail("EVIDENCE_POINTER")
        return
    if any(value is None for value in values):
        _fail("EVIDENCE_POINTER")
    if not isinstance(pointer["evidence_ref"], str):
        _fail("EVIDENCE_POINTER")
    if not isinstance(pointer["platform"], str):
        _fail("EVIDENCE_POINTER")
    digest = pointer["evidence_sha256"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        _fail("EVIDENCE_POINTER")
    if pointer["authentication"] == "not_performed":
        _fail("EVIDENCE_POINTER")


def _schema_validate(index: dict[str, Any]) -> None:
    try:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _fail("SCHEMA_UNAVAILABLE")
    errors = sorted(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(index),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        _fail("SCHEMA_INVALID")


def _validated_manifest(
    manifest: dict[str, Any], expected_commit: str, expected_tree: str
) -> dict[str, Any]:
    if HEX40.fullmatch(expected_commit) is None or HEX40.fullmatch(expected_tree) is None:
        _fail("SOURCE_PIN")
    try:
        value = identity.validate(manifest)
    except identity.EvidenceError:
        _fail("CANDIDATE_INVALID")
    source = value["source"]
    if (
        source["observed_commit"] != expected_commit
        or source["observed_tree"] != expected_tree
    ):
        _fail("SOURCE_MISMATCH")
    return value


def initialize(
    manifest: dict[str, Any], expected_commit: str, expected_tree: str
) -> dict[str, Any]:
    candidate = _validated_manifest(manifest, expected_commit, expected_tree)
    return {
        "schema_version": "megalodon.ubuntu-candidate-coverage/v1",
        "repository": "bartytime4life/MEGALODON",
        "status": "incomplete",
        "subject": {
            "commit": expected_commit,
            "tree": expected_tree,
            "candidate_manifest_sha256": identity.digest(candidate),
        },
        "checks": [
            {
                "id": item["id"],
                "status": item["status"],
                "evidence": empty_pointer(),
            }
            for item in candidate["checks"]
        ],
        "artifacts": [
            {
                "id": item["id"],
                "status": item["status"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "published": False,
                "evidence": empty_pointer(),
            }
            for item in candidate["artifacts"]
        ],
        "optional_components": candidate["optional_components"],
        "gates": [
            {"id": gate_id, "status": "not_run", "evidence": empty_pointer()}
            for gate_id in GATE_IDS
        ],
        "effects": {
            "tag_created": False,
            "release_published": False,
            "package_uploaded": False,
            "deployment_performed": False,
            "service_installed": False,
            "firewall_changed": False,
            "sensor_started": False,
            "model_invoked": False,
            "restored_data_activated": False,
        },
        "limitations": [
            "Initialization copies candidate statuses but attaches no receipt or authentication evidence.",
            "Missing receipt bindings remain not performed and cannot become complete by implication.",
            "A complete coverage index still grants no tag, release, publication, deployment, installation, sensor, model, firewall, or restored-data authority."
        ],
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def validate(
    index: dict[str, Any],
    manifest: dict[str, Any],
    expected_commit: str,
    expected_tree: str,
) -> dict[str, Any]:
    _schema_validate(index)
    candidate = _validated_manifest(manifest, expected_commit, expected_tree)
    subject = index["subject"]
    if subject != {
        "commit": expected_commit,
        "tree": expected_tree,
        "candidate_manifest_sha256": identity.digest(candidate),
    }:
        _fail("SUBJECT_MISMATCH")

    if tuple(row["id"] for row in index["checks"]) != identity.CHECK_IDS:
        _fail("CHECK_SET")
    if tuple(row["id"] for row in index["artifacts"]) != identity.ARTIFACT_IDS:
        _fail("ARTIFACT_SET")
    if tuple(row["id"] for row in index["optional_components"]) != identity.OPTIONAL_IDS:
        _fail("OPTIONAL_SET")
    if tuple(row["id"] for row in index["gates"]) != GATE_IDS:
        _fail("GATE_SET")

    for row, source in zip(index["checks"], candidate["checks"], strict=True):
        if row["status"] != source["status"]:
            _fail("CHECK_STATUS_MISMATCH")
        _validate_pointer(row["evidence"])

    for row, source in zip(index["artifacts"], candidate["artifacts"], strict=True):
        if any(
            row[key] != source[key]
            for key in ("id", "status", "sha256", "size_bytes", "published")
        ):
            _fail("ARTIFACT_MISMATCH")
        _validate_pointer(row["evidence"])

    if index["optional_components"] != candidate["optional_components"]:
        _fail("OPTIONAL_STATE_MISMATCH")

    for gate in index["gates"]:
        pointer = gate["evidence"]
        _validate_pointer(pointer)
        if gate["status"] == "not_run" and _pointer_complete(pointer):
            _fail("GATE_NOT_RUN_HAS_EVIDENCE")
        if gate["status"] == "accepted" and not _pointer_complete(pointer):
            _fail("GATE_ACCEPTANCE_UNBOUND")
        if (
            gate["id"] == "independent_disposition"
            and gate["status"] == "accepted"
            and pointer["authentication"] != "independent"
        ):
            _fail("INDEPENDENT_AUTHENTICATION_REQUIRED")
        if (
            gate["id"] == "owner_disposition"
            and gate["status"] == "accepted"
            and pointer["authentication"] not in {"operator", "independent"}
        ):
            _fail("OWNER_AUTHENTICATION_REQUIRED")

    if index["status"] == "complete":
        if candidate["basis"] == "synthetic_contract_fixture":
            _fail("SYNTHETIC_CANNOT_COMPLETE")
        if candidate["status"] != "candidate_evidence":
            _fail("CANDIDATE_INCOMPLETE")
        if any(row["status"] != "passed" for row in index["checks"]):
            _fail("COVERAGE_INCOMPLETE")
        if any(not _pointer_complete(row["evidence"]) for row in index["checks"]):
            _fail("COVERAGE_INCOMPLETE")
        if any(row["status"] != "built_ephemeral" for row in index["artifacts"]):
            _fail("COVERAGE_INCOMPLETE")
        if any(not _pointer_complete(row["evidence"]) for row in index["artifacts"]):
            _fail("COVERAGE_INCOMPLETE")
        if any(gate["status"] != "accepted" for gate in index["gates"]):
            _fail("COVERAGE_INCOMPLETE")
    return index


def canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize_parser = commands.add_parser("init", allow_abbrev=False)
    initialize_parser.add_argument("manifest", type=Path)
    validate_parser = commands.add_parser("validate", allow_abbrev=False)
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.add_argument("coverage", type=Path)
    for command in (initialize_parser, validate_parser):
        command.add_argument("--expected-commit", required=True)
        command.add_argument("--expected-tree", required=True)
    args = parser.parse_args()
    try:
        manifest = read_json(args.manifest)
        result = (
            initialize(manifest, args.expected_commit, args.expected_tree)
            if args.command == "init"
            else validate(
                read_json(args.coverage),
                manifest,
                args.expected_commit,
                args.expected_tree,
            )
        )
    except CoverageError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "megalodon.ubuntu-candidate-coverage-validation/v1",
                    "status": "blocked",
                    "reason": str(exc),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    print(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
