"""Static SQLite recovery contract tests; no backup or restore runtime."""

from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "sqlite-recovery" / "v1"


def load_json(path: Path) -> object:
    def closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=closed_pairs,
        parse_constant=reject_constant,
    )


SCHEMA = load_json(CONTRACT / "schema.json")
ACCEPTED = {
    path.stem: load_json(path)
    for path in sorted((CONTRACT / "fixtures" / "accepted").glob("*.json"))
}
REJECTED = {
    path.stem: load_json(path)
    for path in sorted((CONTRACT / "fixtures" / "rejected").glob("*.json"))
}
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
REASONS = (
    "COMPLETED",
    "INPUT_INVALID",
    "SOURCE_UNAVAILABLE",
    "SOURCE_UNSAFE",
    "SOURCE_NOT_PRIVATE",
    "SOURCE_IDENTITY_CHANGED",
    "SCHEMA_INCOMPATIBLE",
    "SOURCE_CORRUPT",
    "DESTINATION_UNSAFE",
    "DESTINATION_EXISTS",
    "SAME_FILE_REFUSED",
    "LOCK_TIMEOUT",
    "DEADLINE_EXCEEDED",
    "DISK_RESERVE_INSUFFICIENT",
    "ARTIFACT_LIMIT_EXCEEDED",
    "ARTIFACT_CORRUPT",
    "FOREIGN_KEY_VIOLATION",
    "CLOCK_ROLLBACK",
    "INTERRUPTED_BEFORE_CREATE",
    "INTERRUPTED_AFTER_CREATE",
    "CLEANUP_FAILED",
    "COMPLETION_UNCERTAIN",
    "IO_ERROR",
)


def test_schema_and_fixture_inventory_are_closed() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert set(ACCEPTED) == {
        "backup-failure-receipt",
        "backup-request",
        "backup-success-receipt",
        "policy",
        "restore-failure-receipt",
        "restore-request",
        "restore-success-receipt",
    }
    assert set(REJECTED) == {
        "automatic-deletion",
        "clock-rollback-unmarked",
        "collision-created-destination",
        "failure-with-completed-reason",
        "live-file-copy",
        "network-enabled",
        "overwrite-enabled",
        "raw-telemetry-digest",
        "restore-in-place",
        "same-object-success",
        "uncertain-marked-certain",
    }


@pytest.mark.parametrize("name", sorted(ACCEPTED))
def test_accepted_fixtures_validate(name: str) -> None:
    VALIDATOR.validate(ACCEPTED[name])


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_rejected_fixtures_fail_closed(name: str) -> None:
    with pytest.raises(ValidationError):
        VALIDATOR.validate(REJECTED[name])


def test_policy_fixes_limits_reasons_and_non_effects() -> None:
    policy = ACCEPTED["policy"]
    assert policy["runtime_implemented"] is False
    assert policy["operations"] == ["backup", "restore"]
    assert tuple(policy["reason_codes"]) == REASONS
    assert policy["limits"] == {
        "max_source_bytes": 4 * 1024**3,
        "max_artifact_bytes": 4 * 1024**3,
        "min_free_reserve_bytes": 16 * 1024**2,
        "max_elapsed_ms": 300_000,
        "max_busy_retries": 60,
        "pages_per_step": 1024,
    }
    guarantees = policy["guarantees"]
    assert guarantees["sqlite_online_backup_only"] is True
    assert guarantees["destination_must_not_exist"] is True
    assert guarantees["full_integrity_before_success"] is True
    assert guarantees["foreign_key_check_before_success"] is True
    assert not any(
        guarantees[key]
        for key in (
            "ordinary_live_file_copy",
            "overwrite",
            "restore_in_place",
            "digest_raw_telemetry",
            "automatic_retention",
            "automatic_deletion",
            "automatic_migration",
            "automatic_repair",
            "service_install",
            "dashboard_write",
            "network_access",
            "scheduler",
        )
    )


@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_requests_are_explicit_local_and_new_destination_only(operation: str) -> None:
    request = ACCEPTED[f"{operation}-request"]
    assert request["explicit_operator_request"] is True
    assert request["source"]["method"] == "sqlite_online_backup_api"
    assert request["source"]["required_schema_user_version"] == 3
    assert request["destination"]["must_not_exist"] is True
    assert request["destination"]["overwrite"] is False
    assert request["destination"]["same_as_source"] is False
    assert request["destination"]["owner_private"] is True
    assert not any(request["effects"].values())


@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_success_requires_verified_distinct_destination(operation: str) -> None:
    receipt = ACCEPTED[f"{operation}-success-receipt"]
    assert receipt["status"] == "completed"
    assert receipt["reason"] == "COMPLETED"
    assert receipt["destination_created"] is True
    assert receipt["destination_complete"] is True
    assert receipt["destination_same_as_source"] is False
    assert receipt["completion_uncertain"] is False
    assert receipt["clock_rollback_observed"] is False
    assert receipt["source"]["identity"] != receipt["destination"]["identity"]
    for snapshot in (receipt["source"], receipt["destination"]):
        assert snapshot["schema_user_version"] == 3
        assert snapshot["integrity_check"] == "ok"
        assert snapshot["foreign_key_check"] == "ok"
        assert snapshot["logical_bytes"] == snapshot["page_size"] * snapshot["page_count"]
        assert snapshot["identity"]["path_disclosed"] is False
    assert not any(receipt["effects"].values())
    started = datetime.fromisoformat(receipt["started_at"].replace("Z", "+00:00"))
    finished = datetime.fromisoformat(receipt["finished_at"].replace("Z", "+00:00"))
    assert started <= finished


@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_failures_are_terminal_and_never_complete(operation: str) -> None:
    receipt = ACCEPTED[f"{operation}-failure-receipt"]
    assert receipt["status"] == "failed"
    assert receipt["reason"] in REASONS[1:]
    assert receipt["destination_complete"] is False
    assert receipt["completion_uncertain"] is False
    assert not any(receipt["effects"].values())


def test_success_cannot_hide_bad_verification_or_new_authority() -> None:
    base = ACCEPTED["backup-success-receipt"]
    candidates = []
    for field in ("integrity_check", "foreign_key_check"):
        candidate = deepcopy(base)
        candidate["destination"][field] = "failed"
        candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["destination"].pop("identity")
    candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["effects"]["deletion_performed"] = True
    candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["raw_telemetry_sha256"] = "sha256:" + "a" * 64
    candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["clock_rollback_observed"] = True
    candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["completion_uncertain"] = True
    candidates.append(candidate)
    candidate = deepcopy(base)
    candidate["destination_same_as_source"] = True
    candidate["destination"]["identity"] = deepcopy(candidate["source"]["identity"])
    candidates.append(candidate)
    for value in candidates:
        assert not VALIDATOR.is_valid(value)


def test_documentation_covers_every_reason_and_required_fault() -> None:
    document = (ROOT / "docs" / "sqlite-recovery-contract.md").read_text(
        encoding="utf-8"
    )
    for reason in REASONS:
        assert f"`{reason}`" in document
    for phrase in (
        "WAL changes during backup",
        "Lock contention",
        "Disk full or reserve shortfall",
        "Interruption before destination creation",
        "Interruption after destination creation",
        "Corrupt backup",
        "Wrong schema/version",
        "Wall-clock rollback",
        "Cleanup/disposition failure",
        "Uncertain copy/commit outcome",
    ):
        assert phrase in document


def test_contract_is_packaged_documented_and_not_runtime_wired() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    specification = (ROOT / "SPECIFICATION.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY_REVIEW.md").read_text(encoding="utf-8")
    assert "recursive-include contracts *" in manifest
    assert "recursive-include docs *.md" in manifest
    assert "docs/sqlite-recovery-contract.md" in readme
    assert "contracts/sqlite-recovery/v1" in readme
    assert "SQLite recovery contract v1" in specification
    assert "SQLite recovery contract ([#256]" in security
    for path in (ROOT / "megalodon").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "megalodon-sqlite-recovery" not in text
        assert "sqlite-recovery/v1" not in text


def test_contract_test_has_no_runtime_import() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not any(name == "megalodon" or name.startswith("megalodon.") for name in imported)
