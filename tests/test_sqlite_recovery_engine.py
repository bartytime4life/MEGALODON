"""Tests for the bounded SQLite backup/restore engine (contract v1)."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest
from jsonschema import Draft202012Validator, FormatChecker

import megalodon.sqlite_recovery as sr

CONTRACT_ROOT = Path(__file__).parents[1] / "contracts" / "sqlite-recovery" / "v1"
SCHEMA = json.loads((CONTRACT_ROOT / "schema.json").read_text(encoding="utf-8"))


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker(),
    )


def _as_plain(value):
    if isinstance(value, Mapping):
        return {key: _as_plain(item) for key, item in value.items()}
    return value


def _assert_valid(receipt: Mapping[str, object]) -> None:
    schema_name = "successReceipt" if receipt["status"] == "completed" else "failureReceipt"
    errors = list(_validator(schema_name).iter_errors(_as_plain(receipt)))
    assert errors == []


@pytest.fixture(autouse=True)
def unprivileged(monkeypatch):
    # The real gate is exercised in its own test below; every other test
    # runs in whatever CI/sandbox uid this suite happens to have.
    monkeypatch.setattr(sr, "require_unprivileged_linux", lambda: None)


def _make_database(path: Path, *, user_version: int = 3, mode: int = 0o600, rows: int = 50) -> None:
    connection = sqlite3.connect(str(path))
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(f"PRAGMA user_version={user_version}")
    connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    connection.executemany(
        "INSERT INTO events (name) VALUES (?)", ((f"event-{i}",) for i in range(rows)),
    )
    connection.commit()
    connection.close()
    os.chmod(path, mode)


def _sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- happy path -------------------------------------------------------------

def test_backup_then_restore_round_trip_preserves_data(tmp_path) -> None:
    source = tmp_path / "audit.sqlite3"
    _make_database(source, rows=200)
    source_digest_before = _sha256_of(source)

    backup_path = tmp_path / "backup.sqlite3"
    receipt = sr.backup_database(operation_id="op-backup-1", source_path=source, destination_path=backup_path)
    assert receipt["status"] == "completed"
    assert receipt["reason"] == "COMPLETED"
    _assert_valid(receipt)

    # source_mutated: false is not just claimed, verify it is actually true.
    assert _sha256_of(source) == source_digest_before

    assert backup_path.exists()
    assert not list(tmp_path.glob("backup.sqlite3-*"))  # no leftover WAL/SHM sidecars

    restored_path = tmp_path / "restored.sqlite3"
    restore_receipt = sr.restore_backup(
        operation_id="op-restore-1", artifact_path=backup_path,
        expected_artifact_sha256=receipt["artifact_sha256"],
        destination_path=restored_path,
    )
    assert restore_receipt["status"] == "completed"
    _assert_valid(restore_receipt)

    connection = sqlite3.connect(str(restored_path))
    assert connection.execute("SELECT COUNT(*) FROM events").fetchone() == (200,)
    connection.close()


def test_success_receipt_matches_the_contract_verified_database_shape(tmp_path) -> None:
    source = tmp_path / "audit.sqlite3"
    _make_database(source)
    receipt = sr.backup_database(
        operation_id="op-shape", source_path=source, destination_path=tmp_path / "b.sqlite3",
    )
    for side in ("source", "destination"):
        block = receipt[side]
        assert block["schema_user_version"] == 3
        assert block["integrity_check"] == "ok"
        assert block["foreign_key_check"] == "ok"
        assert block["identity"]["path_disclosed"] is False
        assert block["identity"]["mode"] == "0600"


def test_receipt_never_discloses_a_path(tmp_path) -> None:
    source = tmp_path / "audit.sqlite3"
    _make_database(source)
    receipt = sr.backup_database(
        operation_id="op-privacy", source_path=source, destination_path=tmp_path / "b.sqlite3",
    )
    serialized = json.dumps(_as_plain(receipt))
    assert str(tmp_path) not in serialized


# --- failure paths: each one produces a valid, closed receipt --------------

def test_destination_already_exists(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    destination = tmp_path / "b.sqlite3"
    destination.write_bytes(b"not a database")
    receipt = sr.backup_database(operation_id="op-1", source_path=source, destination_path=destination)
    assert (receipt["status"], receipt["reason"]) == ("failed", "DESTINATION_EXISTS")
    assert receipt["destination_created"] is False
    assert receipt["source_state"] == "admitted"
    _assert_valid(receipt)


def test_source_missing(tmp_path) -> None:
    receipt = sr.backup_database(
        operation_id="op-2", source_path=tmp_path / "missing.sqlite3", destination_path=tmp_path / "b.sqlite3",
    )
    assert (receipt["status"], receipt["reason"]) == ("failed", "SOURCE_UNAVAILABLE")
    _assert_valid(receipt)


def test_source_wrong_mode_is_rejected_as_not_private(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source, mode=0o644)
    receipt = sr.backup_database(operation_id="op-3", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "SOURCE_NOT_PRIVATE")
    _assert_valid(receipt)


def test_source_symlink_is_refused(tmp_path) -> None:
    real = tmp_path / "real.sqlite3"
    _make_database(real)
    link = tmp_path / "link.sqlite3"
    os.symlink(real, link)
    receipt = sr.backup_database(operation_id="op-4", source_path=link, destination_path=tmp_path / "b.sqlite3")
    assert receipt["status"] == "failed"
    assert receipt["reason"] in {"SOURCE_UNAVAILABLE", "SOURCE_UNSAFE"}
    _assert_valid(receipt)


def test_destination_parent_symlink_is_refused(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    link_dir = tmp_path / "link_dir"
    os.symlink(real_dir, link_dir)
    receipt = sr.backup_database(
        operation_id="op-5", source_path=source, destination_path=link_dir / "b.sqlite3",
    )
    assert (receipt["status"], receipt["reason"]) == ("failed", "DESTINATION_UNSAFE")
    _assert_valid(receipt)


def test_schema_incompatible_wrong_user_version(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source, user_version=1)
    receipt = sr.backup_database(operation_id="op-6", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "SCHEMA_INCOMPATIBLE")
    _assert_valid(receipt)


def test_source_corrupt_bytes(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    source.write_bytes(b"not a real sqlite file, just garbage bytes padding it out")
    os.chmod(source, 0o600)
    receipt = sr.backup_database(operation_id="op-7", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "SOURCE_CORRUPT")
    _assert_valid(receipt)


def test_foreign_key_violation_blocks_backup(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    connection = sqlite3.connect(str(source))
    connection.execute("PRAGMA user_version=3")
    connection.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))"
    )
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("INSERT INTO child (id, parent_id) VALUES (1, 999)")
    connection.commit()
    connection.close()
    os.chmod(source, 0o600)
    receipt = sr.backup_database(operation_id="op-8", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "FOREIGN_KEY_VIOLATION")
    _assert_valid(receipt)


def test_same_file_refused(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    receipt = sr.backup_database(operation_id="op-9", source_path=source, destination_path=source)
    assert (receipt["status"], receipt["reason"]) == ("failed", "SAME_FILE_REFUSED")
    _assert_valid(receipt)


def test_restore_rejects_a_digest_mismatch(tmp_path) -> None:
    artifact = tmp_path / "a.sqlite3"
    _make_database(artifact)
    wrong_digest = "sha256:" + "0" * 64
    receipt = sr.restore_backup(
        operation_id="op-10", artifact_path=artifact, expected_artifact_sha256=wrong_digest,
        destination_path=tmp_path / "restored.sqlite3",
    )
    assert (receipt["status"], receipt["reason"]) == ("failed", "ARTIFACT_CORRUPT")
    _assert_valid(receipt)


def test_restore_in_place_is_refused_by_destination_must_not_exist(tmp_path) -> None:
    artifact = tmp_path / "a.sqlite3"
    _make_database(artifact)
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    # Restoring "in place" means the destination is the artifact itself, or
    # any already-existing path; both are rejected before any copy happens.
    receipt = sr.restore_backup(
        operation_id="op-11", artifact_path=artifact, expected_artifact_sha256=digest,
        destination_path=artifact,
    )
    assert receipt["status"] == "failed"
    assert receipt["reason"] in {"SAME_FILE_REFUSED", "DESTINATION_EXISTS"}
    assert receipt["destination_created"] is False


def test_disk_reserve_insufficient(tmp_path, monkeypatch) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)

    class _TinyUsage:
        f_bavail = 1
        f_frsize = 1

    monkeypatch.setattr(sr.os, "statvfs", lambda *_a, **_k: _TinyUsage())
    receipt = sr.backup_database(operation_id="op-12", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "DISK_RESERVE_INSUFFICIENT")
    assert receipt["destination_created"] is False
    _assert_valid(receipt)


def test_oversized_source_is_rejected(tmp_path, monkeypatch) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source, rows=500)
    monkeypatch.setattr(sr, "MAX_SOURCE_BYTES", 1)
    receipt = sr.backup_database(operation_id="op-13", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert (receipt["status"], receipt["reason"]) == ("failed", "ARTIFACT_LIMIT_EXCEEDED")
    _assert_valid(receipt)


def test_clock_rollback_during_a_clean_copy_is_reported_as_failure_not_success(tmp_path, monkeypatch) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    destination = tmp_path / "b.sqlite3"

    from datetime import datetime, timezone

    real_now = datetime.now(timezone.utc)
    calls = {"count": 0}

    class _RolledBackClock(datetime):
        @classmethod
        def now(cls, tz=None):
            calls["count"] += 1
            # First call is _run's started_wall; every later call (finished_wall
            # checks) reports a moment a year earlier, simulating rollback.
            return real_now if calls["count"] == 1 else real_now.replace(year=real_now.year - 1)

    monkeypatch.setattr(sr, "datetime", _RolledBackClock)
    receipt = sr.backup_database(operation_id="op-clock", source_path=source, destination_path=destination)
    assert receipt["status"] == "failed"
    assert receipt["reason"] == "CLOCK_ROLLBACK"
    assert receipt["clock_rollback_observed"] is True
    assert receipt["destination_created"] is True
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()
    _assert_valid(receipt)


# --- incomplete destinations are preserved, never deleted -------------------

def test_incomplete_destination_is_left_for_operator_review(tmp_path, monkeypatch) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source, rows=500)
    destination = tmp_path / "b.sqlite3"

    real_verify = sr._verify_database

    def failing_destination_verify(descriptor, *, read_only):
        if not read_only:
            raise sr._Halt("SOURCE_CORRUPT")
        return real_verify(descriptor, read_only=read_only)

    monkeypatch.setattr(sr, "_verify_database", failing_destination_verify)
    receipt = sr.backup_database(operation_id="op-14", source_path=source, destination_path=destination)
    assert receipt["status"] == "failed"
    assert receipt["destination_created"] is True
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()  # never deleted
    _assert_valid(receipt)


# --- input validation --------------------------------------------------------

@pytest.mark.parametrize("operation_id", ["", "Has Spaces", "UPPER", "-leading-dash", "a" * 65])
def test_invalid_operation_id_raises_before_any_receipt(tmp_path, operation_id) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    with pytest.raises(sr.SqliteRecoveryError) as caught:
        sr.backup_database(operation_id=operation_id, source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert caught.value.reason == "INPUT_INVALID"


def test_invalid_expected_digest_raises_before_any_receipt(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    with pytest.raises(sr.SqliteRecoveryError) as caught:
        sr.restore_backup(
            operation_id="op-15", artifact_path=source, expected_artifact_sha256="not-a-digest",
            destination_path=tmp_path / "b.sqlite3",
        )
    assert caught.value.reason == "INPUT_INVALID"


def test_platform_gate_is_actually_invoked(tmp_path, monkeypatch) -> None:
    def deny():
        raise Exception("PLATFORM_GATE_TRIGGERED")

    monkeypatch.setattr(sr, "require_unprivileged_linux", deny)
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    with pytest.raises(Exception, match="PLATFORM_GATE_TRIGGERED"):
        sr.backup_database(operation_id="op-16", source_path=source, destination_path=tmp_path / "b.sqlite3")


# --- fixed guarantees echoed in every receipt --------------------------------

def test_effects_are_always_the_fixed_closed_set(tmp_path) -> None:
    source = tmp_path / "a.sqlite3"
    _make_database(source)
    receipt = sr.backup_database(operation_id="op-17", source_path=source, destination_path=tmp_path / "b.sqlite3")
    assert dict(receipt["effects"]) == {
        "source_mutated": False,
        "network_access_performed": False,
        "ordinary_copy_performed": False,
        "migration_performed": False,
        "repair_performed": False,
        "deletion_performed": False,
        "path_disclosed": False,
    }


def test_engine_exposes_no_network_scheduler_or_retention_surface() -> None:
    forbidden = ("socket", "http", "retention", "schedule", "delete_old", "cron", "watch")
    public_names = [name for name in dir(sr) if not name.startswith("_")]
    for name in public_names:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden), name
