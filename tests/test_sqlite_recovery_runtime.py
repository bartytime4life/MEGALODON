from __future__ import annotations

from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from megalodon.cli import main
from megalodon.sqlite_recovery_workflow import backup_database, restore_database
import megalodon.sqlite_recovery_workflow as recovery
from megalodon.storage import Store


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "contracts" / "sqlite-recovery" / "v1" / "schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


@pytest.fixture
def private_directory(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path


def create_store(directory: Path, name: str = "source.db") -> Path:
    path = directory / name
    with Store(path):
        pass
    return path


def assert_contract_receipt(receipt: dict[str, object]) -> None:
    VALIDATOR.validate(receipt)
    encoded = json.dumps(receipt, sort_keys=True)
    assert len(encoded.encode("utf-8")) < 8192
    assert "/" not in encoded
    assert "\\" not in encoded
    assert not any(receipt["effects"].values())


def successful_backup(directory: Path) -> tuple[Path, Path, dict[str, object]]:
    source = create_store(directory)
    artifact = directory / "backup.db"
    manifest = directory / "backup.manifest.json"
    receipt = backup_database(
        source, artifact, manifest, operation_id="backup-runtime-1"
    )
    assert receipt["status"] == "completed"
    return artifact, manifest, receipt


def test_backup_and_restore_complete_with_closed_verified_receipts(
    private_directory: Path,
) -> None:
    artifact, manifest, backup = successful_backup(private_directory)
    assert_contract_receipt(backup)
    assert backup["destination_same_as_source"] is False
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600

    destination = private_directory / "restored.db"
    restored = restore_database(
        artifact,
        manifest,
        destination,
        artifact_sha256=str(backup["artifact_sha256"]),
        operation_id="restore-runtime-1",
    )

    assert_contract_receipt(restored)
    assert restored["status"] == "completed"
    assert restored["artifact_sha256"] == backup["artifact_sha256"]
    assert restored["manifest_sha256"] == backup["manifest_sha256"]
    assert restored["source"]["identity"] != restored["destination"]["identity"]
    assert destination.exists()
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchone() is None


@pytest.mark.parametrize("operation", ("backup", "restore"))
def test_existing_destination_is_never_overwritten(
    private_directory: Path, operation: str
) -> None:
    source = create_store(private_directory)
    artifact = private_directory / "backup.db"
    manifest = private_directory / "manifest.json"
    destination = artifact if operation == "backup" else private_directory / "restore.db"
    if operation == "restore":
        backup = backup_database(
            source, artifact, manifest, operation_id="backup-for-collision"
        )
        assert backup["status"] == "completed"
    destination.write_bytes(b"operator-owned-existing-content")
    destination.chmod(0o600)
    before = destination.read_bytes()

    if operation == "backup":
        receipt = backup_database(
            source, destination, manifest, operation_id="backup-collision"
        )
    else:
        receipt = restore_database(
            artifact,
            manifest,
            destination,
            artifact_sha256=str(backup["artifact_sha256"]),
            operation_id="restore-collision",
        )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "DESTINATION_EXISTS"
    assert receipt["destination_created"] is False
    assert destination.read_bytes() == before


@pytest.mark.parametrize("operation", ("backup", "restore"))
@pytest.mark.parametrize("phase", ("anchor", "connect", "validate", "copy"))
def test_destination_replacement_at_creation_boundaries(
    private_directory: Path, monkeypatch, operation: str, phase: str
) -> None:
    """Move real files at fixed boundaries; never rely on a scheduling race."""
    if operation == "restore":
        source, manifest, backup = successful_backup(private_directory)
    else:
        source = create_store(private_directory)
        manifest = private_directory / "manifest.json"
    source_before = source.read_bytes()
    destination = private_directory / "candidate.db"
    displaced = private_directory / "displaced.db"
    replacement = b"operator-owned-replacement"
    connections = []
    descriptors = []
    original_anchor = recovery._anchored_database_path
    original_connect = recovery.sqlite3.connect
    original_validate = recovery._validate_connection_path
    original_copy = recovery._copy_online

    def replace():
        destination.rename(displaced)
        destination.write_bytes(replacement)
        destination.chmod(0o600)

    def anchor(descriptor, path, prefix):
        if prefix == "RECOVERY_DESTINATION":
            descriptors.append(descriptor)
            if phase == "anchor":
                replace()
        return original_anchor(descriptor, path, prefix)

    def connect(database_uri, *args, **kwargs):
        connection = original_connect(database_uri, *args, **kwargs)
        if "mode=rw&" in str(database_uri):
            connections.append(connection)
            if phase == "connect":
                replace()
        return connection

    def validate(connection, path, prefix):
        if prefix == "RECOVERY_DESTINATION" and phase == "validate":
            replace()
        return original_validate(connection, path, prefix)

    def copy(operation, source_db, destination_db):
        if phase == "copy":
            replace()
        return original_copy(operation, source_db, destination_db)

    monkeypatch.setattr(recovery, "_anchored_database_path", anchor)
    monkeypatch.setattr(recovery.sqlite3, "connect", connect)
    monkeypatch.setattr(recovery, "_validate_connection_path", validate)
    monkeypatch.setattr(recovery, "_copy_online", copy)
    if operation == "backup":
        receipt = backup_database(source, destination, manifest, operation_id="binding-backup")
    else:
        receipt = restore_database(source, manifest, destination,
            artifact_sha256=str(backup["artifact_sha256"]), operation_id="binding-restore")

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "COMPLETION_UNCERTAIN"
    assert receipt["completion_uncertain"] is True
    assert receipt["destination_created"] is True
    assert receipt["destination_state"] == "unknown"
    assert destination.read_bytes() == replacement
    assert source.read_bytes() == source_before
    assert displaced.exists()
    assert manifest.exists() is (operation == "restore")
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


@pytest.mark.parametrize("operation", ("backup", "restore"))
@pytest.mark.parametrize("error,reason", ((OSError, "IO_ERROR"),
                                         (KeyboardInterrupt, "INTERRUPTED_AFTER_CREATE")))
def test_creation_failure_with_intact_binding_closes_connection(
    private_directory: Path, monkeypatch, operation: str, error, reason: str
) -> None:
    if operation == "restore":
        source, manifest, backup = successful_backup(private_directory)
    else:
        source = create_store(private_directory)
        manifest = private_directory / "manifest.json"
    destination = private_directory / "candidate.db"
    connections = []
    original_validate = recovery._validate_connection_path

    def fail_validation(connection, path, prefix):
        original_validate(connection, path, prefix)
        if prefix == "RECOVERY_DESTINATION":
            connections.append(connection)
            raise error("synthetic creation failure")

    monkeypatch.setattr(recovery, "_validate_connection_path", fail_validation)
    if operation == "backup":
        receipt = backup_database(source, destination, manifest, operation_id="failed-backup")
    else:
        receipt = restore_database(source, manifest, destination,
            artifact_sha256=str(backup["artifact_sha256"]), operation_id="failed-restore")
    assert_contract_receipt(receipt)
    assert receipt["reason"] == reason
    assert receipt["completion_uncertain"] is False
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()
    assert manifest.exists() is (operation == "restore")
    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_restore_in_place_is_refused_before_creation(private_directory: Path) -> None:
    artifact, manifest, backup = successful_backup(private_directory)
    before = artifact.read_bytes()

    receipt = restore_database(
        artifact,
        manifest,
        artifact,
        artifact_sha256=str(backup["artifact_sha256"]),
        operation_id="restore-in-place",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "SAME_FILE_REFUSED"
    assert artifact.read_bytes() == before


def test_manifest_collision_refuses_backup_before_artifact_creation(
    private_directory: Path,
) -> None:
    source = create_store(private_directory)
    artifact = private_directory / "backup.db"
    manifest = private_directory / "manifest.json"
    manifest.write_text("review pending", encoding="utf-8")
    manifest.chmod(0o600)

    receipt = backup_database(
        source, artifact, manifest, operation_id="backup-manifest-collision"
    )

    assert receipt["reason"] == "DESTINATION_EXISTS"
    assert receipt["destination_created"] is False
    assert not artifact.exists()
    assert manifest.read_text(encoding="utf-8") == "review pending"


def test_restore_rejects_changed_artifact_digest_before_destination_creation(
    private_directory: Path,
) -> None:
    artifact, manifest, backup = successful_backup(private_directory)
    with artifact.open("r+b") as handle:
        handle.seek(-1, os.SEEK_END)
        original = handle.read(1)
        handle.seek(-1, os.SEEK_END)
        handle.write(bytes((original[0] ^ 1,)))
    destination = private_directory / "restore.db"

    receipt = restore_database(
        artifact,
        manifest,
        destination,
        artifact_sha256=str(backup["artifact_sha256"]),
        operation_id="restore-corrupt",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "ARTIFACT_CORRUPT"
    assert receipt["source_state"] == "corrupt"
    assert not destination.exists()


def test_wrong_schema_and_foreign_key_violation_fail_before_creation(
    private_directory: Path,
) -> None:
    wrong_version = create_store(private_directory, "wrong-version.db")
    with sqlite3.connect(wrong_version) as connection:
        connection.execute("PRAGMA user_version=2")
    wrong_destination = private_directory / "wrong-backup.db"
    wrong = backup_database(
        wrong_version,
        wrong_destination,
        private_directory / "wrong-manifest.json",
        operation_id="backup-wrong-version",
    )
    assert wrong["reason"] == "SCHEMA_INCOMPATIBLE"
    assert not wrong_destination.exists()

    invalid_fk = create_store(private_directory, "invalid-fk.db")
    with sqlite3.connect(invalid_fk) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO detections "
            "(event_id, detected_at, rule_id, severity, src_ip, dst_ip, message, "
            "evidence_json, recommendation, suppressed_reason) "
            "VALUES (999, '2026-09-19T00:00:00Z', 'test', 'LOW', '127.0.0.1', "
            "'127.0.0.1', 'test', '{}', 'review', NULL)"
        )
    fk_destination = private_directory / "fk-backup.db"
    foreign_key = backup_database(
        invalid_fk,
        fk_destination,
        private_directory / "fk-manifest.json",
        operation_id="backup-invalid-fk",
    )
    assert foreign_key["reason"] == "FOREIGN_KEY_VIOLATION"
    assert not fk_destination.exists()


def test_non_private_source_and_unsafe_destination_ancestry_fail_closed(
    private_directory: Path,
) -> None:
    source = create_store(private_directory)
    source.chmod(0o640)
    receipt = backup_database(
        source,
        private_directory / "backup.db",
        private_directory / "manifest.json",
        operation_id="backup-public-source",
    )
    assert receipt["reason"] == "SOURCE_NOT_PRIVATE"

    source.chmod(0o600)
    unsafe = private_directory / "unsafe"
    unsafe.mkdir(mode=0o755)
    receipt = backup_database(
        source,
        unsafe / "backup.db",
        private_directory / "safe-manifest.json",
        operation_id="backup-unsafe-destination",
    )
    assert receipt["reason"] == "DESTINATION_UNSAFE"
    assert not (unsafe / "backup.db").exists()


def test_unavailable_corrupt_symlink_and_hardlink_sources_are_classified(
    private_directory: Path,
) -> None:
    cases: list[tuple[Path, str]] = []
    cases.append((private_directory / "missing.db", "SOURCE_UNAVAILABLE"))

    corrupt = private_directory / "corrupt.db"
    corrupt.write_bytes(b"not a sqlite database")
    corrupt.chmod(0o600)
    cases.append((corrupt, "SOURCE_CORRUPT"))

    target = create_store(private_directory, "symlink-target.db")
    symlink = private_directory / "source-link.db"
    symlink.symlink_to(target)
    cases.append((symlink, "SOURCE_UNSAFE"))

    linked = create_store(private_directory, "hardlinked.db")
    os.link(linked, private_directory / "second-link.db")
    cases.append((linked, "SOURCE_NOT_PRIVATE"))

    for index, (source, reason) in enumerate(cases):
        receipt = backup_database(
            source,
            private_directory / f"classified-{index}.db",
            private_directory / f"classified-{index}.json",
            operation_id=f"backup-classified-{index}",
        )
        assert_contract_receipt(receipt)
        assert receipt["reason"] == reason
        assert receipt["destination_created"] is False


def test_source_path_replacement_after_copy_is_identity_failure(
    private_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_store(private_directory)
    moved = private_directory / "moved-source.db"
    original_copy = recovery._copy_online

    def replace_after_copy(operation, source_database, destination_database):
        original_copy(operation, source_database, destination_database)
        source.rename(moved)
        with Store(source):
            pass

    monkeypatch.setattr(recovery, "_copy_online", replace_after_copy)
    destination = private_directory / "backup.db"
    receipt = backup_database(
        source,
        destination,
        private_directory / "manifest.json",
        operation_id="backup-source-replaced",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "SOURCE_IDENTITY_CHANGED"
    assert receipt["source_state"] == "identity_changed"
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()


def test_insufficient_reserve_refuses_before_destination_creation(
    private_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_store(private_directory)
    monkeypatch.setattr(
        recovery.os,
        "fstatvfs",
        lambda _descriptor: SimpleNamespace(f_bavail=1, f_frsize=4096),
    )
    destination = private_directory / "backup.db"

    receipt = backup_database(
        source,
        destination,
        private_directory / "manifest.json",
        operation_id="backup-no-reserve",
    )

    assert receipt["reason"] == "DISK_RESERVE_INSUFFICIENT"
    assert receipt["destination_created"] is False
    assert not destination.exists()


def test_post_copy_reserve_failure_preserves_incomplete_destination(
    private_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_store(private_directory)
    destination = private_directory / "backup.db"
    calls = 0

    def changing_space(_descriptor):
        nonlocal calls
        calls += 1
        available = 8 * 1024**3 if calls == 1 else 1
        return SimpleNamespace(f_bavail=available, f_frsize=1)

    monkeypatch.setattr(recovery.os, "fstatvfs", changing_space)
    receipt = backup_database(
        source,
        destination,
        private_directory / "manifest.json",
        operation_id="backup-reserve-consumed",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "DISK_RESERVE_INSUFFICIENT"
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()


def test_interruption_after_create_preserves_incomplete_destination(
    private_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_store(private_directory)
    destination = private_directory / "backup.db"

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(recovery, "_copy_online", interrupt)
    receipt = backup_database(
        source,
        destination,
        private_directory / "manifest.json",
        operation_id="backup-interrupted",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "INTERRUPTED_AFTER_CREATE"
    assert receipt["destination_state"] == "incomplete_preserved"
    assert destination.exists()


def test_busy_retry_ceiling_and_deadline_are_closed_classifications(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation = recovery._new_operation("backup", "backup-busy")
    calls = 0

    def locked():
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(recovery.time, "sleep", lambda _seconds: None)
    with pytest.raises(recovery._RecoveryFailure) as busy:
        recovery._retry_busy(operation, locked)
    assert busy.value.reason == "LOCK_TIMEOUT"
    assert calls == recovery.MAX_BUSY_RETRIES + 1

    monkeypatch.setattr(
        recovery, "_monotonic", lambda: operation.deadline + 0.001
    )
    with pytest.raises(recovery._RecoveryFailure) as deadline:
        operation.check_deadline()
    assert deadline.value.reason == "DEADLINE_EXCEEDED"


def test_wall_clock_rollback_overrides_failure_reason_with_valid_receipt(
    private_directory: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    moments = iter(
        (
            datetime(2026, 9, 19, 12, 0, 1, tzinfo=timezone.utc),
            datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr(recovery, "_wall_now", lambda: next(moments))

    receipt = backup_database(
        private_directory / "missing.db",
        private_directory / "backup.db",
        private_directory / "manifest.json",
        operation_id="backup-clock-rollback",
    )

    assert_contract_receipt(receipt)
    assert receipt["reason"] == "CLOCK_ROLLBACK"
    assert receipt["clock_rollback_observed"] is True


def test_invalid_manifest_and_config_emit_input_invalid_receipts(
    private_directory: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact, manifest, backup = successful_backup(private_directory)
    manifest.write_text('{"schema_version":"wrong"}\n', encoding="utf-8")
    destination = private_directory / "restore.db"
    receipt = restore_database(
        artifact,
        manifest,
        destination,
        artifact_sha256=str(backup["artifact_sha256"]),
        operation_id="restore-invalid-manifest",
    )
    assert_contract_receipt(receipt)
    assert receipt["reason"] == "INPUT_INVALID"
    assert not destination.exists()

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "database-backup", str(private_directory / "never-created.db"),
                "--manifest", str(private_directory / "never-created.json"),
                "--operation-id", "backup-invalid-config", "--config",
                str(private_directory / "missing.toml"),
            ]
        )
    assert exit_info.value.code == 2
    cli_receipt = json.loads(capsys.readouterr().out)
    assert_contract_receipt(cli_receipt)
    assert cli_receipt["reason"] == "INPUT_INVALID"


def test_runtime_uses_only_online_backup_and_has_no_network_or_copy_primitive() -> None:
    source = inspect.getsource(recovery)
    assert ".backup(" in source
    assert "pages=PAGES_PER_STEP" in source
    assert "import socket" not in source
    assert "import urllib" not in source
    assert "import shutil" not in source
    assert "copyfile" not in source


def test_cli_emits_receipts_and_does_not_activate_restore(
    private_directory: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = create_store(private_directory)
    config = private_directory / "settings.toml"
    config.write_text(f'[app]\ndb_path = "{source}"\n', encoding="utf-8")
    config.chmod(0o600)
    artifact = private_directory / "cli-backup.db"
    manifest = private_directory / "cli-manifest.json"

    with pytest.raises(SystemExit) as backup_exit:
        main(
            [
                "database-backup", str(artifact), "--manifest", str(manifest),
                "--operation-id", "cli-backup", "--config", str(config),
            ]
        )
    assert backup_exit.value.code == 0
    backup = json.loads(capsys.readouterr().out)
    assert_contract_receipt(backup)

    destination = private_directory / "cli-restored.db"
    with pytest.raises(SystemExit) as restore_exit:
        main(
            [
                "database-restore", str(artifact), str(destination),
                "--manifest", str(manifest), "--artifact-sha256",
                str(backup["artifact_sha256"]), "--operation-id", "cli-restore",
            ]
        )
    assert restore_exit.value.code == 0
    restored = json.loads(capsys.readouterr().out)
    assert_contract_receipt(restored)
    assert source != destination
    assert config.read_text(encoding="utf-8").endswith(f'{source}"\n')
