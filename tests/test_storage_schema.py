"""SQLite schema identity and migration boundaries."""

from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from megalodon.storage import (
    MIGRATION_BACKUP_SUFFIX,
    SCHEMA_V1_STATEMENTS,
    SCHEMA_VERSION,
    migrate_database,
    StorageSchemaError,
    Store,
)


APPLICATION_TABLES_V1 = {"events", "detections", "actions"}
APPLICATION_TABLES = {
    *APPLICATION_TABLES_V1,
    "ingestion_runs",
    "ingestion_run_events",
}


def _application_tables(path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
            if row[0] in APPLICATION_TABLES
        }


def _create_v1(path, *, version: int = 1) -> None:
    with sqlite3.connect(path) as connection:
        for statement in SCHEMA_V1_STATEMENTS:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO actions (created_at, action, target, status, reason, details_json) "
            "VALUES ('2026-01-01T00:00:00+00:00', 'test', '192.0.2.1', "
            "'not_attempted', 'legacy', '{}')"
        )
        connection.execute(f"PRAGMA user_version = {version}")


def test_fresh_database_is_created_at_the_explicit_schema_version(tmp_path):
    path = tmp_path / "audit.db"

    with Store(path) as store:
        version = store.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []

    assert _application_tables(path) == APPLICATION_TABLES


@pytest.mark.parametrize("version", (0, 1))
def test_exact_legacy_database_requires_explicit_migration_without_mutation(
    tmp_path, version
):
    path = tmp_path / "audit.db"
    _create_v1(path, version=version)

    with pytest.raises(StorageSchemaError, match="^STORAGE_SCHEMA:MIGRATION_REQUIRED$"):
        Store(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == version
        assert connection.execute("SELECT reason FROM actions").fetchone()[0] == "legacy"
    assert _application_tables(path) == APPLICATION_TABLES_V1


@pytest.mark.parametrize("version", (0, 1))
def test_explicit_migration_backs_up_and_preserves_the_v1_database(tmp_path, version):
    path = tmp_path / "audit.db"
    backup_path = path.with_name(path.name + MIGRATION_BACKUP_SUFFIX)
    _create_v1(path, version=version)

    receipt = migrate_database(path)

    assert receipt == {
        "status": "migrated",
        "from_version": version,
        "to_version": SCHEMA_VERSION,
        "backup": str(backup_path),
    }
    if os.name == "posix":
        assert stat.S_IMODE(backup_path.stat().st_mode) == 0o600
    with Store(path) as migrated:
        assert migrated.connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert migrated.connection.execute("SELECT reason FROM actions").fetchone()[0] == "legacy"
        assert migrated.connection.execute("SELECT COUNT(*) FROM ingestion_runs").fetchone()[0] == 0
        assert migrated.connection.execute(
            "SELECT COUNT(*) FROM ingestion_run_events"
        ).fetchone()[0] == 0
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("PRAGMA user_version").fetchone()[0] == version
        assert backup.execute("SELECT reason FROM actions").fetchone()[0] == "legacy"
        assert {
            row[0]
            for row in backup.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
            if row[0] in APPLICATION_TABLES
        } == APPLICATION_TABLES_V1


def test_current_database_migration_is_an_idempotent_no_op(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path):
        pass

    assert migrate_database(path) == {
        "status": "already_current",
        "from_version": SCHEMA_VERSION,
        "to_version": SCHEMA_VERSION,
        "backup": None,
    }
    assert not path.with_name(path.name + MIGRATION_BACKUP_SUFFIX).exists()


def test_existing_backup_is_never_overwritten(tmp_path):
    path = tmp_path / "audit.db"
    backup_path = path.with_name(path.name + MIGRATION_BACKUP_SUFFIX)
    _create_v1(path)
    backup_path.write_bytes(b"operator-owned")

    with pytest.raises(StorageSchemaError, match="^STORAGE_MIGRATION:BACKUP_EXISTS$"):
        migrate_database(path)

    assert backup_path.read_bytes() == b"operator-owned"
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_migration_refuses_missing_and_symlink_sources(tmp_path):
    with pytest.raises(StorageSchemaError, match="^STORAGE_MIGRATION:NO_DATABASE$"):
        migrate_database(tmp_path / "missing.db")

    path = tmp_path / "audit.db"
    alias = tmp_path / "alias.db"
    _create_v1(path)
    try:
        alias.symlink_to(path)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")

    with pytest.raises(StorageSchemaError, match="^STORAGE_MIGRATION:SYMLINK_REFUSED$"):
        migrate_database(alias)
    assert not alias.with_name(alias.name + MIGRATION_BACKUP_SUFFIX).exists()


def test_failed_v2_migration_rolls_back_and_retains_verified_backup(tmp_path):
    path = tmp_path / "audit.db"
    backup_path = path.with_name(path.name + MIGRATION_BACKUP_SUFFIX)
    _create_v1(path)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sentinel (started_at TEXT)")
        connection.execute(
            "CREATE INDEX idx_ingestion_runs_started_at ON sentinel(started_at)"
        )

    with pytest.raises(StorageSchemaError, match="^STORAGE_MIGRATION:MIGRATION_FAILED$"):
        migrate_database(path)

    assert backup_path.is_file()
    assert _application_tables(path) == APPLICATION_TABLES_V1
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT reason FROM actions").fetchone()[0] == "legacy"
    with sqlite3.connect(backup_path) as backup:
        assert backup.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert backup.execute("SELECT reason FROM actions").fetchone()[0] == "legacy"


def test_partial_unversioned_schema_is_refused_without_completion(tmp_path):
    path = tmp_path / "audit.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY)")

    with pytest.raises(StorageSchemaError, match="^STORAGE_SCHEMA:INCOMPATIBLE$"):
        Store(path)

    assert _application_tables(path) == {"events"}
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0


def test_versioned_schema_with_missing_index_is_refused(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        store.connection.execute("DROP INDEX idx_events_src_ip")
        store.connection.commit()

    with pytest.raises(StorageSchemaError, match="^STORAGE_SCHEMA:INCOMPATIBLE$"):
        Store(path)

    with sqlite3.connect(path) as connection:
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'index'"
            )
        }
        assert "idx_events_src_ip" not in indexes


def test_future_schema_is_refused_before_journal_or_table_mutation(tmp_path):
    path = tmp_path / "audit.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE future_marker (value TEXT NOT NULL)")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")

    with pytest.raises(StorageSchemaError, match="^STORAGE_SCHEMA:FUTURE_VERSION$"):
        Store(path)

    assert _application_tables(path) == set()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION + 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("SELECT COUNT(*) FROM future_marker").fetchone()[0] == 0


def test_failed_initial_migration_rolls_back_all_application_objects(tmp_path):
    path = tmp_path / "audit.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE sentinel (observed_at TEXT)")
        connection.execute(
            "CREATE INDEX idx_events_observed_at ON sentinel(observed_at)"
        )

    with pytest.raises(StorageSchemaError, match="^STORAGE_SCHEMA:MIGRATION_FAILED$"):
        Store(path)

    assert _application_tables(path) == set()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'sentinel'"
        ).fetchone()[0] == 1
