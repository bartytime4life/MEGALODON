"""SQLite schema identity and migration boundaries."""

from __future__ import annotations

import sqlite3

import pytest

from megalodon.storage import SCHEMA_VERSION, StorageSchemaError, Store


APPLICATION_TABLES = {"events", "detections", "actions"}


def _application_tables(path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
            if row[0] in APPLICATION_TABLES
        }


def test_fresh_database_is_created_at_the_explicit_schema_version(tmp_path):
    path = tmp_path / "audit.db"

    with Store(path) as store:
        version = store.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []

    assert _application_tables(path) == APPLICATION_TABLES


def test_exact_unversioned_legacy_database_is_adopted_without_losing_rows(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        store.connection.execute(
            "INSERT INTO actions (created_at, action, target, status, reason, details_json) "
            "VALUES ('2026-01-01T00:00:00+00:00', 'test', '192.0.2.1', "
            "'not_attempted', 'legacy', '{}')"
        )
        store.connection.execute("PRAGMA user_version = 0")
        store.connection.commit()

    with Store(path) as adopted:
        assert adopted.connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        row = adopted.connection.execute("SELECT reason FROM actions").fetchone()
        assert row[0] == "legacy"


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
