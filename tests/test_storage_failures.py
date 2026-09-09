"""Synthetic transaction failures must not become later successful audit rows."""

from datetime import datetime, timezone
import sqlite3

import pytest

from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import Store


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
TABLES = ("events", "detections", "actions")


def _write(store, table, event_id):
    if table == "events":
        return store.record_event(PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP"))
    if table == "detections":
        return store.record_detection(
            event_id,
            DetectionResult(STAMP, "TEST", "LOW", "192.0.2.1", "198.51.100.2", "synthetic"),
        )
    assert table == "actions"
    return store.record_action(
        ActionRecord(STAMP, "test", "192.0.2.1", "not_attempted", "synthetic")
    )


def _counts(connection):
    # Table names are closed test constants, never event data.
    return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in TABLES}


@pytest.mark.parametrize("table", TABLES)
@pytest.mark.parametrize("failure", ("statement", "commit"))
def test_failed_audit_write_is_rolled_back_and_cannot_leak_into_next_commit(tmp_path, table, failure):
    path = tmp_path / "synthetic.db"
    with Store(path) as store:
        event_id = _write(store, "events", None)
        _write(store, "detections", event_id)
        _write(store, "actions", event_id)
        before = _counts(store.connection)

        if failure == "statement":
            # FAIL preserves the tentative row unless the caller rolls back.
            body = "SELECT RAISE(FAIL, 'synthetic statement failure');"
        else:
            # A real deferred constraint makes INSERT succeed but COMMIT fail.
            store.connection.execute(
                "CREATE TABLE deferred_failure (event_id INTEGER REFERENCES events(id) "
                "DEFERRABLE INITIALLY DEFERRED)"
            )
            body = "INSERT INTO deferred_failure VALUES (-1);"
        store.connection.execute(
            f"CREATE TRIGGER fail_audit_write AFTER INSERT ON {table} BEGIN {body} END"
        )
        store.connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            _write(store, table, event_id)

        assert store.connection.in_transaction is False
        assert _counts(store.connection) == before
        with sqlite3.connect(path) as observer:
            assert _counts(observer) == before
        if failure == "commit":
            assert store.connection.execute("SELECT COUNT(*) FROM deferred_failure").fetchone()[0] == 0

        store.connection.execute("DROP TRIGGER fail_audit_write")
        store.connection.commit()
        assert isinstance(_write(store, table, event_id), int)
        expected = dict(before)
        expected[table] += 1
        assert store.connection.in_transaction is False
        assert _counts(store.connection) == expected
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []

    # A successful subsequent write must not durably commit the failed one.
    with sqlite3.connect(path) as observer:
        assert _counts(observer) == expected


@pytest.mark.parametrize("table", TABLES)
def test_read_only_audit_failure_propagates_without_success_or_rows(tmp_path, table):
    with Store(tmp_path / "synthetic.db") as store:
        event_id = _write(store, "events", None)
        before = _counts(store.connection)
        store.connection.execute("PRAGMA query_only=ON")
        try:
            with pytest.raises(sqlite3.OperationalError):
                _write(store, table, event_id)
            assert store.connection.in_transaction is False
            assert _counts(store.connection) == before
        finally:
            store.connection.execute("PRAGMA query_only=OFF")
        assert isinstance(_write(store, table, event_id), int)


def test_synthetic_database_full_stops_without_a_phantom_success(tmp_path):
    path = tmp_path / "synthetic.db"
    with Store(path) as store:
        page_count = store.connection.execute("PRAGMA page_count").fetchone()[0]
        assert store.connection.execute(
            f"PRAGMA max_page_count={page_count}"
        ).fetchone()[0] == page_count
        event = PacketEvent(
            STAMP,
            "192.0.2.1",
            "198.51.100.2",
            "TCP",
            interface="synthetic-page-budget",
        )

        committed = 0
        for _ in range(1000):
            try:
                store.record_event(event)
            except sqlite3.OperationalError as exc:
                assert "full" in str(exc).lower()
                break
            committed += 1
        else:
            pytest.fail("synthetic database did not reach its fixed page budget")

        assert store.connection.in_transaction is False
        assert store.summary()["events"] == committed
        with sqlite3.connect(path) as observer:
            assert observer.execute("SELECT COUNT(*) FROM events").fetchone()[0] == committed


def test_injected_connect_permission_denial_propagates_without_database(tmp_path, monkeypatch):
    path = tmp_path / "private" / "synthetic.db"

    def denied(*_args, **_kwargs):
        raise PermissionError("synthetic permission denial")

    monkeypatch.setattr(sqlite3, "connect", denied)
    with pytest.raises(PermissionError, match="synthetic permission denial"):
        Store(path)
    assert not path.exists()


def test_sqlite_interruption_rolls_back_the_active_write(tmp_path):
    path = tmp_path / "synthetic.db"
    with Store(path) as store:
        before = store.summary()
        store.connection.set_progress_handler(lambda: 1, 1)
        try:
            with pytest.raises(sqlite3.OperationalError, match="interrupted"):
                _write(store, "events", None)
        finally:
            store.connection.set_progress_handler(None, 0)

        assert store.connection.in_transaction is False
        assert store.summary() == before
    with sqlite3.connect(path) as observer:
        assert _counts(observer) == {table: 0 for table in TABLES}
