from __future__ import annotations

from datetime import datetime, timezone
import sqlite3

import pytest

from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import Store


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _populate(store: Store) -> None:
    event = PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")
    event_id = store.record_event(event)
    store.record_detection(
        event_id,
        DetectionResult(STAMP, "TEST", "LOW", event.src_ip, event.dst_ip, "synthetic"),
    )
    store.record_action(
        ActionRecord(STAMP, "test", event.src_ip, "not_attempted", "synthetic")
    )


def test_purge_requires_a_timezone_aware_cutoff(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)
        before = store.summary()

        with pytest.raises(ValueError, match="timezone-aware"):
            store.purge_before(datetime(2027, 1, 1))

        assert store.summary() == before


def test_purge_removes_all_matching_audit_rows(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)

        assert store.purge_before(datetime(2027, 1, 1, tzinfo=timezone.utc)) == {
            "detections": 1,
            "events": 1,
            "actions": 1,
        }
        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "actions": 0,
            "high_or_critical": 0,
        }


def test_purge_rolls_back_every_table_when_one_delete_fails(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate(store)
        before = store.summary()
        store.connection.execute(
            """
            CREATE TRIGGER stop_event_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'synthetic failure');
            END
            """
        )
        store.connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            store.purge_before(datetime(2027, 1, 1, tzinfo=timezone.utc))

        assert store.connection.in_transaction is False
        assert store.summary() == before
