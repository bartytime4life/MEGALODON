"""Bounded, preview-bound retention batches over synthetic audit evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import sqlite3

import pytest

from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import (
    MAX_RETENTION_BATCH_ROWS,
    RETENTION_RECEIPT_VERSION,
    RETENTION_RECONCILIATION_REQUIRED,
    RetentionError,
    StorageSchemaError,
    Store,
)


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)
CUTOFF = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _populate_bundle(store: Store, *, stamp: datetime = STAMP, suffix: int = 1) -> None:
    event = PacketEvent(
        stamp,
        f"192.0.2.{suffix}",
        "198.51.100.2",
        "TCP",
    )
    event_id = store.record_event(event)
    store.record_detection(
        event_id,
        DetectionResult(
            stamp,
            "TEST",
            "LOW",
            event.src_ip,
            event.dst_ip,
            "synthetic",
        ),
    )
    store.record_action(
        ActionRecord(
            stamp,
            "test",
            event.src_ip,
            "not_attempted",
            "synthetic",
        )
    )


def _apply_preview(store: Store, preview: dict[str, object]) -> dict[str, object]:
    return store.purge_before(
        datetime.fromisoformat(str(preview["cutoff"])),
        batch_limit=int(preview["batch_limit"]),
        preview_token=str(preview["preview_token"]),
    )


def test_preview_is_bounded_path_free_and_non_mutating(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        _populate_bundle(store)
        before = store.summary()

        preview = store.preview_purge(CUTOFF, batch_limit=2)

        assert set(preview) == {
            "receipt_version",
            "store_identity",
            "cutoff",
            "batch_limit",
            "candidate_counts",
            "candidate_total",
            "batch_full",
            "preview_token",
        }
        assert preview["receipt_version"] == RETENTION_RECEIPT_VERSION
        assert preview["candidate_counts"] == {
            "detections": 1,
            "events": 1,
            "actions": 0,
        }
        assert preview["candidate_total"] == 2
        assert preview["batch_full"] is True
        assert str(preview["store_identity"]).startswith("sha256:")
        assert str(preview["preview_token"]).startswith("sha256:")
        assert os.fspath(path) not in json.dumps(preview, sort_keys=True)
        assert store.summary() == before


@pytest.mark.parametrize(
    "batch_limit",
    (True, False, 0, -1, MAX_RETENTION_BATCH_ROWS + 1, 1.0, "1", None),
)
def test_preview_rejects_ambiguous_or_unbounded_batch_limits(tmp_path, batch_limit):
    with Store(tmp_path / "audit.db") as store:
        with pytest.raises(RetentionError, match="^RETENTION:INVALID_BATCH_LIMIT$"):
            store.preview_purge(CUTOFF, batch_limit=batch_limit)


@pytest.mark.parametrize("preview_token", ("", "sha256:", "sha256:" + "A" * 64, None))
def test_apply_rejects_malformed_preview_tokens_without_deleting(tmp_path, preview_token):
    with Store(tmp_path / "audit.db") as store:
        _populate_bundle(store)
        before = store.summary()

        with pytest.raises(RetentionError, match="^RETENTION:INVALID_PREVIEW_TOKEN$"):
            store.purge_before(
                CUTOFF,
                batch_limit=1,
                preview_token=preview_token,
            )

        assert store.summary() == before


def test_apply_rejects_stale_preview_after_candidate_change(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        preview = store.preview_purge(CUTOFF, batch_limit=1)
        _populate_bundle(store)
        before = store.summary()

        with pytest.raises(RetentionError, match="^RETENTION:STALE_PREVIEW$"):
            _apply_preview(store, preview)

        assert store.summary() == before


def test_preview_token_binds_cutoff_and_batch_limit(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        _populate_bundle(store)
        preview = store.preview_purge(CUTOFF, batch_limit=1)
        before = store.summary()

        with pytest.raises(RetentionError, match="^RETENTION:STALE_PREVIEW$"):
            store.purge_before(
                CUTOFF + timedelta(seconds=1),
                batch_limit=1,
                preview_token=str(preview["preview_token"]),
            )
        with pytest.raises(RetentionError, match="^RETENTION:STALE_PREVIEW$"):
            store.purge_before(
                CUTOFF,
                batch_limit=2,
                preview_token=str(preview["preview_token"]),
            )

        assert store.summary() == before


def test_preview_token_survives_a_clean_store_restart(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path) as store:
        _populate_bundle(store)
        preview = store.preview_purge(CUTOFF, batch_limit=2)

    with Store(path) as reopened:
        receipt = _apply_preview(reopened, preview)

        assert receipt["deleted_total"] == 2
        assert receipt["complete"] is False


def test_every_transaction_has_a_finite_total_and_reports_completion(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        for suffix in range(1, 4):
            _populate_bundle(store, suffix=suffix)

        receipts = []
        for _ in range(10):
            preview = store.preview_purge(CUTOFF, batch_limit=2)
            receipt = _apply_preview(store, preview)
            receipts.append(receipt)
            assert 0 <= int(receipt["deleted_total"]) <= 2
            assert sum(receipt["deleted"].values()) == receipt["deleted_total"]
            if receipt["complete"]:
                break
        else:
            pytest.fail("bounded retention did not reach a terminal empty batch")

        assert sum(int(receipt["deleted_total"]) for receipt in receipts) == 9
        assert receipts[-1]["complete"] is True
        assert store.summary() == {
            "events": 0,
            "detections": 0,
            "actions": 0,
            "high_or_critical": 0,
        }


def test_batch_does_not_sever_a_link_to_a_non_candidate_detection(tmp_path):
    newer = datetime(2028, 1, 1, tzinfo=timezone.utc)
    event = PacketEvent(newer, "192.0.2.10", "198.51.100.2", "TCP")
    detection = DetectionResult(
        newer,
        "TEST",
        "LOW",
        event.src_ip,
        event.dst_ip,
        "synthetic",
    )
    old_action = ActionRecord(
        STAMP,
        "test",
        event.src_ip,
        "not_attempted",
        "synthetic",
    )
    with Store(tmp_path / "audit.db") as store:
        event_id = store.record_event(event)
        detection_id = store.record_detection(event_id, detection)
        action_id = store.record_action(old_action)
        store.connection.execute(
            "INSERT INTO detection_actions (detection_id, action_id) VALUES (?, ?)",
            (detection_id, action_id),
        )
        store.connection.commit()

        preview = store.preview_purge(CUTOFF)
        assert preview["candidate_total"] == 0
        receipt = _apply_preview(store, preview)

        assert receipt["deleted_total"] == 0
        assert receipt["complete"] is True
        assert store.summary() == {
            "events": 1,
            "detections": 1,
            "actions": 1,
            "high_or_critical": 0,
        }


def test_active_or_reconciliation_required_run_blocks_preview(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        with pytest.raises(RetentionError, match="^RETENTION:ACTIVE_RUN$"):
            store.preview_purge(CUTOFF)

        store.mark_ingestion_run_reconciliation_required(
            run_id, expected_started_at=STAMP
        )
        with pytest.raises(RetentionError, match="^RETENTION:ACTIVE_RUN$"):
            store.preview_purge(CUTOFF)


def test_unrelated_open_transaction_blocks_preview_without_committing_it(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        store.connection.execute("BEGIN")
        try:
            with pytest.raises(
                RetentionError, match="^RETENTION:ACTIVE_TRANSACTION$"
            ):
                store.preview_purge(CUTOFF)
            assert store.connection.in_transaction is True
        finally:
            store.connection.rollback()


@pytest.mark.skipif(os.name != "posix", reason="POSIX pathname replacement semantics")
def test_apply_refuses_replaced_database_path_before_deletion(tmp_path):
    path = tmp_path / "audit.db"
    moved = tmp_path / "moved.db"
    with Store(path) as store:
        _populate_bundle(store)
        preview = store.preview_purge(CUTOFF, batch_limit=1)
        before = store.summary()
        path.rename(moved)
        path.write_bytes(b"replacement")
        path.chmod(0o600)

        with pytest.raises(StorageSchemaError, match="STORAGE_PATH:DATABASE_CHANGED"):
            _apply_preview(store, preview)

        assert store.summary() == before


def test_uncertain_commit_poisoning_emits_no_success_receipt(tmp_path, monkeypatch):
    with Store(tmp_path / "audit.db") as store:
        _populate_bundle(store)
        preview = store.preview_purge(CUTOFF, batch_limit=1)
        before = store.summary()

        def fail_commit():
            raise sqlite3.OperationalError("synthetic uncertain commit")

        monkeypatch.setattr(store, "_connection_commit", fail_commit)
        with pytest.raises(
            RetentionError, match=f"^{RETENTION_RECONCILIATION_REQUIRED}$"
        ):
            _apply_preview(store, preview)

        assert store._write_poisoned is True
        assert store.summary() == before
