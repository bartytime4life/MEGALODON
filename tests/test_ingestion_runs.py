"""Bounded ingestion-run lifecycle and provenance receipts."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import io
import json
import signal
import sqlite3
from threading import Barrier

import pytest

from megalodon.cli import main
from megalodon.config import Settings
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import IngestionRunError, Store


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event() -> PacketEvent:
    return PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")


def _detection(event: PacketEvent) -> DetectionResult:
    return DetectionResult(
        event.observed_at,
        "TEST",
        "LOW",
        event.src_ip,
        event.dst_ip,
        "synthetic",
    )


def _action(event: PacketEvent) -> ActionRecord:
    return ActionRecord(
        event.observed_at,
        "block",
        event.src_ip,
        "not_attempted",
        "synthetic policy decision",
    )


def _config(tmp_path) -> tuple[object, object]:
    database = tmp_path / "audit.db"
    config = tmp_path / "settings.toml"
    config.write_text(
        f'[app]\ndb_path = "{database.as_posix()}"\n', encoding="utf-8"
    )
    return config, database


def test_completed_run_derives_counts_and_links_each_event(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        event = _event()
        event_id = store.record_event_bundle(
            event, [_detection(event)], [_action(event)], run_id=run_id
        )

        receipt = store.finish_ingestion_run(
            run_id, "source_exhausted", finished_at=STAMP + timedelta(seconds=1)
        )

        assert receipt == {
            "run_id": run_id,
            "source": "sample",
            "status": "completed",
            "termination_reason": "source_exhausted",
            "processed": 1,
            "detections": 1,
            "actions": 1,
            "failure_code": None,
        }
        row = store.connection.execute(
            "SELECT status, processed_count, detection_count, action_count, "
            "failure_code, termination_reason "
            "FROM ingestion_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        assert tuple(row) == ("completed", 1, 1, 1, None, "source_exhausted")
        assert tuple(
            store.connection.execute(
                "SELECT run_id, event_id FROM ingestion_run_events"
            ).fetchone()
        ) == (run_id, event_id)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM detection_actions"
        ).fetchone()[0] == 1


def test_run_finalization_reconciles_a_counter_mismatch(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        event = _event()
        store.record_event_bundle(
            event, [_detection(event)], [_action(event)], run_id=run_id
        )
        store.connection.execute(
            "UPDATE ingestion_runs SET detection_count = 0 WHERE id = ?", (run_id,)
        )
        store.connection.commit()

        receipt = store.finish_ingestion_run(
            run_id, "source_exhausted", finished_at=STAMP + timedelta(seconds=1)
        )

        assert receipt["status"] == "reconciliation_required"
        assert receipt["termination_reason"] == "reconciliation_required"
        assert receipt["detections"] == 1
        assert store.connection.execute(
            "SELECT finished_at FROM ingestion_runs WHERE id = ?", (run_id,)
        ).fetchone()[0] is None


def test_event_bundle_and_all_run_counters_roll_back_together(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        store.connection.execute(
            "CREATE TRIGGER fail_run_count BEFORE UPDATE OF detection_count "
            "ON ingestion_runs BEGIN SELECT RAISE(FAIL, 'synthetic failure'); END"
        )
        store.connection.commit()

        with pytest.raises(sqlite3.DatabaseError, match="synthetic failure"):
            event = _event()
            store.record_event_bundle(
                event, [_detection(event)], [_action(event)], run_id=run_id
            )

        assert store.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert store.connection.execute(
            "SELECT COUNT(*) FROM detections"
        ).fetchone()[0] == 0
        assert store.connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0] == 0
        assert tuple(
            store.connection.execute(
                "SELECT processed_count, detection_count, action_count "
                "FROM ingestion_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        ) == (0, 0, 0)


def test_terminal_run_cannot_transition_or_accept_another_event(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("jsonl", started_at=STAMP)
        store.finish_ingestion_run(
            run_id,
            "failed",
            failure_code="CAPTURE_ERROR",
            finished_at=STAMP + timedelta(seconds=1),
        )

        with pytest.raises(IngestionRunError, match="^INGESTION_RUN:NOT_ACTIVE$"):
            store.finish_ingestion_run(
                run_id, "source_exhausted", finished_at=STAMP + timedelta(seconds=2)
            )
        with pytest.raises(IngestionRunError, match="^INGESTION_RUN:NOT_ACTIVE$"):
            store.record_event_bundle(_event(), [], [], run_id=run_id)

        assert store.summary()["events"] == 0
        assert store.connection.execute(
            "SELECT COUNT(*) FROM ingestion_run_events"
        ).fetchone()[0] == 0


def test_run_fields_are_closed_and_rejected_before_mutation(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        for source in ("", "pcap", 7):
            with pytest.raises(
                IngestionRunError, match="^INGESTION_RUN:INVALID_SOURCE$"
            ):
                store.start_ingestion_run(source)  # type: ignore[arg-type]
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:INVALID_TIMESTAMP$"
        ):
            store.start_ingestion_run("sample", started_at="")  # type: ignore[arg-type]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM ingestion_runs"
        ).fetchone()[0] == 0

        run_id = store.start_ingestion_run("scapy", started_at=STAMP)
        invalid = (
            ("running", None, "INVALID_TERMINATION"),
            ([], None, "INVALID_TERMINATION"),
            ("source_exhausted", "IO_ERROR", "INVALID_FAILURE"),
            ("failed", None, "INVALID_FAILURE"),
            ("failed", [], "INVALID_FAILURE"),
            ("failed", "SECRET/raw failure", "INVALID_FAILURE"),
        )
        for status, failure, code in invalid:
            with pytest.raises(IngestionRunError, match=f"^INGESTION_RUN:{code}$"):
                store.finish_ingestion_run(
                    run_id, status, failure_code=failure, finished_at=STAMP  # type: ignore[arg-type]
                )
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:INVALID_TIMESTAMP$"
        ):
            store.finish_ingestion_run(
                run_id, "source_exhausted", finished_at=STAMP - timedelta(seconds=1)
            )
        assert store.connection.execute(
            "SELECT status FROM ingestion_runs WHERE id = ?", (run_id,)
        ).fetchone()[0] == "running"


def test_unknown_or_invalid_run_id_rolls_back_the_event(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        for run_id, code in ((0, "INVALID_ID"), (False, "INVALID_ID"), (999, "NOT_ACTIVE")):
            with pytest.raises(IngestionRunError, match=f"^INGESTION_RUN:{code}$"):
                store.record_event_bundle(_event(), [], [], run_id=run_id)
        assert store.summary()["events"] == 0


def test_low_level_write_cannot_bypass_active_run_bundle(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:ATOMIC_WRITE_REQUIRED$"
        ):
            store.record_event(_event(), run_id=run_id)
        assert store.summary()["events"] == 0


def test_event_bundle_rejects_unbounded_or_oversized_collections_before_write(
    tmp_path
):
    event = _event()

    def forbidden_iterable():
        pytest.fail("unbounded input must not be materialized")
        yield _detection(event)

    class DeceptiveList(list):
        def __iter__(self):
            pytest.fail("list subclass input must not be iterated")
            return super().__iter__()

    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        invalid = (
            (forbidden_iterable(), []),
            (DeceptiveList([_detection(event)]), [_action(event)]),
            ([_detection(event)], []),
            ([_detection(event)] * 4, [_action(event)] * 4),
        )
        for detections, actions in invalid:
            with pytest.raises(
                IngestionRunError, match="^INGESTION_RUN:INVALID_BUNDLE$"
            ):
                store.record_event_bundle(  # type: ignore[arg-type]
                    event, detections, actions, run_id=run_id
                )

        assert store.summary()["events"] == 0
        assert tuple(
            store.connection.execute(
                "SELECT processed_count, detection_count, action_count "
                "FROM ingestion_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        ) == (0, 0, 0)


def test_concurrent_starts_create_exactly_one_running_receipt(tmp_path):
    path = tmp_path / "audit.db"
    with Store(path):
        pass
    with Store(path) as first, Store(path) as second:
        barrier = Barrier(2)

        def start(store):
            barrier.wait()
            try:
                return store.start_ingestion_run("sample", started_at=STAMP)
            except IngestionRunError as exc:
                return str(exc)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(start, (first, second)))

        assert sum(isinstance(item, int) for item in results) == 1
        assert results.count("INGESTION_RUN:RECONCILIATION_REQUIRED") == 1
        assert first.connection.execute(
            "SELECT COUNT(*) FROM ingestion_runs WHERE status = 'running'"
        ).fetchone()[0] == 1


def test_running_receipt_blocks_start_until_pinned_explicit_reconciliation(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        assert store.pending_ingestion_reconciliation() == [
            {
                "run_id": run_id,
                "started_at": STAMP.isoformat(),
                "source": "sample",
                "status": "running",
                "processed": 0,
                "detections": 0,
                "actions": 0,
                "receipt_version": 3,
                "termination_reason": None,
            }
        ]
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            store.start_ingestion_run("jsonl")
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:STALE_RECONCILIATION$"
        ):
            store.mark_ingestion_run_reconciliation_required(
                run_id, expected_started_at=STAMP + timedelta(seconds=1)
            )

        receipt = store.mark_ingestion_run_reconciliation_required(
            run_id, expected_started_at=STAMP
        )
        assert receipt["termination_reason"] == "reconciliation_required"
        assert store.mark_ingestion_run_reconciliation_required(
            run_id, expected_started_at=STAMP
        ) == receipt
        assert store.start_ingestion_run("jsonl") == run_id + 1


def test_running_orphan_is_visible_above_reconciliation_history_limit(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        for offset in range(101):
            started_at = STAMP + timedelta(seconds=offset)
            run_id = store.start_ingestion_run("sample", started_at=started_at)
            store.mark_ingestion_run_reconciliation_required(
                run_id, expected_started_at=started_at
            )
        orphan_id = store.start_ingestion_run(
            "jsonl", started_at=STAMP + timedelta(seconds=200)
        )

        pending = store.pending_ingestion_reconciliation(limit=100)

        assert len(pending) == 100
        assert pending[0]["run_id"] == orphan_id
        assert pending[0]["status"] == "running"
        assert sum(item["status"] == "running" for item in pending) == 1
        assert pending[1]["run_id"] == orphan_id - 1


def test_unknown_bundle_commit_poison_requires_reopen_and_reconciliation(
    tmp_path, monkeypatch
):
    path = tmp_path / "audit.db"
    settings = Settings(db_path=path)
    event = PacketEvent(
        STAMP,
        "192.0.2.1",
        "198.51.100.2",
        "DNS",
        dns_query_length=settings.detection.dns_query_length,
    )
    with Store(path) as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        service = MegalodonService(settings, store)

        def commit_then_report_failure():
            store.connection.commit()
            raise sqlite3.OperationalError("synthetic uncertain commit")

        monkeypatch.setattr(store, "_connection_commit", commit_then_report_failure)
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            service.process(event, run_id=run_id)

        assert event.src_ip not in service.detector.source_high_watermarks
        assert ("DNS_TUNNELING", event.src_ip) not in service.detector.last_emitted
        assert tuple(
            store.connection.execute(
                "SELECT processed_count, detection_count, action_count, status "
                "FROM ingestion_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        ) == (1, 1, 1, "running")
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            service.process(event, run_id=run_id)

    with Store(path) as reopened:
        assert [item["run_id"] for item in reopened.pending_ingestion_reconciliation()] == [
            run_id
        ]
        receipt = reopened.mark_ingestion_run_reconciliation_required(
            run_id, expected_started_at=STAMP
        )
        assert receipt["processed"] == receipt["detections"] == receipt["actions"] == 1


def test_bundle_rollback_failure_poison_refuses_every_later_write(
    tmp_path, monkeypatch
):
    path = tmp_path / "audit.db"
    settings = Settings(db_path=path)
    event = PacketEvent(
        STAMP,
        "192.0.2.1",
        "198.51.100.2",
        "DNS",
        dns_query_length=settings.detection.dns_query_length,
    )
    with Store(path) as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)
        service = MegalodonService(settings, store)
        store.connection.execute(
            "CREATE TEMP TRIGGER fail_action AFTER INSERT ON actions "
            "BEGIN SELECT RAISE(FAIL, 'synthetic action failure'); END"
        )
        store.connection.commit()

        def fail_rollback():
            raise sqlite3.OperationalError("synthetic uncertain rollback")

        monkeypatch.setattr(store, "_connection_rollback", fail_rollback)
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            service.process(event, run_id=run_id)
        assert event.src_ip not in service.detector.source_high_watermarks
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            store.record_action(_action(event))
        with pytest.raises(
            IngestionRunError, match="^INGESTION_RUN:RECONCILIATION_REQUIRED$"
        ):
            store.purge_before(STAMP + timedelta(seconds=1))

    with Store(path) as reopened:
        assert reopened.summary() == {
            "events": 0,
            "detections": 0,
            "actions": 0,
            "high_or_critical": 0,
        }
        assert [item["run_id"] for item in reopened.pending_ingestion_reconciliation()] == [
            run_id
        ]


def test_cli_records_event_limit_as_incomplete_and_emits_run_scoped_counts(tmp_path):
    config, database = _config(tmp_path)
    output = io.StringIO()
    with redirect_stdout(output), pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                "--config",
                str(config),
                "--source",
                "sample",
                "--max-events",
                "1",
            ]
        )

    assert raised.value.code == 0
    receipt = json.loads(output.getvalue())
    assert receipt["source"] == "sample"
    assert receipt["status"] == "incomplete"
    assert receipt["termination_reason"] == "event_limit_reached"
    assert receipt["processed"] == 1
    assert receipt["detections"] == 0
    assert receipt["actions"] == 0
    assert receipt["failure_code"] is None
    assert receipt["totals"]["events"] == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, processed_count, detection_count, action_count, "
            "termination_reason FROM ingestion_runs"
        ).fetchone() == ("incomplete", 1, 0, 0, "event_limit_reached")
        assert connection.execute(
            "SELECT COUNT(*) FROM ingestion_run_events"
        ).fetchone()[0] == 1


def test_cli_records_a_bounded_failure_after_a_valid_jsonl_prefix(tmp_path):
    config, database = _config(tmp_path)
    source = tmp_path / "events.jsonl"
    source.write_text(
        json.dumps(_event().to_dict()) + "\n{not-json}\n", encoding="utf-8"
    )
    error = io.StringIO()
    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                "--config",
                str(config),
                "--source",
                "jsonl",
                "--input",
                str(source),
            ]
        )

    assert raised.value.code == 2
    assert error.getvalue() == "megalodon: ingestion failed (CAPTURE_ERROR)\n"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT status, processed_count, detection_count, failure_code, "
            "termination_reason "
            "FROM ingestion_runs"
        ).fetchone()
        assert row == ("failed", 1, 0, "CAPTURE_ERROR", "failed")
        assert connection.execute(
            "SELECT COUNT(*) FROM ingestion_run_events"
        ).fetchone()[0] == 1


def test_cli_records_deep_json_recursion_as_a_bounded_failure(tmp_path):
    config, database = _config(tmp_path)
    source = tmp_path / "events.jsonl"
    source.write_text("[" * 1100 + "]" * 1100 + "\n", encoding="ascii")
    error = io.StringIO()

    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                "--config",
                str(config),
                "--source",
                "jsonl",
                "--input",
                str(source),
            ]
        )

    assert raised.value.code == 2
    assert error.getvalue() == "megalodon: ingestion failed (CAPTURE_ERROR)\n"
    assert "[[[" not in error.getvalue()
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, processed_count, detection_count, failure_code "
            "FROM ingestion_runs"
        ).fetchone() == ("failed", 0, 0, "CAPTURE_ERROR")


def test_cli_records_storage_failure_without_a_phantom_event(tmp_path, monkeypatch):
    config, database = _config(tmp_path)

    def fail_event_write(self, event, detections, actions, *, run_id=None):
        raise sqlite3.OperationalError("sensitive synthetic storage detail")

    monkeypatch.setattr(Store, "record_event_bundle", fail_event_write)

    error = io.StringIO()
    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                "--config",
                str(config),
                "--source",
                "sample",
                "--max-events",
                "1",
            ]
    )

    assert raised.value.code == 2
    assert error.getvalue() == "megalodon: ingestion failed (STORAGE_ERROR)\n"
    assert "sensitive synthetic storage detail" not in error.getvalue()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert connection.execute(
            "SELECT status, processed_count, detection_count, failure_code "
            "FROM ingestion_runs"
        ).fetchone() == ("failed", 0, 0, "STORAGE_ERROR")


def test_cli_records_keyboard_interrupt_without_a_traceback(tmp_path, monkeypatch):
    config, database = _config(tmp_path)

    def interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("megalodon.cli._events_for", interrupted)
    error = io.StringIO()
    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(["run", "--config", str(config), "--source", "sample"])

    assert raised.value.code == 130
    assert error.getvalue() == "megalodon: ingestion interrupted\n"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, processed_count, detection_count, failure_code, "
            "termination_reason "
            "FROM ingestion_runs"
        ).fetchone() == ("failed", 0, 0, "INTERRUPTED", "interrupted")


def test_cli_records_sigterm_as_interrupted_when_handler_can_finalize(
    tmp_path, monkeypatch
):
    config, database = _config(tmp_path)

    def terminated(*_args, **_kwargs):
        def events():
            signal.raise_signal(signal.SIGTERM)
            yield _event()

        return events()

    monkeypatch.setattr("megalodon.cli._events_for", terminated)
    error = io.StringIO()
    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(["run", "--config", str(config), "--source", "sample"])

    assert raised.value.code == 143
    assert error.getvalue() == "megalodon: ingestion interrupted\n"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, failure_code, termination_reason FROM ingestion_runs"
        ).fetchone() == ("failed", "INTERRUPTED", "interrupted")


def test_cli_natural_exhaustion_records_completed_source_exhausted(tmp_path):
    config, database = _config(tmp_path)
    output = io.StringIO()

    with redirect_stdout(output), pytest.raises(SystemExit) as raised:
        main(["run", "--config", str(config), "--source", "sample"])

    assert raised.value.code == 0
    receipt = json.loads(output.getvalue())
    assert receipt["status"] == "completed"
    assert receipt["termination_reason"] == "source_exhausted"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, termination_reason FROM ingestion_runs"
        ).fetchone() == ("completed", "source_exhausted")


def test_cli_limit_does_not_read_or_misclassify_a_malformed_suffix(tmp_path):
    config, database = _config(tmp_path)
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(_event().to_dict()) + "\n{not-json}\n", encoding="utf-8")
    output = io.StringIO()

    with redirect_stdout(output), pytest.raises(SystemExit) as raised:
        main(
            [
                "run",
                "--config",
                str(config),
                "--source",
                "jsonl",
                "--input",
                str(source),
                "--max-events",
                "1",
            ]
        )

    assert raised.value.code == 0
    receipt = json.loads(output.getvalue())
    assert receipt["status"] == "incomplete"
    assert receipt["termination_reason"] == "event_limit_reached"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_cli_reconciliation_readback_and_pinned_mark(tmp_path):
    config, _database = _config(tmp_path)
    with Store(_database) as store:
        run_id = store.start_ingestion_run("sample", started_at=STAMP)

    output = io.StringIO()
    with redirect_stdout(output), pytest.raises(SystemExit) as raised:
        main(["database-reconciliation-status", "--config", str(config)])
    assert raised.value.code == 0
    pending = json.loads(output.getvalue())["pending"]
    assert [item["run_id"] for item in pending] == [run_id]

    output = io.StringIO()
    with redirect_stdout(output), pytest.raises(SystemExit) as raised:
        main(
            [
                "database-reconcile",
                str(run_id),
                "--started-at",
                STAMP.isoformat(),
                "--config",
                str(config),
            ]
        )
    assert raised.value.code == 0
    assert json.loads(output.getvalue())["status"] == "reconciliation_required"


@pytest.mark.parametrize(
    "argv",
    (
        ["database-reconciliation-status"],
        [
            "database-reconcile",
            "1",
            "--started-at",
            STAMP.isoformat(),
        ],
    ),
)
def test_reconciliation_commands_never_create_a_missing_database(tmp_path, argv):
    config, database = _config(tmp_path)
    error = io.StringIO()

    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main([*argv, "--config", str(config)])

    assert raised.value.code == 2
    assert not database.exists()


def test_cli_refuses_new_intake_while_running_receipt_needs_review(tmp_path):
    config, database = _config(tmp_path)
    with Store(database) as store:
        store.start_ingestion_run("sample", started_at=STAMP)

    error = io.StringIO()
    with redirect_stderr(error), pytest.raises(SystemExit) as raised:
        main(["run", "--config", str(config), "--source", "sample"])

    assert raised.value.code == 2
    assert error.getvalue() == (
        "megalodon: ingestion reconciliation required; stop all ingestion, "
        "then inspect database-reconciliation-status\n"
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ingestion_runs").fetchone()[0] == 1
