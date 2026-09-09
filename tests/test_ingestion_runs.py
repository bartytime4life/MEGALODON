"""Bounded ingestion-run lifecycle and provenance receipts."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import sqlite3

import pytest

from megalodon.cli import main
from megalodon.models import DetectionResult, PacketEvent
from megalodon.storage import IngestionRunError, Store


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event() -> PacketEvent:
    return PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")


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
        event_id = store.record_event(event, run_id=run_id)
        store.record_detection(
            event_id,
            DetectionResult(
                STAMP,
                "TEST",
                "LOW",
                event.src_ip,
                event.dst_ip,
                "synthetic",
            ),
        )

        receipt = store.finish_ingestion_run(
            run_id, "completed", finished_at=STAMP + timedelta(seconds=1)
        )

        assert receipt == {
            "run_id": run_id,
            "source": "sample",
            "status": "completed",
            "processed": 1,
            "detections": 1,
            "failure_code": None,
        }
        row = store.connection.execute(
            "SELECT status, processed_count, detection_count, failure_code "
            "FROM ingestion_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        assert tuple(row) == ("completed", 1, 1, None)
        assert tuple(
            store.connection.execute(
                "SELECT run_id, event_id FROM ingestion_run_events"
            ).fetchone()
        ) == (run_id, event_id)


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
                run_id, "completed", finished_at=STAMP + timedelta(seconds=2)
            )
        with pytest.raises(IngestionRunError, match="^INGESTION_RUN:NOT_ACTIVE$"):
            store.record_event(_event(), run_id=run_id)

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
            ("running", None, "INVALID_STATUS"),
            ([], None, "INVALID_STATUS"),
            ("completed", "IO_ERROR", "INVALID_FAILURE"),
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
                run_id, "completed", finished_at=STAMP - timedelta(seconds=1)
            )
        assert store.connection.execute(
            "SELECT status FROM ingestion_runs WHERE id = ?", (run_id,)
        ).fetchone()[0] == "running"


def test_unknown_or_invalid_run_id_rolls_back_the_event(tmp_path):
    with Store(tmp_path / "audit.db") as store:
        for run_id, code in ((0, "INVALID_ID"), (False, "INVALID_ID"), (999, "NOT_ACTIVE")):
            with pytest.raises(IngestionRunError, match=f"^INGESTION_RUN:{code}$"):
                store.record_event(_event(), run_id=run_id)
        assert store.summary()["events"] == 0


def test_cli_records_completed_run_and_emits_run_scoped_counts(tmp_path):
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
    assert receipt["status"] == "completed"
    assert receipt["processed"] == 1
    assert receipt["detections"] == 0
    assert receipt["failure_code"] is None
    assert receipt["totals"]["events"] == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, processed_count, detection_count FROM ingestion_runs"
        ).fetchone() == ("completed", 1, 0)
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
            "SELECT status, processed_count, detection_count, failure_code "
            "FROM ingestion_runs"
        ).fetchone()
        assert row == ("failed", 1, 0, "CAPTURE_ERROR")
        assert connection.execute(
            "SELECT COUNT(*) FROM ingestion_run_events"
        ).fetchone()[0] == 1


def test_cli_records_storage_failure_without_a_phantom_event(tmp_path, monkeypatch):
    config, database = _config(tmp_path)

    def fail_event_write(self, event, *, run_id=None):
        raise sqlite3.OperationalError("sensitive synthetic storage detail")

    monkeypatch.setattr(Store, "record_event", fail_event_write)

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
            "SELECT status, processed_count, detection_count, failure_code "
            "FROM ingestion_runs"
        ).fetchone() == ("failed", 0, 0, "INTERRUPTED")
