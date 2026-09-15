"""CLI-owned source closure precedes terminal receipts; no capture is started."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import signal
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pytest

from megalodon import cli
from megalodon.capture import CaptureError
from megalodon.models import PacketEvent
from megalodon.storage import IngestionRunError, RECONCILIATION_REQUIRED, Store


CANARY = "private-source-cleanup-canary"
CLEANUP_ERROR = "event source cleanup failed; shutdown is unverified"


class Source:
    """Retained explicitly so tests cannot pass through garbage collection."""

    def __init__(self, journal, rows=(object(),), *, read_error=None, close_error=None):
        self.journal = journal
        self.rows = iter(rows)
        self.read_error = read_error
        self.close_error = close_error
        self.close_calls = 0
        self.next_calls = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.next_calls += 1
        try:
            return next(self.rows)
        except StopIteration:
            if self.read_error is not None:
                raise self.read_error
            raise

    def close(self):
        self.close_calls += 1
        self.journal.append("close")
        if self.close_error is not None:
            raise self.close_error


class SourceOwnershipTests(unittest.TestCase):
    def setUp(self):
        for target in (
            "socket.socket", "socket.create_connection", "socket.getaddrinfo",
            "subprocess.Popen", "subprocess.run",
        ):
            self.enterContext(patch(target, side_effect=AssertionError("unexpected I/O")))
        self.args = SimpleNamespace(
            config=None, source="sample", max_events=0, demo_threat=False,
            input=None, interface=None,
        )
        self.settings = SimpleNamespace(db_path=Path("unused.db"), capture_source="sample")

    def run_source(self, source, *, process_error=None, finish_error=None):
        journal = source.journal
        store = Mock()
        store.__enter__ = Mock(return_value=store)
        store.__exit__ = Mock(return_value=False)
        store.start_ingestion_run.return_value = 1
        store.summary.return_value = {"events": 0, "detections": 0, "actions": 0}

        def finish(run_id, reason, **kwargs):
            journal.append("finish")
            if finish_error is not None:
                raise finish_error
            status = {
                "source_exhausted": "completed", "event_limit_reached": "incomplete",
                "failed": "failed", "interrupted": "failed",
            }[reason]
            return {"status": status, "termination_reason": reason, **kwargs}

        store.finish_ingestion_run.side_effect = finish
        service = Mock()

        def process(event, *, run_id):
            journal.append("process")
            if process_error is not None:
                raise process_error

        service.process.side_effect = process
        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(cli, "_load", return_value=self.settings),
            patch.object(cli, "Store", return_value=store),
            patch.object(cli, "MegalodonService", return_value=service),
            patch.object(cli, "_events_for", return_value=source),
            redirect_stdout(out), redirect_stderr(err),
        ):
            code = cli._run(self.args)
        return code, store, out.getvalue(), err.getvalue()

    def test_limit_closes_before_incomplete_receipt_without_reading_ahead(self):
        source = Source([], rows=(object(), object()))
        self.args.max_events = 1
        code, store, out, err = self.run_source(source)
        self.assertEqual(code, 0)
        self.assertEqual(source.journal, ["process", "close", "finish"])
        self.assertEqual(source.next_calls, 1)
        self.assertEqual(source.close_calls, 1)
        self.assertEqual(json.loads(out)["status"], "incomplete")
        self.assertEqual(err, "")
        store.finish_ingestion_run.assert_called_once_with(1, "event_limit_reached")

    def test_exhaustion_including_empty_closes_before_completed_receipt(self):
        for rows in ((), (object(),)):
            with self.subTest(rows=len(rows)):
                source = Source([], rows=rows)
                code, store, out, _ = self.run_source(source)
                self.assertEqual(code, 0)
                self.assertEqual(source.journal[-2:], ["close", "finish"])
                self.assertEqual(source.close_calls, 1)
                self.assertEqual(json.loads(out)["status"], "completed")
                store.finish_ingestion_run.assert_called_once_with(1, "source_exhausted")

    def test_close_failure_cannot_become_completed_or_event_limit_success(self):
        for limit in (0, 1):
            for error_type in (CaptureError, OSError, RuntimeError):
                with self.subTest(limit=limit, error=error_type):
                    self.args.max_events = limit
                    source = Source([], close_error=error_type(CANARY))
                    code, store, out, err = self.run_source(source)
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    self.assertEqual(err, "megalodon: ingestion failed (CAPTURE_ERROR)\n")
                    self.assertEqual(source.journal, ["process", "close", "finish"])
                    store.finish_ingestion_run.assert_called_once_with(
                        1, "failed", failure_code="CAPTURE_ERROR"
                    )
                    store.summary.assert_not_called()

    def test_consumer_failure_keeps_its_category_after_failed_close(self):
        for error, category in (
            (sqlite3.OperationalError("synthetic store error"), "STORAGE_ERROR"),
            (ValueError("synthetic validation error"), "VALIDATION_ERROR"),
            (OSError("synthetic input error"), "IO_ERROR"),
            (CaptureError("synthetic capture error"), "CAPTURE_ERROR"),
        ):
            with self.subTest(category=category):
                source = Source([], close_error=RuntimeError(CANARY))
                code, store, out, err = self.run_source(source, process_error=error)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertNotIn(CANARY, err)
                self.assertEqual(source.journal, ["process", "close", "finish"])
                self.assertEqual(error.__notes__, [CLEANUP_ERROR])
                store.finish_ingestion_run.assert_called_once_with(
                    1, "failed", failure_code=category
                )

    def test_read_failure_still_closes_before_failed_receipt(self):
        error = CaptureError("synthetic framing failure")
        source = Source([], rows=(), read_error=error, close_error=OSError(CANARY))
        code, store, out, _ = self.run_source(source)
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(source.journal, ["close", "finish"])
        self.assertEqual(error.__notes__, [CLEANUP_ERROR])
        store.finish_ingestion_run.assert_called_once_with(1, "failed", failure_code="CAPTURE_ERROR")

    def test_interrupt_keeps_exit_code_after_failed_close(self):
        for error, expected in ((KeyboardInterrupt(), 130), (cli._RunInterrupted(signal.SIGTERM), 143)):
            with self.subTest(code=expected):
                source = Source([], close_error=RuntimeError(CANARY))
                code, store, out, err = self.run_source(source, process_error=error)
                self.assertEqual((code, out), (expected, ""))
                self.assertEqual(source.journal, ["process", "close", "finish"])
                self.assertEqual(err, "megalodon: ingestion interrupted\n")
                store.finish_ingestion_run.assert_called_once_with(1, "interrupted")

    def test_reconciliation_required_is_not_replaced_or_finalized_after_cleanup(self):
        primary = IngestionRunError(RECONCILIATION_REQUIRED)
        source = Source([], close_error=OSError(CANARY))
        code, store, out, err = self.run_source(source, process_error=primary)
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(source.journal, ["process", "close"])
        self.assertIn("ingestion reconciliation required", err)
        self.assertEqual(primary.__notes__, [CLEANUP_ERROR])
        store.finish_ingestion_run.assert_not_called()
        store.summary.assert_not_called()

    def test_finalization_failure_does_not_repeat_close(self):
        source = Source([])
        code, store, out, err = self.run_source(
            source, finish_error=IngestionRunError(RECONCILIATION_REQUIRED)
        )
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(source.journal, ["process", "close", "finish"])
        self.assertEqual(source.close_calls, 1)
        self.assertIn("reconciliation required", err)
        store.finish_ingestion_run.assert_called_once()

    def test_primary_exception_identity_survives_ordinary_and_control_flow_cleanup(self):
        for primary_type in (ValueError, RuntimeError, KeyboardInterrupt, SystemExit):
            for cleanup_type in (OSError, KeyboardInterrupt, SystemExit):
                with self.subTest(primary=primary_type, cleanup=cleanup_type):
                    primary = primary_type("synthetic primary")
                    source = Source([], close_error=cleanup_type(CANARY))
                    try:
                        with cli._owned_source(source):
                            raise primary
                    except BaseException as observed:
                        self.assertIs(observed, primary)
                        self.assertEqual(observed.args, ("synthetic primary",))
                        self.assertEqual(observed.__notes__, [CLEANUP_ERROR])
                    else:
                        self.fail("primary error was suppressed")
                    self.assertEqual(source.close_calls, 1)

    def test_standalone_close_interrupt_remains_control_flow(self):
        for error in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(error=type(error)):
                source = Source([], close_error=error)
                try:
                    with cli._owned_source(source):
                        pass
                except BaseException as observed:
                    self.assertIs(observed, error)
                else:
                    self.fail("control flow was suppressed")

    def test_standalone_close_failure_has_fixed_suppressed_diagnostic(self):
        source = Source([], close_error=OSError(CANARY))
        with self.assertRaises(CaptureError) as caught:
            with cli._owned_source(source):
                pass
        self.assertEqual(str(caught.exception), CLEANUP_ERROR)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_nonclosable_iterator_remains_supported(self):
        source = iter([1])
        with cli._owned_source(source) as events:
            self.assertEqual(list(events), [1])

    def test_close_lookup_failure_does_not_mask_primary(self):
        class BrokenClose:
            @property
            def close(self):
                raise RuntimeError(CANARY)

        primary = ValueError("synthetic primary")
        with self.assertRaises(ValueError) as caught:
            with cli._owned_source(BrokenClose()):
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, [CLEANUP_ERROR])

    def file_source(self, *, close_error=None, read_error=None):
        stream = Mock()
        stream.close.side_effect = close_error
        path = Mock(spec=Path)
        path.open.return_value = stream

        def parse(actual):
            self.assertIs(actual, stream)
            yield "synthetic"
            if read_error is not None:
                raise read_error

        self.enterContext(patch.object(cli, "iter_jsonl", side_effect=parse))
        self.args.source, self.args.input = "jsonl", path
        return cli._events_for(self.args, self.settings), path, stream

    def test_jsonl_file_is_lazy_and_unstarted_close_does_not_open(self):
        source, path, stream = self.file_source()
        source.close()
        path.open.assert_not_called()
        stream.close.assert_not_called()

    def test_jsonl_file_closes_after_exhaustion_and_early_close(self):
        for exhaust in (False, True):
            with self.subTest(exhaust=exhaust):
                source, path, stream = self.file_source()
                self.assertEqual(next(source), "synthetic")
                if exhaust:
                    self.assertEqual(list(source), [])
                source.close()
                path.open.assert_called_once_with("r", encoding="utf-8")
                stream.close.assert_called_once_with()

    def test_jsonl_failed_file_close_is_not_hidden_by_generator_exit(self):
        source, _, stream = self.file_source(close_error=OSError(CANARY))
        self.assertEqual(next(source), "synthetic")
        with self.assertRaises(CaptureError) as caught:
            source.close()
        self.assertEqual(str(caught.exception), CLEANUP_ERROR)
        stream.close.assert_called_once_with()

    def test_jsonl_parser_primary_survives_file_close_failure(self):
        primary = CaptureError("synthetic parse failure")
        source, _, stream = self.file_source(close_error=OSError(CANARY), read_error=primary)
        self.assertEqual(next(source), "synthetic")
        with self.assertRaises(CaptureError) as caught:
            next(source)
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, [CLEANUP_ERROR])
        stream.close.assert_called_once_with()

    def test_stdin_is_borrowed_and_not_closed(self):
        self.args.source = "jsonl"
        stream = io.StringIO("synthetic\n")

        def parse(actual):
            self.assertIs(actual, stream)
            yield actual.readline()

        with patch.object(cli.sys, "stdin", stream), patch.object(cli, "iter_jsonl", side_effect=parse):
            with cli._owned_source(cli._events_for(self.args, self.settings)) as source:
                self.assertEqual(next(source), "synthetic\n")
            self.assertFalse(stream.closed)
        stream.close()


@pytest.mark.parametrize("limit,read_fails,close_fails,status,reason", [
    (1, False, False, "incomplete", "event_limit_reached"),
    (0, False, False, "completed", "source_exhausted"),
    (1, False, True, "failed", "failed"),
    (0, False, True, "failed", "failed"),
    (0, True, False, "failed", "failed"),
    (0, True, True, "failed", "failed"),
])
def test_real_ledger_keeps_committed_prefix_and_terminalizes_after_close(
    tmp_path, monkeypatch, capsys, limit, read_fails, close_fails, status, reason
):
    """Actual CLI/service/Store; only the input producer is synthetic."""
    database = tmp_path / "audit.db"
    config = tmp_path / "settings.toml"
    config.write_text(f'[app]\ndb_path = "{database.as_posix()}"\n', encoding="utf-8")
    event = PacketEvent(datetime(2026, 1, 1, tzinfo=timezone.utc), "192.0.2.1", "198.51.100.2", "TCP")
    source = Source(
        [], rows=(event,),
        read_error=CaptureError("synthetic framing failure") if read_fails else None,
        close_error=OSError(CANARY) if close_fails else None,
    )
    monkeypatch.setattr(cli, "_events_for", lambda *_: source)
    original_finish = Store.finish_ingestion_run

    def finish_after_close(self, *args, **kwargs):
        assert source.close_calls == 1
        return original_finish(self, *args, **kwargs)

    monkeypatch.setattr(Store, "finish_ingestion_run", finish_after_close)
    for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
        monkeypatch.setattr(target, Mock(side_effect=AssertionError("unexpected I/O")))
    with pytest.raises(SystemExit) as caught:
        cli.main(["run", "--source", "sample", "--config", str(config), "--max-events", str(limit)])
    assert caught.value.code == (2 if status == "failed" else 0)
    out, err = capsys.readouterr()
    assert CANARY not in out + err
    assert source.close_calls == 1
    with Store(database) as store:
        row = store.connection.execute(
            "SELECT status, termination_reason, processed_count, failure_code FROM ingestion_runs"
        ).fetchone()
        assert tuple(row) == (status, reason, 1, "CAPTURE_ERROR" if status == "failed" else None)
        assert store.summary() == {"events": 1, "detections": 0, "actions": 0, "high_or_critical": 0}
        assert store.connection.execute("SELECT COUNT(*) FROM ingestion_run_events").fetchone()[0] == 1
    if status == "failed":
        assert out == ""
        assert err == "megalodon: ingestion failed (CAPTURE_ERROR)\n"
    else:
        assert json.loads(out)["status"] == status
