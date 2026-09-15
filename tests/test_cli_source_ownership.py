"""CLI-owned source closure precedes terminal receipts; no capture is started."""

from __future__ import annotations

import _thread
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
            config=None, source="sample", max_events=None, demo_threat=False,
            input=None, interface=None, max_seconds=None,
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
        for limit in (None, 1):
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

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_signal_closes_before_failed_receipt(self):
        class DeadlineSource(Source):
            def __next__(inner_self):
                inner_self.next_calls += 1
                signal.raise_signal(signal.SIGALRM)
                raise AssertionError("deadline handler did not interrupt source read")

        self.args.max_seconds = 60
        source = DeadlineSource([])

        code, store, out, err = self.run_source(source)

        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err, "megalodon: ingestion failed (CAPTURE_ERROR)\n")
        self.assertEqual(source.journal, ["close", "finish"])
        store.finish_ingestion_run.assert_called_once_with(
            1, "failed", failure_code="CAPTURE_ERROR"
        )

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_keeps_alarm_active_through_source_close(self):
        class DeadlineOnClose(Source):
            def close(inner_self):
                inner_self.close_calls += 1
                inner_self.journal.append("close")
                signal.raise_signal(signal.SIGALRM)

        self.args.max_events = 1
        self.args.max_seconds = 60
        source = DeadlineOnClose([], rows=(object(),))

        code, store, out, err = self.run_source(source)

        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err, "megalodon: ingestion failed (CAPTURE_ERROR)\n")
        self.assertEqual(source.journal, ["process", "close", "finish"])
        store.finish_ingestion_run.assert_called_once_with(
            1, "failed", failure_code="CAPTURE_ERROR"
        )

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_restores_prior_handler_when_timer_is_inactive(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)

        def prior_handler(_signum, _frame):
            return None

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with cli._scoped_run_deadline(10):
                active_delay, active_interval = signal.getitimer(signal.ITIMER_REAL)
                self.assertGreater(active_delay, 9.0)
                self.assertEqual(active_interval, 0.0)

            restored_delay, restored_interval = signal.getitimer(
                signal.ITIMER_REAL
            )
            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
            self.assertEqual(restored_delay, 0.0)
            self.assertEqual(restored_interval, 0.0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_refuses_alarm_pending_during_arming(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)
        calls = []

        def prior_handler(_signum, _frame):
            return None

        def setitimer(timer_kind, seconds, interval=0.0):
            calls.append((timer_kind, seconds, interval))
            if seconds:
                signal.raise_signal(signal.SIGALRM)
            return (0.0, 0.0)

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with (
                patch.object(cli.signal, "setitimer", side_effect=setitimer),
                self.assertRaisesRegex(
                    ValueError,
                    "^max-seconds cannot start with a pending SIGALRM$",
                ),
            ):
                with cli._scoped_run_deadline(1):
                    self.fail("pending alarm should refuse before entry")

            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
            self.assertEqual(
                calls,
                [
                    (signal.ITIMER_REAL, 1, 0.0),
                    (signal.ITIMER_REAL, 0.0, 0.0),
                ],
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_refuses_without_replacing_active_process_timer(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)

        def prior_handler(_signum, _frame):
            return None

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            signal.setitimer(signal.ITIMER_REAL, 30.0)
            before_delay, before_interval = signal.getitimer(signal.ITIMER_REAL)

            with self.assertRaisesRegex(
                ValueError,
                "^max-seconds cannot replace an active POSIX process timer$",
            ):
                with cli._scoped_run_deadline(10):
                    self.fail("conflicting timer should refuse before entry")

            after_delay, after_interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
            self.assertLessEqual(after_delay, before_delay)
            self.assertGreater(after_delay, before_delay - 1.0)
            self.assertEqual(after_interval, before_interval)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(
        cli._run_deadline_supported(), "POSIX interval timers required"
    )
    def test_deadline_rechecks_blocked_alarm_at_protected_boundary(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "blocked boundary must refuse before handler or timer setup"
            )

        with (
            patch.object(cli, "_require_run_deadline_support"),
            patch.object(
                cli.signal,
                "pthread_sigmask",
                return_value={signal.SIGALRM},
            ) as inspect_mask,
            patch.object(cli.signal, "signal", side_effect=forbidden),
            patch.object(cli.signal, "setitimer", side_effect=forbidden),
            self.assertRaisesRegex(
                ValueError, "^max-seconds requires SIGALRM to be unblocked$"
            ),
        ):
            with cli._scoped_run_deadline(10):
                self.fail("blocked boundary should refuse before entry")

        inspect_mask.assert_called_once_with(signal.SIG_BLOCK, {signal.SIGALRM})

    @unittest.skipUnless(
        cli._run_deadline_supported(), "POSIX interval timers required"
    )
    def test_deadline_refuses_alarm_pending_during_protected_setup(self):
        alarm_blocked = False
        timer_calls = []
        handler_calls = []
        prior_handler = object()

        def pthread_sigmask(how, mask):
            nonlocal alarm_blocked
            mask = set(mask)
            previous = {signal.SIGALRM} if alarm_blocked else set()
            if how == signal.SIG_BLOCK:
                alarm_blocked = alarm_blocked or signal.SIGALRM in mask
            elif how == signal.SIG_SETMASK:
                alarm_blocked = signal.SIGALRM in mask
            else:
                self.fail("unexpected signal-mask operation")
            return previous

        def setitimer(timer_kind, seconds, interval=0.0):
            timer_calls.append((timer_kind, seconds, interval, alarm_blocked))
            return (0.0, 0.0)

        def install_handler(alarm_signal, handler):
            handler_calls.append((alarm_signal, handler, alarm_blocked))

        with (
            patch.object(cli, "_require_run_deadline_support"),
            patch.object(cli, "_require_single_threaded_run_deadline"),
            patch.object(cli.signal, "getsignal", return_value=prior_handler),
            patch.object(cli.signal, "pthread_sigmask", side_effect=pthread_sigmask),
            patch.object(
                cli.signal,
                "sigpending",
                side_effect=[set(), {signal.SIGALRM}],
            ),
            patch.object(cli.signal, "setitimer", side_effect=setitimer),
            patch.object(cli.signal, "signal", side_effect=install_handler),
            self.assertRaisesRegex(
                ValueError, "^max-seconds cannot start with a pending SIGALRM$"
            ),
        ):
            with cli._scoped_run_deadline(10):
                self.fail("pending alarm should refuse before entry")

        self.assertFalse(alarm_blocked)
        self.assertEqual(
            [(seconds, blocked) for _, seconds, _, blocked in timer_calls],
            [(10, True), (0.0, True)],
        )
        self.assertIs(handler_calls[-1][1], prior_handler)
        self.assertTrue(handler_calls[-1][2])

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_restores_timer_armed_after_preflight(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)
        calls = []
        mask_calls = []
        alarm_blocked = False

        def prior_handler(_signum, _frame):
            return None

        def setitimer(timer_kind, seconds, interval=0.0):
            self.assertTrue(alarm_blocked)
            calls.append((timer_kind, seconds, interval))
            if len(calls) == 1:
                return (30.0, 0.5)
            return (1.0, 0.0)

        def pthread_sigmask(how, mask):
            nonlocal alarm_blocked
            mask = set(mask)
            mask_calls.append((how, mask))
            previous = {signal.SIGALRM} if alarm_blocked else set()
            if how == signal.SIG_BLOCK:
                alarm_blocked = alarm_blocked or signal.SIGALRM in mask
            elif how == signal.SIG_SETMASK:
                alarm_blocked = signal.SIGALRM in mask
            else:
                self.fail("unexpected signal-mask operation")
            return previous

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with (
                patch.object(cli.signal, "getitimer", return_value=(0.0, 0.0)),
                patch.object(cli.signal, "setitimer", side_effect=setitimer),
                patch.object(
                    cli.signal, "pthread_sigmask", side_effect=pthread_sigmask
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "^max-seconds cannot replace an active POSIX process timer$",
                ),
            ):
                with cli._scoped_run_deadline(10):
                    self.fail("concurrently armed timer should refuse before entry")

            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
            self.assertFalse(alarm_blocked)
            self.assertEqual(
                calls,
                [
                    (signal.ITIMER_REAL, 10, 0.0),
                    (signal.ITIMER_REAL, 30.0, 0.5),
                ],
            )
            self.assertEqual(
                mask_calls,
                [
                    (signal.SIG_BLOCK, set()),
                    (signal.SIG_BLOCK, {signal.SIGALRM}),
                    (signal.SIG_SETMASK, set()),
                ],
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(cli._run_deadline_supported(), "Linux interval timers required")
    def test_deadline_refuses_unregistered_os_thread(self):
        started = _thread.allocate_lock()
        release = _thread.allocate_lock()
        finished = _thread.allocate_lock()
        started.acquire()
        release.acquire()
        finished.acquire()

        def worker():
            started.release()
            release.acquire()
            finished.release()

        _thread.start_new_thread(worker, ())
        self.assertTrue(started.acquire(timeout=5))
        try:
            with self.assertRaisesRegex(
                ValueError, "^max-seconds requires a single-threaded process$"
            ):
                cli._require_run_deadline_support(1)
        finally:
            release.release()
            self.assertTrue(finished.acquire(timeout=5))

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_restores_handler_when_alarm_fires_during_cancellation(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)
        calls = []

        def prior_handler(_signum, _frame):
            return None

        def setitimer(timer_kind, seconds, interval=0.0):
            calls.append((timer_kind, seconds, interval))
            if not seconds:
                signal.raise_signal(signal.SIGALRM)
            return (0.0, 0.0)

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with (
                patch.object(cli.signal, "setitimer", side_effect=setitimer),
                self.assertRaisesRegex(CaptureError, "^ingestion deadline exceeded$"),
            ):
                with cli._scoped_run_deadline(10):
                    pass

            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
            self.assertEqual(
                calls,
                [
                    (signal.ITIMER_REAL, 10, 0.0),
                    (signal.ITIMER_REAL, 0.0, 0.0),
                ],
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(
        cli._run_deadline_supported(), "POSIX interval timers required"
    )
    def test_deadline_blocks_alarm_across_successful_cancellation(self):
        alarm_blocked = False
        mask_calls = []
        timer_calls = []
        handler_calls = []
        prior_handler = object()

        def pthread_sigmask(how, mask):
            nonlocal alarm_blocked
            mask = set(mask)
            mask_calls.append((how, mask))
            previous = {signal.SIGALRM} if alarm_blocked else set()
            if how == signal.SIG_BLOCK:
                alarm_blocked = alarm_blocked or signal.SIGALRM in mask
            elif how == signal.SIG_SETMASK:
                alarm_blocked = signal.SIGALRM in mask
            else:
                self.fail("unexpected signal-mask operation")
            return previous

        def setitimer(timer_kind, seconds, interval=0.0):
            timer_calls.append((timer_kind, seconds, interval, alarm_blocked))
            return (0.0, 0.0)

        def install_handler(alarm_signal, handler):
            handler_calls.append((alarm_signal, handler, alarm_blocked))

        with (
            patch.object(cli, "_require_run_deadline_support"),
            patch.object(cli, "_require_single_threaded_run_deadline"),
            patch.object(cli.signal, "getsignal", return_value=prior_handler),
            patch.object(cli.signal, "pthread_sigmask", side_effect=pthread_sigmask),
            patch.object(cli.signal, "setitimer", side_effect=setitimer),
            patch.object(cli.signal, "signal", side_effect=install_handler),
        ):
            with cli._scoped_run_deadline(10):
                self.assertFalse(alarm_blocked)

        self.assertFalse(alarm_blocked)
        self.assertEqual(
            [(seconds, blocked) for _, seconds, _, blocked in timer_calls],
            [(10, True), (0.0, True)],
        )
        self.assertEqual(
            mask_calls,
            [
                (signal.SIG_BLOCK, {signal.SIGALRM}),
                (signal.SIG_SETMASK, set()),
                (signal.SIG_BLOCK, {signal.SIGALRM}),
                (signal.SIG_SETMASK, set()),
            ],
        )
        self.assertIs(handler_calls[-1][1], prior_handler)
        self.assertFalse(handler_calls[-1][2])

    @unittest.skipUnless(cli._run_deadline_supported(), "POSIX interval timers required")
    def test_deadline_restores_handler_when_failed_cancel_left_timer_inactive(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)

        def prior_handler(_signum, _frame):
            return None

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with (
                patch.object(cli.signal, "getitimer", return_value=(0.0, 0.0)),
                patch.object(
                    cli.signal,
                    "setitimer",
                    side_effect=[(0.0, 0.0), OSError("synthetic cancel failure")],
                ),
                self.assertRaisesRegex(OSError, "^synthetic cancel failure$"),
            ):
                with cli._scoped_run_deadline(10):
                    pass

            self.assertIs(signal.getsignal(signal.SIGALRM), prior_handler)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

    @unittest.skipUnless(cli._run_deadline_supported(), "Linux interval timers required")
    def test_deadline_retains_handler_when_failed_cancel_leaves_timer_active(self):
        original_handler = signal.getsignal(signal.SIGALRM)
        original_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)

        def prior_handler(_signum, _frame):
            return None

        try:
            signal.signal(signal.SIGALRM, prior_handler)
            with (
                patch.object(
                    cli.signal,
                    "getitimer",
                    side_effect=[(0.0, 0.0), (9.0, 0.0)],
                ),
                patch.object(
                    cli.signal,
                    "setitimer",
                    side_effect=[(0.0, 0.0), OSError("synthetic cancel failure")],
                ),
                self.assertRaisesRegex(OSError, "^synthetic cancel failure$"),
            ):
                with cli._scoped_run_deadline(10):
                    pass

            self.assertIsNot(signal.getsignal(signal.SIGALRM), prior_handler)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, original_handler)
            if original_timer[0] > 0.0:
                signal.setitimer(signal.ITIMER_REAL, *original_timer)

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
    (None, False, False, "completed", "source_exhausted"),
    (1, False, True, "failed", "failed"),
    (None, False, True, "failed", "failed"),
    (None, True, False, "failed", "failed"),
    (None, True, True, "failed", "failed"),
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
        argv = ["run", "--source", "sample", "--config", str(config)]
        if limit is not None:
            argv.extend(["--max-events", str(limit)])
        cli.main(argv)
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
