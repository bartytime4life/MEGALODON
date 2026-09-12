"""Synthetic Scapy lifecycle failures; no installed sensor or capture required."""

from __future__ import annotations

import builtins
from contextlib import ExitStack
import sys
from types import ModuleType
import traceback
import unittest
from unittest.mock import Mock, patch

from megalodon import capture
from megalodon.capture import _BoundedCaptureQueue


PRIVATE_DIAGNOSTIC = "private-scapy-diagnostic-canary"
PRIVATE_INTERFACE = "private-interface-canary"
CLEANUP_NOTE = "live capture cleanup failed; shutdown is unverified"
STOP_ERROR = "unable to stop live capture; shutdown is unverified"


class CaptureFailureReportingTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.sniffer = Mock()
        self.sniffer.running = True
        self.thread = Mock()
        self.thread.is_alive.return_value = False
        self.sniffer.thread = self.thread
        self.factory = Mock(return_value=self.sniffer)
        package = ModuleType("scapy")
        package.__path__ = []
        module = ModuleType("scapy.all")
        module.AsyncSniffer = self.factory
        for name in ("DNS", "DNSQR", "IP", "IPv6", "TCP", "UDP"):
            setattr(module, name, object())
        package.all = module
        self.stack.enter_context(patch.dict(sys.modules, {"scapy": package, "scapy.all": module}))
        self.stack.enter_context(patch.object(capture, "runtime_platform", return_value="linux"))
        self.queue = Mock()
        self.queue.take.return_value = object()
        self.stack.enter_context(patch.object(capture, "_BoundedCaptureQueue", return_value=self.queue))
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("external operation forbidden")))

    def assert_redacted(self, error):
        rendered = "".join(traceback.format_exception(error))
        self.assertNotIn(PRIVATE_DIAGNOSTIC, rendered)
        self.assertNotIn(PRIVATE_INTERFACE, rendered)
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)

    def test_constructor_failure_has_fixed_diagnostic(self):
        self.factory.side_effect = OSError(PRIVATE_DIAGNOSTIC)
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "unable to start live capture")
        self.assert_redacted(caught.exception)
        self.sniffer.start.assert_not_called()
        self.sniffer.stop.assert_not_called()
        self.queue.take.assert_not_called()

    def test_start_failure_has_fixed_diagnostic(self):
        self.sniffer.start.side_effect = OSError(PRIVATE_DIAGNOSTIC)
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "unable to start live capture")
        self.assert_redacted(caught.exception)
        self.sniffer.stop.assert_called_once_with(join=False)
        self.thread.join.assert_called_once_with(capture.SCAPY_SHUTDOWN_TIMEOUT_SECONDS)
        self.queue.take.assert_not_called()

    def test_missing_extra_does_not_display_import_error_context(self):
        original_import = builtins.__import__

        def import_without_scapy(name, *args, **kwargs):
            if name == "scapy.all":
                raise ImportError(PRIVATE_DIAGNOSTIC)
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=import_without_scapy):
            with self.assertRaises(capture.CaptureError) as caught:
                next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "install the optional capture extra: pip install -e '.[capture]'")
        self.assert_redacted(caught.exception)
        self.factory.assert_not_called()

    def test_start_control_flow_is_not_reclassified(self):
        for error in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(kind=type(error).__name__):
                self.sniffer.start.side_effect = error
                with self.assertRaises(type(error)) as caught:
                    next(capture.iter_scapy("synthetic"))
                self.assertIs(caught.exception, error)
        self.assertEqual(self.sniffer.stop.call_count, 2)
        self.assertTrue(all(call.kwargs == {"join": False} for call in self.sniffer.stop.call_args_list))

    def test_close_after_a_yield_stops_once_and_preserves_fixed_options(self):
        source = capture.iter_scapy("synthetic")
        self.assertIs(next(source), self.queue.take.return_value)
        self.assertIsNone(source.close())
        self.sniffer.start.assert_called_once_with()
        self.sniffer.stop.assert_called_once_with(join=False)
        self.assertEqual(self.factory.call_args.kwargs["iface"], "synthetic")
        self.assertIs(self.factory.call_args.kwargs["store"], False)
        self.assertTrue(callable(self.factory.call_args.kwargs["prn"]))
        self.assertEqual(set(self.factory.call_args.kwargs), {"iface", "prn", "store"})

    def test_close_failure_is_not_silently_treated_as_success(self):
        source = capture.iter_scapy(PRIVATE_INTERFACE)
        next(source)
        self.sniffer.stop.side_effect = OSError(PRIVATE_DIAGNOSTIC)
        with self.assertRaises(capture.CaptureError) as caught:
            source.close()
        self.assertEqual(str(caught.exception), STOP_ERROR)
        self.assert_redacted(caught.exception)
        self.sniffer.stop.assert_called_once_with(join=False)

    def test_close_control_flow_is_not_swallowed(self):
        for error in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(kind=type(error).__name__):
                source = capture.iter_scapy("synthetic")
                next(source)
                self.sniffer.stop.side_effect = error
                with self.assertRaises(type(error)) as caught:
                    source.close()
                self.assertIs(caught.exception, error)

    def test_primary_errors_survive_secondary_cleanup_failures(self):
        for primary_type in (capture.CaptureError, RuntimeError, KeyboardInterrupt, SystemExit):
            for cleanup_type in (OSError, KeyboardInterrupt, SystemExit):
                with self.subTest(primary=primary_type.__name__, cleanup=cleanup_type.__name__):
                    primary = primary_type("synthetic primary failure")
                    self.queue.take.side_effect = primary
                    self.sniffer.stop.side_effect = cleanup_type(PRIVATE_DIAGNOSTIC)
                    with self.assertRaises(BaseException) as caught:
                        next(capture.iter_scapy("synthetic"))
                    self.assertIs(caught.exception, primary)
                    self.assertEqual(primary.args, ("synthetic primary failure",))
                    self.assertEqual(primary.__notes__, [CLEANUP_NOTE])
                    self.assertNotIn(PRIVATE_DIAGNOSTIC, "".join(traceback.format_exception(primary)))
        self.assertEqual(self.sniffer.stop.call_count, 12)

    def test_primary_error_with_successful_cleanup_has_no_new_note(self):
        primary = capture.CaptureError("synthetic primary failure")
        self.queue.take.side_effect = primary
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy("synthetic"))
        self.assertIs(caught.exception, primary)
        self.assertFalse(hasattr(primary, "__notes__"))
        self.sniffer.stop.assert_called_once_with(join=False)

    def test_error_thrown_at_yield_remains_primary(self):
        source = capture.iter_scapy("synthetic")
        next(source)
        primary = RuntimeError("synthetic caller failure")
        self.sniffer.stop.side_effect = OSError(PRIVATE_DIAGNOSTIC)
        with self.assertRaises(RuntimeError) as caught:
            source.throw(primary)
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, [CLEANUP_NOTE])
        self.assertNotIn(PRIVATE_DIAGNOSTIC, "".join(traceback.format_exception(primary)))
        self.sniffer.stop.assert_called_once_with(join=False)


    def test_queue_telemetry_counts_accepted_and_dropped_events(self):
        events = _BoundedCaptureQueue(maximum=2)
        self.assertTrue(events.offer(object()))
        self.assertTrue(events.offer(object()))
        self.assertFalse(events.offer(object()))
        self.assertFalse(events.offer(object()))
        self.assertEqual(
            events.telemetry(),
            {
                "capacity": 2,
                "offered": 4,
                "accepted": 2,
                "dropped": 2,
                "queued": 2,
                "overflowed": True,
            },
        )

    def test_async_sniffer_exception_is_reported_without_upstream_details(self):
        def fail_after_start():
            self.sniffer.exception = RuntimeError(PRIVATE_DIAGNOSTIC)
            self.sniffer.running = False
            return None
        self.queue.take.side_effect = fail_after_start
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "live capture failed after startup")
        self.assert_redacted(caught.exception)

    def test_async_sniffer_exit_is_reported_without_upstream_details(self):
        self.queue.take.side_effect = lambda: setattr(self.sniffer, "running", False) or None
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "live capture stopped unexpectedly")
        self.assert_redacted(caught.exception)

    def test_startup_exit_is_reported_before_queue_consumption(self):
        self.sniffer.running = False
        self.thread.is_alive.return_value = False
        with self.assertRaises(capture.CaptureError) as caught:
            next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "live capture stopped during startup")
        self.assert_redacted(caught.exception)
        self.queue.take.assert_not_called()

    def test_startup_timeout_is_reported_without_unbounded_wait(self):
        self.sniffer.running = False
        self.thread.is_alive.return_value = True
        with patch.object(capture, "SCAPY_STARTUP_TIMEOUT_SECONDS", 0):
            with self.assertRaises(capture.CaptureError) as caught:
                next(capture.iter_scapy(PRIVATE_INTERFACE))
        self.assertEqual(str(caught.exception), "live capture startup timed out")
        self.assert_redacted(caught.exception)
        self.queue.take.assert_not_called()

    def test_shutdown_deadline_is_not_reported_as_success(self):
        source = capture.iter_scapy(PRIVATE_INTERFACE)
        next(source)
        self.thread.is_alive.return_value = True
        with self.assertRaises(capture.CaptureError) as caught:
            source.close()
        self.assertEqual(str(caught.exception), "unable to stop live capture; shutdown deadline exceeded")
        self.assert_redacted(caught.exception)
        self.sniffer.stop.assert_called_once_with(join=False)
        self.thread.join.assert_called_once_with(capture.SCAPY_SHUTDOWN_TIMEOUT_SECONDS)

    def test_invalid_platform_refuses_before_sniffer_construction(self):
        with patch.object(capture, "runtime_platform", return_value="windows"):
            with self.assertRaisesRegex(capture.CaptureError, "^live Scapy capture is supported only on Linux$"):
                next(capture.iter_scapy("synthetic"))
        self.factory.assert_not_called()
        self.queue.take.assert_not_called()

    def test_missing_interface_refuses_before_sniffer_construction(self):
        with self.assertRaisesRegex(capture.CaptureError, "^a capture interface is required for the scapy source$"):
            next(capture.iter_scapy(""))
        self.factory.assert_not_called()
        self.queue.take.assert_not_called()
