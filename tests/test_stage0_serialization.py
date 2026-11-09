"""Inert Stage 0 transition schedules and consistent status snapshots."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def fresh_boundary():
    path = ROOT / 'megalodon/execution_boundary.py'
    spec = importlib.util.spec_from_file_location('isolated_boundary_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def pause_at_assignment(module, function, variable):
    tree = ast.parse(Path(module.__file__).read_text())
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function))
    line = next((n.lineno for n in ast.walk(fn) if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == variable for t in n.targets))))
    paused, resume = (threading.Event(), threading.Event())
    code = getattr(module, function).__code__

    def trace(frame, event, argument):
        if frame.f_code is code and event == 'line' and (frame.f_lineno == line):
            paused.set()
            if not resume.wait(3):
                raise RuntimeError('bounded test interleaving expired')
        return trace
    return (paused, resume, trace)

class Stage0SerializationTests(unittest.TestCase):

    def setUp(self):
        self.boundary = fresh_boundary()

    def schedule(self, first, variable, second):
        b = self.boundary
        paused, resume, trace = pause_at_assignment(b, first, variable)
        attempted, completed = (threading.Event(), threading.Event())
        results = {}

        def invoke(which, traced=False):
            if traced:
                sys.settrace(trace)
            else:
                attempted.set()
            try:
                getattr(b, which)()
                results[which] = 'ALLOWED'
            except b.Stage0Denied as exc:
                results[which] = str(exc)
            except BaseException as exc:
                results[which] = type(exc).__name__ + ':' + str(exc)
            finally:
                sys.settrace(None)
                if not traced:
                    completed.set()
        one = threading.Thread(target=invoke, args=(first, True), daemon=True)
        two = threading.Thread(target=invoke, args=(second,), daemon=True)
        one.start()
        try:
            self.assertTrue(paused.wait(2))
            two.start()
            self.assertTrue(attempted.wait(2))
            completed_before_release = completed.wait(0.05)
        finally:
            resume.set()
            one.join(2)
            if two.ident is not None:
                two.join(2)
        self.assertFalse(one.is_alive() or two.is_alive(), 'test worker did not exit')
        self.assertFalse(completed_before_release, 'competing transition passed paused admission')
        return results

    def test_admission_wins_and_late_selection_refuses(self):
        values = self.schedule('require_effects_allowed', '_effects_entered', 'select_stage0')
        self.assertEqual(values, {'require_effects_allowed': 'ALLOWED', 'select_stage0': self.boundary.DENIAL})
        self.assertEqual(self.boundary.status()['mode'], 'unavailable')
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.require_effects_allowed()

    def test_selection_wins_and_entry_refuses(self):
        values = self.schedule('select_stage0', '_stage0_selected', 'require_effects_allowed')
        self.assertEqual(values, {'select_stage0': 'ALLOWED', 'require_effects_allowed': self.boundary.DENIAL})
        self.assertEqual(self.boundary.status()['mode'], 'stage0_offline')

    def test_status_fields_share_one_observation(self):
        b = self.boundary
        paused, resume, trace = pause_at_assignment(b, 'status', 'mode')
        values = []

        def observe():
            sys.settrace(trace)
            try:
                values.append(b.status())
            finally:
                sys.settrace(None)
        worker = threading.Thread(target=observe, daemon=True)
        worker.start()
        try:
            self.assertTrue(paused.wait(2))
            b.select_stage0()
        finally:
            resume.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(values), 1)
        self.assertEqual((values[0]['mode'], values[0]['effectful_entries_denied'], values[0]['denial_code']), ('installed_runtime', False, None))
        self.assertEqual(b.status()['mode'], 'stage0_offline')

    def test_latch_repeated_selection_and_path_free_denial(self):
        b = self.boundary
        for _ in range(2):
            b.select_stage0()
        for _ in range(3):
            with self.assertRaisesRegex(b.Stage0Denied, '^STAGE0_OFFLINE_EFFECT_DENIED$'):
                b.require_effects_allowed()
        self.assertFalse(b.status()['acceptance_authority'])

    def test_invalid_or_missing_mode_refuses(self):
        for value in (None, 0, 1, 'stage0_offline', [], {}):
            b = fresh_boundary()
            b._stage0_selected = value
            with self.subTest(value=value):
                with self.assertRaises(b.Stage0Denied):
                    b.select_stage0()
                with self.assertRaises(b.Stage0Denied):
                    b.require_effects_allowed()
        b = fresh_boundary()
        del b._stage0_selected
        with self.assertRaises(b.Stage0Denied):
            b.require_effects_allowed()

    def test_denied_invocations_do_not_construct_another_lock(self):
        b = self.boundary
        b.select_stage0()
        with patch.object(b, 'Lock', side_effect=AssertionError('new invocation lock'), create=True):
            for _ in range(20):
                with self.assertRaises(b.Stage0Denied):
                    b.require_effects_allowed()

    def test_late_selection_rejects_invalid_or_missing_admission_mark(self):
        for value in (None, 0, 1, 'entered', [], {}):
            b = fresh_boundary()
            b._effects_entered = value
            with self.subTest(value=value), self.assertRaises(b.Stage0Denied):
                b.select_stage0()
            self.assertEqual(b.status()['mode'], 'unavailable')
        b = fresh_boundary()
        del b._effects_entered
        with self.assertRaises(b.Stage0Denied):
            b.select_stage0()
        self.assertEqual(b.status()['mode'], 'unavailable')

    def test_cli_rechecks_admission_after_stale_query(self):
        from megalodon import cli
        b = self.boundary
        query = b.effects_denied

        def select_after_query():
            denied = query()
            b.select_stage0()
            return denied

        with patch.object(cli, 'execution_boundary', b), patch.object(b, 'effects_denied', select_after_query), patch.object(cli, 'build_parser', side_effect=AssertionError('parser reached')), redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as result:
                cli.main(['database-migrate'])
        self.assertEqual(result.exception.code, 2)
        self.assertEqual(stderr.getvalue(), b.DENIAL + '\n')
        self.assertEqual(b.status()['mode'], 'stage0_offline')

    def test_cli_ordinary_parser_marks_admission(self):
        from megalodon import cli
        b = self.boundary

        class ParserReached(Exception):
            pass

        with patch.object(cli, 'execution_boundary', b), patch.object(cli, 'build_parser', side_effect=ParserReached):
            with self.assertRaises(ParserReached):
                cli.main(['database-migrate'])
        with self.assertRaises(b.Stage0Denied):
            b.select_stage0()

    def test_exact_cli_status_does_not_mark_admission(self):
        from megalodon import cli
        b = self.boundary
        with patch.object(cli, 'execution_boundary', b), redirect_stdout(io.StringIO()) as stdout:
            with self.assertRaises(SystemExit) as result:
                cli.main(['stage0-status'])
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(json.loads(stdout.getvalue())['mode'], 'installed_runtime')
        b.select_stage0()
        self.assertEqual(b.status()['mode'], 'stage0_offline')

    def test_dashboard_action_refuses_before_headers(self):
        from megalodon import dashboard
        b = self.boundary
        b.select_stage0()
        replies = []

        class Handler:
            def _send_json(self, body, *, status):
                replies.append((body, status))

            @property
            def headers(self):
                raise AssertionError('headers reached')

        with patch.object(dashboard, 'execution_boundary', b):
            dashboard.DashboardHandler._support_config_action(Handler())
        self.assertEqual(replies, [({'state': 'denied', 'error_code': b.DENIAL}, 403)])

    def test_dashboard_ordinary_action_marks_admission(self):
        from megalodon import dashboard
        b = self.boundary

        class HeadersReached(Exception):
            pass

        class Handler:
            @property
            def headers(self):
                raise HeadersReached

        with patch.object(dashboard, 'execution_boundary', b):
            with self.assertRaises(HeadersReached):
                dashboard.DashboardHandler._support_config_action(Handler())
        with self.assertRaises(b.Stage0Denied):
            b.select_stage0()
if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Stage0SerializationTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = {'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'failed_cases': [test.id().rsplit('.', 1)[-1] for test, _ in result.failures], 'scope': 'inert_transition_schedules_and_status_snapshots', 'native_analyzers_run': False, 'owner_pc_verified': False}
    print(json.dumps(receipt, sort_keys=True))
    raise SystemExit(not result.wasSuccessful())
