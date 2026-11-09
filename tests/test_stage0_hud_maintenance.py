"""Inert startup/reopen fences; never operate a service, socket or browser."""

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import builtins
import importlib.util
import io
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from megalodon import hud_autostart as startup, hud_reopen as reopen, install_lifecycle


def fresh_boundary():
    spec = importlib.util.spec_from_file_location('isolated_hud_boundary', ROOT / 'megalodon/execution_boundary.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def entries():
    return {
        'start': lambda: startup.start(),
        'enable': lambda: startup.enable(start=object()),
        'disable_login': lambda: startup.disable_login(),
        'disable': lambda: startup.disable(None),
        'validate_unit': lambda: startup.validate_unit(None),
        'loaded_dropins': lambda: startup.loaded_dropins(None),
        'prepare_unit': lambda: startup._prepare_unit(),
        'systemctl': lambda: startup._systemctl('start', startup.UNIT),
        'service_state': lambda: startup._service_state(),
        'vendor_metadata': lambda: startup._vendor_type_wide(None),
        'listener_probe': lambda: install_lifecycle._listener_pid(None, None),
        'socket_wait': lambda: reopen._wait_until_listening(None, None),
    }


@contextmanager
def no_preflight():
    attempts = []

    def forbidden(*args, **kwargs):
        attempts.append('preflight')
        raise AssertionError('preflight reached')

    with ExitStack() as stack:
        for owner, names in (
            (builtins, ('open',)), (io, ('open',)),
            (startup, ('install_paths', 'status', 'load_settings')),
            (reopen, ('load_settings', 'install_paths', 'service_running')),
            (startup.argparse, ('ArgumentParser',)),
            (startup.subprocess, ('run', 'Popen')),
            (startup.os, ('lstat', 'stat', 'open', 'mkdir', 'unlink', 'readlink')),
            (startup.os.path, ('lexists',)),
            (Path, ('open', 'stat', 'lstat', 'exists', 'readlink', 'iterdir', 'unlink')),
            (reopen.socket, ('create_connection', 'socket', 'getaddrinfo')),
            (reopen.time, ('sleep', 'monotonic')),
            (threading.Thread, ('start',)),
            (reopen.webbrowser, ('open_new_tab',)),
        ):
            for name in names:
                stack.enter_context(patch.object(owner, name, forbidden))
        yield attempts
    if attempts:
        raise AssertionError('preflight attempts observed')


class Stage0HUDMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.boundary = fresh_boundary()
        stack = ExitStack()
        self.addCleanup(stack.close)
        for module in (startup, reopen, install_lifecycle):
            stack.enter_context(patch.object(module, 'execution_boundary', self.boundary, create=True))

    def test_selected_entries_refuse_before_preflight(self):
        self.boundary.select_stage0()
        with no_preflight() as attempts:
            for name, invoke in entries().items():
                with self.subTest(entry=name), self.assertRaisesRegex(self.boundary.Stage0Denied, '^STAGE0_OFFLINE_EFFECT_DENIED$'):
                    invoke()
        self.assertEqual(attempts, [])

    def test_cli_denies_before_parser_arguments_or_settings(self):
        self.boundary.select_stage0()
        for module in (startup, reopen):
            for argv in ([], ['--help'], ['enable', '--start'], ['disable'], ['/synthetic/not-read'], [None], object()):
                with self.subTest(module=module.__name__, argv=type(argv).__name__), no_preflight(), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(module.main(argv), 2)
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(err.getvalue(), self.boundary.DENIAL + '\n')

    def test_invalid_or_missing_state_cannot_recover_permission(self):
        for state in (None, 0, 1, 'installed_runtime'):
            self.boundary._stage0_selected = state
            with no_preflight():
                for name, invoke in entries().items():
                    with self.subTest(state=state, entry=name), self.assertRaises(self.boundary.Stage0Denied):
                        invoke()
        del self.boundary._stage0_selected
        with no_preflight(), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(reopen.main(object()), 2)
        self.assertEqual(err.getvalue(), self.boundary.DENIAL + '\n')

    def test_late_selection_keeps_cli_denial_fixed(self):
        for module, target, argv in ((startup, 'start', ['start']),
                                     (reopen, 'load_settings', ['/synthetic/not-read'])):
            b = fresh_boundary()
            def poison(*args, **kwargs):
                b.select_stage0()  # CLI admission has already won; this refuses.
            with self.subTest(module=module.__name__), patch.object(module, 'execution_boundary', b), patch.object(module, target, poison), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                self.assertEqual(module.main(argv), 2)
                self.assertEqual(out.getvalue(), '')
                self.assertEqual(err.getvalue(), b.DENIAL + '\n')
                self.assertEqual(b.status()['mode'], 'unavailable')

    def test_pure_unit_templates_and_state_projection_remain_available(self):
        paths = SimpleNamespace(config=Path('/synthetic/config/megalodon'),
            current=Path('/synthetic/current'), settings=Path('/synthetic/settings.toml'),
            hud_launcher=Path('/synthetic/megalodon-hud'))
        self.boundary.select_stage0()
        with no_preflight():
            unit = startup.unit_path(paths)
            self.assertEqual(startup.dropin_path(paths), unit.with_name(startup.UNIT + '.d'))
            self.assertIn(b' -I -m megalodon hud --config ', startup.unit_contents(paths))
            self.assertFalse(startup.loaded_elsewhere(None, unit, False))
        self.assertEqual(self.boundary.status()['mode'], 'stage0_offline')

    def test_ordinary_start_preserves_fixed_service_dispatch(self):
        with patch.object(startup, '_prepare_unit') as prepare, patch.object(startup, '_systemctl') as command:
            startup.start()
        prepare.assert_called_once_with()
        command.assert_called_once_with('start', startup.UNIT)
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()

    def test_ordinary_reopen_preserves_managed_loopback_browser_target(self):
        settings = SimpleNamespace(dashboard=SimpleNamespace(host='127.0.0.1', port=8787))
        with patch.object(reopen, 'load_settings', return_value=settings), patch.object(reopen, '_wait_until_listening', return_value=True), patch.object(reopen, 'install_paths', return_value=None), patch.object(reopen, 'service_running', return_value=True), patch.object(reopen, '_listener_pid', return_value=777), patch.object(reopen.webbrowser, 'open_new_tab', return_value=True) as browser:
            self.assertEqual(reopen.main(['/synthetic/not-read']), 0)
        browser.assert_called_once_with('http://127.0.0.1:8787/')
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()

    def test_ordinary_reopen_keeps_non_loopback_refusal(self):
        settings = SimpleNamespace(dashboard=SimpleNamespace(host='0.0.0.0', port=8787))
        with patch.object(reopen, 'load_settings', return_value=settings), patch.object(reopen, '_wait_until_listening', side_effect=AssertionError('socket reached')), redirect_stderr(io.StringIO()):
            self.assertEqual(reopen.main(['/synthetic/not-read']), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
