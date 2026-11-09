"""Inert installer admission tests; no installation or service operation runs."""

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import builtins
import importlib.util
import io
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from megalodon import install_lifecycle, local_install


def fresh_boundary():
    spec = importlib.util.spec_from_file_location(
        'isolated_installer_boundary', ROOT / 'megalodon/execution_boundary.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_entries():
    return {
        'install': lambda: local_install.install(None),
        'repair': lambda: local_install.repair(None),
        'uninstall': lambda: local_install.uninstall(None),
        'status': lambda: local_install.status(None),
        'password_read': lambda: local_install.load_hud_password_verifier(None),
        'password_set': lambda: local_install.set_hud_password(None),
        'password_clear': lambda: local_install.clear_hud_password(None),
        'extras': lambda: install_lifecycle.selected_extras(None),
        'service_status': lambda: install_lifecycle.service_running(None),
        'service_action': lambda: install_lifecycle.service_action(None),
        'verify_running': lambda: install_lifecycle.verify_running(None, None),
        'retire_releases': lambda: install_lifecycle.retire_releases(None, None),
    }


@contextmanager
def effect_tripwires():
    attempts = []

    def forbidden(name):
        def fail(*args, **kwargs):
            attempts.append(name)
            raise AssertionError('unexpected effect: ' + name)
        return fail

    surfaces = [
        (builtins, ('open',)), (io, ('open',)),
        (Path, ('open', 'stat', 'lstat', 'exists', 'is_file', 'is_dir',
                'readlink', 'iterdir', 'glob', 'mkdir', 'unlink', 'rename',
                'replace', 'chmod', 'symlink_to')),
        (local_install, ('_require_supported_user', 'install_paths', '_validated_source',
                         '_prepare_directories', '_mutation_lock')),
        (local_install.getpass, ('getpass',)),
        (local_install.os, ('open', 'write', 'stat', 'lstat', 'mkdir', 'makedirs',
                            'unlink', 'remove', 'rmdir', 'rename', 'replace',
                            'chmod', 'chown', 'symlink', 'system', 'fork')),
        (local_install.os.path, ('lexists',)),
        (subprocess, ('Popen', 'run', 'call', 'check_call', 'check_output')),
        (socket, ('socket', 'create_connection', 'getaddrinfo')),
        (sqlite3, ('connect',)), (threading.Thread, ('start',)),
        (shutil, ('which', 'rmtree')),
    ]
    with ExitStack() as stack:
        for owner, names in surfaces:
            for name in names:
                if hasattr(owner, name):
                    stack.enter_context(patch.object(owner, name, forbidden(name)))
        yield attempts
    if attempts:
        raise AssertionError('effect attempts: ' + ', '.join(attempts))


class Stage0InstallerTests(unittest.TestCase):
    def setUp(self):
        self.boundary = fresh_boundary()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for module in (local_install, install_lifecycle):
            self.stack.enter_context(patch.object(module, 'execution_boundary', self.boundary, create=True))

    def test_selected_public_apis_deny_before_preflight(self):
        self.boundary.select_stage0()
        with effect_tripwires() as attempts:
            for name, invoke in public_entries().items():
                with self.subTest(entry=name), self.assertRaisesRegex(
                        self.boundary.Stage0Denied, '^STAGE0_OFFLINE_EFFECT_DENIED$'):
                    invoke()
        self.assertEqual(attempts, [])

    def test_cli_denies_before_parser_dispatch_or_password_prompt(self):
        self.boundary.select_stage0()
        arguments = [[], ['--help'], ['unknown'], ['INSTALL'],
                     ['install', '--source', '/synthetic/not-read'], ['repair'],
                     ['uninstall'], ['status', '--json'], ['password', 'set'],
                     ['password', 'clear'], ['password', 'status'], [None]]
        with patch.object(local_install, 'build_parser', side_effect=AssertionError('parser reached')):
            for argv in arguments:
                with self.subTest(argv=argv), effect_tripwires(), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(local_install.main(argv), 2)
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(err.getvalue(), self.boundary.DENIAL + '\n')

    def test_invalid_and_missing_mode_do_not_recover_permission(self):
        for state in (None, 0, 1, 'installed_runtime'):
            self.boundary._stage0_selected = state
            with effect_tripwires():
                for name, invoke in public_entries().items():
                    with self.subTest(state=state, entry=name), self.assertRaises(self.boundary.Stage0Denied):
                        invoke()
        del self.boundary._stage0_selected
        with effect_tripwires(), self.assertRaises(self.boundary.Stage0Denied):
            local_install.install(None)

    def test_invalid_service_actions_and_manifest_refuse_before_validation(self):
        self.boundary.select_stage0()
        with effect_tripwires():
            for value in ('start', 'stop', 'START', [], {}):
                with self.subTest(action=value), self.assertRaises(self.boundary.Stage0Denied):
                    install_lifecycle.service_action(value)
            for manifest in ({}, [], 'invalid'):
                with self.subTest(manifest=manifest), self.assertRaises(self.boundary.Stage0Denied):
                    install_lifecycle.retire_releases(None, manifest, inspect_protected=True)

    def test_parser_construction_and_boundary_status_remain_available(self):
        self.boundary.select_stage0()
        # argparse locale discovery is trusted developer setup, outside the
        # guarded installer invocation. main() must never reach it after denial.
        parser = local_install.build_parser()
        self.assertEqual(parser.parse_args(['repair']).command, 'repair')
        with effect_tripwires():
            self.assertEqual(self.boundary.status()['mode'], 'stage0_offline')
            self.assertFalse(self.boundary.status()['acceptance_authority'])

    def test_ordinary_cli_dispatch_preserves_arguments_and_marks_admission(self):
        result = {'version': 'synthetic'}
        with patch.object(local_install, 'install', return_value=result) as install, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(local_install.main(['install', '--source', '/synthetic/not-read', '--inspect-protected']), 0)
        install.assert_called_once_with(Path('/synthetic/not-read'), inspect_protected=True)
        self.assertIn('MEGALODON synthetic is installed for this user.', out.getvalue())
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()

    def test_ordinary_public_mutator_reaches_existing_preflight(self):
        class PreflightReached(Exception):
            pass

        with patch.object(local_install, '_require_supported_user', side_effect=PreflightReached):
            with self.assertRaises(PreflightReached):
                local_install.install(None)
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()

    def test_ordinary_lifecycle_preserves_action_validation(self):
        with self.assertRaisesRegex(local_install.InstallError, '^Unsupported service transition$'):
            install_lifecycle.service_action('invalid')
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()


if __name__ == '__main__':
    unittest.main(verbosity=2)
