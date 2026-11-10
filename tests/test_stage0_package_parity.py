"""Inert parity validation; no build, package installation, model or native tool."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('stage0_package_parity', ROOT / 'tools/stage0_package_parity.py')
parity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parity)


def wheel_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, raw in files:
            archive.writestr(name, raw)
    return output.getvalue()


class Stage0PackageParityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.checkout = Path(self.temporary.name) / 'source'
        self.package = self.checkout / 'megalodon'
        self.package.mkdir(parents=True)
        self.content = b'__version__ = "0.1.0"\n'
        (self.package / '__init__.py').write_bytes(self.content)
        self.wheel = Path(self.temporary.name) / 'megalodon_defense-0.1.0-py3-none-any.whl'
        self.wheel.write_bytes(wheel_bytes([('megalodon/__init__.py', self.content)]))
        files, size = parity.package_files(self.package)
        self.identity = {'version': '0.1.0', 'file_count': 1, 'size_bytes': size,
                         'runtime': {'python': list(sys.version_info[:3]),
                             'implementation': sys.implementation.name, 'isolated': True,
                             'bytecode_writes_disabled': True},
                         'file_map_sha256': parity.digest(parity.canonical(files))}
        self.source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'working_tree_dirty': False}
        self.calls = []

    def fake_probe(self, python, mode, checkout, wheel_hash, case, directory):
        self.calls.append((mode, case))
        self.assertFalse(directory.is_relative_to(checkout))
        if case == 'identity':
            value = deepcopy(self.identity)
        elif case == 'status':
            value = {'exit_code': 0, 'stdout': json.dumps(parity.STATUS) + '\n', 'stderr': ''}
        else:
            value = {'exit_code': 2, 'stdout': '', 'stderr': parity.STATUS['denial_code'] + '\n'}
        return value, parity.digest(parity.canonical(value))

    def collect(self, probe=None):
        with patch.object(parity, 'source_identity', return_value=self.source), \
                patch.object(parity, 'command', return_value=b'megalodon/__init__.py\0'), \
                patch.object(parity, 'probe', side_effect=probe or self.fake_probe), \
                patch.object(parity.os, 'geteuid', return_value=1000):
            return parity.collect(self.checkout, 'a' * 40, 'b' * 40, self.wheel, Path('/unused/python'))

    def test_success_is_scoped_and_never_promotes_authority(self):
        value = self.collect()
        self.assertEqual(value['source'], self.source)
        self.assertEqual(value['package']['file_count'], 1)
        self.assertEqual(value['comparison']['package_files'], 'source_wheel_installed_equal')
        self.assertEqual(len(self.calls), 6)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertIsNone(value['tripwire_counts'])
        self.assertEqual(value['full_stage0_suite_package_parity'], 'NOT_RUN')
        self.assertTrue(all(status == 'NOT_RUN' for status in value['native_lanes'].values()))
        self.assertNotIn(str(self.checkout), json.dumps(value))

    def test_missing_extra_or_changed_wheel_package_file_refuses(self):
        for files in ([('other', b'x')], [('megalodon/__init__.py', b'changed')],
                      [('megalodon/__init__.py', self.content), ('megalodon/extra.py', b'x')]):
            self.wheel.write_bytes(wheel_bytes(files))
            with self.subTest(files=files), self.assertRaises(ValueError):
                self.collect()
        self.assertEqual(self.calls, [])

    def test_installed_identity_or_projection_mismatch_refuses(self):
        for target, key, damaged in (
            ('identity', 'file_map_sha256', '0' * 64),
            ('identity', 'version', 'other'),
            ('identity', 'file_count', True),
            ('identity', 'runtime', {'python': [3, 10, 0]}),
            ('status', 'stdout', '{"mode":"installed_runtime"}'),
            ('status', 'exit_code', False),
            ('denial', 'exit_code', True),
            ('denial', 'stdout', 'unexpected'),
        ):
            def probe(*args):
                value, hashed = self.fake_probe(*args)
                if args[1] == 'installed' and args[4] == target:
                    value[key] = damaged
                return value, hashed
            with self.subTest(case=target, key=key), self.assertRaises(ValueError):
                self.collect(probe)

    def test_source_or_wheel_mutation_after_probe_refuses(self):
        for kind in ('source', 'wheel'):
            def probe(*args):
                value = self.fake_probe(*args)
                if args[1] == 'installed' and args[4] == 'denial':
                    (self.package / '__init__.py' if kind == 'source' else self.wheel).write_bytes(b'changed')
                return value
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.collect(probe)
            (self.package / '__init__.py').write_bytes(self.content)

    def test_wheel_path_aliases_and_symlinks_refuse(self):
        for name in ('megalodon/../escape.py', '/megalodon/escape.py',
                     'megalodon//escape.py', 'megalodon\\escape.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                parity.wheel_files(wheel_bytes([(name, b'x')]))
        info = zipfile.ZipInfo('megalodon/link')
        info.external_attr = 0o120777 << 16
        with self.assertRaises(ValueError):
            parity.wheel_files(wheel_bytes([(info, b'target')]))

    def test_package_caches_are_excluded_but_symlinks_refuse(self):
        cache = self.package / '__pycache__'
        cache.mkdir()
        (cache / 'ignored.pyc').write_bytes(b'cache')
        (self.package / 'ignored.pyc').write_bytes(b'cache')
        self.assertEqual(parity.package_files(self.package)[0], {'__init__.py': parity.digest(self.content)})
        (self.package / 'linked.py').symlink_to(self.package / '__init__.py')
        with self.assertRaises(ValueError):
            parity.package_files(self.package)

    def test_source_pin_dirty_or_wrong_identity_refuses(self):
        for outputs in ((str(self.checkout).encode(), b'x' * 40, b'b' * 40, b''),
                        (str(self.checkout).encode(), b'a' * 40, b'b' * 40, b' M changed.py'),
                        (str(self.checkout.parent).encode(),)):
            with patch.object(parity, 'command', side_effect=outputs), self.assertRaises(ValueError):
                parity.source_identity(self.checkout, 'a' * 40, 'b' * 40)
        with self.assertRaises(ValueError):
            parity.source_identity(self.checkout, 'A' * 40, 'b' * 40)

    def test_untracked_package_file_cannot_inherit_git_tree_identity(self):
        (self.package / 'extra.py').write_bytes(b'extra')
        self.wheel.write_bytes(wheel_bytes([('megalodon/__init__.py', self.content),
                                           ('megalodon/extra.py', b'extra')]))
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(self.calls, [])

    def test_child_cli_capture_is_bounded_before_wrapper_prints(self):
        injected = parity.PROBE.replace("runpy.run_module('megalodon', run_name='__main__')",
                                        "print('x' * 20000)")
        result = parity.subprocess.run([sys.executable, '-I', '-B', '-c', injected,
            'source', str(ROOT), '0' * 64, 'status'], cwd=self.checkout,
            stdout=parity.subprocess.PIPE, stderr=parity.subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'PROBE_OUTPUT_LIMIT', result.stderr)

    def test_command_caps_output_errors_and_deadline(self):
        cases = [
            ('print("x" * 1000)', {'limit': 32}),
            ('import sys; sys.stderr.write("private detail")', {}),
            ('raise SystemExit(2)', {}),
            ('while True: pass', {'timeout': 0.05}),
        ]
        for code, options in cases:
            with self.subTest(code=code), self.assertRaises((ValueError, parity.subprocess.TimeoutExpired)):
                parity.command([sys.executable, '-I', '-B', '-c', code], self.checkout, **options)
        self.assertEqual(parity.command([sys.executable, '-I', '-B', '-c', 'print("ok")'], self.checkout), b'ok\n')

    def test_cli_failure_has_fixed_path_free_diagnostic(self):
        args = ['--checkout', str(self.checkout), '--commit', 'a' * 40, '--tree', 'b' * 40,
                '--wheel', str(self.wheel), '--installed-python', '/unused/python']
        with patch.object(parity, 'collect', side_effect=ValueError('private path')), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(parity.main(args), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(err.getvalue(), parity.DENIAL + '\n')


class Stage0PackageParityWorkflowTests(unittest.TestCase):
    def test_workflow_is_exact_scoped_and_offline_after_locked_setup(self):
        raw = (ROOT / '.github/workflows/stage0-package-parity.yml').read_text()
        for required in ('github.event.pull_request.head.sha || github.sha',
                         'persist-credentials: false', 'constraints/test-linux-cp311.txt',
                         '--require-hashes', '--no-build-isolation', '--no-deps', '--without-pip',
                         '--no-index', '-I -B', '--python "$RUNNER_TEMP/stage0-installed/bin/python"',
                         'tools/stage0_package_parity.py', 'if: ${{ always() }}',
                         'stage0-package-projection-parity.json'):
            self.assertIn(required, raw)
        for prohibited in ('ollama pull', 'ollama run', 'systemctl', 'curl ', 'wget ', 'sudo '):
            self.assertNotIn(prohibited, raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
