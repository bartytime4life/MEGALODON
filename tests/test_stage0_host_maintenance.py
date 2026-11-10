"""Inert fences for startup policy, removal review and default path discovery."""
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from megalodon import hud_autostart as hud, startup_policy as startup
from megalodon import uninstall_audit as audit, uninstall_plan as plan


def fresh_boundary():
    spec = importlib.util.spec_from_file_location(
        'isolated_host_boundary', Path(hud.__file__).with_name('execution_boundary.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def entries():
    return {
        'constructor': lambda: startup.StartupPolicy(),
        'observation': lambda: startup.service_observation(object()),
        'check': lambda: startup.StartupPolicy.check(None),
        'login': lambda: startup.StartupPolicy.login(None, object()),
        'enable_services': lambda: startup.StartupPolicy.enable_services(None, clamav_configured=object()),
        'audit': lambda: audit.audit(object(), home=object()),
        'entry': lambda: audit._entry(None),
        'packages': lambda: audit._package_status(),
        'dumpcap': lambda: audit._dumpcap_state(None),
        'plan': lambda: plan.plan(packages=object(), include_saved_data=object()),
        'preview': lambda: plan.package_preview(object()),
        'simulation': lambda: plan._simulate(object()),
        'file_item': lambda: plan._file_item(None, None, None),
        'default_unit_path': lambda: hud.unit_path(),
        'default_dropin_path': lambda: hud.dropin_path(),
        'default_unit_contents': lambda: hud.unit_contents(),
    }


@contextmanager
def no_preflight():
    from test_stage0_installer import effect_tripwires
    def forbidden(*args, **kwargs):
        raise AssertionError('host preflight reached')
    with effect_tripwires() as attempts, ExitStack() as stack:
        for owner, names in (
            (startup, ('Lock', '_trusted_system_executable')),
            (audit, ('install_paths', 'load_directories', 'local_status')),
            (hud, ('install_paths',)),
            (plan, ('_selected_packages',)),
            (plan.selectors, ('DefaultSelector',)),
            (plan.time, ('monotonic',)),
        ):
            for name in names:
                stack.enter_context(patch.object(owner, name, forbidden))
        yield attempts


class Stage0HostMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.boundary = fresh_boundary()
        stack = ExitStack()
        self.addCleanup(stack.close)
        for module in (startup, audit, plan, hud):
            stack.enter_context(patch.object(module, 'execution_boundary', self.boundary))

    def test_selected_entries_refuse_before_preflight(self):
        self.boundary.select_stage0()
        with no_preflight() as attempts:
            for name, invoke in entries().items():
                with self.subTest(entry=name), self.assertRaisesRegex(
                        self.boundary.Stage0Denied, '^STAGE0_OFFLINE_EFFECT_DENIED$'):
                    invoke()
        self.assertEqual(attempts, [])

    def test_invalid_and_missing_state_refuse(self):
        for state in (None, 0, 1, 'installed_runtime', {}, []):
            self.boundary._stage0_selected = state
            with no_preflight():
                for name, invoke in entries().items():
                    with self.subTest(state=state, entry=name), self.assertRaises(self.boundary.Stage0Denied):
                        invoke()
        del self.boundary._stage0_selected
        with no_preflight(), self.assertRaises(self.boundary.Stage0Denied):
            audit.audit()

    def test_cli_denies_before_parser_or_arguments(self):
        self.boundary.select_stage0()
        for module in (audit, plan):
            for argv in (None, [], ['--help'], ['--json'], ['--package', 'nmap'], [None], object()):
                with self.subTest(module=module.__name__, argv=type(argv).__name__), no_preflight(), patch.object(module.argparse, 'ArgumentParser', side_effect=AssertionError('parser reached')), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(module.main(argv), 2)
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(err.getvalue(), self.boundary.DENIAL + '\n')

    def test_late_cli_denial_is_fixed(self):
        for module, operation in ((audit, 'audit'), (plan, 'plan')):
            b = fresh_boundary()
            with self.subTest(module=module.__name__), patch.object(module, 'execution_boundary', b), patch.object(module, operation, side_effect=lambda *a, **kw: b.select_stage0()), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                self.assertEqual(module.main([]), 2)
                self.assertEqual((out.getvalue(), err.getvalue()), ('', b.DENIAL + '\n'))
                self.assertEqual(b.status()['mode'], 'unavailable')

    def test_startup_denial_is_not_downgraded_to_unknown(self):
        b = self.boundary
        policy = startup.StartupPolicy()
        old = policy.snapshot()
        with patch.object(hud, 'validate_unit', side_effect=lambda *a, **kw: b.select_stage0()), patch.object(startup, 'service_observation', side_effect=AssertionError('continued after denial')):
            with self.assertRaises(b.Stage0Denied):
                policy.check()
        self.assertEqual(policy.snapshot(), old)
        b = fresh_boundary()
        with patch.object(startup, 'execution_boundary', b), patch.object(startup, '_trusted_system_executable', return_value='/synthetic/systemctl'):
            with self.assertRaises(b.Stage0Denied):
                startup.service_observation('qwen', run=lambda *a: b.select_stage0())

    def test_preview_and_audit_propagate_nested_denial(self):
        b = self.boundary
        with patch.object(plan.sys, 'platform', 'linux'), patch.object(plan.os, 'geteuid', return_value=1000), patch.object(plan, '_simulate', side_effect=lambda *a, **kw: b.select_stage0()):
            with self.assertRaises(b.Stage0Denied):
                plan.package_preview(('nmap',))
        b = fresh_boundary()
        paths = SimpleNamespace(**{name: Path('/synthetic') / name for name in (
            'app', 'manifest', 'data', 'config', 'settings', 'hud_password',
            'hud_launcher', 'manager_launcher', 'desktop_entry', 'icon')})
        with patch.object(audit, 'execution_boundary', b), patch.object(audit, '_entry', return_value={}), patch.object(audit, 'load_directories', side_effect=lambda *a, **kw: b.select_stage0()), patch.object(Path, 'iterdir', side_effect=AssertionError('continued after denial')):
            with self.assertRaises(b.Stage0Denied):
                audit.audit(paths, home=Path('/synthetic'))

    def test_pure_parsers_and_explicit_templates_remain_available(self):
        self.boundary.select_stage0()
        paths = SimpleNamespace(config=Path('/synthetic/config/megalodon'), current=Path('/synthetic/current'),
                                settings=Path('/synthetic/settings'), hud_launcher=Path('/synthetic/hud'))
        with patch.object(hud, 'install_paths', side_effect=AssertionError('default discovery')):
            self.assertEqual(hud.unit_path(paths).name, hud.UNIT)
            self.assertEqual(hud.dropin_path(paths).name, hud.UNIT + '.d')
            self.assertIn(b'ExecStart=', hud.unit_contents(paths))
            self.assertEqual(plan._selected_packages(('nmap',)), ('nmap',))
            self.assertEqual(plan._parse_simulation('0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n'), [])
        self.assertEqual(self.boundary.status()['mode'], 'stage0_offline')

    def test_ordinary_read_only_preview_and_snapshot_are_preserved(self):
        policy = startup.StartupPolicy()
        self.assertEqual(policy.snapshot()['login'], 'unchecked')
        with patch.object(plan.sys, 'platform', 'linux'), patch.object(plan.os, 'geteuid', return_value=1000), patch.object(plan, '_simulate', return_value=(0, '0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv nmap [1.0]\n')) as simulate:
            self.assertEqual(plan.package_preview()['state'], 'not_selected')
            self.assertEqual(plan.package_preview(('nmap',))['state'], 'reviewable')
            simulate.assert_called_once_with(('nmap',))
        with self.assertRaises(self.boundary.Stage0Denied):
            self.boundary.select_stage0()


if __name__ == '__main__':
    unittest.main()
