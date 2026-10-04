"""Removal previews fail closed and cannot become removal commands."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from megalodon import hud_autostart, local_install, uninstall_audit, uninstall_plan


def simulation(*packages):
    return (f'0 upgraded, 0 newly installed, {len(packages)} to remove and 3 not upgraded.\n'
            + ''.join(f'Remv {name} [1.0-1]\n' for name in packages))


@pytest.fixture
def non_root_linux(monkeypatch):
    monkeypatch.setattr(uninstall_plan.sys, 'platform', 'linux')
    monkeypatch.setattr(uninstall_plan.os, 'geteuid', lambda: 1000)


@pytest.mark.parametrize('packages', [('nmap+',), ('--purge',), ('python3',), ('git',),
                                      ('nftables',), ('nmap;id',), ('nmap', 'nmap')])
def test_invalid_selections_never_launch_a_process(monkeypatch, packages):
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: pytest.fail('must not execute'))
    with pytest.raises(ValueError):
        uninstall_plan.package_preview(packages)


def test_no_default_package_selection(monkeypatch):
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: pytest.fail('must not execute'))
    assert uninstall_plan.package_preview()['state'] == 'not_selected'


@pytest.mark.parametrize('platform,uid', [('win32', 1000), ('linux', 0)])
def test_no_privileged_or_unsupported_simulation(monkeypatch, platform, uid):
    monkeypatch.setattr(uninstall_plan.sys, 'platform', platform)
    monkeypatch.setattr(uninstall_plan.os, 'geteuid', lambda: uid)
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: pytest.fail('must not execute'))
    assert uninstall_plan.package_preview(('nmap',))['state'] == 'unavailable'


def test_combined_plan_includes_every_dependency_and_protects_python_git(non_root_linux, monkeypatch):
    observed = []
    def run(packages):
        observed.append(packages)
        return 0, simulation('nmap', 'tshark', 'python3.12:amd64', 'git', 'libpython3.12', 'ufw', 'desktop-app')
    monkeypatch.setattr(uninstall_plan, '_simulate', run)
    result = uninstall_plan.package_preview(('tshark', 'nmap'))
    assert observed == [('nmap', 'tshark')]
    assert result['state'] == 'blocked'
    assert result['protected'] == ['git', 'libpython3.12', 'python3.12:amd64', 'ufw']
    assert result['additional'] == ['desktop-app', 'git', 'libpython3.12', 'python3.12:amd64', 'ufw']


@pytest.mark.parametrize('output', [
    '', 'Remv nmap [1.0]\n', simulation('nmap') + 'Remv nmap [1.0]\n',
    simulation('nmap').replace('1 to remove', '2 to remove'),
    simulation('nmap') + 'Inst dependency [1.0]\n', simulation('nmap') + 'Conf dependency\n',
    simulation('nmap') + 'Purg dependency\n', simulation('nmap') + 'W: unreadable config\n',
    simulation('nmap').replace('Remv nmap [1.0-1]', 'Remv nmap+ [1.0] extra'),
    simulation('nmap') + '\x1b[32m', simulation('nmap') * 2,
    simulation('nmap').replace('0 newly installed', '1 newly installed'),
    simulation(*('package-' + str(i) for i in range(uninstall_plan.MAX_REMOVALS + 1))),
    'x' * (uninstall_plan.MAX_OUTPUT_BYTES + 1),
])
def test_uncertain_or_nonremoval_transactions_are_unavailable(non_root_linux, monkeypatch, output):
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: (0, output))
    result = uninstall_plan.package_preview(('nmap',))
    assert result['state'] == 'unavailable'
    assert result['removals'] == []


@pytest.mark.parametrize('failure', [OSError(), subprocess.TimeoutExpired('apt', 30), UnicodeError()])
def test_process_failures_cannot_look_like_empty_success(non_root_linux, monkeypatch, failure):
    def run(_):
        raise failure
    monkeypatch.setattr(uninstall_plan, '_simulate', run)
    assert uninstall_plan.package_preview(('nmap',))['state'] == 'unavailable'


def test_success_and_explicit_zero_removals(non_root_linux, monkeypatch):
    for output, removed in [(simulation('nmap:amd64'), ['nmap:amd64']), (simulation(), [])]:
        monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: (0, output))
        result = uninstall_plan.package_preview(('nmap',))
        assert result['state'] == 'reviewable'
        assert result['removals'] == removed
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: (100, simulation('nmap')))
    assert uninstall_plan.package_preview(('nmap',))['state'] == 'unavailable'


def test_real_reader_uses_only_simulation_and_discards_environment_overrides(monkeypatch):
    original = subprocess.Popen
    calls = []
    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        # Exercise the actual pipe reader against an inert child, never apt.
        return original([sys.executable, '-c', 'print(' + repr(simulation('nmap')) + ')'], **kwargs)
    monkeypatch.setenv('APT_CONFIG', '/untrusted/config')
    monkeypatch.setenv('LD_PRELOAD', '/untrusted/library')
    monkeypatch.setattr(uninstall_plan.subprocess, 'Popen', launch)
    code, output = uninstall_plan._simulate(('nmap',))
    assert code == 0 and uninstall_plan._parse_simulation(output) == ['nmap']
    argv, kwargs = calls[0]
    assert argv[0] == '/usr/bin/apt-get'
    assert '--simulate' in argv and '--no-download' in argv
    assert argv[-3:] == ['remove', '--', 'nmap']
    assert kwargs['env'] == {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    assert kwargs['stdin'] == subprocess.DEVNULL
    assert not kwargs.get('shell')


@pytest.mark.parametrize('script,timeout', [
    ('import os; os.write(1, b"x" * 100000); import time; time.sleep(10)', 5),
    ('import time; time.sleep(10)', 0.1),
])
def test_real_reader_bounds_output_and_time_and_reaps_child(monkeypatch, script, timeout):
    original = subprocess.Popen
    children = []
    def launch(argv, **kwargs):
        process = original([sys.executable, '-c', script], **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(uninstall_plan.subprocess, 'Popen', launch)
    monkeypatch.setattr(uninstall_plan, 'PREVIEW_TIMEOUT', timeout)
    with pytest.raises(ValueError):
        uninstall_plan._simulate(('nmap',))
    assert children[0].poll() is not None


def test_plan_preserves_data_by_default_and_reports_custom_locations(private_tmp_path, monkeypatch):
    home = private_tmp_path / 'home'
    home.mkdir()
    paths = local_install.install_paths({'HOME': str(home), 'XDG_DATA_HOME': str(home / 'chosen-data'),
                                         'XDG_CONFIG_HOME': str(home / 'chosen-config')})
    paths.data.mkdir(parents=True)
    evidence = paths.data / 'saved.sqlite'
    evidence.write_text('private evidence must not appear in output')
    paths.config.mkdir(parents=True)
    (home / '.local/zeek-8.0').mkdir(parents=True)
    for folder in (home, *(p for p in home.rglob('*') if p.is_dir())):
        folder.chmod(0o700)
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {'nmap': 'installed'})
    monkeypatch.setattr(uninstall_plan, '_simulate', lambda _: pytest.fail('not selected'))
    before = sorted(str(p) for p in home.rglob('*'))
    for include_data in (False, True):
        report = uninstall_plan.plan(paths=paths, home=home, include_saved_data=include_data)
        data = next(item for item in report['files'] if item['name'] == 'data')
        assert data['path'] == str(paths.data)
        assert data['disposition'] == ('candidate' if include_data else 'preserve')
        assert report['state'] == 'review_required' and report['execution_available'] is False
        assert report['scope']['shared_models'] == report['scope']['host_firewall'] == 'preserve'
        assert report['companions_for_review'][0]['disposition'] == 'preserve_for_review'
        assert evidence.read_text() not in json.dumps(report)
    assert sorted(str(p) for p in home.rglob('*')) == before
    assert evidence.read_text() == 'private evidence must not appear in output'


def test_selected_data_symlink_is_never_a_removal_candidate(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = local_install.install_paths({'HOME': str(home)})
    paths.config.parent.mkdir(parents=True)
    paths.config.symlink_to(tmp_path / 'unrelated-files')
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    report = uninstall_plan.plan(paths=paths, home=home, include_saved_data=True)
    item = next(row for row in report['files'] if row['name'] == 'config')
    assert item['disposition'] == 'preserve_for_review'
    assert paths.config.is_symlink()


def test_symlinked_ancestor_and_foreign_owner_are_held(tmp_path):
    actual = tmp_path / 'actual'
    actual.mkdir()
    linked = tmp_path / 'linked'
    linked.symlink_to(actual)
    child = actual / 'data'
    child.mkdir()
    entry = uninstall_audit._entry(linked / 'data')
    assert entry['state'] == 'directory'
    assert uninstall_plan._file_item('data', entry, True)['disposition'] == 'preserve_for_review'
    entry = {**uninstall_audit._entry(child), 'owner_current_user': False}
    assert uninstall_plan._file_item('data', entry, True)['disposition'] == 'preserve_for_review'


def test_manifest_paths_and_modified_launchers_are_reported_without_mutation(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = local_install.install_paths({'HOME': str(home)})
    release = paths.releases / 'synthetic-release'
    release.mkdir(parents=True)
    paths.current.symlink_to(release)
    paths.hud_launcher.parent.mkdir(parents=True)
    paths.hud_launcher.write_text('modified launcher')
    monkeypatch.setattr(local_install, '_load_manifest', lambda _: {'releases': [{'id': release.name}]})
    monkeypatch.setattr(uninstall_audit, 'local_status', lambda _: (2, {
        'status': 'needs_repair', 'artifacts': {'hud_launcher': 'modified'}}))
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    report = uninstall_plan.plan(paths=paths, home=home)
    rows = report['files']
    assert next(row for row in rows if row['name'] == 'managed_release')['path'] == str(release)
    assert next(row for row in rows if row['name'] == 'release_selector')['disposition'] == 'preserve_for_review'
    assert next(row for row in rows if row['name'] == 'hud_launcher')['disposition'] == 'preserve_for_review'
    assert paths.hud_launcher.read_text() == 'modified launcher'
    assert paths.current.is_symlink()


def test_cli_rejects_apply_and_returns_nonzero_for_failed_preview(monkeypatch, capsys):
    with pytest.raises(SystemExit) as error:
        uninstall_plan.main(['--apply'])
    assert error.value.code == 2
    monkeypatch.setattr(uninstall_plan, 'plan', lambda **_: {'package_preview': {'state': 'unavailable'}})
    assert uninstall_plan.main(['--json']) == 2
    assert json.loads(capsys.readouterr().out)['package_preview']['state'] == 'unavailable'


@pytest.mark.parametrize('kind,disposition', [
    ('managed', 'candidate'), ('modified', 'preserve_for_review'),
    ('symlink', 'preserve_for_review'), ('hardlink', 'preserve_for_review'),
    ('oversized', 'preserve_for_review'), ('unreadable', 'preserve_for_review'),
    ('absent', 'absent'),
])
def test_service_preview_uses_same_identity_check_as_disable(private_tmp_path, monkeypatch, kind, disposition):
    home = private_tmp_path / 'home'
    home.mkdir(mode=0o700)
    paths = local_install.install_paths({'HOME': str(home), 'XDG_CONFIG_HOME': str(home / 'selected-config')})
    unit = hud_autostart.unit_path(paths)
    local_install._create_directory_chain(unit.parent, 0o700)
    expected = hud_autostart.unit_contents(paths)
    if kind != 'absent':
        unit.write_bytes(expected)
    if kind == 'modified':
        unit.write_bytes(expected + b'# owner change\n')
    elif kind == 'oversized':
        unit.write_bytes(b'x' * 8193)
    elif kind in {'symlink', 'hardlink'}:
        other = home / 'unrelated-unit'
        unit.rename(other)
        if kind == 'symlink':
            unit.symlink_to(other)
        else:
            unit.hardlink_to(other)
    elif kind == 'unreadable':
        def denied(*args, **kwargs):
            raise PermissionError('denied')
        monkeypatch.setattr(hud_autostart, '_regular_owned_file', denied)
    monkeypatch.setattr(local_install, '_load_manifest', lambda _: {'releases': [{'id': 'synthetic'}]})
    monkeypatch.setattr(uninstall_audit, 'local_status', lambda _: (0, {'status': 'ready', 'artifacts': {}}))
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    monkeypatch.setattr(hud_autostart, '_systemctl', lambda *a: pytest.fail('preview must not change services'))
    before = unit.read_bytes() if kind != 'absent' else None

    report = uninstall_plan.plan(paths=paths, home=home)

    service = next(item for item in report['files'] if item['name'] == 'hud_user_service')
    assert service['disposition'] == disposition
    if kind != 'absent':
        assert service['installed_artifact_status'] == ('matches_managed_unit' if kind == 'managed' else 'needs_review')
        assert unit.read_bytes() == before
    else:
        assert not unit.exists()
