"""The full-uninstall scan observes fixed surfaces without changing them."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from megalodon import uninstall_audit
from megalodon.local_install import install_paths


def test_audit_marks_presence_without_claiming_ownership(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = install_paths({'HOME': str(home)})
    paths.data.mkdir(parents=True)
    (home / '.local/zeek-9.1.0').mkdir()
    (home / '.config/wireshark/profiles/MEGALODON').mkdir(parents=True)
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {'nmap': 'installed'})
    before = sorted(str(path) for path in home.rglob('*'))

    result = uninstall_audit.audit(paths, home=home)

    assert result['schema'] == uninstall_audit.SCHEMA
    assert result['mode'] == 'read_only'
    assert result['artifacts']['data']['state'] == 'directory'
    assert result['artifacts']['wireshark_profile']['state'] == 'directory'
    assert result['private_zeek_candidates'][0]['state'] == 'directory'
    assert result['apt_package_presence']['nmap'] == 'installed'
    assert result['preserve_packages'] == ['python3', 'git']
    assert any('does not prove' in row for row in result['unresolved'])
    assert sorted(str(path) for path in home.rglob('*')) == before


def test_package_probe_uses_fixed_read_only_names(monkeypatch):
    captured = []
    def run(argv, **kwargs):
        captured.append((argv, kwargs))
        return SimpleNamespace(stdout='nmap\tinstall ok installed\nunknown\tinstall ok installed\n', returncode=1)
    monkeypatch.setattr(uninstall_audit.sys, 'platform', 'linux')
    monkeypatch.setattr(uninstall_audit.subprocess, 'run', run)
    result = uninstall_audit._package_status()
    assert result['nmap'] == 'installed'
    assert result['suricata'] == 'unknown'
    assert set(result) == set(uninstall_audit.APT_PACKAGES)
    argv, options = captured[0]
    assert argv[:3] == ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Status}\n']
    assert tuple(argv[3:]) == uninstall_audit.APT_PACKAGES
    assert options['timeout'] == 5
    assert 'shell' not in options


def test_symlink_is_reported_without_following_it(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = install_paths({'HOME': str(home)})
    paths.config.parent.mkdir(parents=True)
    paths.config.symlink_to(tmp_path / 'outside')
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    assert uninstall_audit.audit(paths, home=home)['artifacts']['config']['state'] == 'symlink'


def test_dumpcap_snapshot_cannot_imply_prior_permissions(tmp_path, monkeypatch):
    binary = tmp_path / 'dumpcap'
    binary.write_text('inert')
    binary.chmod(0o750)
    def xattr(path, key, **kwargs):
        assert path == binary and kwargs == {'follow_symlinks': False}
        return b'present' if key == 'security.capability' else b''
    monkeypatch.setattr(uninstall_audit.os, 'getxattr', xattr)
    assert uninstall_audit._dumpcap_state(binary) == {
        'path': str(binary), 'state': 'file', 'owner_current_user': True,
        'mode': '0o750', 'capability_xattr': 'present', 'acl_xattr': 'absent',
    }


@pytest.mark.parametrize('count,state', [(32, 'complete'), (33, 'limited'), (513, 'limited')])
def test_private_zeek_output_marks_either_scan_limit(tmp_path, monkeypatch, capsys, count, state):
    home = tmp_path / 'home'
    home.mkdir()
    local = home / '.local'
    local.mkdir()
    for index in range(count):
        (local / f'zeek-{index:04}').mkdir()
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(install_paths({'HOME': str(home)}), home=home)
    assert len(result['private_zeek_candidates']) == 32
    assert result['private_zeek_scan_state'] == state
    names = [entry['path'] for entry in result['private_zeek_candidates']]
    assert names == sorted(names)
    monkeypatch.setattr(uninstall_audit, 'audit', lambda: result)
    assert uninstall_audit.main([]) == 0
    assert ('Private Zeek scan: limited' in capsys.readouterr().out) is (state == 'limited')


def test_private_zeek_discovery_reads_at_most_513_entries(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    consumed = []
    original = Path.iterdir
    def iterdir(path):
        if path == home / '.local':
            for index in range(10000):
                consumed.append(index)
                yield path / f'zeek-{index:05}'
        else:
            yield from original(path)
    monkeypatch.setattr(Path, 'iterdir', iterdir)
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(install_paths({'HOME': str(home)}), home=home)
    assert len(consumed) == 513
    assert result['private_zeek_scan_state'] == 'limited'


@pytest.mark.parametrize('package_state,expected', [
    ('install ok installed', 'installed'), ('hold ok installed', 'installed'),
    ('deinstall ok installed', 'installed'), ('purge ok not-installed', 'not_installed'),
    ('unknown ok not-installed', 'not_installed'), ('deinstall ok config-files', 'unknown'),
    ('install ok unpacked', 'unknown'), ('install ok half-configured', 'unknown'),
    ('install ok half-installed', 'unknown'), ('install ok triggers-pending', 'unknown'),
    ('install ok triggers-awaited', 'unknown'), ('install reinstreq installed', 'unknown'),
    ('unexpected ok installed', 'unknown'), ('malformed', 'unknown'),
])
def test_package_status_does_not_infer_absence_from_other_states(monkeypatch, package_state, expected):
    monkeypatch.setattr(uninstall_audit.sys, 'platform', 'linux')
    monkeypatch.setattr(uninstall_audit.subprocess, 'run', lambda *a, **k:
                        SimpleNamespace(stdout=f'nmap\t{package_state}\n', returncode=0))
    assert uninstall_audit._package_status()['nmap'] == expected


def test_conflicting_duplicate_package_rows_stay_unknown(monkeypatch):
    monkeypatch.setattr(uninstall_audit.sys, 'platform', 'linux')
    monkeypatch.setattr(uninstall_audit.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        stdout='nmap\tinstall ok installed\nnmap\tpurge ok not-installed\nnmap\tinstall ok installed\n', returncode=0))
    assert uninstall_audit._package_status()['nmap'] == 'unknown'


def test_custom_xdg_roots_do_not_hide_fixed_support_paths(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = install_paths({'HOME': str(home), 'XDG_DATA_HOME': str(home / 'xdg-data'),
                           'XDG_CONFIG_HOME': str(home / 'xdg-config')})
    fixed_data = home / '.local/share/megalodon/support'
    fixed_config = home / '.config/megalodon'
    fixed_data.mkdir(parents=True)
    fixed_config.mkdir(parents=True)
    (fixed_config / 'support-config.json').write_text('private evidence')
    before = sorted(str(path) for path in home.rglob('*'))
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(paths, home=home)
    for name, path in [('fixed_support_data', fixed_data), ('fixed_support_config', fixed_config)]:
        assert result['artifacts'][name] == {'path': str(path), 'state': 'directory', 'owner_current_user': True}
    assert result['artifacts']['data']['state'] == result['artifacts']['config']['state'] == 'absent'
    assert sorted(str(path) for path in home.rglob('*')) == before
    assert (fixed_config / 'support-config.json').read_text() == 'private evidence'


def test_default_config_is_not_listed_twice(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(install_paths({'HOME': str(home)}), home=home)
    assert 'fixed_support_data' in result['artifacts']
    assert 'fixed_support_config' not in result['artifacts']


def test_unreadable_paths_and_discovery_remain_unavailable(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir()
    paths = install_paths({'HOME': str(home)})
    original = Path.lstat
    def lstat(path, *a, **k):
        if path == paths.data:
            raise PermissionError('denied')
        return original(path, *a, **k)
    def iterdir(path):
        raise PermissionError('denied')
    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(Path, 'iterdir', iterdir)
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(paths, home=home)
    assert result['artifacts']['data']['state'] == 'unavailable'
    assert result['artifacts']['data']['owner_current_user'] is None
    assert result['private_zeek_scan_state'] == 'unavailable'


@pytest.mark.parametrize('profile', ['{', '{}', '{"schema":"v1","schema":"v1","directories":{}}'])
def test_malformed_tool_profile_requires_review_without_changes(tmp_path, monkeypatch, profile):
    home = tmp_path / 'home'
    home.mkdir()
    paths = install_paths({'HOME': str(home)})
    paths.config.mkdir(parents=True)
    file = paths.config / 'tool-directories.json'
    file.write_text(profile)
    file.chmod(0o600)
    monkeypatch.setattr(uninstall_audit, '_package_status', lambda: {})
    result = uninstall_audit.audit(paths, home=home)
    assert result['tool_directory_profile'] == 'needs_review'
    assert result['selected_tool_directories'] == {}
    assert file.read_text() == profile
