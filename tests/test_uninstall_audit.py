"""The full-uninstall scan observes fixed surfaces without changing them."""
from pathlib import Path
from types import SimpleNamespace

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
    assert argv[:3] == ['dpkg-query', '-W', '-f=${Package}\t${Status}\n']
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
