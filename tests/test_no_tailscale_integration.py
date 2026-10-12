"""Removal guards; provider names here are negative controls, not integration."""
from pathlib import Path
import re
import subprocess

import pytest

from megalodon import local_setup, readiness, tool_setup
from megalodon.network_topology import parse_inventory

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIERS = re.compile(
    rb'tailscale|tailscaled|tailscale0|tailnet|magicdns|ts\.net|tailscale_|ts_authkey',
    re.IGNORECASE,
)


@pytest.mark.parametrize('relative', [
    'megalodon', 'scripts', '.github', 'config', 'constraints',
    'Start-MEGALODON.sh', 'pyproject.toml', 'MANIFEST.in',
])
def test_active_distribution_has_no_tailscale_hooks(relative):
    # Tests and historical review documents may retain negative/security evidence.
    # Inspect source, executable UI assets, setup/startup, dependencies and CI.
    target = ROOT / relative
    assert target.exists(), f'Missing audited distribution path: {relative}'
    files = target.rglob('*') if target.is_dir() else [target]
    for path in files:
        if path.is_symlink() or not path.is_file() or '__pycache__' in path.parts:
            continue
        if path.suffix in {'.pyc', '.pyo'}:
            continue
        name = str(path.relative_to(ROOT))
        assert not IDENTIFIERS.search(name.encode()), f'Provider filename: {name}'
        # Only report the path: never echo matching configuration/credential bytes.
        assert not IDENTIFIERS.search(path.read_bytes()), f'Provider reference: {name}'


@pytest.mark.parametrize('action', ['plan', 'install', 'configure', 'verify', 'uninstall'])
def test_retired_companion_is_refused_before_process_work(monkeypatch, action):
    def forbidden(*args, **kwargs):
        pytest.fail('Unsupported companion attempted process work')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    with pytest.raises(SystemExit) as error:
        tool_setup.main(['tailscale', action, '--apply'])
    assert error.value.code == 2


def test_preflight_and_readiness_work_with_no_optional_executables(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PATH', str(tmp_path))
    monkeypatch.setattr(local_setup.sys, 'platform', 'linux')
    monkeypatch.setattr(readiness, 'runtime_platform', lambda: 'linux')
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only setup attempted process work')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    report = readiness.readiness_report()
    assert all(row['status'] in {'not_found', 'not_checked'} for row in report['tools'])
    assert not IDENTIFIERS.search(str(report).encode())
    assert local_setup.main([]) == 0
    assert 'not configured' in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('name,kind,expected', [
    ('tailscale0', None, 'lan'),
    ('tailscale0', 'tun', 'vpn'),
    ('wg0', None, 'vpn'),
    ('tun0', None, 'vpn'),
    ('tap0', None, 'vpn'),
    ('ppp0', None, 'vpn'),
    ('eth0', 'wireguard', 'vpn'),
    ('eth0', None, 'lan'),
])
def test_topology_uses_generic_tunnel_metadata_without_vendor_rules(name, kind, expected):
    row = {'ifname': name, 'addr_info': []}
    if kind is not None:
        row['linkinfo'] = {'info_kind': kind}
    value = parse_inventory([row], [], [], '2026-10-12T00:00:00Z')
    assert value['groups'][name]['kind'] == expected
