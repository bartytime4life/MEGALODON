"""Owner-selected tool directories must agree across checks and execution."""
import json
from pathlib import Path

import pytest

from megalodon import readiness, support_sensors, tool_heartbeat, tool_locations


def test_selected_zeek_directory_is_used_by_setup_heartbeat_and_sampler(private_tmp_path, monkeypatch):
    tmp_path = private_tmp_path
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    directory = tmp_path / 'custom apps' / 'bin'
    directory.mkdir(parents=True)
    marker = tmp_path / 'unexpected-execution'
    binary = directory / 'zeek'
    binary.write_text(f'#!/bin/sh\ntouch "{marker}"\n', encoding='utf-8')
    binary.chmod(0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('PATH', str(tmp_path / 'empty-path'))
    monkeypatch.setattr(readiness, 'runtime_platform', lambda: 'linux')
    monkeypatch.setattr(tool_heartbeat, 'runtime_platform', lambda: 'linux')

    assert support_sensors.zeek_binary(home) is None
    assert tool_locations.save_directory(home, 'zeek', str(directory)) == {'zeek': str(directory)}
    assert tool_locations.profile_path(home).stat().st_mode & 0o777 == 0o600
    assert tool_locations.load_directories(home) == {'zeek': str(directory)}
    assert next(row for row in readiness.local_readiness_report()['tools'] if row['id'] == 'zeek')['status'] == 'executable_found'
    assert next(row for row in tool_heartbeat.heartbeat_report()['tools'] if row['id'] == 'zeek')['installed'] == 'yes'
    assert support_sensors.zeek_binary(home) == str(binary)
    assert not marker.exists()

    binary.unlink()
    assert support_sensors.zeek_binary(home) is None
    assert next(row for row in readiness.local_readiness_report()['tools'] if row['id'] == 'zeek')['status'] == 'not_found'
    assert tool_locations.save_directory(home, 'zeek', '') == {}
    assert tool_locations.load_directories(home) == {}
    other = directory / 'nmap'
    other.write_text('inert', encoding='utf-8')
    other.chmod(0o700)
    tool_locations.save_directory(home, 'nmap', str(directory))
    assert next(row for row in readiness.local_readiness_report()['tools'] if row['id'] == 'nmap')['status'] == 'executable_found'


@pytest.mark.parametrize('directory', ['relative/bin', '/tmp/../bin', '//remote/bin', '/tmp/\n/bin', '/' + 'x' * 1025])
def test_invalid_selected_directory_is_rejected(tmp_path, directory):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        tool_locations.save_directory(home, 'zeek', directory)
    assert not tool_locations.profile_path(home).exists()


def test_unsafe_or_duplicate_profile_is_rejected(tmp_path):
    home = tmp_path / 'home'
    profile = tool_locations.profile_path(home)
    profile.parent.mkdir(parents=True, mode=0o700)
    profile.write_text(json.dumps({'schema': tool_locations.SCHEMA, 'directories': {}}))
    profile.chmod(0o644)
    with pytest.raises(ValueError):
        tool_locations.load_directories(home)
    profile.chmod(0o600)
    profile.write_text('{"schema":"megalodon-tool-directories-v1","directories":{"zeek":"/a","zeek":"/b"}}')
    with pytest.raises(ValueError):
        tool_locations.load_directories(home)
    profile.unlink()
    profile.symlink_to(tmp_path / 'other')
    with pytest.raises(ValueError):
        tool_locations.load_directories(home)


def test_selected_executable_rejects_publicly_writable_ancestor(tmp_path):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    directory = tmp_path / 'public' / 'bin'
    directory.mkdir(parents=True)
    binary = directory / 'zeek'
    binary.write_text('inert')
    binary.chmod(0o700)
    directory.parent.chmod(0o777)
    with pytest.raises(ValueError):
        tool_locations.save_directory(home, 'zeek', str(directory))


def test_unselected_private_zeek_versions_are_discovered(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    binary = home / '.local/zeek-9.1.0/bin/zeek'
    binary.parent.mkdir(parents=True)
    binary.write_text('inert')
    binary.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path / 'empty-path'))
    assert support_sensors.zeek_binary(home) == str(binary)
