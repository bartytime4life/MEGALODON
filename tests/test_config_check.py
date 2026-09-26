"""Preflight validates text, never the configured host resources."""
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest
from megalodon.config import load_settings
from megalodon.config_check import MAX_BYTES, check_configuration


def test_defaults_and_effective_configuration_match_runtime_parser(tmp_path):
    raw = b'[capture]\nsource="jsonl"\n[dashboard]\nrefresh_seconds=12\nevent_limit=125\n'
    path = tmp_path/'settings.toml'
    path.write_bytes(raw)
    runtime = load_settings(path)
    report = check_configuration(raw)
    assert report['status'] == 'valid'
    assert all(value == 'passed' for value in report['checks'].values())
    assert report['options']['capture_source'] == runtime.capture_source
    assert report['options']['refresh_seconds'] == runtime.dashboard.refresh_seconds
    assert report['options']['event_limit'] == runtime.dashboard.event_limit
    assert report['runtime_verified'] is False
    assert report['options']['firewall_application_supported'] is False


@pytest.mark.parametrize('raw,code', [
    (b'', 'input_empty_or_too_large'),
    (b' '*(MAX_BYTES+1), 'input_empty_or_too_large'),
    (b'\xff', 'input_not_utf8'),
    (b'[bad', 'invalid_toml'),
    (b'[dashboard]\nport=8787\nport=8888', 'invalid_toml'),
    (b'[dashbord]\nport=8888', 'unknown_table'),
    (b'[dashboard]\nrefresh_second=12', 'unknown_setting'),
    (b'dashboard="not a table"', 'table_required'),
    (b'[dashboard]\nrefresh_seconds=true', 'invalid_setting_value'),
    (b'[dashboard]\nrefresh_seconds=1', 'invalid_setting_value'),
    (b'[dashboard]\nport=65536', 'invalid_setting_value'),
    (b'[storage]\nmax_database_bytes=10', 'invalid_setting_value'),
    (b'[ai]\nendpoint="https://private.invalid"', 'invalid_setting_value'),
    (b'[blocking]\nauto_block=true\ndry_run=false', 'invalid_setting_value'),
    (b'[detection]\nsyn_flood_threshold=200\nmax_events_per_source_window=100', 'invalid_setting_value'),
    (b'[dashboard]\nhost="0.0.0.0"', 'unsupported_dashboard_binding'),
    (b'[dashboard]\nhost="::1"', 'unsupported_dashboard_binding'),
    (b'[dashboard]\nhost="private.invalid"', 'unsupported_dashboard_binding'),
    (b'[capture]\nsource="scapy"', 'capture_interface_required'),
])
def test_fixed_failure_categories_without_input_echo(raw, code):
    report = check_configuration(raw)
    assert report['status'] == 'invalid' and report['code'] == code
    assert report['options'] is None
    assert 'failed' in report['checks'].values()
    assert 'private.invalid' not in json.dumps(report)


@pytest.mark.parametrize('host', ['localhost', '127.0.0.1', '127.0.0.2'])
def test_binding_matches_supported_server_addresses(host):
    assert check_configuration(f'[dashboard]\nhost="{host}"'.encode())['status'] == 'valid'


def test_no_runtime_operations_or_sensitive_values(monkeypatch, tmp_path):
    def forbidden(*a, **k):
        pytest.fail('configuration preflight performed a runtime operation')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(Path, 'open', forbidden)
    raw = b'[app]\nname="private-name"\ndb_path="/private/missing/secret.db"\n[capture]\nsource="scapy"\ninterface="private-device"\n'
    report = check_configuration(raw)
    assert report['status'] == 'valid'
    assert 'private' not in json.dumps(report)
    assert not list(tmp_path.iterdir())


def test_cli_defaults_stdin_and_nonzero_failure(tmp_path):
    for args, raw, expected in [(['--defaults'], b'invalid input deliberately ignored', 0),
                                 ([], b'[dashboard]\nrefresh_seconds=10', 0),
                                 ([], b'[dashboard]\nrefresh_second=10', 1)]:
        result = subprocess.run([sys.executable, '-m', 'megalodon.config_check', *args], input=raw,
                                capture_output=True, timeout=10)
        assert result.returncode == expected
        assert not result.stderr
        receipt = json.loads(result.stdout)
        assert receipt['status'] == ('valid' if expected == 0 else 'invalid')


def test_all_existing_config_sections_have_shared_typed_validation():
    # Runtime loading keeps its compatibility behavior; explicit preflight is strict.
    from megalodon.config import _settings_from_mapping
    assert _settings_from_mapping({'legacy_extension': {}}) == load_settings()
    assert check_configuration(b'[legacy_extension]')['code'] == 'unknown_table'
