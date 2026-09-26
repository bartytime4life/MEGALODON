"""Explicit, bounded stdin configuration preflight; never starts the application."""
from __future__ import annotations

import argparse
from dataclasses import fields
import json
import sys
import tomllib

from .config import (AISettings, BlockingSettings, DashboardSettings, DetectionSettings,
                     StorageSettings, _settings_from_mapping)
from .dashboard import loopback_host
from .validation import ValidationError

MAX_BYTES = 65536
SCHEMA = 'megalodon-config-preflight-v1'
TABLE_FIELDS = {
    'app': frozenset(('name', 'db_path', 'log_level')),
    'capture': frozenset(('source', 'interface')),
    **{name: frozenset(field.name for field in fields(cls)) for name, cls in (
        ('ai', AISettings), ('blocking', BlockingSettings),
        ('dashboard', DashboardSettings), ('detection', DetectionSettings),
        ('storage', StorageSettings))},
}
CHECKS = ('input', 'toml', 'field_names', 'typed_values', 'dashboard_binding', 'capture_interface')


def check_configuration(raw: bytes) -> dict:
    """Return fixed categories and effective non-sensitive options, never input text."""
    report = {
        'schema': SCHEMA, 'status': 'invalid', 'code': 'input_unavailable',
        'checks': {name: 'not_checked' for name in CHECKS}, 'options': None,
        'runtime_verified': False,
        'limits': ['Configuration only; no database, paths, permissions, executables, devices or provider inspected.',
                   'No installation, configuration write, program launch, capture, model or firewall action performed.'],
    }

    def fail(check, code):
        report['checks'][check] = 'failed'
        report['code'] = code
        return report

    if not isinstance(raw, bytes) or not raw.strip() or len(raw) > MAX_BYTES:
        return fail('input', 'input_empty_or_too_large')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError:
        return fail('input', 'input_not_utf8')
    report['checks']['input'] = 'passed'
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return fail('toml', 'invalid_toml')
    report['checks']['toml'] = 'passed'
    if set(value) - set(TABLE_FIELDS):
        return fail('field_names', 'unknown_table')
    for name, table in value.items():
        if not isinstance(table, dict):
            return fail('field_names', 'table_required')
        if set(table) - TABLE_FIELDS[name]:
            return fail('field_names', 'unknown_setting')
    report['checks']['field_names'] = 'passed'
    try:
        settings = _settings_from_mapping(value)
    except (ValidationError, ValueError, TypeError, OverflowError):
        return fail('typed_values', 'invalid_setting_value')
    report['checks']['typed_values'] = 'passed'
    try:
        loopback_host(settings.dashboard.host)
    except ValueError:
        return fail('dashboard_binding', 'unsupported_dashboard_binding')
    report['checks']['dashboard_binding'] = 'passed'
    if settings.capture_source == 'scapy' and not settings.interface:
        return fail('capture_interface', 'capture_interface_required')
    report['checks']['capture_interface'] = 'passed'
    report['status'] = 'valid'
    report['code'] = 'configuration_valid_runtime_unverified'
    report['options'] = {
        'capture_source': settings.capture_source,
        'dashboard_enabled': settings.dashboard.enabled,
        'refresh_seconds': settings.dashboard.refresh_seconds,
        'event_limit': settings.dashboard.event_limit,
        'ai_enabled': settings.ai.enabled,
        'firewall_application_supported': False,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Validate core settings TOML from stdin without starting MEGALODON. Exit 0: valid configuration only; 1: invalid/unavailable input. No paths or raw values are printed.')
    parser.add_argument('--defaults', action='store_true', help='Check built-in defaults without reading stdin')
    args = parser.parse_args(argv)
    try:
        raw = b'# explicit built-in defaults\n' if args.defaults else sys.stdin.buffer.read(MAX_BYTES + 1)
        report = check_configuration(raw)
    except OSError:
        report = check_configuration(b'')
        report['code'] = 'input_unavailable'
    print(json.dumps(report, separators=(',', ':'), allow_nan=False))
    return 0 if report['status'] == 'valid' else 1


if __name__ == '__main__':
    raise SystemExit(main())
