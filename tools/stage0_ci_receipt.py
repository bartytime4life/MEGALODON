#!/usr/bin/env python3
"""Summarize bounded CI evidence; never grant acceptance or host authority."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree

DENIAL = 'STAGE0_CI_RECEIPT_INVALID'
MAX_BYTES = 2 * 1024 * 1024
EFFECTS = {'network_access_performed', 'model_pulled', 'model_installed',
           'model_started', 'alias_created', 'host_configuration_changed',
           'detector_authority_granted', 'action_authority_granted'}
AUTHORITY = {'contacts_provider', 'starts_provider', 'pulls_model', 'changes_host',
             'attests_loaded_bytes', 'accepts_model', 'grants_detector_authority',
             'grants_action_authority', 'authorizes_release', 'authorizes_deployment'}
REQUIRED_CASES = {
    ('Stage0SerializationTests', 'test_admission_wins_and_late_selection_refuses'),
    ('Stage0SerializationTests', 'test_selection_wins_and_entry_refuses'),
    ('Stage0SerializationTests', 'test_status_fields_share_one_observation'),
    ('Stage0SerializationTests', 'test_cli_rechecks_admission_after_stale_query'),
    ('Stage0InstallerTests', 'test_selected_public_apis_deny_before_preflight'),
    ('Stage0InstallerTests', 'test_cli_denies_before_parser_dispatch_or_password_prompt'),
    ('Stage0HUDMaintenanceTests', 'test_selected_entries_refuse_before_preflight'),
    ('Stage0HUDMaintenanceTests', 'test_cli_denies_before_parser_arguments_or_settings'),
    ('TSharkStage0EntryTests', 'test_selected_replay_refuses_before_any_preflight'),
}


def _require(condition):
    if not condition:
        raise ValueError(DENIAL)


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                       parse_constant=lambda _: _require(False))
    _require(type(value) is dict)
    return value


def _all_false(value, keys):
    return type(value) is dict and set(value) == keys and all(
        item is False for item in value.values())


def build_receipt(commit, tree, binding_raw, readiness_raw, boundary_raw, junit_raw):
    """Identity is supplied by the workflow's exact-checkout gate, not attested here."""
    for identity in (commit, tree):
        _require(type(identity) is str and re.fullmatch('[0-9a-f]{40}', identity))
    binding = _json(binding_raw)
    readiness = _json(readiness_raw)
    boundary = _json(boundary_raw)
    _require(binding.get('status') == 'validated')
    record = binding['binding']
    _require(record['status'] == 'UNBOUND')
    _require(record['operator_decision']['status'] == 'NOT_RECORDED')
    _require(_all_false(record['effects'], EFFECTS))
    _require(readiness.get('state') == readiness.get('binding_status') == 'UNBOUND')
    _require(readiness.get('tools_used_or_authorized') is False)
    _require(readiness.get('gate_failures') == ['OWNER_MODEL_BINDING_NOT_RECORDED'])
    _require(_all_false(readiness.get('authority'), AUTHORITY))
    _require(boundary.get('schema') == 'megalodon-execution-boundary-v1')
    _require(boundary.get('mode') == 'stage0_offline')
    _require(boundary.get('effectful_entries_denied') is True)
    _require(boundary.get('denial_code') == 'STAGE0_OFFLINE_EFFECT_DENIED')
    _require(boundary.get('acceptance_authority') is False)
    _require(boundary.get('scope') == 'application_entry_fences_not_os_containment')

    _require(type(junit_raw) is bytes and 0 < len(junit_raw) <= MAX_BYTES)
    # Only UTF-8, declaration-free JUnit is accepted; no entity expansion.
    junit_text = junit_raw.decode('utf-8')
    _require('<!DOCTYPE' not in junit_text and '<!ENTITY' not in junit_text)
    root = ElementTree.fromstring(junit_text)
    _require(root.tag in {'testsuites', 'testsuite'})
    # Collection/setup failures can be represented outside a testcase.
    _require(next(root.iter('error'), None) is None and
             next(root.iter('failure'), None) is None)
    for suite in root.iter('testsuite'):
        for field in ('errors', 'failures'):
            _require(suite.get(field, '0') == '0')
    cases = list(root.iter('testcase'))
    _require(0 < len(cases) <= 20000)
    counts = {'passed': 0, 'failed': 0, 'errors': 0, 'skipped': 0}
    passed = set()
    for case in cases:
        outcome = ('errors' if case.find('error') is not None else
                   'failed' if case.find('failure') is not None else
                   'skipped' if case.find('skipped') is not None else 'passed')
        counts[outcome] += 1
        if outcome == 'passed':
            passed.add((case.get('classname', '').rsplit('.', 1)[-1], case.get('name')))
    _require(counts['failed'] == counts['errors'] == 0)
    _require(REQUIRED_CASES <= passed)

    return {
        'schema': 'megalodon-stage0-ci-receipt-v1',
        'evidence_level': 'synthetic',
        'commit': commit, 'tree': tree,
        'identity_source': 'workflow_exact_checkout_gate',
        'input_sha256': {name: sha256(raw).hexdigest() for name, raw in (
            ('binding', binding_raw), ('readiness', readiness_raw),
            ('boundary', boundary_raw), ('junit', junit_raw))},
        'junit_testcases': counts,
        'required_cases': [dict(classname=c, name=n) for c, n in sorted(REQUIRED_CASES)],
        'binding_state': 'UNBOUND',
        'denial_code': boundary['denial_code'],
        'tripwire_counts': None,
        'tripwire_measurement': 'not_aggregated_from_test_report',
        'source_package_parity': 'NOT_RUN',
        'native_lanes': {name: 'NOT_RUN' for name in ('tshark', 'zeek', 'suricata', 'qwen')},
        'independent_review': 'NOT_RECORDED',
        'owner_acceptance': 'NOT_RECORDED',
        'authority': {name: False for name in ('release', 'deployment', 'installation',
                      'model_execution', 'detector', 'response', 'host_control')},
    }


def _read(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    _require(0 < len(raw) <= MAX_BYTES)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tree', required=True)
    for name in ('binding', 'readiness', 'boundary', 'junit'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = build_receipt(args.commit, args.tree, *(
            _read(getattr(args, name)) for name in ('binding', 'readiness', 'boundary', 'junit')))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ElementTree.ParseError):
        print(DENIAL, file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
