"""Explicit one-shot anomaly evidence and optional local Qwen explanation."""

from __future__ import annotations

import argparse
import json
import os
import re

from ..advisory import AirlockDecision, FIXED_LIMITS
from ..anomaly_advisory import POLICY_VERSION, REQUEST_SCHEMA
from ..qwen_advisory import invoke_qwen_anomaly_advisory, validated_qwen_result
from .anomaly import INPUT_SCHEMA, build_anomaly_dossier, selection_fingerprint
from .baseline import read_reference
from .common import Limits, OfflineError, open_input, require_unprivileged_linux
from .zeek import json_object

MAX_RECEIPT_BYTES = 32 * 1024


def _failure(code: str) -> dict:
    return {'schema': 'offline-anomaly-triage-v2', 'status': 'failed',
            'reason_code': code, 'provider_request_performed': False,
            'persistence_status': 'not_attempted', 'action_status': 'not_attempted'}


def _json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's normal message echoes untrusted arguments and file names.
        self.exit(2, _json(_failure('INVALID_ARGUMENTS')) + '\n')


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error('duplicate argument')
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def _read_small_json(root: str, relative: str) -> dict:
    limit = 8192
    data = bytearray()
    with open_input(root, relative, Limits(input_bytes=limit)) as (fd, _):
        while True:
            chunk = os.read(fd, min(4096, limit - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise OfflineError('INPUT_SIZE_LIMIT')
    try:
        return json_object(data.decode('ascii'))
    except UnicodeDecodeError:
        raise OfflineError('INVALID_ENCODING') from None


def _explain(args, data: dict, dossier: dict) -> tuple[dict, bool | None, int]:
    """Provider failure must not discard the already constructed evidence."""
    try:
        registry = _read_small_json(args.input_root, args.registry)
    except (OfflineError, OSError):
        return {'outcome': 'DENY', 'reason_code': 'LOCAL_REGISTRY_UNAVAILABLE',
                'policy_version': POLICY_VERSION}, False, 3
    models = registry.get('models')
    entry = models[0] if type(models) is list and len(models) == 1 else {}
    receipt = entry.get('model_receipt', {}) if type(entry) is dict else {}
    request = {'schema': REQUEST_SCHEMA, 'question_type': args.question_type or 'explain_anomalies',
               'input': data, 'model_receipt': receipt, 'limits': dict(FIXED_LIMITS)}
    try:
        result = invoke_qwen_anomaly_advisory(
            request, enabled=True, local_model_registry=registry,
            local_model_registry_sha256=args.registry_sha256,
            selection_sha256=args.selection_sha256,
        )
        if type(result) is AirlockDecision:
            if (type(result.decision) is not str or result.decision != 'DENY'
                    or type(result.code) is not str or result.code != 'POLICY_DENIED'
                    or type(result.policy_version) is not str or result.policy_version != POLICY_VERSION
                    or type(result.reason_code) is not str
                    or re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', result.reason_code) is None
                    or result.provider_request_performed is not False or result.prompt is not None):
                raise ValueError('invalid preflight denial')
            return {'outcome': 'DENY', 'reason_code': result.reason_code,
                    'policy_version': POLICY_VERSION}, False, 3
        expected_ids = tuple(row['id'] for row in dossier['candidates'])
        result = validated_qwen_result(
            result, policy_version=POLICY_VERSION, candidate_ids=expected_ids)
        projection = result.to_dict()
        if projection['model_receipt'] != receipt:
            raise ValueError('provider receipt identity mismatch')
        ai = dict(projection, reason_code=result.reason_code)
        # Serialization is also inside the provider isolation boundary. No
        # malformed return may discard the already constructed dossier.
        _json(ai)
        return ai, result.provider_request_performed, (3 if result.outcome in {'DENY', 'ERROR'} else 0)
    except Exception:
        # An unexpected escape from the provider boundary cannot prove that
        # no request started. Preserve evidence and record unknown, never retry.
        return {'outcome': 'ERROR', 'reason_code': 'PROVIDER_COMPLETION_UNKNOWN',
                'policy_version': POLICY_VERSION}, None, 3


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description='Compare selected offline baselines; optional one-shot local Qwen explanation.',
                     allow_abbrev=False)
    for name in ('input-root', 'reference', 'current', 'selection', 'selection-sha256'):
        parser.add_argument('--' + name, required=True, action=_Once)
    parser.add_argument('--qwen', action=_Once, nargs=0, help='Explicitly enable at most one local model request.')
    parser.add_argument('--registry', action=_Once, help='Relative approved anomaly-registry file under input-root.')
    parser.add_argument('--registry-sha256', action=_Once, help='Independently approved canonical registry fingerprint.')
    parser.add_argument('--question-type', action=_Once,
                        choices=('explain_anomalies', 'explain_anomaly_limitations'))
    args = parser.parse_args(argv)
    if (args.qwen and (args.registry is None or args.registry_sha256 is None)) or (
            not args.qwen and any(value is not None for value in (
                args.registry, args.registry_sha256, args.question_type))):
        parser.error('incomplete explicit model selection')
    try:
        # Real privilege/capability checks precede every selected-file open.
        require_unprivileged_linux()
        selection = _read_small_json(args.input_root, args.selection)
        fingerprint = selection_fingerprint(selection)
        if (re.fullmatch(r'[a-f0-9]{64}', args.selection_sha256) is None
                or fingerprint != args.selection_sha256):
            raise OfflineError('ANOMALY_SELECTION_FINGERPRINT_MISMATCH')
        data = {
            'schema': INPUT_SCHEMA,
            'selection_sha256': fingerprint,
            'as_of': selection['as_of'],
            'reference': {
                'window': selection['reference']['window'],
                'baseline_sha256': selection['reference']['baseline_sha256'],
                'baseline': read_reference(args.input_root, args.reference, Limits()),
            },
            'current': {
                'window': selection['current']['window'],
                'baseline_sha256': selection['current']['baseline_sha256'],
                'baseline': read_reference(args.input_root, args.current, Limits()),
            },
        }
        dossier = build_anomaly_dossier(data)
    except (OfflineError, OSError) as exc:
        print(_json(_failure(str(exc) if isinstance(exc, OfflineError) else 'LOCAL_IO_ERROR')))
        return 1
    ai = {'outcome': 'not_requested', 'reason_code': 'QWEN_DISABLED'}
    performed, exit_code = False, 0
    if args.qwen and dossier['status'] == 'candidates' and not dossier['truncated']:
        ai, performed, exit_code = _explain(args, data, dossier)
    elif args.qwen:
        ai = {'outcome': 'not_attempted', 'reason_code': 'EVIDENCE_NOT_ELIGIBLE'}
    result = {'schema': 'offline-anomaly-triage-v2', 'status': 'complete',
              'dossier': dossier, 'ai': ai, 'provider_request_performed': performed,
              'persistence_status': 'not_attempted', 'action_status': 'not_attempted'}
    output = _json(result)
    # The validated fixed shapes should stay below this complete-receipt budget.
    if len(output.encode('ascii')) + 1 > MAX_RECEIPT_BYTES:
        # Retain deterministic evidence even if advisory serialization overflows.
        result.update(ai={'outcome': 'ERROR', 'reason_code': 'ADVISORY_RECEIPT_LIMIT'})
        output, exit_code = _json(result), 3
    print(output)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
