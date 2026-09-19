"""Bounded, deterministic anomaly candidates from operator-selected baselines.

These are descriptive review candidates, never calibrated threat scores. No
network, file, database, model, detector-state or action path exists here.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re

from .baseline import BASELINE_SCHEMA, validate_baseline
from .common import OfflineError

INPUT_SCHEMA = 'offline-anomaly-input-v2'
SELECTION_SCHEMA = 'offline-anomaly-selection-v2'
DOSSIER_SCHEMA = 'offline-anomaly-dossier-v2'
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_CANDIDATES = 8
MIN_RECORDS = 20
MIN_SUPPORT = 5
SHARE_SHIFT_PERCENT = 20
LIMITATIONS = (
    'Descriptive candidates only; uncalibrated and not proof of an attack.',
    'Window identity and completeness are operator declarations, not attestation.',
    'Accepted-record shares do not establish traffic rates or capture coverage.',
    'A new service port or changed share can have a legitimate explanation.',
    'No candidates does not establish that the host or network is safe.',
)
_UTC = re.compile(r'20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z')
_SOURCE = re.compile(r'source-[0-9]{4}\Z')
_SHA256 = re.compile(r'[a-f0-9]{64}\Z')


def owned_input(value: object) -> dict:
    """Copy only bounded exact JSON primitives without calling input methods."""
    nodes = 0
    text_bytes = 0

    def copy(item: object, depth: int = 0):
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > 200_000 or depth > 8:
            raise OfflineError('ANOMALY_INPUT_LIMIT')
        kind = type(item)
        if kind is str:
            if len(item) > 128 or not item.isascii():
                raise OfflineError('ANOMALY_INPUT_INVALID')
            text_bytes += len(item)
            if text_bytes > MAX_INPUT_BYTES:
                raise OfflineError('ANOMALY_INPUT_LIMIT')
            return item
        if kind is int and 0 <= item <= 2**63 - 1:
            return item
        if kind is list and len(item) <= 10_000:
            return [copy(child, depth + 1) for child in tuple(item)]
        if kind is dict and len(item) <= 32:
            pairs = tuple(dict.items(item))
            if not all(type(key) is str for key, _ in pairs):
                raise OfflineError('ANOMALY_INPUT_INVALID')
            return {copy(key, depth + 1): copy(child, depth + 1)
                    for key, child in pairs}
        raise OfflineError('ANOMALY_INPUT_INVALID')

    try:
        snapshot = copy(value)
        if type(snapshot) is not dict:
            raise OfflineError('ANOMALY_INPUT_INVALID')
        return snapshot
    except (MemoryError, OverflowError, RecursionError, RuntimeError):
        raise OfflineError('ANOMALY_INPUT_INVALID') from None


def _time(value: object) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise OfflineError('ANOMALY_WINDOW_INVALID')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise OfflineError('ANOMALY_WINDOW_INVALID') from None


def _window(value: object) -> tuple[datetime, datetime]:
    if (type(value) is not dict or set(value) != {
            'source_id', 'started_at', 'finished_at', 'completeness'} or
            type(value.get('source_id')) is not str or
            _SOURCE.fullmatch(value['source_id']) is None or
            value['completeness'] not in ('complete', 'incomplete', 'unknown')):
        raise OfflineError('ANOMALY_WINDOW_INVALID')
    start, end = _time(value['started_at']), _time(value['finished_at'])
    if not 0 < (end - start).total_seconds() <= 86400:
        raise OfflineError('ANOMALY_WINDOW_INVALID')
    return start, end


def _canonical_baseline(value: object) -> tuple[dict, object]:
    """Return the semantic normal form used by identities and selection pins."""
    baseline = validate_baseline(value)
    normalized = {
        'schema': BASELINE_SCHEMA,
        'adapter': baseline.adapter,
        'record_kind': baseline.record_kind,
        'record_count': baseline.record_count,
        'total_bytes': baseline.total_bytes,
        'protocols': [{'protocol': protocol, 'count': count}
                      for protocol, count in baseline.protocols],
        'destination_ports': [
            {'protocol': protocol, 'port': port, 'count': count}
            for protocol, port, count in baseline.destination_ports
        ],
        'byte_bands': dict(zip(('small', 'medium', 'large'), baseline.byte_bands)),
        'relative_minutes': [{'minute': minute, 'count': count}
                             for minute, count in baseline.relative_minutes],
    }
    return normalized, baseline


def _fingerprint(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(canonical).hexdigest()


def baseline_fingerprint(value: object) -> str:
    """Hash one validated baseline's normalized aggregate meaning."""
    normalized, _ = _canonical_baseline(owned_input(value))
    return _fingerprint(normalized)


def selection_fingerprint(value: object) -> str:
    """Validate and fingerprint a manifest that binds windows to baselines."""
    data = owned_input(value)
    if (set(data) != {'schema', 'reference', 'current', 'as_of'}
            or data['schema'] != SELECTION_SCHEMA):
        raise OfflineError('ANOMALY_SELECTION_INVALID')
    _time(data['as_of'])
    for name in ('reference', 'current'):
        side = data[name]
        if (type(side) is not dict or set(side) != {'window', 'baseline_sha256'}
                or type(side['baseline_sha256']) is not str
                or _SHA256.fullmatch(side['baseline_sha256']) is None):
            raise OfflineError('ANOMALY_SELECTION_INVALID')
        _window(side['window'])
    return _fingerprint(data)


def build_anomaly_dossier(value: object) -> dict:
    """Validate two complete compatible windows before constructing evidence.

    Age is relative to required caller-supplied ``as_of``, never a hidden clock.
    Incomplete, stale or incomparable windows abstain with no partial candidates.
    """
    data = owned_input(value)
    if (set(data) != {'schema', 'reference', 'current', 'as_of', 'selection_sha256'}
            or data['schema'] != INPUT_SCHEMA
            or type(data['selection_sha256']) is not str
            or _SHA256.fullmatch(data['selection_sha256']) is None):
        raise OfflineError('ANOMALY_INPUT_INVALID')
    for name in ('reference', 'current'):
        if (type(data[name]) is not dict
                or set(data[name]) != {'window', 'baseline', 'baseline_sha256'}
                or type(data[name]['baseline_sha256']) is not str
                or _SHA256.fullmatch(data[name]['baseline_sha256']) is None):
            raise OfflineError('ANOMALY_INPUT_INVALID')
    reference_normalized, before = _canonical_baseline(data['reference']['baseline'])
    current_normalized, after = _canonical_baseline(data['current']['baseline'])
    if (_fingerprint(reference_normalized) != data['reference']['baseline_sha256']
            or _fingerprint(current_normalized) != data['current']['baseline_sha256']):
        raise OfflineError('ANOMALY_BASELINE_FINGERPRINT_MISMATCH')
    rw, cw = data['reference']['window'], data['current']['window']
    rs, re_ = _window(rw)
    cs, ce = _window(cw)
    as_of = _time(data['as_of'])
    selection = {
        'schema': SELECTION_SCHEMA,
        'reference': {'window': rw, 'baseline_sha256': data['reference']['baseline_sha256']},
        'current': {'window': cw, 'baseline_sha256': data['current']['baseline_sha256']},
        'as_of': data['as_of'],
    }
    if selection_fingerprint(selection) != data['selection_sha256']:
        raise OfflineError('ANOMALY_SELECTION_FINGERPRINT_MISMATCH')
    # Identity covers normalized aggregate meaning and the pinned selection only.
    normalized_input = {
        'schema': INPUT_SCHEMA,
        'selection_sha256': data['selection_sha256'],
        'as_of': data['as_of'],
        'reference': {'window': rw, 'baseline_sha256': data['reference']['baseline_sha256'],
                      'baseline': reference_normalized},
        'current': {'window': cw, 'baseline_sha256': data['current']['baseline_sha256'],
                    'baseline': current_normalized},
    }
    canonical = json.dumps(normalized_input, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(canonical) > MAX_INPUT_BYTES:
        raise OfflineError('ANOMALY_INPUT_LIMIT')
    result = {
        'schema': DOSSIER_SCHEMA,
        'dossier_id': hashlib.sha256(canonical).hexdigest(),
        'status': 'no_candidates', 'reason_code': 'NO_THRESHOLD_CROSSING',
        'adapter': after.adapter, 'record_kind': after.record_kind,
        'reference_records': before.record_count, 'current_records': after.record_count,
        'reference_window': rw, 'current_window': cw, 'as_of': data['as_of'],
        'selection_sha256': data['selection_sha256'],
        'comparison_basis': 'accepted_record_share', 'quality_label': 'uncalibrated',
        'candidate_count': 0, 'candidate_total': 0, 'candidates': [], 'truncated': False,
        'action_status': 'not_attempted', 'limitations': list(LIMITATIONS),
    }

    def abstain(code: str) -> dict:
        return dict(result, status='abstained', reason_code=code)

    if (before.adapter, before.record_kind, rw['source_id']) != (
            after.adapter, after.record_kind, cw['source_id']):
        return abstain('INCOMPARABLE_SOURCE')
    if rw['completeness'] != 'complete' or cw['completeness'] != 'complete':
        return abstain('INCOMPLETE_WINDOW')
    if re_ > cs or re_ - rs != ce - cs:
        return abstain('INCOMPARABLE_WINDOWS')
    if not 0 <= (as_of - ce).total_seconds() <= 3600:
        return abstain('CURRENT_WINDOW_NOT_FRESH')
    if (cs - re_).total_seconds() > 7 * 86400:
        return abstain('REFERENCE_TOO_OLD')
    if min(before.record_count, after.record_count) < MIN_RECORDS:
        return abstain('INSUFFICIENT_RECORDS')
    # A relative bin outside its declared window contradicts that declaration.
    for baseline, duration in ((before, re_ - rs), (after, ce - cs)):
        if any(minute * 60 >= duration.total_seconds() for minute, _ in baseline.relative_minutes):
            return abstain('BASELINE_OUTSIDE_WINDOW')

    candidates = []

    def add(rule: str, reference_count: int, current_count: int,
            protocol: str | None = None, port: int | None = None) -> None:
        delta = abs(current_count * before.record_count
                    - reference_count * after.record_count)
        candidates.append({'rule': rule, 'protocol': protocol, 'port': port,
                           'reference_count': reference_count, 'current_count': current_count,
                           '_delta': delta, '_support': max(reference_count, current_count),
                           '_ordinal': len(candidates)})

    def shift(x: int, y: int) -> bool:
        return (max(x, y) >= MIN_SUPPORT and
                abs(y * before.record_count - x * after.record_count) * 100 >=
                SHARE_SHIFT_PERCENT * before.record_count * after.record_count)

    previous_ports = {(protocol, port): count
                      for protocol, port, count in before.destination_ports}
    current_ports = {(protocol, port): count
                     for protocol, port, count in after.destination_ports}
    for protocol, port in sorted(previous_ports.keys() | current_ports.keys()):
        x = previous_ports.get((protocol, port), 0)
        y = current_ports.get((protocol, port), 0)
        if x == 0 and y >= MIN_SUPPORT:
            add('NEW_DESTINATION_PORT', x, y, protocol, port)
        elif shift(x, y):
            add('PORT_SHARE_SHIFT', x, y, protocol, port)
    previous_protocols = dict(before.protocols)
    current_protocols = dict(after.protocols)
    for protocol in sorted(previous_protocols.keys() | current_protocols.keys()):
        x = previous_protocols.get(protocol, 0)
        y = current_protocols.get(protocol, 0)
        if shift(x, y):
            add('PROTOCOL_SHARE_SHIFT', x, y, protocol)
    x, y = before.byte_bands[2], after.byte_bands[2]
    if shift(x, y):
        add('LARGE_RECORD_SHARE_SHIFT', x, y)
    if candidates:
        total = len(candidates)
        truncated = total > MAX_CANDIDATES
        if truncated:
            candidates = sorted(candidates, key=lambda row: (
                -row['_delta'], -row['_support'], row['_ordinal']))[:MAX_CANDIDATES]
        projected = []
        for index, row in enumerate(candidates, 1):
            projected.append({'id': f'a{index:02d}', **{
                key: item for key, item in row.items() if not key.startswith('_')}})
        result.update(status='candidates',
                      reason_code=('REVIEW_CANDIDATES_TRUNCATED' if truncated
                                   else 'REVIEW_CANDIDATES'),
                      candidate_count=len(projected), candidate_total=total,
                      candidates=projected, truncated=truncated)
    return result
