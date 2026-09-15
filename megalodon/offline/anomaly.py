"""Bounded, deterministic anomaly candidates from operator-selected baselines.

These are descriptive review candidates, never calibrated threat scores. No
network, file, database, model, detector-state or action path exists here.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re

from .baseline import validate_baseline
from .common import OfflineError
from .compare import compare_baselines

INPUT_SCHEMA = 'offline-anomaly-input-v1'
DOSSIER_SCHEMA = 'offline-anomaly-dossier-v1'
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


def build_anomaly_dossier(value: object) -> dict:
    """Validate two complete compatible windows before constructing evidence.

    Age is relative to required caller-supplied ``as_of``, never a hidden clock.
    Incomplete, stale or incomparable windows abstain with no partial candidates.
    """
    data = owned_input(value)
    if set(data) != {'schema', 'reference', 'current', 'as_of'} or data['schema'] != INPUT_SCHEMA:
        raise OfflineError('ANOMALY_INPUT_INVALID')
    for name in ('reference', 'current'):
        if type(data[name]) is not dict or set(data[name]) != {'window', 'baseline'}:
            raise OfflineError('ANOMALY_INPUT_INVALID')
    before = validate_baseline(data['reference']['baseline'])
    after = validate_baseline(data['current']['baseline'])
    rw, cw = data['reference']['window'], data['current']['window']
    rs, re_ = _window(rw)
    cs, ce = _window(cw)
    as_of = _time(data['as_of'])
    # Identity covers validated aggregate metadata only, never packet payloads.
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(canonical) > MAX_INPUT_BYTES:
        raise OfflineError('ANOMALY_INPUT_LIMIT')
    result = {
        'schema': DOSSIER_SCHEMA,
        'dossier_id': hashlib.sha256(canonical).hexdigest(),
        'status': 'no_candidates', 'reason_code': 'NO_THRESHOLD_CROSSING',
        'adapter': after.adapter, 'record_kind': after.record_kind,
        'reference_records': before.record_count, 'current_records': after.record_count,
        'reference_window': rw, 'current_window': cw, 'as_of': data['as_of'],
        'comparison_basis': 'accepted_record_share', 'quality_label': 'uncalibrated',
        'candidate_count': 0, 'candidates': [], 'truncated': False,
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

    try:
        comparison = compare_baselines(data['reference']['baseline'], data['current']['baseline'])
    except OfflineError as exc:
        if str(exc) == 'COMPARISON_PORT_LIMIT':
            return abstain('ANOMALY_CANDIDATE_LIMIT')
        raise
    candidates = []

    def add(rule: str, reference_count: int, current_count: int,
            protocol: str | None = None, port: int | None = None) -> None:
        if len(candidates) == MAX_CANDIDATES:
            raise OfflineError('ANOMALY_CANDIDATE_LIMIT')
        candidates.append({'id': f'a{len(candidates) + 1:02d}', 'rule': rule,
                           'protocol': protocol, 'port': port,
                           'reference_count': reference_count, 'current_count': current_count})

    def shift(x: int, y: int) -> bool:
        return (max(x, y) >= MIN_SUPPORT and
                abs(y * before.record_count - x * after.record_count) * 100 >=
                SHARE_SHIFT_PERCENT * before.record_count * after.record_count)

    try:
        for row in comparison['changed_destination_ports']:
            x, y = row['reference_count'], row['current_count']
            if x == 0 and y >= MIN_SUPPORT:
                add('NEW_DESTINATION_PORT', x, y, row['protocol'], row['port'])
            elif shift(x, y):
                add('PORT_SHARE_SHIFT', x, y, row['protocol'], row['port'])
        for row in comparison['protocols']:
            if shift(row['reference_count'], row['current_count']):
                add('PROTOCOL_SHARE_SHIFT', row['reference_count'], row['current_count'], row['protocol'])
        x, y = before.byte_bands[2], after.byte_bands[2]
        if shift(x, y):
            add('LARGE_RECORD_SHARE_SHIFT', x, y)
    except OfflineError:
        return abstain('ANOMALY_CANDIDATE_LIMIT')
    if candidates:
        result.update(status='candidates', reason_code='REVIEW_CANDIDATES',
                      candidate_count=len(candidates), candidates=candidates)
    return result
