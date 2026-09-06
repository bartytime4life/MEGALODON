"""Deterministic metadata summaries and review-only candidate heuristics."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median_low

from .common import Batch, FlowRecord, OfflineError, uint

BASELINE_SCHEMA = 'offline-baseline-v1'
PROTOCOLS = {'TCP', 'UDP', 'ICMP', 'ICMPV6', 'OTHER'}
MAX_CANDIDATES = 256


def offsets(batch: Batch) -> list[int]:
    if not batch.records:
        return []
    first = min(record.observed_at for record in batch.records)
    return [((record.observed_at - first).days * 86400 +
             (record.observed_at - first).seconds) * 1_000_000 +
            (record.observed_at - first).microseconds for record in batch.records]


def host_labels(batch: Batch) -> dict[str, str]:
    addresses = sorted({address for record in batch.records for address in (record.src_ip, record.dst_ip)})
    return {address: f'host-{index:05d}' for index, address in enumerate(addresses, 1)}


def baseline(batch: Batch) -> dict:
    protocols = Counter(record.protocol for record in batch.records)
    ports = Counter((record.protocol, record.dst_port) for record in batch.records
                    if record.protocol in {'TCP', 'UDP'} and record.dst_port is not None)
    bands = Counter('small' if record.byte_count < 512 else
                    'medium' if record.byte_count < 4096 else 'large' for record in batch.records)
    bins = Counter(offset // 60_000_000 for offset in offsets(batch))
    return {
        'schema': BASELINE_SCHEMA, 'adapter': batch.adapter, 'record_kind': batch.kind,
        'record_count': len(batch.records), 'total_bytes': sum(r.byte_count for r in batch.records),
        'protocols': [{'protocol': p, 'count': n} for p, n in sorted(protocols.items())],
        'destination_ports': [{'protocol': p, 'port': port, 'count': n}
                              for (p, port), n in sorted(ports.items())],
        'byte_bands': {band: bands[band] for band in ('small', 'medium', 'large')},
        'relative_minutes': [{'minute': minute, 'count': n} for minute, n in sorted(bins.items())],
    }


def validate_reference(value: dict, batch: Batch) -> set[tuple[str, int]]:
    expected = {'schema', 'adapter', 'record_kind', 'record_count', 'total_bytes',
                'protocols', 'destination_ports', 'byte_bands', 'relative_minutes'}
    if (set(value) != expected or value['schema'] != BASELINE_SCHEMA or
            value['adapter'] != batch.adapter or value['record_kind'] != batch.kind):
        raise OfflineError('INCOMPATIBLE_BASELINE')
    size = uint(value['record_count'], 10_000)
    if size < 5:
        raise OfflineError('REFERENCE_BASELINE_TOO_SMALL')
    uint(value['total_bytes'], size * (2**41 - 2))
    for field in ('protocols', 'destination_ports', 'relative_minutes'):
        if not isinstance(value[field], list) or len(value[field]) > size:
            raise OfflineError('INVALID_BASELINE')
    protocols = set()
    count = 0
    for item in value['protocols']:
        if (not isinstance(item, dict) or set(item) != {'protocol', 'count'} or
                not isinstance(item['protocol'], str) or item['protocol'] not in PROTOCOLS or
                item['protocol'] in protocols):
            raise OfflineError('INVALID_BASELINE')
        protocols.add(item['protocol'])
        amount = uint(item['count'], size)
        if amount == 0:
            raise OfflineError('INVALID_BASELINE')
        count += amount
    if count != size:
        raise OfflineError('INVALID_BASELINE')
    known = set()
    count = 0
    for item in value['destination_ports']:
        if (not isinstance(item, dict) or set(item) != {'protocol', 'port', 'count'} or
                not isinstance(item['protocol'], str) or item['protocol'] not in {'TCP', 'UDP'}):
            raise OfflineError('INVALID_BASELINE')
        if item['protocol'] not in protocols:
            raise OfflineError('INVALID_BASELINE')
        pair = item['protocol'], uint(item['port'], 65535)
        if pair in known:
            raise OfflineError('INVALID_BASELINE')
        known.add(pair)
        amount = uint(item['count'], size)
        if amount == 0:
            raise OfflineError('INVALID_BASELINE')
        count += amount
    if count > size:
        raise OfflineError('INVALID_BASELINE')
    bands = value['byte_bands']
    if not isinstance(bands, dict) or set(bands) != {'small', 'medium', 'large'}:
        raise OfflineError('INVALID_BASELINE')
    if sum(uint(v, size) for v in bands.values()) != size:
        raise OfflineError('INVALID_BASELINE')
    minutes = set()
    count = 0
    for item in value['relative_minutes']:
        if not isinstance(item, dict) or set(item) != {'minute', 'count'}:
            raise OfflineError('INVALID_BASELINE')
        minute = uint(item['minute'], 68_374_080)
        if minute in minutes:
            raise OfflineError('INVALID_BASELINE')
        minutes.add(minute)
        amount = uint(item['count'], size)
        if amount == 0:
            raise OfflineError('INVALID_BASELINE')
        count += amount
    if count != size:
        raise OfflineError('INVALID_BASELINE')
    return known


def candidates(batch: Batch, reference: dict | None = None) -> list[dict]:
    """No severity escalation, fixed-rule changes, or response authorization."""
    result = []
    labels = host_labels(batch)
    def add(rule: str, evidence: dict) -> None:
        if len(result) >= MAX_CANDIDATES:
            raise OfflineError('CANDIDATE_LIMIT')
        result.append({'rule': rule, 'status': 'candidate', 'record_kind': batch.kind,
                       'action_status': 'not_attempted', 'evidence': evidence})

    if reference is not None:
        known = validate_reference(reference, batch)
        ports = Counter((r.protocol, r.dst_port) for r in batch.records
                        if r.protocol in {'TCP', 'UDP'} and r.dst_port is not None)
        for (protocol, port), count in sorted(ports.items()):
            if (protocol, port) not in known:
                add('NEW_DESTINATION_PORT', {'protocol': protocol, 'port': port, 'records': count})
    groups = defaultdict(set)
    bursts = Counter()
    for record, offset in zip(batch.records, offsets(batch)):
        if record.protocol in {'TCP', 'UDP'} and record.dst_port is not None:
            groups[(record.src_ip, record.dst_ip, record.protocol, record.dst_port)].add(offset)
            if record.dst_port == 53:
                bursts[(record.src_ip, offset // 60_000_000)] += 1
    for (src, dst, protocol, port), times in sorted(groups.items()):
        ordered = sorted(times)
        if len(ordered) < 5:
            continue
        intervals = [b - a for a, b in zip(ordered, ordered[1:])]
        mid = median_low(intervals)
        spread = max(intervals) - min(intervals)
        if 1_000_000 <= mid <= 3_600_000_000 and spread <= mid // 20:
            add('REGULAR_INTERVAL', {'src': labels[src], 'dst': labels[dst],
                                    'protocol': protocol, 'port': port,
                                    'unique_observations': len(ordered), 'median_interval_us': mid,
                                    'interval_spread_us': spread})
    for (src, minute), count in sorted(bursts.items()):
        if count >= 20:
            add('PORT_53_BURST', {'src': labels[src], 'relative_minute': minute, 'records': count})
    return result


def redacted_records(batch: Batch) -> list[dict]:
    labels = host_labels(batch)
    rows = []
    for index, (record, offset) in enumerate(zip(batch.records, offsets(batch)), 1):
        is_flow = isinstance(record, FlowRecord)
        rows.append({
            'record': index, 'record_kind': batch.kind, 'offset_us': offset,
            'src': labels[record.src_ip], 'dst': labels[record.dst_ip],
            'protocol': record.protocol, 'src_port': record.src_port, 'dst_port': record.dst_port,
            'byte_count': record.byte_count,
            'tcp_flags': '' if is_flow else '|'.join(sorted(record.tcp_flags)),
            'orig_packets': record.orig_packets if is_flow else None,
            'resp_packets': record.resp_packets if is_flow else None,
            'duration_us': record.duration_us if is_flow else None,
            'conn_state': record.conn_state if is_flow else '',
        })
    return rows
