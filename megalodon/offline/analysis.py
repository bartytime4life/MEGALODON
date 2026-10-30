"""Deterministic metadata summaries and review-only candidate heuristics."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
import ipaddress
from statistics import median_low

from .common import Batch, FlowRecord, OfflineError
from .baseline import BASELINE_SCHEMA, validate_baseline

MAX_CANDIDATES = 256
FANOUT_DESTINATIONS = 16
FANOUT_WINDOW_US = 60_000_000
MAX_FANOUT_RECORDS = 20_000
MAX_PROVENANCE_RECORDS = 20_000


def _fanout_windows(batch: Batch, interval: tuple[datetime, datetime] | None):
    """First qualifying connection-start window per source/transport/port.

    Count destinations, not packets, retries, bytes or successful sessions.
    Return at most sixteen representative record numbers per candidate so the
    retained-evidence adapter can cite the actual qualifying observations.
    """
    if batch.kind != 'flow':
        return
    if len(batch.records) > MAX_FANOUT_RECORDS:
        raise OfflineError('FANOUT_RECORD_LIMIT')
    groups = defaultdict(list)
    relative = offsets(batch)
    for index, (record, offset) in enumerate(zip(batch.records, relative)):
        if interval is not None and not interval[0] <= record.observed_at < interval[1]:
            continue
        if record.protocol not in {'TCP', 'UDP'} or record.dst_port is None:
            continue
        address = ipaddress.ip_address(record.dst_ip)
        address = getattr(address, 'ipv4_mapped', None) or address
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            continue
        groups[(record.src_ip, record.protocol, record.dst_port)].append(
            (offset, index, str(address)))
    for key, observations in sorted(groups.items()):
        window, counts, latest = deque(), Counter(), {}
        for offset, index, destination in sorted(observations):
            while window and window[0][0] < offset - FANOUT_WINDOW_US:
                _, _, expired = window.popleft()
                counts[expired] -= 1
                if not counts[expired]:
                    del counts[expired]
                    del latest[expired]
            window.append((offset, index, destination))
            counts[destination] += 1
            latest[destination] = index
            if len(counts) >= FANOUT_DESTINATIONS:
                representatives = sorted(latest.values())
                yield key, {
                    'distinct_destinations': len(counts),
                    'window_seconds': FANOUT_WINDOW_US // 1_000_000,
                    'first_offset_us': min(relative[i] for i in representatives),
                    'last_offset_us': offset,
                    'record_numbers': [i + 1 for i in representatives],
                }
                break


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
    summary = validate_baseline(value)
    if summary.adapter != batch.adapter or summary.record_kind != batch.kind:
        raise OfflineError('INCOMPATIBLE_BASELINE')
    if summary.record_count < 5:
        raise OfflineError('REFERENCE_BASELINE_TOO_SMALL')
    return {(protocol, port) for protocol, port, _ in summary.destination_ports}


def candidates(batch: Batch, reference: dict | None = None, *,
               fanout_interval: tuple[datetime, datetime] | None = None,
               timing_provenance: bool = False) -> list[dict]:
    """No severity escalation, fixed-rule changes, or response authorization.

    The retained-hour adapter opts into bounded record numbers for timing
    checks. Default offline reports keep their existing closed evidence shape.
    """
    if timing_provenance and len(batch.records) > MAX_PROVENANCE_RECORDS:
        raise OfflineError('TIMING_PROVENANCE_RECORD_LIMIT')
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
    groups = defaultdict(dict)
    bursts = Counter()
    burst_refs = defaultdict(list)
    for number, (record, offset) in enumerate(zip(batch.records, offsets(batch)), 1):
        if record.protocol in {'TCP', 'UDP'} and record.dst_port is not None:
            # One representative per distinct time; simultaneous connection
            # starts cannot inflate the cadence's unique-observation count.
            groups[(record.src_ip, record.dst_ip, record.protocol, record.dst_port)].setdefault(offset, number)
            if record.dst_port == 53:
                bursts[(record.src_ip, offset // 60_000_000)] += 1
                if timing_provenance:
                    burst_refs[(record.src_ip, offset // 60_000_000)].append(number)
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
                                    'interval_spread_us': spread,
                                    **({'record_numbers': [times[t] for t in ordered]} if timing_provenance else {})})
    for (src, minute), count in sorted(bursts.items()):
        if count >= 20:
            add('PORT_53_BURST', {'src': labels[src], 'relative_minute': minute, 'records': count,
                                **({'record_numbers': burst_refs[(src, minute)]} if timing_provenance else {})})
    for (src, protocol, port), evidence in _fanout_windows(batch, fanout_interval):
        add('HOST_FANOUT', {'src': labels[src], 'protocol': protocol, 'port': port, **evidence})
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
