"""Non-authoritative Community ID v1 grouping hint for offline flow records.

This module never mutates a supplied ``FlowRecord`` or ``Batch``, launches Zeek,
reads a file, contacts a network, mutates storage, or grants action authority. A
shared identifier only means two records hash the same normalized 5-tuple under
the same seed; it is not identity, attribution, deduplication proof, NAT
awareness, or any claim about the underlying traffic.
"""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha1
from ipaddress import ip_address
from struct import pack
from typing import Iterable

from .common import Batch, FlowRecord, OfflineError

# IANA-assigned protocol numbers for the two transports this module supports.
_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17}
MAX_SEED = 65535
MAX_TOTAL_RECORDS = 100_000


def community_id(record: FlowRecord, *, seed: int = 0) -> str:
    """Compute the published Community ID v1 string for a TCP or UDP flow.

    Raises ``OfflineError('COMMUNITY_ID_UNSUPPORTED_PROTOCOL')`` for any other
    protocol (including ICMP): the reference algorithm remaps ICMP type/code
    pairs through a request/reply table this module does not implement, so it
    fails closed instead of guessing at an unverified mapping.
    """
    if type(seed) is not int or not 0 <= seed <= MAX_SEED:
        raise OfflineError("INVALID_COMMUNITY_ID_SEED")
    proto = _PROTOCOL_NUMBERS.get(record.protocol)
    if proto is None:
        raise OfflineError("COMMUNITY_ID_UNSUPPORTED_PROTOCOL")
    src = (ip_address(record.src_ip).packed, record.src_port)
    dst = (ip_address(record.dst_ip).packed, record.dst_port)
    lo, hi = (src, dst) if src <= dst else (dst, src)
    buf = (
        pack("!H", seed)
        + lo[0] + hi[0]
        + bytes((proto, 0))
        + pack("!H", lo[1])
        + pack("!H", hi[1])
    )
    return "1:" + b64encode(sha1(buf).digest()).decode("ascii")


@dataclass(frozen=True)
class CorrelationHit:
    source: str
    batch_index: int
    src_ip: str
    dst_ip: str
    protocol: str
    observed_at: datetime


def correlate(sources: Iterable[tuple[str, Batch]], *, seed: int = 0) -> dict[str, object]:
    """Build a read-only cross-source Community ID grouping index.

    ``sources`` pairs an operator-chosen source label (for example ``"zeek"`` or
    ``"suricata"``) with an already-validated :class:`Batch`. Only
    ``FlowRecord`` entries participate; every other record kind is left alone.
    No input record or batch is copied, reordered, merged, or reinterpreted:
    this function only reads already-validated fields and returns a derived
    index describing what it found.
    """
    materialized = list(sources)
    total = 0
    for label, batch in materialized:
        if not isinstance(label, str) or not label or len(label) > 64:
            raise OfflineError("INVALID_CORRELATION_SOURCE_LABEL")
        if not isinstance(batch, Batch):
            raise OfflineError("INVALID_CORRELATION_BATCH")
        total += len(batch.records)
    if total > MAX_TOTAL_RECORDS:
        raise OfflineError("CORRELATION_RECORD_LIMIT")

    groups: dict[str, list[CorrelationHit]] = {}
    considered = 0
    excluded = 0
    for label, batch in materialized:
        for index, record in enumerate(batch.records):
            if not isinstance(record, FlowRecord):
                continue
            considered += 1
            try:
                identity = community_id(record, seed=seed)
            except OfflineError:
                excluded += 1
                continue
            groups.setdefault(identity, []).append(
                CorrelationHit(label, index, record.src_ip, record.dst_ip,
                               record.protocol, record.observed_at)
            )
    correlated = {
        identity: tuple(
            {
                "source": hit.source,
                "batch_index": hit.batch_index,
                "src_ip": hit.src_ip,
                "dst_ip": hit.dst_ip,
                "protocol": hit.protocol,
                "observed_at": hit.observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            }
            for hit in hits
        )
        for identity, hits in groups.items()
        if len(hits) > 1
    }
    return {
        "schema": "zeek-community-id-correlation-v1",
        "seed": seed,
        "sources": len(materialized),
        "considered_flow_records": considered,
        "excluded_unsupported_protocol": excluded,
        "correlated_community_ids": len(correlated),
        "groups": correlated,
        "interpretation": "non_authoritative_grouping_hint",
        "mutates_source_evidence": False,
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }
