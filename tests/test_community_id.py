"""Community ID grouping-hint tests: published vectors plus fail-closed limits.

Reference vectors are the corelight/community-id-spec baseline fixtures
(``baseline/baseline_deflt.json`` for seed 0 and ``baseline/baseline_seed1.json``
for seed 1), the same reference dataset used by third-party consumers such as
Suricata's ``community_id`` EVE field. They are reproduced here as literal
constants; this suite does not fetch them at run time.
"""

from __future__ import annotations

import pytest

from megalodon.offline import zeek
from megalodon.offline.common import Batch, OfflineError
from megalodon.offline.community_id import (
    MAX_TOTAL_RECORDS,
    community_id,
    correlate,
)


def _flow(proto: str, saddr: str, sport: int, daddr: str, dport: int, *,
          ts: int = 0, conn_state: str = "SF", orig_pkts: int = 1, resp_pkts: int = 1,
          orig_bytes: int = 0, resp_bytes: int = 0):
    return zeek.parse_flow({
        "ts": ts, "id.orig_h": saddr, "id.orig_p": sport,
        "id.resp_h": daddr, "id.resp_p": dport, "proto": proto,
        "conn_state": conn_state, "orig_pkts": orig_pkts, "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_bytes, "resp_ip_bytes": resp_bytes,
    })


TCP_V4 = ("tcp", "128.232.110.120", 34855, "66.35.250.204", 80)
UDP_V4 = ("udp", "192.168.1.52", 54585, "8.8.8.8", 53)
TCP_V6 = ("tcp", "2001:470:e5bf:dead:4957:2174:e82c:4887", 63943, "2607:f8b0:400c:c03::1a", 25)


@pytest.mark.parametrize(
    "case,expected",
    [
        (TCP_V4, "1:LQU9qZlK+B5F3KDmev6m5PMibrg="),
        (UDP_V4, "1:d/FP5EW3wiY1vCndhwleRRKHowQ="),
        (TCP_V6, "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4="),
    ],
)
def test_matches_published_vector_both_directions(case, expected):
    proto, saddr, sport, daddr, dport = case
    forward = _flow(proto, saddr, sport, daddr, dport)
    reverse = _flow(proto, daddr, dport, saddr, sport)
    assert community_id(forward) == expected
    assert community_id(reverse) == expected


@pytest.mark.parametrize(
    "case,expected",
    [
        (TCP_V4, "1:3V71V58M3Ksw/yuFALMcW0LAHvc="),
        (UDP_V4, "1:Q9We8WO3piVF8yEQBNJF4uiSVrI="),
    ],
)
def test_seed_one_matches_published_vector(case, expected):
    proto, saddr, sport, daddr, dport = case
    record = _flow(proto, saddr, sport, daddr, dport)
    assert community_id(record, seed=1) == expected
    assert community_id(record, seed=1) != community_id(record, seed=0)


def test_icmp_fails_closed_instead_of_guessing():
    record = _flow("icmp", "192.168.0.89", 8, "192.168.0.1", 0)
    with pytest.raises(OfflineError, match="COMMUNITY_ID_UNSUPPORTED_PROTOCOL"):
        community_id(record)


@pytest.mark.parametrize("seed", [-1, 65536, 1.0, True, "0"])
def test_invalid_seed_rejected(seed):
    record = _flow(*TCP_V4)
    with pytest.raises(OfflineError, match="INVALID_COMMUNITY_ID_SEED"):
        community_id(record, seed=seed)


def test_protocol_mismatch_is_a_negative_not_a_collision():
    """Same addresses/ports on TCP vs UDP must not correlate."""
    tcp = _flow("tcp", "10.0.0.1", 1234, "10.0.0.2", 80)
    udp = _flow("udp", "10.0.0.1", 1234, "10.0.0.2", 80)
    assert community_id(tcp) != community_id(udp)


def test_nat_translation_breaks_correlation():
    """Community ID hashes observed addresses; it is not NAT-aware identity."""
    internal = _flow("tcp", "10.0.0.5", 51000, "93.184.216.34", 443)
    translated = _flow("tcp", "203.0.113.9", 51000, "93.184.216.34", 443)
    assert community_id(internal) != community_id(translated)


def test_capture_loss_does_not_change_identity():
    """Byte/packet-count divergence between vantage points must not affect the hash."""
    complete = _flow(*TCP_V4, orig_pkts=40, resp_pkts=38, orig_bytes=2000, resp_bytes=1900)
    lossy = _flow(*TCP_V4, orig_pkts=3, resp_pkts=0, orig_bytes=120, resp_bytes=0,
                  conn_state="S0")
    assert community_id(complete) == community_id(lossy)


def _batch(adapter: str, records) -> Batch:
    return Batch(adapter, "flow", tuple(records), len(records), 0, 1, "1.0.0",
                 "operator_declared_unverified")


def test_correlate_groups_matching_flows_across_sources():
    shared_a = _flow(*TCP_V4)
    shared_b = _flow("tcp", TCP_V4[3], TCP_V4[4], TCP_V4[1], TCP_V4[2])  # reversed direction
    unique = _flow("tcp", "198.51.100.7", 4444, "198.51.100.8", 22)
    zeek_batch = _batch("zeek-conn-json-v1", [shared_a, unique])
    suricata_batch = _batch("suricata-eve-v1", [shared_b])

    result = correlate([("zeek", zeek_batch), ("suricata", suricata_batch)])

    assert result["considered_flow_records"] == 3
    assert result["excluded_unsupported_protocol"] == 0
    assert result["correlated_community_ids"] == 1
    [(identity, hits)] = result["groups"].items()
    assert identity == community_id(shared_a)
    assert {hit["source"] for hit in hits} == {"zeek", "suricata"}
    assert result["mutates_source_evidence"] is False
    assert result["action_status"] == "not_attempted"
    # Inputs are read, never rewritten.
    assert zeek_batch.records == (shared_a, unique)
    assert suricata_batch.records == (shared_b,)


def test_correlate_excludes_unsupported_protocol_without_failing():
    icmp = _flow("icmp", "192.168.0.89", 8, "192.168.0.1", 0)
    result = correlate([("zeek", _batch("zeek-conn-json-v1", [icmp]))])
    assert result["considered_flow_records"] == 1
    assert result["excluded_unsupported_protocol"] == 1
    assert result["groups"] == {}


def test_correlate_rejects_invalid_source_label():
    batch = _batch("zeek-conn-json-v1", [_flow(*TCP_V4)])
    with pytest.raises(OfflineError, match="INVALID_CORRELATION_SOURCE_LABEL"):
        correlate([("", batch)])
    with pytest.raises(OfflineError, match="INVALID_CORRELATION_SOURCE_LABEL"):
        correlate([(b"zeek", batch)])  # type: ignore[list-item]


def test_correlate_rejects_non_batch_input():
    with pytest.raises(OfflineError, match="INVALID_CORRELATION_BATCH"):
        correlate([("zeek", [_flow(*TCP_V4)])])  # type: ignore[list-item]


def test_correlate_enforces_total_record_limit(monkeypatch):
    monkeypatch.setattr("megalodon.offline.community_id.MAX_TOTAL_RECORDS", 1)
    batch = _batch("zeek-conn-json-v1", [_flow(*TCP_V4), _flow(*UDP_V4)])
    with pytest.raises(OfflineError, match="CORRELATION_RECORD_LIMIT"):
        correlate([("zeek", batch)])


def test_default_record_limit_is_bounded():
    assert 0 < MAX_TOTAL_RECORDS <= 1_000_000
