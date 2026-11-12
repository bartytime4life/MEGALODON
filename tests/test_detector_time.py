"""Exact datetime oracles for process-local detector timing, without host actions."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from megalodon.config import DetectionSettings
from megalodon.detector import Detector
from megalodon.models import PacketEvent
from megalodon.validation import ValidationError


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MICROSECOND = timedelta(microseconds=1)
# The 2**30 crossing reproduced different answers after a 100-second shift.
# Distant and negative epochs exercise precision beyond current wall-clock dates.
ORIGINS = (
    datetime(1, 1, 2, microsecond=3, tzinfo=timezone.utc),
    datetime(1960, 1, 1, microsecond=3, tzinfo=timezone.utc),
    EPOCH + timedelta(seconds=2**30 - 5, microseconds=3),
    EPOCH + timedelta(seconds=2**30 + 95, microseconds=3),
    datetime(2026, 1, 1, microsecond=3, tzinfo=timezone.utc),
    datetime(3000, 1, 1, microsecond=3, tzinfo=timezone.utc),
    datetime(9999, 1, 1, microsecond=3, tzinfo=timezone.utc),
)


def packet(at, *, port=443, dns=False, source="192.0.2.1"):
    return PacketEvent(
        at, source, "198.51.100.1", "UDP" if dns else "TCP",
        src_port=40000, dst_port=53 if dns else port,
        tcp_flags=frozenset() if dns else frozenset({"SYN"}),
        dns_query_length=100 if dns else None,
    )


def state(detector):
    """Snapshot committed and provisional state without mutating defaultdicts."""
    return (
        {source: tuple(window) for source, window in detector.syn_windows.items()},
        {source: tuple(window) for source, window in detector.port_windows.items()},
        {source: dict(counts) for source, counts in detector.port_counts.items()},
        dict(detector.last_emitted), dict(detector.source_high_watermarks),
        tuple(detector.source_order), detector._pending_token,
    )


@pytest.mark.parametrize("origin", ORIGINS)
@pytest.mark.parametrize("delta_us", (-1, 0, 1))
@pytest.mark.parametrize("rule", ("SYN_FLOOD", "PORT_SCAN"))
def test_window_cutoff_inclusive_and_translation_invariant(origin, delta_us, rule):
    last = origin + timedelta(seconds=10, microseconds=delta_us)
    detector = Detector(
        DetectionSettings(
            syn_flood_window_seconds=10, port_scan_window_seconds=10,
            syn_flood_threshold=2 if rule == "SYN_FLOOD" else 999,
            port_scan_distinct_ports=2 if rule == "PORT_SCAN" else 999,
        ),
        clock=lambda: last + timedelta(seconds=1),
    )
    assert detector.analyze(packet(origin)) == []
    results = detector.analyze(packet(last, port=444))
    # Independent oracle: the oldest observation is retained at exact equality.
    expected = last - origin <= timedelta(seconds=10)
    assert [item.rule_id for item in results] == ([rule] if expected else [])
    if results:
        assert results[0].detected_at == last


@pytest.mark.parametrize("origin", tuple(at.replace(microsecond=2) for at in ORIGINS))
@pytest.mark.parametrize("delta_us", (-1, 0, 1))
@pytest.mark.parametrize("rule", ("SYN_FLOOD", "PORT_SCAN", "DNS_TUNNELING"))
def test_cooldown_equality_and_translation_invariance(origin, delta_us, rule):
    last = origin + timedelta(seconds=10, microseconds=delta_us)
    detector = Detector(
        DetectionSettings(alert_cooldown_seconds=10,
                          syn_flood_threshold=1 if rule == "SYN_FLOOD" else 999,
                          port_scan_distinct_ports=1 if rule == "PORT_SCAN" else 999),
        clock=lambda: last + timedelta(seconds=1),
    )
    first_results = detector.analyze(packet(origin, dns=rule == "DNS_TUNNELING"))
    assert [item.rule_id for item in first_results] == [rule]
    results = detector.analyze(packet(last, dns=rule == "DNS_TUNNELING"))
    expected = last - origin >= timedelta(seconds=10)
    assert [item.rule_id for item in results] == ([rule] if expected else [])


@pytest.mark.parametrize("origin", (
    *ORIGINS,
    EPOCH + timedelta(seconds=2**30 - 30, microseconds=3),
    EPOCH + timedelta(seconds=2**30 + 70, microseconds=3),
))
@pytest.mark.parametrize("delta_us", (-1, 0, 1))
def test_future_skew_equality_and_translation_invariance(origin, delta_us):
    observed = origin + timedelta(seconds=60, microseconds=delta_us)
    detector = Detector(DetectionSettings(), clock=lambda: origin)
    before = state(detector)
    if observed - origin > timedelta(seconds=60):
        with pytest.raises(ValidationError, match="future skew"):
            detector.analyze(packet(observed))
        assert state(detector) == before
    else:
        detector.analyze(packet(observed))
        assert detector.source_high_watermarks


@pytest.mark.parametrize("origin", ORIGINS)
def test_high_watermark_orders_adjacent_microseconds_and_allows_equality(origin):
    detector = Detector(DetectionSettings(), clock=lambda: origin + timedelta(seconds=1))
    detector.analyze(packet(origin))
    before = state(detector)
    with pytest.raises(ValidationError, match="high watermark"):
        detector.analyze(packet(origin - MICROSECOND))
    assert state(detector) == before
    detector.analyze(packet(origin))
    detector.analyze(packet(origin + MICROSECOND))
    assert detector.source_high_watermarks["192.0.2.1"] == (
        (origin + MICROSECOND - EPOCH) // MICROSECOND
    )


def test_timezone_equivalent_clock_and_original_result_datetime():
    origin = EPOCH + timedelta(seconds=2**30 - 30, microseconds=3)
    observed = origin + timedelta(seconds=60)
    clock = origin.astimezone(timezone(timedelta(hours=-7)))
    detector = Detector(DetectionSettings(syn_flood_threshold=1), clock=lambda: clock)
    event = packet(observed.astimezone(timezone(timedelta(hours=5, minutes=30))))
    result = detector.analyze(event)[0]
    assert result.detected_at is event.observed_at
    assert result.detected_at == observed


def test_integer_time_state_commit_rollback_eviction_and_zero_cooldown():
    origin = datetime(3000, 1, 1, microsecond=1, tzinfo=timezone.utc)
    detector = Detector(
        DetectionSettings(syn_flood_threshold=1, port_scan_distinct_ports=1,
                          alert_cooldown_seconds=0, max_tracked_sources=1,
                          max_events_per_source_window=1),
        clock=lambda: origin + timedelta(seconds=1),
    )
    first = packet(origin)
    expected_us = (origin - EPOCH) // MICROSECOND
    prepared = detector.prepare(first)
    assert prepared.observed_us == expected_us
    assert type(prepared.observed_us) is int
    assert detector.source_high_watermarks == {}
    assert all(item.detected_at is first.observed_at for item in prepared.results)
    prepared.commit()
    committed = state(detector)
    next_event = packet(origin + MICROSECOND, port=444)
    staged = detector.prepare(next_event)
    assert all(type(window[0][0]) is int for windows in (
        detector.syn_windows, detector.port_windows) for window in windows.values())
    assert all(type(value) is int for value in detector.last_emitted.values())
    staged.rollback()
    assert state(detector) == committed
    # A rolled-back timestamp must not become the source watermark/cooldown.
    assert len(detector.analyze(first)) == 2
    detector.analyze(packet(origin + MICROSECOND, source="192.0.2.2"))
    assert set(detector.source_high_watermarks) == {"192.0.2.2"}
    assert set(detector.syn_windows) == {"192.0.2.2"}
    assert set(detector.port_windows) == {"192.0.2.2"}
    assert {key[1] for key in detector.last_emitted} == {"192.0.2.2"}
    assert all(type(value) is int for value in detector.source_high_watermarks.values())


def test_rejected_clock_and_stale_event_leave_state_reusable():
    origin = datetime(3000, 1, 1, microsecond=1, tzinfo=timezone.utc)
    clock = [origin + timedelta(seconds=1)]
    detector = Detector(DetectionSettings(syn_flood_threshold=1), clock=lambda: clock[0])
    detector.analyze(packet(origin))
    before = state(detector)
    clock[0] = origin.replace(tzinfo=None)
    with pytest.raises(RuntimeError, match="timezone-aware"):
        detector.prepare(packet(origin + MICROSECOND))
    assert state(detector) == before
    clock[0] = origin + timedelta(seconds=1)
    with pytest.raises(ValidationError, match="high watermark"):
        detector.prepare(packet(origin - MICROSECOND))
    assert state(detector) == before
    detector.analyze(packet(origin + MICROSECOND))


@pytest.mark.parametrize("field", (
    "syn_flood_window_seconds", "port_scan_window_seconds", "alert_cooldown_seconds",
))
@pytest.mark.parametrize("value", (True, False, 1.0, 0.5, float("nan"), float("inf"), "10", None))
def test_temporal_settings_must_be_integer_seconds(field, value):
    with pytest.raises(ValueError, match=f"{field} must be an integer"):
        Detector(replace(DetectionSettings(), **{field: value}))


@pytest.mark.parametrize("field", ("syn_flood_window_seconds", "port_scan_window_seconds"))
@pytest.mark.parametrize("value", (0, -1))
def test_window_settings_must_be_positive(field, value):
    with pytest.raises(ValueError, match=f"{field} must be positive"):
        Detector(replace(DetectionSettings(), **{field: value}))


def test_negative_cooldown_is_refused():
    with pytest.raises(ValueError, match="alert_cooldown_seconds must be nonnegative"):
        Detector(DetectionSettings(alert_cooldown_seconds=-1))
