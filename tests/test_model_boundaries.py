"""Persistence-facing domain objects reject unbounded or ambiguous values."""

from datetime import datetime, timezone

import pytest

from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.storage import Store
from megalodon.validation import SQLITE_INTEGER_MAX, ValidationError


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _detection(**changes):
    values = {
        "detected_at": STAMP,
        "rule_id": "TEST",
        "severity": "LOW",
        "src_ip": "192.0.2.1",
        "dst_ip": "198.51.100.2",
        "message": "synthetic",
    }
    values.update(changes)
    return DetectionResult(**values)


def test_packet_counts_fit_sqlite_integer_storage():
    event = PacketEvent(
        STAMP,
        "192.0.2.1",
        "198.51.100.2",
        "TCP",
        byte_count=SQLITE_INTEGER_MAX,
        dns_query_length=SQLITE_INTEGER_MAX,
    )
    assert event.byte_count == SQLITE_INTEGER_MAX
    for field in ("byte_count", "dns_query_length"):
        with pytest.raises(ValidationError, match=field):
            PacketEvent(
                STAMP,
                "192.0.2.1",
                "198.51.100.2",
                "TCP",
                **{field: SQLITE_INTEGER_MAX + 1},
            )


@pytest.mark.parametrize("severity", ("UNKNOWN", "", "high\n"))
def test_detection_severity_is_closed_and_safe(severity):
    with pytest.raises(ValidationError, match="severity"):
        _detection(severity=severity)


def test_detection_json_and_text_fields_are_bounded():
    with pytest.raises(ValidationError, match="metadata .*exceeds"):
        _detection(evidence={"value": "x" * 9000})
    with pytest.raises(ValidationError, match="recommendation"):
        _detection(recommendation="x" * 65)
    with pytest.raises(ValidationError, match="suppressed_reason"):
        _detection(suppressed_reason="line\nbreak")


@pytest.mark.parametrize("status", ("invented", "", "planned\n"))
def test_action_status_is_closed_and_safe(status):
    with pytest.raises(ValidationError, match="status"):
        ActionRecord(STAMP, "block", "192.0.2.1", status, "synthetic")


def test_action_text_and_details_are_bounded():
    with pytest.raises(ValidationError, match="reason"):
        ActionRecord(STAMP, "block", "192.0.2.1", "planned", "line\nbreak")
    with pytest.raises(ValidationError, match="metadata .*exceeds"):
        ActionRecord(
            STAMP,
            "block",
            "192.0.2.1",
            "planned",
            "synthetic",
            details={"value": "x" * 9000},
        )
    with pytest.raises(ValidationError, match="control characters"):
        ActionRecord(
            STAMP,
            "block",
            "192.0.2.1",
            "planned",
            "synthetic",
            details={"value": "line\nbreak"},
        )


def test_store_revalidates_mutable_json_before_each_write(tmp_path):
    event = PacketEvent(
        STAMP,
        "192.0.2.1",
        "198.51.100.2",
        "TCP",
        metadata={"stage": "valid"},
    )
    detection = _detection(evidence={"stage": "valid"})
    action = ActionRecord(
        STAMP,
        "block",
        "192.0.2.1",
        "not_attempted",
        "synthetic",
        details={"stage": "valid"},
    )

    with Store(tmp_path / "audit.db") as store:
        event.metadata["value"] = "x" * 9000
        with pytest.raises(ValidationError, match="metadata .*exceeds"):
            store.record_event(event)
        assert store.summary()["events"] == 0

        valid_event_id = store.record_event(
            PacketEvent(STAMP, "192.0.2.1", "198.51.100.2", "TCP")
        )
        detection.evidence["value"] = "x" * 9000
        with pytest.raises(ValidationError, match="metadata .*exceeds"):
            store.record_detection(valid_event_id, detection)
        assert store.summary()["detections"] == 0

        action.details["value"] = "x" * 9000
        with pytest.raises(ValidationError, match="metadata .*exceeds"):
            store.record_action(action)
        assert store.summary()["actions"] == 0
