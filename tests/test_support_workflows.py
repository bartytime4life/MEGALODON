"""Saved scan positives need operator review; reading status starts no work."""
from types import SimpleNamespace

import pytest

from megalodon.support_workflows import snapshot


@pytest.mark.parametrize("flagged,message,expected", (
    (0, "ClamAV · completed; saved aggregate", "connected"),
    (2, "ClamAV · completed; saved aggregate", "needs_review"),
    (2, "ClamAV · scanning", "collecting"),
    (2, "ClamAV · failed; retained prior aggregate", "error"),
))
def test_saved_scan_positive_is_distinct_from_current_activity(flagged, message, expected):
    sensor=dict(state="stopped", message="Synthetic stopped sensor", updated_at=None, metrics=[])
    configuration=SimpleNamespace(
        capture=SimpleNamespace(snapshot=lambda: dict(accepted=0, skipped=0, state="stopped",
            message="Synthetic stopped capture", started_at=None)),
        sensors=SimpleNamespace(snapshot=lambda: dict(zeek=sensor, suricata=sensor)),
        qwen_status=sensor)
    companions=SimpleNamespace(snapshot=lambda: dict(results={"clamav":dict(scanned_files=10,
        infected_files=flagged, errors=0, exported_at="2026-10-27T12:00:00Z")},
        status={"clamav":message}, advisory={}))
    row=next(item for item in snapshot(configuration, companions)["tools"] if item["id"]=="clamav")
    assert row["state"] == expected
    assert row["metrics"][1] == dict(label="Flagged files", value=flagged, unit="")
    assert row["updated_at"] == "2026-10-27T12:00:00Z"
    if expected=="needs_review":
        assert "Review the scan summary" in row["message"]
    else:
        assert row["message"] == message
