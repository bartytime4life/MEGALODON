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
    assert row['review_required'] is bool(flagged)
    if flagged:
        assert "Review the scan summary" in row["message"]
    else:
        assert row["message"] == message


@pytest.mark.parametrize('state,expected', [('checked','connected'),('not_checked','needs_review'),
    ('partial','needs_review'),('unavailable','needs_review'),('stale','needs_review')])
def test_log_activity_does_not_hide_managed_intake_failure(state,expected):
    stamp='2026-10-27T12:00:00Z'
    sensor=dict(state='connected',message='Recent bounded EVE tail.',updated_at=stamp,
                metrics=[dict(label='Tail '+str(n),value=n,unit='') for n in range(6)])
    intake=dict(state=state,message='Synthetic managed intake '+state,checked_at=stamp,
                imported_findings=2,rejected=1 if state=='partial' else 0)
    configuration=SimpleNamespace(
        capture=SimpleNamespace(snapshot=lambda:dict(accepted=0,skipped=0,state='stopped',message='Stopped',started_at=None)),
        sensors=SimpleNamespace(snapshot=lambda:dict(zeek=sensor,suricata=sensor)),
        flow_ingestor=SimpleNamespace(snapshot=lambda:dict(suricata_intake=intake)),qwen_status=sensor)
    row=next(item for item in snapshot(configuration,None)['tools'] if item['id']=='suricata')
    assert row['state']==expected
    assert row['updated_at']==stamp and len(row['metrics'])==6
    assert row['metrics'][-2]['value']==2 and row['metrics'][-1]['value']==intake['rejected']
    assert intake['message'] in row['message'] and 'Intake checked '+stamp in row['message']
    assert sensor['message']=='Recent bounded EVE tail.' and len(sensor['metrics'])==6
