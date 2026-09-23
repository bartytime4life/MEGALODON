"""Heartbeat observations must not turn missing or expired evidence into health."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import tool_heartbeat
from megalodon.dashboard_heartbeat import HEARTBEAT_JS


@pytest.mark.parametrize("installed,service,expects_service,model,expected", [
    ("yes", "unknown", True, None, "grey"),
    ("yes", "running", True, "unknown", "grey"),
    ("yes", "stopped", True, "unknown", "amber"),
    ("yes", "running", True, "missing", "amber"),
    ("yes", "running", True, "present", "green"),
    ("yes", "standalone", False, None, "green"),
    ("no", "none", True, "unknown", "red"),
    ("unknown", "unknown", True, None, "grey"),
])
def test_light_requires_evidence(installed, service, expects_service, model, expected):
    assert tool_heartbeat._light(installed, service, expects_service, model) == expected


def test_busy_collector_does_not_return_expired_success(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(tool_heartbeat, "monotonic", lambda: clock[0])
    monkeypatch.setattr(tool_heartbeat, "heartbeat_report", lambda root: {"tools": []})
    heartbeat = tool_heartbeat.Heartbeat()
    first = heartbeat.snapshot()
    heartbeat._lock.acquire()
    try:
        assert heartbeat.snapshot() == first
        clock[0] += tool_heartbeat.HEARTBEAT_CACHE_SECONDS + 1
        with pytest.raises(tool_heartbeat.HeartbeatBusy):
            heartbeat.snapshot()
    finally:
        heartbeat._lock.release()


def test_browser_marks_failed_observations_stale_and_recovers():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for heartbeat browser behavior")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("heartbeat_observation.cjs"))],
        input=json.dumps({"code": HEARTBEAT_JS}), text=True,
        capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_history_excludes_unobserved_gaps_and_clock_reversal():
    history = tool_heartbeat.HeartbeatHistory(started=1000)
    report = lambda light: {"tools": [{"id": "suricata", "light": light}]}
    history.observe(report("green"), now=1000)
    first = history.observe(report("amber"), now=1060)["tools"]["suricata"]
    assert first["healthy_percent"] == 100.0 and first["observed_seconds"] == 60
    for at in (2000, 1900):
        entry = history.observe(report("amber"), now=at)["tools"]["suricata"]
        assert entry["healthy_percent"] == 100.0 and entry["observed_seconds"] == 60
    entry = history.observe(report("green"), now=1960)["tools"]["suricata"]
    assert entry["healthy_percent"] == 50.0 and entry["observed_seconds"] == 120
