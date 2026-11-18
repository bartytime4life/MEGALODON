"""The HUD's buffered capture path runs the threat-signal layer, atomically."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from megalodon.buffered_recording import BufferedRecording
from megalodon.config import Settings
from megalodon.models import PacketEvent
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings, ThreatDetector
from megalodon.watchlist import Watchlist, parse_lines

ATTACKER, HOST = "203.0.113.9", "192.168.1.10"


def syn(i, start):
    return PacketEvent(start + timedelta(seconds=i), ATTACKER, HOST, "TCP", src_port=40000 + i,
                       dst_port=22, tcp_flags=frozenset({"SYN"}), byte_count=60)


@pytest.fixture
def recorder(tmp_path):
    settings = Settings(db_path=tmp_path / "rec.db",
                        threat=ThreatDetectionSettings(dns_names=True))
    with Store(settings.db_path) as store:
        clock = [0.0]
        recorder = BufferedRecording(settings, store, run_id=store.start_ingestion_run("jsonl"),
                                     monotonic=lambda: clock[0])
        recorder.clock = clock
        yield recorder


def test_hud_capture_raises_threat_findings(recorder):
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    found = []
    for i in range(15):
        found += [d.rule_id for d in recorder.process(syn(i, start))]
    assert found == ["BRUTE_FORCE"]
    assert recorder.store.summary()["detections"] == 1  # a finding flushes immediately
    query = PacketEvent(start + timedelta(seconds=20), HOST, "192.168.1.1", "DNS", dst_port=53,
                        dns_query_name="x7kq9zr2vbn4lp8wmt3c.com")
    assert [d.rule_id for d in recorder.process(query)] == ["DGA_DOMAIN"]


def test_failed_flush_never_advances_committed_threat_state(recorder, monkeypatch):
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    for i in range(10):
        recorder.process(syn(i, start))
    recorder.clock[0] = 5
    recorder.flush_due()
    committed = deepcopy(recorder.service.threat_detector.brute)

    def refuse(*args, **kwargs):
        raise OSError("disk unavailable")

    monkeypatch.setattr(recorder.store, "record_event_bundles", refuse)
    for i in range(10, 13):
        recorder.process(syn(i, start))
    with pytest.raises(OSError):
        recorder.flush()
    assert recorder.service.threat_detector.brute == committed
    assert recorder.staged_threat is None


def test_staged_copies_share_the_immutable_watchlist():
    watchlist = Watchlist(parse_lines(["198.51.100.0/24", "evil.example"]))
    detector = ThreatDetector(ThreatDetectionSettings(), watchlist=watchlist)
    detector.analyze(syn(0, datetime(2030, 1, 1, tzinfo=timezone.utc)))
    clone = deepcopy(detector)
    assert clone.watchlist is watchlist and clone.settings is detector.settings
    assert clone.brute == detector.brute and clone.brute is not detector.brute
    detector.prepare(syn(1, datetime(2030, 1, 1, tzinfo=timezone.utc)))
    with pytest.raises(RuntimeError, match="pending"):
        deepcopy(detector)
