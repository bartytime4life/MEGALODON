"""Synthetic metadata fixtures exercise the real read-only projection boundary."""
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import sqlite3
from threading import Thread

import pytest

from megalodon.dashboard import DashboardHandler, UnconfiguredDashboardReader
from megalodon.dashboard_traffic import TrafficDashboardStore, MAX_BYTES, unavailable
from megalodon.models import PacketEvent, DetectionResult, ActionRecord
from megalodon.storage import Store, StorageSchemaError
import megalodon.storage as storage

TIME = datetime(2026, 9, 17, 12, tzinfo=timezone.utc)


def add_run(writer, source="jsonl", count=1, termination="source_exhausted", finding=False):
    run_id = writer.start_ingestion_run(source, started_at=TIME)
    for _ in range(count):
        detections = [DetectionResult(TIME, "PORT_SCAN", "MEDIUM", "192.0.2.1", "198.51.100.1",
            "PRIVATE_MESSAGE", {"private": "PRIVATE_EVIDENCE"}, "PRIVATE_RECOMMENDATION")] if finding else []
        actions = [ActionRecord(TIME, "block", "192.0.2.1", "not_attempted", "PRIVATE_REASON")] if finding else []
        event_id = writer.record_event_bundle(PacketEvent(TIME, "192.0.2.1", "198.51.100.1", "TCP",
                                                    src_port=12345, dst_port=443, tcp_flags=frozenset({"SYN"}),
                                                    byte_count=2**63-1), detections, actions, run_id=run_id)
    writer.finish_ingestion_run(run_id, termination, finished_at=TIME)
    return event_id


@pytest.fixture
def audit(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        add_run(writer, finding=True)
        with TrafficDashboardStore(path) as reader:
            yield path, writer, reader


def test_projection_preserves_ids_units_large_integers_and_privacy(audit):
    _, writer, reader = audit
    before = writer.summary()
    value = reader.traffic()
    assert value["status"] == "available" and value["quality"] == "unknown"
    assert value["events"][0]["byte_count"] == str(2**63-1)
    assert value["events"][0]["tcp_flags"] == ["SYN"]
    assert value["findings"][0]["event_id"] == value["events"][0]["id"]
    assert value["findings"][0]["detector_version"].startswith("unknown")
    encoded = json.dumps(value).encode()
    assert len(encoded) < MAX_BYTES and b"PRIVATE_" not in encoded
    assert writer.summary() == before
    assert not reader._connection.in_transaction
    assert reader._connection.execute("PRAGMA query_only").fetchone()[0] == 1
    for query in ("SELECT metadata_json FROM events", "SELECT interface FROM events", "SELECT evidence_json FROM detections",
                  "SELECT recommendation FROM detections", "SELECT details_json FROM actions", "DELETE FROM events", "PRAGMA journal_mode=WAL"):
        with pytest.raises(sqlite3.DatabaseError):
            reader._connection.execute(query)


def test_sample_and_unlinked_rows_never_become_traffic(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        add_run(writer, "sample")
        writer.record_event(PacketEvent(TIME, "192.0.2.2", "198.51.100.2", "UDP"))
        with TrafficDashboardStore(path) as reader:
            value = reader.traffic()
            assert value["status"] == "unavailable" and value["events"] == []
            assert value["window"] == {"start": None, "end": None}
            assert value["excluded_event_candidates"] == 2


def test_candidate_limit_is_visible_not_silent(audit):
    _, writer, reader = audit
    add_run(writer, count=501)
    value = reader.traffic()
    assert len(value["events"]) == 500
    assert value["truncated"] is True and value["quality"] == "degraded"


@pytest.mark.parametrize("column,value", [("src_ip", "PRIVATE_"*20000), ("src_ip", b"bad"),
    ("protocol", "<script>"), ("tcp_flags", "COOKIE_SECRET"), ("observed_at", "invalid"),
    ("byte_count", "PRIVATE_NUMBER"), ("dst_port", 70000)], ids=["oversize", "blob", "protocol", "flags", "time", "integer", "port"])
def test_bad_metadata_refuses_entire_projection(audit, column, value):
    _, writer, reader = audit
    # Closed test parameters, never user/telemetry SQL input.
    writer.connection.execute(f"UPDATE events SET {column}=?", (value,))
    writer.connection.commit()
    with pytest.raises(StorageSchemaError, match="INVALID_TRAFFIC"):
        reader.traffic()


def test_budget_fails_closed_and_recovers(audit, monkeypatch):
    _, _, reader = audit
    with monkeypatch.context() as patch:
        patch.setattr(storage, "DASHBOARD_QUERY_PROGRESS_STEPS", 1)
        patch.setattr(storage, "DASHBOARD_QUERY_VM_STEPS", 5)
        with pytest.raises(StorageSchemaError, match="READ_BUDGET_EXCEEDED"):
            reader.traffic()
    assert reader.traffic()["status"] == "available"


def test_incomplete_receipt_is_degraded(audit):
    _, writer, reader = audit
    add_run(writer, termination="event_limit_reached")
    assert reader.traffic()["quality"] == "degraded"


def test_http_unavailable_is_not_zero_and_query_cannot_choose_path():
    handler = type("TrafficTestHandler", (DashboardHandler,), {"store": UnconfiguredDashboardReader()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    try:
        for target, method, headers, expected in [
            ("/api/traffic", "GET", {}, 503),
            ("/api/traffic?path=/tmp/secret", "GET", {}, 400),
            ("/api/traffic", "GET", {"Host": "evil.example"}, 400),
            ("/api/traffic", "POST", {}, 405),
        ]:
            conn = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            conn.request(method, target, headers=headers)
            response = conn.getresponse(); body = response.read(); conn.close()
            assert response.status == expected and len(body) < 2048
            assert response.getheader("Access-Control-Allow-Origin") is None
            assert "default-src 'none'" in response.getheader("Content-Security-Policy")
            if expected == 503:
                value = json.loads(body)
                assert value["status"] == "unavailable"
                assert value["window"] == {"start": None, "end": None}
                assert value["events"] == [] and value["findings"] == []
                assert value["limits"] == {"events": 500, "findings": 200, "bytes": MAX_BYTES}
                assert value["build"]["projection_sha256"] == unavailable()["build"]["projection_sha256"]
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)
