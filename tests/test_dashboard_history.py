"""Database-backed history using synthetic metadata, never native traffic."""
from datetime import timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread
from urllib.parse import urlencode

import pytest

from megalodon.dashboard import DashboardHandler, UnconfiguredDashboardReader
from megalodon.dashboard_traffic import MAX_BYTES, TrafficDashboardStore, history_parameters
from megalodon.models import PacketEvent
from megalodon.storage import Store, StorageSchemaError
import megalodon.storage as storage
from test_dashboard_traffic import TIME, add_run

START = "2026-09-17T00:00:00.000Z"
END = "2026-09-17T23:59:59.999Z"


def test_history_reads_older_events_and_their_findings_outside_latest_window(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        older = add_run(writer, finding=True)
        run = writer.start_ingestion_run("jsonl", started_at=TIME)
        for _ in range(510):
            writer.record_event_bundle(PacketEvent(TIME + timedelta(days=1), "192.0.2.1", "198.51.100.1", "UDP"), [], [], run_id=run)
        writer.finish_ingestion_run(run, "source_exhausted", finished_at=TIME + timedelta(days=1))
        with TrafficDashboardStore(path) as reader:
            assert str(older) not in {e["id"] for e in reader.traffic()["events"]}
            page = reader.traffic_history(START, END)
            assert [e["id"] for e in page["traffic"]["events"]] == [str(older)]
            assert page["traffic"]["findings"][0]["event_id"] == str(older)
            assert page["candidate_count"] == 1 and page["next_before"] is None
            assert "PRIVATE_" not in json.dumps(page)
            assert len(json.dumps(page).encode()) < MAX_BYTES


def test_pagination_advances_across_excluded_pages_and_concurrent_inserts(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        older = add_run(writer, count=2)
        add_run(writer, source="sample", count=500)
        with TrafficDashboardStore(path) as reader:
            first = reader.traffic_history(START, END)
            assert first["traffic"]["events"] == []
            assert first["candidate_count"] == 500 and first["next_before"] == "3"
            add_run(writer, count=2)
            second = reader.traffic_history(START, END, first["next_before"])
            assert [e["id"] for e in second["traffic"]["events"]] == [str(older), "1"]
            assert second["next_before"] is None
            assert reader.traffic()["events"][0]["id"] == "504"


def test_history_utc_boundaries_include_exact_seconds_and_microseconds(tmp_path):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        run = writer.start_ingestion_run("jsonl", started_at=TIME)
        for delta in (0, 1, 999999, 1000000):
            writer.record_event_bundle(PacketEvent(TIME + timedelta(microseconds=delta), "192.0.2.1", "198.51.100.1", "UDP"), [], [], run_id=run)
        writer.finish_ingestion_run(run, "source_exhausted", finished_at=TIME)
        with TrafficDashboardStore(path) as reader:
            page = reader.traffic_history("2026-09-17T12:00:00.000Z", "2026-09-17T12:00:00.999999Z")
            assert [e["id"] for e in page["traffic"]["events"]] == ["3", "2", "1"]
            exact = reader.traffic_history("2026-09-17T12:00:00Z", "2026-09-17T12:00:00.000000Z")
            assert [e["id"] for e in exact["traffic"]["events"]] == ["1"]


@pytest.mark.parametrize("start,end,before", [
    (END, START, None), ("2026-02-30T00:00:00Z", END, None),
    ("2026-01-01T00:00:00Z", END, None), (START, "9999-12-31T00:00:00Z", None),
    ("2026-09-17T00:00:00", END, None), (START, END, "01"), (START, END, "0"),
    (START, END, "9007199254740992"), (START, END, "1 OR 1=1"),
])
def test_history_rejects_invalid_ranges_and_cursors(start, end, before):
    with pytest.raises(ValueError):
        history_parameters(start, end, before)


def test_history_budget_fails_closed_and_reader_recovers(tmp_path, monkeypatch):
    path = tmp_path / "private" / "audit.db"
    with Store(path) as writer:
        add_run(writer)
        with TrafficDashboardStore(path) as reader:
            with monkeypatch.context() as patch:
                patch.setattr(storage, "DASHBOARD_QUERY_PROGRESS_STEPS", 1)
                patch.setattr(storage, "DASHBOARD_QUERY_VM_STEPS", 5)
                with pytest.raises(StorageSchemaError, match="READ_BUDGET_EXCEEDED"):
                    reader.traffic_history(START, END)
            assert reader.traffic_history(START, END)["candidate_count"] == 1


def test_history_http_is_closed_and_unavailable_is_not_empty():
    handler = type("HistoryTestHandler", (DashboardHandler,), {"store": UnconfiguredDashboardReader()})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    query = urlencode({"start": START, "end": END})
    try:
        for suffix, method, expected in [("?" + query, "GET", 503), ("", "GET", 400),
            ("?" + query + "&path=/etc/passwd", "GET", 400),
            ("?" + query + "&start=" + START, "GET", 400), ("?" + query, "POST", 405)]:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request(method, "/api/traffic-history" + suffix)
            response = connection.getresponse(); body = response.read(); connection.close()
            assert response.status == expected
            assert response.getheader("Cache-Control") == "no-store"
            assert "connect-src 'self'" in response.getheader("Content-Security-Policy")
            if expected == 503:
                assert json.loads(body) == {"error": "history unavailable"}
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)
