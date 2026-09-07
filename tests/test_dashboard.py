"""Dashboard projection tests use only synthetic metadata and loopback HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import re
from threading import Thread
from urllib.request import urlopen

import pytest

from megalodon.cli import build_parser
from megalodon.dashboard import DashboardHandler, INDEX_HTML, serve
from megalodon.models import PacketEvent
from megalodon.offline.common import Batch, Limits, OfflineError
from megalodon.offline import reports, tshark
from megalodon.offline_projection import MAX_PROJECTED_PORTS, load_offline_projection
from megalodon.storage import Store


def _packet(index: int, port: int = 443) -> PacketEvent:
    return PacketEvent(
        observed_at=datetime(2026, 9, 7, tzinfo=timezone.utc) + timedelta(seconds=index * 10),
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        protocol="TCP",
        src_port=40_000,
        dst_port=port,
        tcp_flags=frozenset({"ACK"}),
        byte_count=60,
    )


def _run(tmp_path: Path, records: list[PacketEvent] | None = None) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    records = records if records is not None else [_packet(index) for index in range(5)]
    batch = Batch(
        adapter=tshark.ADAPTER,
        kind="packet",
        records=tuple(records),
        scanned=len(records),
        skipped=0,
        input_bytes=128,
        tool_version="4.6.0",
        version_basis="subprocess_version",
    )
    output = tmp_path / "run"
    with reports.output_directory(str(output)) as directory:
        reports.finish(directory, reports.manifest("case1", "tshark", Limits()), Limits(), batch=batch)
    return output


def test_projection_is_source_qualified_bounded_and_redacted(tmp_path):
    output = _run(tmp_path)
    projection = load_offline_projection(output)
    encoded = json.dumps(projection, sort_keys=True)

    assert projection["schema"] == "dashboard-offline-summary-v1"
    assert projection["run"]["source"] == "tshark"
    assert projection["run"]["record_kind"] == "packet"
    assert projection["run"]["accepted_records"] == 5
    assert projection["summary"]["relative_window_minutes"] == 1
    assert projection["candidates"] == [
        {"rule": "REGULAR_INTERVAL", "status": "candidate", "count": 1}
    ]
    assert len(projection["summary"]["destination_ports"]) <= MAX_PROJECTED_PORTS
    assert "192.0.2.10" not in encoded
    assert "198.51.100.20" not in encoded
    assert str(tmp_path) not in encoded
    assert "median_interval_us" not in encoded


def test_projection_caps_destination_ports_and_discloses_truncation(tmp_path):
    records = [_packet(index, 1000 + index) for index in range(MAX_PROJECTED_PORTS + 3)]
    projection = load_offline_projection(_run(tmp_path, records))
    summary = projection["summary"]
    assert len(summary["destination_ports"]) == MAX_PROJECTED_PORTS
    assert summary["destination_ports_total"] == MAX_PROJECTED_PORTS + 3
    assert summary["destination_ports_truncated"] is True


def test_projection_accepts_an_empty_but_complete_run(tmp_path):
    projection = load_offline_projection(_run(tmp_path, []))
    assert projection["run"]["accepted_records"] == 0
    assert projection["summary"]["protocols"] == []
    assert projection["summary"]["relative_window_minutes"] == 0
    assert projection["candidates"] == []


def test_projection_rejects_relative_symlink_public_and_incomplete_runs(tmp_path):
    output = _run(tmp_path)
    with pytest.raises(OfflineError, match="ABSOLUTE_OFFLINE_RUN_REQUIRED"):
        load_offline_projection("run")

    alias = tmp_path / "alias"
    alias.symlink_to(output, target_is_directory=True)
    with pytest.raises(OfflineError, match="OFFLINE_REPORT_IO_ERROR"):
        load_offline_projection(alias)

    manifest = output / "manifest.json"
    manifest.chmod(0o644)
    with pytest.raises(OfflineError, match="PRIVATE_OFFLINE_REPORT_REQUIRED"):
        load_offline_projection(output)
    manifest.chmod(0o600)

    (output / "unexpected.txt").write_text("not part of the committed report set")
    with pytest.raises(OfflineError, match="COMPLETE_OFFLINE_REPORT_SET_REQUIRED"):
        load_offline_projection(output)


def test_projection_rejects_manifest_candidate_and_baseline_tampering(tmp_path):
    output = _run(tmp_path)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["candidate_count"] = 0
    manifest_path.write_text(json.dumps(manifest), encoding="ascii")
    with pytest.raises(OfflineError, match="INVALID_OFFLINE_CANDIDATES"):
        load_offline_projection(output)

    output = _run(tmp_path / "second")
    baseline_path = output / "baseline.json"
    baseline = json.loads(baseline_path.read_text())
    baseline["raw_address"] = "192.0.2.10"
    baseline_path.write_text(json.dumps(baseline), encoding="ascii")
    with pytest.raises(OfflineError, match="INVALID_OFFLINE_BASELINE"):
        load_offline_projection(output)


def test_dashboard_parser_and_remote_projection_boundary(tmp_path):
    args = build_parser().parse_args(["dashboard", "--offline-run", str(tmp_path / "run")])
    assert args.offline_run == tmp_path / "run"
    with Store(tmp_path / "events.db") as store:
        with pytest.raises(ValueError, match="loopback"):
            serve(store, "0.0.0.0", 8787, allow_remote=True, offline_summary={})


def test_dashboard_ui_has_accessible_read_only_states():
    assert "Offline analysis snapshot" in INDEX_HTML
    assert 'aria-live="polite"' in INDEX_HTML
    assert 'scope="col"' in INDEX_HTML
    assert "prefers-reduced-motion" in INDEX_HTML
    assert "replaceChildren" in INDEX_HTML
    assert "innerHTML" not in INDEX_HTML
    assert "<button" not in INDEX_HTML
    assert 'type="file"' not in INDEX_HTML
    assert "/api/run" not in INDEX_HTML
    ids = re.findall(r'\bid="([^"]+)"', INDEX_HTML)
    referenced_ids = re.findall(r"getElementById\('([^']+)'\)", INDEX_HTML)
    assert len(ids) == len(set(ids))
    assert set(referenced_ids) <= set(ids)


def test_offline_api_is_local_bounded_and_security_hardened(tmp_path):
    projection = load_offline_projection(_run(tmp_path))
    with Store(tmp_path / "events.db") as store:
        handler = type(
            "TestDashboardHandler",
            (DashboardHandler,),
            {"store": store, "offline_summary": projection},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/api/offline-summary", timeout=2) as response:
                body = response.read().decode("utf-8")
                assert response.headers["Cache-Control"] == "no-store"
                assert response.headers["X-Frame-Options"] == "DENY"
                assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
            payload = json.loads(body)
            assert payload["available"] is True
            assert payload["snapshot"]["run"]["case_id"] == "case1"
            assert str(tmp_path) not in body
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
