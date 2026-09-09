"""Dashboard projection tests use only synthetic metadata and loopback HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import re
import shutil
import subprocess
from threading import Thread
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from megalodon.cli import build_parser
from megalodon.dashboard import (
    DASHBOARD_CSS,
    DASHBOARD_EVENT_FIELDS,
    DASHBOARD_JS,
    DashboardHandler,
    INDEX_HTML,
    serve,
)
from megalodon.models import DetectionResult, PacketEvent
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


def test_projection_rejects_type_confused_json_with_fixed_diagnostics(tmp_path):
    output = _run(tmp_path / "manifest")
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["source"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="ascii")
    with pytest.raises(OfflineError, match="INVALID_OFFLINE_MANIFEST"):
        load_offline_projection(output)

    output = _run(tmp_path / "baseline")
    baseline_path = output / "baseline.json"
    baseline = json.loads(baseline_path.read_text())
    baseline["protocols"][0]["protocol"] = []
    baseline_path.write_text(json.dumps(baseline), encoding="ascii")
    with pytest.raises(OfflineError, match="INVALID_OFFLINE_BASELINE"):
        load_offline_projection(output)

    output = _run(tmp_path / "candidate")
    candidate_path = output / "candidates.jsonl"
    candidate = json.loads(candidate_path.read_text())
    candidate["evidence"]["protocol"] = []
    candidate_path.write_text(json.dumps(candidate) + "\n", encoding="ascii")
    with pytest.raises(OfflineError, match="INVALID_OFFLINE_CANDIDATE"):
        load_offline_projection(output)


@pytest.mark.parametrize(
    ("source", "adapter", "kind", "valid_basis", "invalid_basis"),
    [
        ("tshark", "tshark-fields-v1", "packet", "subprocess_version", "operator_declared_unverified"),
        (
            "zeek-json",
            "zeek-conn-json-v1",
            "flow",
            "operator_declared_unverified",
            "subprocess_version",
        ),
        (
            "zeek-tsv",
            "zeek-conn-tsv-v1",
            "flow",
            "operator_declared_unverified",
            "subprocess_version",
        ),
    ],
)
def test_projection_rejects_source_inconsistent_tool_version_basis(
    tmp_path, source, adapter, kind, valid_basis, invalid_basis
):
    batch = Batch(
        adapter=adapter,
        kind=kind,
        records=(),
        scanned=0,
        skipped=0,
        input_bytes=128,
        tool_version="4.6.0",
        version_basis=valid_basis,
    )
    output = tmp_path / "run"
    with reports.output_directory(str(output)) as directory:
        reports.finish(directory, reports.manifest("case1", source, Limits()), Limits(), batch=batch)
    assert load_offline_projection(output)["run"]["tool_version_basis"] == valid_basis

    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["tool_version_basis"] = invalid_basis
    manifest_path.write_text(json.dumps(manifest), encoding="ascii")

    with pytest.raises(OfflineError, match="INVALID_OFFLINE_MANIFEST"):
        load_offline_projection(output)


@pytest.mark.parametrize(
    ("rule", "evidence"),
    [
        ("NEW_DESTINATION_PORT", {"protocol": "TCP", "port": 443, "records": 6}),
        (
            "REGULAR_INTERVAL",
            {
                "src": "host-00001",
                "dst": "host-00002",
                "protocol": "TCP",
                "port": 443,
                "unique_observations": 6,
                "median_interval_us": 10_000_000,
                "interval_spread_us": 0,
            },
        ),
        ("PORT_53_BURST", {"src": "host-00001", "relative_minute": 0, "records": 20}),
    ],
)
def test_projection_rejects_candidate_counts_above_accepted_records(tmp_path, rule, evidence):
    output = _run(tmp_path)
    if rule == "NEW_DESTINATION_PORT":
        manifest_path = output / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["reference_baseline_used"] = True
        manifest_path.write_text(json.dumps(manifest), encoding="ascii")
    candidate_path = output / "candidates.jsonl"
    candidate = json.loads(candidate_path.read_text())
    candidate["rule"] = rule
    candidate["evidence"] = evidence
    candidate_path.write_text(json.dumps(candidate) + "\n", encoding="ascii")

    with pytest.raises(OfflineError, match="INVALID_OFFLINE_CANDIDATE"):
        load_offline_projection(output)


def test_projection_rejects_new_port_candidate_without_reference_baseline(tmp_path):
    output = _run(tmp_path)
    candidate_path = output / "candidates.jsonl"
    candidate = json.loads(candidate_path.read_text())
    candidate["rule"] = "NEW_DESTINATION_PORT"
    candidate["evidence"] = {"protocol": "TCP", "port": 443, "records": 5}
    candidate_path.write_text(json.dumps(candidate) + "\n", encoding="ascii")

    with pytest.raises(OfflineError, match="INVALID_OFFLINE_CANDIDATE"):
        load_offline_projection(output)


def test_dashboard_parser_and_remote_projection_boundary(tmp_path):
    args = build_parser().parse_args(
        [
            "dashboard",
            "--offline-run",
            str(tmp_path / "run"),
            "--refresh-seconds",
            "12",
            "--event-limit",
            "125",
        ]
    )
    assert args.offline_run == tmp_path / "run"
    assert args.refresh_seconds == 12
    assert args.event_limit == 125
    with Store(tmp_path / "events.db") as store:
        with pytest.raises(ValueError, match="loopback"):
            serve(store, "0.0.0.0", 8787, allow_remote=True, offline_summary={})


def test_dashboard_rejects_invalid_programmatic_polling_controls(tmp_path):
    with Store(tmp_path / "events.db") as store:
        with pytest.raises(ValueError, match="refresh_seconds"):
            serve(store, "127.0.0.1", 8787, refresh_seconds=1)
        with pytest.raises(ValueError, match="event_limit"):
            serve(store, "127.0.0.1", 8787, event_limit=201)
        with pytest.raises(ValueError, match="event_limit"):
            serve(store, "127.0.0.1", 8787, event_limit=True)


def test_dashboard_ui_has_accessible_read_only_states():
    assert "Offline analysis snapshot" in INDEX_HTML
    assert 'aria-live="polite"' in INDEX_HTML
    assert 'scope="col"' in INDEX_HTML
    assert 'href="#detections-title"' in INDEX_HTML
    assert 'type="search"' in INDEX_HTML
    assert 'aria-pressed="false"' in INDEX_HTML
    assert "<button" in INDEX_HTML
    assert "<style" not in INDEX_HTML
    assert "<script>" not in INDEX_HTML
    assert 'src="/assets/dashboard.js"' in INDEX_HTML
    assert 'href="/assets/dashboard.css"' in INDEX_HTML
    assert "prefers-reduced-motion" in DASHBOARD_CSS
    assert "replaceChildren" in DASHBOARD_JS
    assert "AbortController" in DASHBOARD_JS
    assert "knownSeverities.has(normalized)" in DASHBOARD_JS
    assert "`severity ${severity}`" in DASHBOARD_JS
    assert "row.append(timeNode(event.detected_at))" not in DASHBOARD_JS
    assert "const timeCell = document.createElement('td');" in DASHBOARD_JS
    assert "timeCell.append(timeNode(event.detected_at));" in DASHBOARD_JS
    assert "setInterval" not in DASHBOARD_JS
    assert "innerHTML" not in DASHBOARD_JS
    assert "localStorage" not in DASHBOARD_JS
    assert "navigator.clipboard" not in DASHBOARD_JS
    assert 'type="file"' not in INDEX_HTML
    assert "/api/run" not in INDEX_HTML + DASHBOARD_JS
    ids = re.findall(r'\bid="([^"]+)"', INDEX_HTML)
    referenced_ids = re.findall(r"byId\('([^']+)'\)", DASHBOARD_JS)
    assert len(ids) == len(set(ids))
    assert set(referenced_ids) <= set(ids)


def test_refresh_guard_covers_both_peer_requests_after_partial_failure():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")

    harness = r"""
const vm = require('vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { code += chunk; });
process.stdin.on('end', async () => {
  try {
    const withoutBootstrap = code.replace(/\nbootstrap\(\);\s*$/, '\n');
    if (withoutBootstrap === code) throw new Error('dashboard bootstrap marker was not found');
    code = withoutBootstrap;
    const nodes = new Map();
    function fakeNode(id = '') {
      return {id, value: id === 'filter-severity' ? 'ALL' : '', textContent: '',
        className: '', disabled: false, hidden: false, dateTime: '', colSpan: 0,
        append() {}, replaceChildren() {}, setAttribute() {}, addEventListener() {}};
    }
    const document = {hidden: false,
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, fakeNode(id)); return nodes.get(id); },
      createElement(tag) { return fakeNode(tag); }, addEventListener() {}};
    class FakeAbortController { constructor() { this.signal = {}; } abort() {} }
    const calls = []; let finishEvents;
    const response = value => ({ok: true, json: async () => value});
    function fetch(path) {
      calls.push(path);
      if (path === '/api/summary') return Promise.reject(new Error('summary failed'));
      if (path.startsWith('/api/events?')) {
        return new Promise(resolve => { finishEvents = () => resolve(response([])); });
      }
      return Promise.reject(new Error(`unexpected path: ${path}`));
    }
    const context = {document, fetch, AbortController: FakeAbortController,
      Intl, Date, Number, String, Math, Set,
      Promise, Error, Array, window: {setTimeout() { return 1; }, clearTimeout() {}}};
    vm.createContext(context); vm.runInContext(code, context);
    const first = vm.runInContext('refresh(false)', context);
    await new Promise(resolve => setImmediate(resolve));
    await vm.runInContext('refresh(false)', context);
    if (calls.length !== 2) throw new Error(`overlap: ${JSON.stringify(calls)}`);
    finishEvents(); await first; process.stdout.write('no-overlap\n');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
});
"""
    result = subprocess.run(
        [node, "-e", harness],
        input=DASHBOARD_JS,
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "no-overlap\n"


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
                assert "script-src 'self'" in response.headers["Content-Security-Policy"]
                assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]
                assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
            payload = json.loads(body)
            assert payload["available"] is True
            assert payload["snapshot"]["run"]["case_id"] == "case1"
            assert str(tmp_path) not in body
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_dashboard_config_assets_and_query_validation(tmp_path):
    with Store(tmp_path / "events.db") as store:
        handler = type(
            "TestConfiguredDashboardHandler",
            (DashboardHandler,),
            {"store": store, "refresh_seconds": 12, "event_limit": 125},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(f"{base}/api/config", timeout=2) as response:
                config = json.loads(response.read())
            assert config == {
                "schema": "dashboard-config-v1",
                "read_only": True,
                "refresh_seconds": 12,
                "event_limit": 125,
                "offline_summary_available": False,
            }

            with urlopen(f"{base}/assets/dashboard.css", timeout=2) as response:
                assert response.headers["Content-Type"] == "text/css; charset=utf-8"
                assert response.read().decode() == DASHBOARD_CSS
            with urlopen(f"{base}/assets/dashboard.js", timeout=2) as response:
                assert response.headers["Content-Type"] == "text/javascript; charset=utf-8"
                assert response.read().decode() == DASHBOARD_JS

            for query in ("limit=0", "limit=201", "limit=abc", "limit=1&limit=2", "other=1"):
                with pytest.raises(HTTPError) as raised:
                    urlopen(f"{base}/api/events?{query}", timeout=2)
                assert raised.value.code == 400
                assert "error" in json.loads(raised.value.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_events_api_projects_only_fields_required_by_the_ui(tmp_path):
    with Store(tmp_path / "events.db") as store:
        event = _packet(0)
        event_id = store.record_event(event)
        store.record_detection(
            event_id,
            DetectionResult(
                detected_at=event.observed_at,
                rule_id="TEST_RULE",
                severity="HIGH",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                message="Synthetic dashboard projection test",
                evidence={"private_detail": "not served"},
                recommendation="REVIEW_PRIVATE_EVIDENCE",
                suppressed_reason="synthetic suppression detail",
            ),
        )
        handler = type("TestMinimalEventsHandler", (DashboardHandler,), {"store": store})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/api/events?limit=1", timeout=2) as response:
                payload = json.loads(response.read())
            assert len(payload) == 1
            assert set(payload[0]) == set(DASHBOARD_EVENT_FIELDS)
            assert payload[0]["src_ip"] == "192.0.2.10"
            assert payload[0]["message"] == "Synthetic dashboard projection test"
            assert "dst_ip" not in payload[0]
            assert "evidence" not in payload[0]
            assert "recommendation" not in payload[0]
            assert "suppressed_reason" not in payload[0]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
