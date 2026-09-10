"""Dashboard projection tests use only synthetic metadata and loopback HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
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
    MAX_REFERENCE_CACHE_ENTRIES,
    ReferenceLibrary,
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
    assert "Recent detection triage" in INDEX_HTML
    assert 'aria-live="polite"' in INDEX_HTML
    assert 'scope="col"' in INDEX_HTML
    assert 'href="#detections-title"' in INDEX_HTML
    assert 'type="search"' in INDEX_HTML
    assert 'aria-pressed="false"' in INDEX_HTML
    assert '<fieldset class="toolbar" id="triage-controls" disabled>' in INDEX_HTML
    assert '<legend class="sr-only">Detection triage filters and refresh controls</legend>' in INDEX_HTML
    assert '<select id="filter-rule"><option value="">All rules</option></select>' in INDEX_HTML
    assert '<option value="PRIORITY">High + critical</option>' in INDEX_HTML
    assert '<button id="clear-filters" type="button"' in INDEX_HTML
    assert '<button id="clear-time-filter" type="button"' in INDEX_HTML
    assert 'id="priority-announcement" aria-live="polite" aria-atomic="true"' in INDEX_HTML
    assert 'id="timeline" role="group" aria-label="Filter detections by returned timestamp range"' in INDEX_HTML
    assert 'id="connection" role="status"' not in INDEX_HTML
    assert 'id="snapshot-status" role="status" aria-live="polite" aria-atomic="true"' in INDEX_HTML
    assert 'class="table-scroll" role="region" aria-label="Scrollable recent detections table"' in INDEX_HTML
    assert 'aria-describedby="table-scroll-help" tabindex="0"' in INDEX_HTML
    assert "Dashboard API reachability does not measure capture or ingestion health." in INDEX_HTML
    assert "Sequential count-change signal only" in INDEX_HTML
    assert "High / critical stored" in INDEX_HTML
    assert "Action records" in INDEX_HTML
    assert "Reference Library" in INDEX_HTML
    assert 'id="reference-port-form"' in INDEX_HTML
    assert 'id="reference-protocol-form"' in INDEX_HTML
    assert 'id="reference-status" role="status" aria-live="polite"' in INDEX_HTML
    assert "manifest-verified IANA snapshot" in INDEX_HTML
    assert "Registration is analyst context" in INDEX_HTML
    assert "<button" in INDEX_HTML
    assert "<style" not in INDEX_HTML
    assert "<script>" not in INDEX_HTML
    assert 'src="/assets/dashboard.js"' in INDEX_HTML
    assert 'href="/assets/dashboard.css"' in INDEX_HTML
    assert "prefers-reduced-motion" in DASHBOARD_CSS
    assert "forced-colors: active" in DASHBOARD_CSS
    assert ".timeline-bar.level-0 { height: 0; }" in DASHBOARD_CSS
    assert "replaceChildren" in DASHBOARD_JS
    assert "AbortController" in DASHBOARD_JS
    assert "knownSeverities.has(normalized)" in DASHBOARD_JS
    assert "Audit decisions; no live application" in DASHBOARD_JS
    assert "Schema-checked startup snapshot" in DASHBOARD_JS
    assert "Showing preserved stale dashboard data" in DASHBOARD_JS
    assert "No successful dashboard data fetch is available" in DASHBOARD_JS
    assert "Recent SQLite telemetry is checked separately" in DASHBOARD_JS
    assert "Live telemetry remains available" not in DASHBOARD_JS
    assert "`severity ${severity}`" in DASHBOARD_JS
    assert "row.append(timeNode(event.detected_at))" not in DASHBOARD_JS
    assert "const timeCell = document.createElement('td');" in DASHBOARD_JS
    assert "timeCell.append(timeNode(event.detected_at));" in DASHBOARD_JS
    assert "setInterval" not in DASHBOARD_JS
    assert "innerHTML" not in DASHBOARD_JS
    assert "localStorage" not in DASHBOARD_JS
    assert "navigator.clipboard" not in DASHBOARD_JS
    assert "reference-library-lookup-v1" in DASHBOARD_JS
    assert "integrity_failure" in DASHBOARD_JS
    assert "last successful reference result as stale" in DASHBOARD_JS
    for forbidden in ("Notification", "Audio(", "WebSocket", "EventSource"):
        assert forbidden not in INDEX_HTML + DASHBOARD_JS
    for private_field in ("dst_ip", "evidence", "recommendation", "suppressed_reason"):
        assert private_field not in INDEX_HTML + DASHBOARD_JS
    assert "method: 'POST'" not in DASHBOARD_JS
    assert 'method: "POST"' not in DASHBOARD_JS
    assert not re.search(r'tabindex="[1-9][0-9]*"', INDEX_HTML)
    assert 'type="file"' not in INDEX_HTML
    assert "/api/run" not in INDEX_HTML + DASHBOARD_JS
    ids = re.findall(r'\bid="([^"]+)"', INDEX_HTML)
    referenced_ids = re.findall(r"byId\('([^']+)'\)", DASHBOARD_JS)
    assert len(ids) == len(set(ids))
    assert set(referenced_ids) <= set(ids)


def _reference_http(server, method, path):
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    connection.request(method, path, headers={"Host": f"127.0.0.1:{server.server_port}"})
    response = connection.getresponse()
    payload = json.loads(response.read())
    headers = dict(response.getheaders())
    connection.close()
    return response.status, payload, headers


def test_reference_library_is_verified_bounded_and_provenance_pinned():
    library = ReferenceLibrary.load()
    status = library.status()
    assert status["schema"] == "reference-library-status-v1"
    assert status["status"] == "ready"
    assert status["available"] is True
    assert status["bundle_version"] == "v1"
    assert status["service_records"] == 12_577
    assert status["protocol_records"] == 152
    assert len(status["sources"]) == 2
    assert all(
        set(source) == {
            "id", "registry_url", "registry_last_updated", "retrieved_at", "retrieved_at_basis"
        }
        for source in status["sources"]
    )
    one = library.lookup_port("tcp", 443)
    assert one["status"] == "one_match"
    assert one["sources"][0]["id"] == "iana-service-names-port-numbers"
    assert "warning" in one and "proof" in one["warning"]
    multiple = library.lookup_port("tcp", 80)
    assert multiple["status"] == "multiple_matches"
    assert multiple["match_count"] == 3
    empty = library.lookup_port("dccp", 65_535)
    assert empty["status"] == "no_match"
    assert empty["matches"] == []
    assert library.lookup_protocol(6)["status"] == "one_match"
    for operation in (
        lambda: library.lookup_port("tcp", -1),
        lambda: library.lookup_port("tcp", 65_536),
        lambda: library.lookup_protocol(-1),
        lambda: library.lookup_protocol(256),
    ):
        with pytest.raises(ValueError, match="invalid reference lookup"):
            operation()
    for number in range(MAX_REFERENCE_CACHE_ENTRIES + 5):
        library.lookup_protocol(number)
    assert library.cache_size <= MAX_REFERENCE_CACHE_ENTRIES


def test_reference_dashboard_api_is_get_only_closed_and_side_effect_free(tmp_path):
    with Store(tmp_path / "events.db") as store:
        handler = type(
            "ReferenceDashboardHandler",
            (DashboardHandler,),
            {"store": store, "reference_library": ReferenceLibrary.load()},
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, payload, headers = _reference_http(server, "GET", "/api/reference/status")
            assert status == 200
            assert payload["status"] == "ready"
            assert headers["Cache-Control"] == "no-store"
            assert headers["X-Frame-Options"] == "DENY"
            assert "'unsafe-inline'" not in headers["Content-Security-Policy"]

            cases = (
                ("/api/reference/port?transport=tcp&port=443", "one_match"),
                ("/api/reference/port?transport=tcp&port=80", "multiple_matches"),
                ("/api/reference/port?transport=dccp&port=65535", "no_match"),
                ("/api/reference/protocol?number=6", "one_match"),
            )
            for path, expected in cases:
                code, result, _ = _reference_http(server, "GET", path)
                assert code == 200
                assert result["status"] == expected
                assert result["network_access_performed"] is False
                assert result["persistence_status"] == "not_attempted"
                assert result["action_status"] == "not_attempted"
                assert "sources" in result and "warning" in result

            invalid = (
                "/api/reference/port?transport=TCP&port=443",
                "/api/reference/port?transport=tcp&port=0443",
                "/api/reference/port?transport=tcp&port=443.0",
                "/api/reference/port?transport=tcp&port=true",
                "/api/reference/port?transport=tcp&port=65536",
                "/api/reference/port?transport=tcp&port=443&port=80",
                "/api/reference/port?transport=tcp&port=443&extra=1",
                "/api/reference/protocol?number=256",
                "/api/reference/protocol?number=6.0",
                "/api/reference/protocol?number=true",
                "/api/reference/protocol?number=6&number=7",
                "/api/reference/status?extra=1",
            )
            for path in invalid:
                code, error, _ = _reference_http(server, "GET", path)
                assert code == 400
                assert set(error) == {"error"}
                assert str(tmp_path) not in json.dumps(error)

            code, error, headers = _reference_http(server, "POST", "/api/reference/port?transport=tcp&port=443")
            assert code == 405
            assert error == {"error": "method not allowed"}
            assert headers["Allow"] == "GET"
            assert store.summary() == {"events": 0, "detections": 0, "actions": 0, "high_or_critical": 0}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def test_reference_dashboard_fails_closed_without_partial_bundle_data(tmp_path):
    with Store(tmp_path / "events.db") as store:
        for failure in ("unavailable", "integrity_failure"):
            handler = type(
                "UnavailableReferenceDashboardHandler",
                (DashboardHandler,),
                {"store": store, "reference_library": ReferenceLibrary(failure=failure)},
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                code, payload, _ = _reference_http(server, "GET", "/api/reference/status")
                assert code == 503
                assert payload["status"] == failure
                assert "path" not in json.dumps(payload).lower()
                code, payload, _ = _reference_http(server, "GET", "/api/reference/port?transport=tcp&port=443")
                assert code == 503
                assert payload["status"] == failure
                assert "matches" not in payload
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


def test_dashboard_triage_filter_timeline_priority_and_response_contracts():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for dashboard JavaScript behavior")

    harness = r"""
const vm = require('vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { code += chunk; });
process.stdin.on('end', () => {
  try {
    const withoutBootstrap = code.replace(/\nbootstrap\(\);\s*$/, '\n');
    if (withoutBootstrap === code) throw new Error('dashboard bootstrap marker was not found');
    code = withoutBootstrap;
    const nodes = new Map();
    function fakeNode(id = '') {
      let text = '';
      return {
        id,
        value: id === 'filter-severity' ? 'ALL' : '',
        className: '', disabled: false, hidden: false, dateTime: '', colSpan: 0,
        children: [], attributes: new Map(), listeners: new Map(), textWrites: 0,
        get textContent() { return text; },
        set textContent(value) { text = String(value); this.textWrites += 1; },
        append(...children) { this.children.push(...children); },
        replaceChildren(...children) { this.children = children; },
        setAttribute(name, value) { this.attributes.set(name, String(value)); },
        getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; },
        removeAttribute(name) { this.attributes.delete(name); },
        addEventListener(name, listener) { this.listeners.set(name, listener); },
        click() { const listener = this.listeners.get('click'); if (listener) listener(); }
      };
    }
    const document = {
      hidden: false,
      getElementById(id) {
        if (!nodes.has(id)) nodes.set(id, fakeNode(id));
        return nodes.get(id);
      },
      createElement(tag) { return fakeNode(tag); },
      addEventListener() {}
    };
    class FakeAbortController { constructor() { this.signal = {}; } abort() {} }
    const context = {
      document, AbortController: FakeAbortController,
      Intl, Date, Number, String, Math, Set, Promise, Error, Array,
      window: {setTimeout() { return 1; }, clearTimeout() {}}
    };
    vm.createContext(context);
    vm.runInContext(code, context);
    vm.runInContext(`
      state.config.event_limit = 20;
      state.lastSuccessfulRefresh = new Date('2026-09-10T02:00:00Z');
      state.events = [
        {detected_at: '2026-09-10T00:00:00Z', message: 'Alpha needle', rule_id: 'RULE_A', severity: 'HIGH', src_ip: '192.0.2.1'},
        {detected_at: '2026-09-10T00:10:00Z', message: 'Alpha needle', rule_id: 'RULE_A_EXTRA', severity: 'CRITICAL', src_ip: '192.0.2.2'},
        {detected_at: '2026-09-10T00:20:00Z', message: 'Alpha needle', rule_id: 'RULE_A', severity: 'MEDIUM', src_ip: '192.0.2.3'},
        {detected_at: 'not-a-timestamp', message: 'Other', rule_id: 'ALL', severity: 'LOW', src_ip: '192.0.2.4'},
        {detected_at: '2026-09-10T00:30:00Z', message: 'Other', rule_id: 'RULE_A', severity: 'CRITICAL', src_ip: '192.0.2.5'}
      ];
      renderRuleOptions();
    `, context);

    const ruleValues = nodes.get('filter-rule').children.map(option => option.value);
    if (JSON.stringify(ruleValues) !== JSON.stringify(['', 'ALL', 'RULE_A', 'RULE_A_EXTRA'])) {
      throw new Error(`rule options are not unique and deterministic: ${JSON.stringify(ruleValues)}`);
    }

    vm.runInContext(`
      byId('filter-severity').value = 'PRIORITY';
      byId('filter-rule').value = '';
      byId('filter-query').value = '';
    `, context);
    let filtered = vm.runInContext('baseFilteredEvents().map(event => event.severity).join(",")', context);
    if (filtered !== 'HIGH,CRITICAL,CRITICAL') throw new Error(`priority grouping failed: ${filtered}`);

    vm.runInContext("byId('filter-rule').value = 'RULE_A'", context);
    filtered = vm.runInContext('baseFilteredEvents().map(event => event.src_ip).join(",")', context);
    if (filtered !== '192.0.2.1,192.0.2.5') throw new Error(`rule matching was not exact: ${filtered}`);
    vm.runInContext("byId('filter-query').value = 'alpha'", context);
    filtered = vm.runInContext('baseFilteredEvents().map(event => event.src_ip).join(",")', context);
    if (filtered !== '192.0.2.1') throw new Error(`combined query filter failed: ${filtered}`);
    vm.runInContext(`
      byId('filter-severity').value = 'ALL';
      byId('filter-rule').value = 'ALL';
      byId('filter-query').value = '';
    `, context);
    filtered = vm.runInContext('baseFilteredEvents().map(event => event.src_ip).join(",")', context);
    if (filtered !== '192.0.2.4') throw new Error(`literal ALL rule was not selectable: ${filtered}`);

    vm.runInContext(`
      byId('filter-severity').value = 'ALL';
      byId('filter-rule').value = '';
      byId('filter-query').value = '';
      state.activeBin = null;
      applyFilters();
    `, context);
    if (nodes.get('events').children.length !== 5) throw new Error('invalid-time row left the unfiltered table');
    if (!nodes.get('timeline-status').textContent.includes('excluded from the timeline only')) {
      throw new Error('invalid-time timeline boundary is not disclosed');
    }
    const firstTimelineButton = nodes.get('timeline').children[0];
    if (firstTimelineButton.getAttribute('aria-pressed') !== 'false') throw new Error('timeline starts selected');
    firstTimelineButton.click();
    if (vm.runInContext('state.activeBin', context) !== 0) throw new Error('timeline click did not select a bin');
    if (nodes.get('timeline').children[0].getAttribute('aria-pressed') !== 'true') throw new Error('selected bin state is not exposed');
    nodes.get('timeline').children[0].click();
    if (vm.runInContext('state.activeBin', context) !== null) throw new Error('selected timeline bin did not toggle off');

    vm.runInContext(`
      {
        const timelineEvents = Array.from({length: 13}, (_, index) => ({
          detected_at: new Date(Date.UTC(2026, 8, 10, 0, index)).toISOString()
        })).concat([{detected_at: 'not-a-timestamp'}]);
        const model = buildTimeline(timelineEvents);
        if (model.bins.length !== 12) throw new Error('timeline is not capped at 12 bins');
        if (model.bins.reduce((total, bin) => total + bin.members.length, 0) !== 13) throw new Error('timeline lost or duplicated valid rows');
        if (model.invalidCount !== 1) throw new Error('timeline invalid count is wrong');
        if (!model.bins[0].members.includes(0) || !model.bins[11].members.includes(12)) throw new Error('timeline endpoints were not assigned once');
        const equal = buildTimeline([{detected_at: '2026-09-10T01:00:00Z'}, {detected_at: '2026-09-10T01:00:00Z'}]);
        if (equal.bins.length !== 1 || equal.bins[0].members.length !== 2) throw new Error('equal timestamps did not form one bin');
        const sparse = buildTimeline([
          {detected_at: '1970-01-01T00:00:00.000Z'},
          {detected_at: '1970-01-01T00:00:00.001Z'},
          {detected_at: '1970-01-01T00:00:10.000Z'}
        ]);
        for (let index = 1; index < sparse.bins.length; index += 1) {
          if (sparse.bins[index - 1].end >= sparse.bins[index].start) throw new Error('timeline ranges overlap');
          if (displayTime(new Date(sparse.bins[index - 1].end)) === displayTime(new Date(sparse.bins[index].start))) {
            throw new Error('adjacent timeline labels lose their millisecond boundary');
          }
        }
        renderTimeline(sparse);
        const emptyButton = byId('timeline').children.find(button => button.getAttribute('aria-label').startsWith('0 returned'));
        if (!emptyButton || emptyButton.children[0].className !== 'timeline-bar level-0') throw new Error('zero-count bin rendered a positive bar');
      }
    `, context);

    vm.runInContext(`
      byId('filter-query').value = 'alpha';
      byId('filter-severity').value = 'PRIORITY';
      byId('filter-rule').value = 'RULE_A';
      state.activeBin = 0;
      clearFilters();
      if (byId('filter-query').value !== '' || byId('filter-severity').value !== 'ALL' || byId('filter-rule').value !== '' || state.activeBin !== null) {
        throw new Error('clear filters did not reset every local dimension');
      }
      if (state.events.length !== 5) throw new Error('clear filters mutated returned data');
    `, context);

    vm.runInContext(`
      updatePriorityChange({high_or_critical: 2});
      if (byId('priority-change').textContent !== 'Priority baseline established: 2 stored.') throw new Error('priority baseline is unclear');
      updatePriorityChange({high_or_critical: 2});
      if (byId('priority-change').textContent !== 'No stored high/critical count change · 2 stored.') throw new Error('priority no-change state is unclear');
    `, context);
    const noChangeWrites = nodes.get('priority-change').textWrites;
    vm.runInContext('updatePriorityChange({high_or_critical: 2})', context);
    if (nodes.get('priority-change').textWrites !== noChangeWrites) throw new Error('unchanged priority state rewrote its status');
    vm.runInContext(`
      updatePriorityChange({high_or_critical: 5});
      if (byId('priority-change').textContent !== 'Stored high/critical count increased by 3 to 5.') throw new Error('priority increase is unclear');
      updatePriorityChange({high_or_critical: 1});
      if (byId('priority-change').textContent !== 'Stored high/critical count decreased by 4 to 1.') throw new Error('priority decrease is unclear');
      if (!byId('priority-announcement').textContent.includes('decreased by 4')) throw new Error('priority decrease was not announced');
      updatePriorityChange({high_or_critical: 1});
      if (byId('priority-announcement').textContent !== '') throw new Error('no-change state retained an obsolete priority announcement');
      if (state.lastPriorityTotal !== 1) throw new Error('priority baseline did not advance sequentially');
    `, context);

    vm.runInContext(`
      {
        const validSummary = {actions: 0, detections: 1, events: 1, high_or_critical: 1};
        const validEvent = {detected_at: 'not-a-timestamp', message: 'bounded', rule_id: 'RULE_A', severity: 'HIGH', src_ip: '192.0.2.1'};
        validatedSummary(validSummary);
        validatedEvents([validEvent]);
        const mustReject = [
          () => validatedSummary(null),
          () => validatedSummary({...validSummary, extra: 1}),
          () => validatedSummary({actions: 0, detections: 1, events: 1}),
          () => validatedSummary({...validSummary, actions: -1}),
          () => validatedSummary({...validSummary, detections: 1.5}),
          () => validatedSummary({...validSummary, high_or_critical: 2}),
          () => validatedEvents({}),
          () => validatedEvents(Array.from({length: 21}, () => validEvent)),
          () => validatedEvents([{...validEvent, extra: ''}]),
          () => validatedEvents([{detected_at: validEvent.detected_at, message: validEvent.message, rule_id: validEvent.rule_id, severity: validEvent.severity}]),
          () => validatedEvents([{...validEvent, message: 1}]),
          () => validatedEvents([{...validEvent, severity: 'UNKNOWN'}])
        ];
        mustReject.forEach((operation, index) => {
          let rejected = false;
          try { operation(); } catch (_) { rejected = true; }
          if (!rejected) throw new Error('closed response validation accepted case ' + index);
        });
      }
    `, context);
    vm.runInContext("state.lastSuccessfulRefresh = null; renderInitialUnavailable(); byId('filter-query').value = 'x'; applyFilters()", context);
    if (!nodes.get('events').children[0].children[0].textContent.includes('unavailable')) throw new Error('initial failure left a loading table');
    if (!nodes.get('priority-change').textContent.includes('baseline unavailable')) throw new Error('initial failure left a waiting priority state');
    process.stdout.write('triage-contracts\n');
  } catch (error) {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  }
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
    assert result.stdout == "triage-contracts\n"


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
        className: '', disabled: false, hidden: false, dateTime: '', colSpan: 0, children: [], attributes: new Map(),
        append(...children) { this.children.push(...children); },
        replaceChildren(...children) { this.children = children; },
        setAttribute(name, value) { this.attributes.set(name, String(value)); },
        removeAttribute(name) { this.attributes.delete(name); }, addEventListener() {}};
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
    const first = vm.runInContext('refresh(true)', context);
    await new Promise(resolve => setImmediate(resolve));
    await vm.runInContext('refresh(false)', context);
    if (calls.length !== 2) throw new Error(`overlap: ${JSON.stringify(calls)}`);
    finishEvents(); await first;
    if (!nodes.get('events').children[0].children[0].textContent.includes('unavailable')) throw new Error('first failure left the loading row');
    if (nodes.get('triage-controls').disabled) throw new Error('first failure left retry controls disabled');
    if (nodes.get('triage-panel').attributes.get('aria-busy') !== 'false') throw new Error('first failure left the triage panel busy');
    if (nodes.get('refresh-announcement').textContent !== 'Dashboard refresh failed. No prior dashboard data is available.') {
      throw new Error('first failure falsely claimed existing rows were preserved');
    }
    process.stdout.write('no-overlap\n');
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


def test_dashboard_trust_status_distinguishes_api_freshness_pause_and_stale_data():
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
    const nodes = new Map(), textWrites = new Map();
    function fakeNode(id = '') {
      let text = '';
      return {id, value: id === 'filter-severity' ? 'ALL' : '',
        get textContent() { return text; },
        set textContent(value) { text = value; textWrites.set(id, (textWrites.get(id) || 0) + 1); },
        className: '', disabled: false, hidden: false, dateTime: '', colSpan: 0,
        append() {}, replaceChildren() {}, setAttribute() {}, removeAttribute() {}, addEventListener() {}};
    }
    const document = {hidden: false,
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, fakeNode(id)); return nodes.get(id); },
      createElement(tag) { return fakeNode(tag); }, addEventListener() {}};
    class FakeAbortController { constructor() { this.signal = {}; } abort() {} }
    let failRequests = false, eventTime = '2026-09-10T00:00:00Z', eventRule = 'TEST_RULE';
    const response = value => ({ok: true, json: async () => value});
    function fetch(path) {
      if (failRequests) return Promise.reject(new Error('synthetic refresh failure'));
      if (path === '/api/summary') {
        return Promise.resolve(response({events: 3, detections: 1, high_or_critical: 1, actions: 2}));
      }
      if (path === '/api/events?limit=25') {
        return Promise.resolve(response([{detected_at: eventTime, rule_id: eventRule,
          severity: 'HIGH', src_ip: '192.0.2.10', message: 'Synthetic status test'}]));
      }
      return Promise.reject(new Error(`unexpected path: ${path}`));
    }
    const context = {document, fetch, AbortController: FakeAbortController,
      Intl, Date, Number, String, Math, Set,
      Promise, Error, Array, window: {setTimeout() { return 1; }, clearTimeout() {}}};
    vm.createContext(context); vm.runInContext(code, context);
    vm.runInContext("applyConfig({schema: 'dashboard-config-v1', read_only: true, event_limit: 25, refresh_seconds: 7})", context);
    if (nodes.get('scope-status').textContent !== 'Newest 25 detections maximum') throw new Error('bounded scope is unclear');

    vm.runInContext('togglePause()', context);
    const pausedBeforeSuccess = nodes.get('snapshot-status').textContent;
    if (!pausedBeforeSuccess.includes('No successful dashboard data fetch is available')) throw new Error(`early pause overclaims freshness: ${pausedBeforeSuccess}`);
    if (nodes.get('connection').textContent !== 'Dashboard API · refresh paused before first snapshot') throw new Error('early pause overclaims API reachability');
    vm.runInContext('state.paused = false', context);

    await vm.runInContext('refresh(false)', context);
    const current = nodes.get('snapshot-status').textContent;
    if (!current.includes('Dashboard data fetched successfully')) throw new Error(`missing successful-fetch state: ${current}`);
    if (!current.includes('does not measure capture or ingestion health')) throw new Error(`health overclaim: ${current}`);
    if (nodes.get('connection').textContent !== 'Dashboard API · reachable') throw new Error('API state is unclear');
    if (nodes.get('trust-strip').className !== 'trust-strip current') throw new Error('current state class is missing');
    const currentStatusWrites = textWrites.get('snapshot-status');
    await vm.runInContext('refresh(false)', context);
    if (textWrites.get('snapshot-status') !== currentStatusWrites) throw new Error('routine refresh rewrote the live status region');
    vm.runInContext("state.activeBin = 0; byId('filter-rule').value = 'TEST_RULE'", context);
    eventTime = '2026-09-10T01:00:00Z';
    eventRule = 'NEW_RULE';
    await vm.runInContext('refresh(false)', context);
    if (vm.runInContext('state.activeBin', context) !== null) throw new Error('changed rows silently reinterpreted the time filter');
    if (!nodes.get('timeline-status').textContent.includes('prior time filter was cleared')) throw new Error('time-filter reset was not disclosed');
    if (nodes.get('filter-rule').value !== 'TEST_RULE') throw new Error('changed rows silently broadened an absent rule filter');
    if (!nodes.get('filter-status').textContent.startsWith('0 of 1')) throw new Error('absent rule filter did not remain visibly narrow');

    vm.runInContext('togglePause()', context);
    const paused = nodes.get('snapshot-status').textContent;
    if (!paused.includes('Automatic refresh paused.')) throw new Error(`pause is unclear: ${paused}`);
    if (nodes.get('connection').textContent !== 'Dashboard API · reachable, refresh paused') throw new Error('paused API state is unclear');
    if (nodes.get('trust-strip').className !== 'trust-strip paused') throw new Error('paused state class is missing');

    vm.runInContext('togglePause()', context);
    if (nodes.get('connection').textContent !== 'Dashboard API · checking') throw new Error('resume does not expose the pending API check');
    if (nodes.get('trust-strip').className !== 'trust-strip checking') throw new Error('resume briefly overclaims preserved data as current');
    if (!nodes.get('snapshot-status').textContent.includes('not treated as current until a refresh succeeds')) throw new Error('resume does not bound preserved data freshness');
    await new Promise(resolve => setImmediate(resolve));
    if (nodes.get('trust-strip').className !== 'trust-strip current') throw new Error('successful resumed refresh did not restore current state');
    vm.runInContext('togglePause()', context);

    vm.runInContext(`
      byId('filter-query').value = 'status';
      byId('filter-severity').value = 'PRIORITY';
      byId('filter-rule').value = 'TEST_RULE';
      state.activeBin = 0;
    `, context);
    const preservedDateTime = nodes.get('updated').dateTime;

    failRequests = true;
    await vm.runInContext('refresh(false)', context);
    const pausedFailure = nodes.get('snapshot-status').textContent;
    if (!pausedFailure.includes('Automatic refresh remains paused.')) throw new Error(`paused failure is unclear: ${pausedFailure}`);
    if (nodes.get('connection').textContent !== 'Dashboard API · unavailable, refresh paused') throw new Error('paused failure API state is unclear');

    vm.runInContext('togglePause()', context);
    if (nodes.get('trust-strip').className !== 'trust-strip checking') throw new Error('resume does not expose the pending stale-data recheck');
    if (!nodes.get('snapshot-status').textContent.includes('remains stale until a refresh succeeds')) throw new Error('resume loses the preserved stale-data boundary');
    await new Promise(resolve => setImmediate(resolve));
    const stale = nodes.get('snapshot-status').textContent;
    if (!stale.includes('Showing preserved stale dashboard data')) throw new Error(`stale state is unclear: ${stale}`);
    if (!nodes.get('updated').textContent.startsWith('Stale · last success')) throw new Error('stale timestamp is unclear');
    if (nodes.get('connection').textContent !== 'Dashboard API · unavailable') throw new Error('failed API state is unclear');
    if (nodes.get('trust-strip').className !== 'trust-strip stale') throw new Error('stale state class is missing');
    if (vm.runInContext('state.events.length', context) !== 1) throw new Error('existing rows were not preserved');
    if (nodes.get('filter-query').value !== 'status' || nodes.get('filter-severity').value !== 'PRIORITY' || nodes.get('filter-rule').value !== 'TEST_RULE') {
      throw new Error('failed refresh did not preserve triage filters');
    }
    if (vm.runInContext('state.activeBin', context) !== 0) throw new Error('failed refresh did not preserve the time filter');
    if (vm.runInContext('state.lastPriorityTotal', context) !== 1) throw new Error('failed refresh advanced the priority baseline');
    if (nodes.get('updated').dateTime !== preservedDateTime) throw new Error('failed refresh replaced the last-success timestamp');
    const staleStatusWrites = textWrites.get('snapshot-status');
    await vm.runInContext('refresh(false)', context);
    if (textWrites.get('snapshot-status') !== staleStatusWrites) throw new Error('repeated outage rewrote the live status region');

    vm.runInContext('togglePause()', context);
    if (nodes.get('connection').textContent !== 'Dashboard API · unavailable, refresh paused') throw new Error('pause after failure overclaims API reachability');
    if (nodes.get('trust-strip').className !== 'trust-strip stale') throw new Error('pause after failure hides stale state');
    if (!nodes.get('snapshot-status').textContent.includes('Automatic refresh remains paused.')) throw new Error('pause after failure loses pause context');
    vm.runInContext('state.paused = false', context);

    vm.runInContext('state.lastSuccessfulRefresh = null', context);
    await vm.runInContext('refresh(false)', context);
    const emptyFailure = nodes.get('snapshot-status').textContent;
    if (!emptyFailure.includes('No successful dashboard data fetch is available')) throw new Error(`no-success state is unclear: ${emptyFailure}`);
    process.stdout.write('truthful-trust-states\n');
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
    assert result.stdout == "truthful-trust-states\n"


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
