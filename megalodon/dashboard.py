"""Local read-only dashboard. It exposes telemetry, never control actions."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any
from urllib.parse import parse_qs, urlparse

from .storage import Store


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>MEGALODON · Local telemetry</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --bg: #061017; --surface: rgba(13, 31, 42, .88); --line: rgba(148, 188, 202, .18);
      --text: #e8f4f5; --muted: #99b2ba; --aqua: #51e6cf; --cyan: #6ed8ff;
      --amber: #ffd166; --orange: #ff9f68; --rose: #ff758f; --radius: 18px;
      --shadow: 0 24px 70px rgba(0, 0, 0, .28);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-width: 300px; min-height: 100vh; color: var(--text);
      background: radial-gradient(circle at 12% -8%, rgba(32, 151, 166, .22), transparent 34rem),
                  radial-gradient(circle at 92% 8%, rgba(48, 103, 161, .18), transparent 30rem), var(--bg);
    }
    body::before {
      position: fixed; inset: 0; pointer-events: none; content: ""; opacity: .16;
      background-image: linear-gradient(rgba(132, 196, 207, .12) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(132, 196, 207, .12) 1px, transparent 1px);
      background-size: 42px 42px; mask-image: linear-gradient(to bottom, black, transparent 72%);
    }
    :focus-visible { outline: 3px solid var(--cyan); outline-offset: 3px; }
    .shell { width: min(1240px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 48px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 34px; }
    .brand { display: flex; align-items: center; gap: 13px; }
    .mark {
      display: grid; width: 46px; height: 46px; place-items: center; color: var(--aqua);
      border: 1px solid rgba(81, 230, 207, .42); border-radius: 15px;
      background: linear-gradient(145deg, rgba(81, 230, 207, .2), rgba(110, 216, 255, .05));
      box-shadow: inset 0 1px rgba(255, 255, 255, .1), 0 10px 28px rgba(25, 164, 157, .12);
      font-weight: 900; letter-spacing: -.08em;
    }
    .brand-name { margin: 0; font-size: 1.05rem; letter-spacing: .13em; }
    .brand-subtitle { margin: 3px 0 0; color: var(--muted); font-size: .78rem; }
    .connection {
      display: inline-flex; align-items: center; gap: 8px; min-height: 36px; padding: 7px 12px;
      border: 1px solid var(--line); border-radius: 999px; background: rgba(4, 14, 20, .56);
      color: var(--muted); font-size: .78rem; font-weight: 700;
    }
    .connection::before { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); content: ""; }
    .connection.ok::before { background: var(--aqua); box-shadow: 0 0 0 5px rgba(81, 230, 207, .1); }
    .connection.error::before { background: var(--rose); box-shadow: 0 0 0 5px rgba(255, 117, 143, .1); }
    .hero { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: 24px; margin-bottom: 24px; }
    .eyebrow { margin: 0 0 9px; color: var(--aqua); font-size: .75rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
    h1 { max-width: 760px; margin: 0; font-size: clamp(2rem, 5vw, 4.25rem); line-height: .98; letter-spacing: -.055em; }
    .lede { max-width: 720px; margin: 16px 0 0; color: var(--muted); font-size: clamp(.95rem, 1.7vw, 1.08rem); line-height: 1.65; }
    .read-only {
      align-self: start; padding: 12px 15px; border: 1px solid rgba(81, 230, 207, .25);
      border-radius: 14px; background: rgba(81, 230, 207, .07); color: #b7fff2;
      font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
    }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 28px 0; }
    .metric, .panel {
      border: 1px solid var(--line); background: linear-gradient(145deg, rgba(18, 45, 59, .92), rgba(8, 24, 33, .9));
      box-shadow: var(--shadow);
    }
    .metric { min-height: 128px; padding: 18px; border-radius: var(--radius); }
    .metric-label { color: var(--muted); font-size: .75rem; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
    .metric-value { margin-top: 18px; font-size: clamp(1.8rem, 4vw, 2.65rem); font-variant-numeric: tabular-nums; font-weight: 800; letter-spacing: -.04em; }
    .metric-note { margin-top: 5px; color: var(--muted); font-size: .76rem; }
    .panel { overflow: hidden; border-radius: var(--radius); }
    .panel + .panel { margin-top: 18px; }
    .panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 22px; border-bottom: 1px solid var(--line); }
    .panel-head h2 { margin: 0; font-size: 1rem; letter-spacing: -.01em; }
    .panel-head p { margin: 6px 0 0; color: var(--muted); font-size: .82rem; line-height: 1.5; }
    .timestamp { color: var(--muted); font-size: .75rem; white-space: nowrap; }
    .table-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
    th, td { padding: 13px 16px; border-bottom: 1px solid rgba(148, 188, 202, .12); text-align: left; font-size: .82rem; vertical-align: top; }
    th { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
    tbody tr:last-child td { border-bottom: 0; }
    tbody tr:hover { background: rgba(110, 216, 255, .035); }
    .empty { padding: 34px 20px; color: var(--muted); text-align: center; }
    .severity { display: inline-flex; padding: 4px 8px; border: 1px solid currentColor; border-radius: 999px; font-size: .68rem; font-weight: 850; letter-spacing: .04em; }
    .CRITICAL { color: var(--rose); } .HIGH { color: var(--orange); } .MEDIUM { color: var(--amber); } .LOW { color: var(--cyan); }
    .offline-grid { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(280px, .9fr); }
    .offline-main, .offline-side { padding: 22px; }
    .offline-side { border-left: 1px solid var(--line); background: rgba(4, 15, 21, .32); }
    .run-id { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .72rem; word-break: break-all; }
    .facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 18px; }
    .fact { padding: 12px; border: 1px solid var(--line); border-radius: 13px; background: rgba(5, 18, 25, .48); }
    .fact b { display: block; margin-top: 5px; font-size: .92rem; word-break: break-word; }
    .fact span { color: var(--muted); font-size: .68rem; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
    .subhead { margin: 24px 0 11px; font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .bars { display: grid; gap: 10px; }
    .bar-row { display: grid; grid-template-columns: 58px minmax(80px, 1fr) auto; align-items: center; gap: 10px; font-size: .78rem; }
    .bar-track { height: 8px; overflow: hidden; border-radius: 999px; background: rgba(148, 188, 202, .12); }
    .bar-fill { height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--aqua), var(--cyan)); }
    .chips { display: flex; flex-wrap: wrap; gap: 7px; }
    .chip { padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; background: rgba(110, 216, 255, .05); color: #c9e9f0; font: 700 .72rem ui-monospace, SFMono-Regular, Menlo, monospace; }
    .candidate-list, .limitations { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
    .candidate-list li { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 11px 12px; border: 1px solid rgba(255, 209, 102, .2); border-radius: 12px; background: rgba(255, 209, 102, .045); font-size: .76rem; }
    .candidate-list b { color: var(--amber); font-variant-numeric: tabular-nums; }
    .limitations li { position: relative; padding-left: 17px; color: var(--muted); font-size: .76rem; line-height: 1.5; }
    .limitations li::before { position: absolute; top: .53em; left: 0; width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); content: ""; }
    .offline-empty { padding: 28px 22px; color: var(--muted); font-size: .86rem; line-height: 1.65; }
    code { padding: 2px 5px; border: 1px solid var(--line); border-radius: 6px; background: rgba(0, 0, 0, .2); color: #c8f7ef; font-size: .85em; }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    [hidden] { display: none !important; }
    @media (max-width: 820px) {
      .hero { grid-template-columns: 1fr; } .read-only { justify-self: start; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .offline-grid { grid-template-columns: 1fr; }
      .offline-side { border-top: 1px solid var(--line); border-left: 0; }
    }
    @media (max-width: 520px) {
      .shell { width: min(100% - 20px, 1240px); padding-top: 18px; }
      .topbar { align-items: flex-start; } .brand-subtitle { display: none; } .connection { max-width: 126px; }
      .metrics { grid-template-columns: 1fr 1fr; } .metric { min-height: 108px; padding: 14px; }
      .panel-head { display: block; } .timestamp { display: block; margin-top: 7px; }
      th, td { padding: 11px 12px; } .facts { grid-template-columns: 1fr; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
  </style>
</head>
<body>
<main class="shell">
  <header class="topbar">
    <div class="brand" aria-label="MEGALODON">
      <div class="mark" aria-hidden="true">M</div>
      <div><p class="brand-name">MEGALODON</p><p class="brand-subtitle">Local defense telemetry</p></div>
    </div>
    <div class="connection" id="connection" role="status" aria-live="polite">Connecting</div>
  </header>

  <section class="hero" aria-labelledby="page-title">
    <div>
      <p class="eyebrow">Operational overview</p>
      <h1 id="page-title">Signal without surrendering control.</h1>
      <p class="lede">Review local metadata detections and one explicitly selected offline analysis snapshot. This surface cannot start analysis or apply a response.</p>
    </div>
    <div class="read-only">Read only · local first</div>
  </section>

  <section class="metrics" id="live-metrics" aria-label="Live telemetry summary">
    <article class="metric"><div class="metric-label">Events</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Detections</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">High / critical</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Actions</div><div class="metric-value">—</div></article>
  </section>

  <section class="panel" aria-labelledby="detections-title">
    <div class="panel-head">
      <div><h2 id="detections-title">Recent detections</h2><p>Newest fixed-rule findings from the local SQLite audit store.</p></div>
      <time class="timestamp" id="updated">Awaiting first refresh</time>
    </div>
    <div class="table-scroll">
      <table>
        <caption>Recent MEGALODON detections</caption>
        <thead><tr><th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Source</th><th scope="col">Message</th></tr></thead>
        <tbody id="events"><tr><td class="empty" colspan="5">Loading local detections…</td></tr></tbody>
      </table>
    </div>
  </section>

  <section class="panel" aria-labelledby="offline-title">
    <div class="panel-head">
      <div><h2 id="offline-title">Offline analysis snapshot</h2><p>Validated, source-qualified, privacy-bounded summary loaded once at dashboard startup.</p></div>
      <span class="timestamp" id="offline-status">Checking</span>
    </div>
    <div class="offline-empty" id="offline-empty" hidden>
      No offline run is selected. Restart with <code>megalodon dashboard --offline-run /absolute/private/run</code> to view one completed report snapshot.
    </div>
    <div class="offline-grid" id="offline-content" hidden>
      <div class="offline-main">
        <p class="eyebrow" id="offline-case">Offline run</p>
        <div class="run-id" id="offline-run-id"></div>
        <div class="facts" id="offline-facts"></div>
        <h3 class="subhead">Protocol distribution</h3><div class="bars" id="protocols"></div>
        <h3 class="subhead">Top destination ports</h3><div class="chips" id="ports"></div>
      </div>
      <aside class="offline-side" aria-label="Offline review context">
        <h3 class="subhead">Review candidates</h3><ul class="candidate-list" id="candidates"></ul>
        <h3 class="subhead">Interpretation limits</h3><ul class="limitations" id="limitations"></ul>
      </aside>
    </div>
  </section>
  <p class="sr-only" id="refresh-announcement" aria-live="polite"></p>
  <noscript><p class="offline-empty">JavaScript is required to render this local dashboard.</p></noscript>
</main>
<script>
const metricSpec = [
  ['events', 'Events', 'Validated metadata records'],
  ['detections', 'Detections', 'Fixed-rule findings'],
  ['high_or_critical', 'High / critical', 'Priority review items'],
  ['actions', 'Actions', 'Planned or explicit records']
];

function textNode(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value);
  return node;
}
function formatNumber(value) { return new Intl.NumberFormat().format(Number(value)); }
function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
}
async function requestJSON(path) {
  const response = await fetch(path, {headers: {'Accept': 'application/json'}, cache: 'no-store'});
  if (!response.ok) throw new Error('request failed');
  return response.json();
}

function renderMetrics(summary) {
  const cards = metricSpec.map(([key, label, note]) => {
    const card = document.createElement('article'); card.className = 'metric';
    card.append(textNode('div', label, 'metric-label'), textNode('div', formatNumber(summary[key]), 'metric-value'), textNode('div', note, 'metric-note'));
    return card;
  });
  document.getElementById('live-metrics').replaceChildren(...cards);
}
function renderEvents(events) {
  const body = document.getElementById('events');
  if (!events.length) {
    const row = document.createElement('tr'); const cell = textNode('td', 'No detections recorded.', 'empty');
    cell.colSpan = 5; row.append(cell); body.replaceChildren(row); return;
  }
  const rows = events.map(event => {
    const row = document.createElement('tr'); row.append(textNode('td', formatTime(event.detected_at)));
    const severityCell = document.createElement('td');
    severityCell.append(textNode('span', event.severity || 'UNKNOWN', `severity ${event.severity || ''}`));
    row.append(severityCell, textNode('td', event.rule_id || ''), textNode('td', event.src_ip || ''), textNode('td', event.message || ''));
    return row;
  });
  body.replaceChildren(...rows);
}
function fact(label, value) {
  const item = document.createElement('div'); item.className = 'fact';
  item.append(textNode('span', label), textNode('b', value)); return item;
}
function renderOffline(payload) {
  const empty = document.getElementById('offline-empty');
  const content = document.getElementById('offline-content');
  const status = document.getElementById('offline-status');
  if (!payload.available) { empty.hidden = false; content.hidden = true; status.textContent = 'Not selected'; return; }
  const data = payload.snapshot, run = data.run, summary = data.summary;
  empty.hidden = true; content.hidden = false; status.textContent = 'Validated summary snapshot';
  document.getElementById('offline-case').textContent = `${run.case_id} · ${run.record_kind} summary`;
  document.getElementById('offline-run-id').textContent = `Run ${run.run_id}`;
  document.getElementById('offline-facts').replaceChildren(
    fact('Accepted records', formatNumber(run.accepted_records)), fact('Review candidates', formatNumber(run.candidate_count)),
    fact('Source adapter', run.adapter), fact('Tool provenance', `${run.source} ${run.tool_version}`),
    fact('Relative window', `${formatNumber(summary.relative_window_minutes)} min`), fact('Metadata volume', `${formatNumber(summary.total_bytes)} bytes`)
  );
  const denominator = Math.max(summary.record_count, 1);
  const bars = summary.protocols.map(item => {
    const row = document.createElement('div'); row.className = 'bar-row';
    const track = document.createElement('div'); track.className = 'bar-track';
    const fill = document.createElement('div'); fill.className = 'bar-fill';
    fill.style.width = `${Math.max(2, item.count / denominator * 100)}%`;
    track.append(fill); row.append(textNode('span', item.protocol), track, textNode('b', formatNumber(item.count))); return row;
  });
  document.getElementById('protocols').replaceChildren(...(bars.length ? bars : [textNode('p', 'No accepted records.', 'offline-empty')]));
  const ports = summary.destination_ports.map(item => textNode('span', `${item.protocol}/${item.port} · ${item.count}`, 'chip'));
  if (summary.destination_ports_truncated) ports.push(textNode('span', `+${summary.destination_ports_total - summary.destination_ports.length} more`, 'chip'));
  document.getElementById('ports').replaceChildren(...(ports.length ? ports : [textNode('span', 'No TCP/UDP destination ports', 'chip')]));
  const candidates = data.candidates.map(item => {
    const entry = document.createElement('li');
    entry.append(textNode('span', item.rule.replaceAll('_', ' ')), textNode('b', formatNumber(item.count))); return entry;
  });
  if (!candidates.length) candidates.push(textNode('li', 'No review candidates in this run.'));
  document.getElementById('candidates').replaceChildren(...candidates);
  document.getElementById('limitations').replaceChildren(...data.limitations.map(value => textNode('li', value)));
}

let refreshing = false;
async function refresh() {
  if (refreshing) return; refreshing = true;
  const connection = document.getElementById('connection');
  try {
    const [summary, events, offline] = await Promise.all([
      requestJSON('/api/summary'), requestJSON('/api/events?limit=50'), requestJSON('/api/offline-summary')
    ]);
    renderMetrics(summary); renderEvents(events); renderOffline(offline);
    const now = new Date(); document.getElementById('updated').textContent = `Updated ${now.toLocaleTimeString()}`;
    document.getElementById('refresh-announcement').textContent = 'Dashboard data refreshed.';
    connection.textContent = 'Local data connected'; connection.className = 'connection ok';
  } catch (_) {
    connection.textContent = 'Refresh unavailable'; connection.className = 'connection error';
    document.getElementById('refresh-announcement').textContent = 'Dashboard refresh failed.';
  } finally { refreshing = false; }
}
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 3000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    store: Store
    offline_summary: dict[str, Any] | None = None

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path)
        if route.path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            return
        if route.path == "/api/summary":
            self._send_json(self.store.summary())
            return
        if route.path == "/api/events":
            values = parse_qs(route.query).get("limit", ["50"])
            try:
                limit = int(values[0])
            except (ValueError, TypeError):
                limit = 50
            self._send_json(self.store.recent(limit))
            return
        if route.path == "/api/offline-summary":
            self._send_json({"available": False} if self.offline_summary is None else {"available": True, "snapshot": self.offline_summary})
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def _send_json(self, value: object) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self._send(200, "application/json; charset=utf-8", payload)

    def _send(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "
            "img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


def serve(
    store: Store,
    host: str,
    port: int,
    *,
    enabled: bool = True,
    allow_remote: bool = False,
    offline_summary: dict[str, Any] | None = None,
) -> None:
    if not enabled:
        raise ValueError("dashboard is disabled by configuration")
    loopback = host in {"127.0.0.1", "::1", "localhost"}
    if not loopback and not allow_remote:
        raise ValueError("dashboard must bind to localhost unless --allow-remote is explicit")
    if not loopback and offline_summary is not None:
        raise ValueError("offline summaries require a loopback dashboard bind")
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"store": store, "offline_summary": offline_summary})
    server = ThreadingHTTPServer((host, port), handler)
    try:
        print(f"MEGALODON dashboard listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
