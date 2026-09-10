"""Local read-only dashboard. It exposes telemetry, never control actions."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import AddressValueError, IPv4Address
import json
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse

from .storage import StorageSchemaError


MIN_REFRESH_SECONDS = 2
MAX_REFRESH_SECONDS = 300
MAX_EVENT_LIMIT = 200
DASHBOARD_EVENT_FIELDS = ("detected_at", "rule_id", "severity", "src_ip", "message")


class DashboardReader(Protocol):
    def summary(self) -> dict[str, Any]: ...

    def recent(self, limit: int = 50) -> list[dict[str, Any]]: ...


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>MEGALODON · Local telemetry</title>
  <link rel="stylesheet" href="/assets/dashboard.css">
  <script src="/assets/dashboard.js" defer></script>
</head>
<body>
<a class="skip-link" href="#detections-title">Skip to detections</a>
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
    <div class="toolbar" aria-label="Detection view controls">
      <label class="field field-search" for="filter-query">
        <span>Search detections</span>
        <input id="filter-query" type="search" maxlength="160" autocomplete="off" placeholder="Rule, source, or message">
      </label>
      <label class="field" for="filter-severity">
        <span>Severity</span>
        <select id="filter-severity">
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </label>
      <div class="toolbar-actions">
        <button id="refresh-button" type="button">Refresh now</button>
        <button id="pause-button" type="button" class="button-secondary" aria-pressed="false">Pause refresh</button>
      </div>
      <p class="filter-status" id="filter-status" role="status" aria-live="polite">Waiting for recent detections.</p>
    </div>
    <div class="table-scroll">
      <table aria-describedby="filter-status">
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
</body>
</html>"""


DASHBOARD_CSS = """
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
.skip-link { position: fixed; z-index: 10; top: 10px; left: 10px; padding: 9px 12px; transform: translateY(-160%); border-radius: 9px; background: var(--text); color: var(--bg); font-weight: 800; }
.skip-link:focus { transform: translateY(0); }
.shell { position: relative; width: min(1240px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 48px; }
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
.toolbar { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(150px, .4fr) auto; align-items: end; gap: 12px; padding: 16px 22px; border-bottom: 1px solid var(--line); background: rgba(4, 15, 21, .26); }
.field { display: grid; gap: 7px; }
.field span { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
input, select, button { min-height: 42px; border: 1px solid var(--line); border-radius: 11px; font: inherit; }
input, select { width: 100%; padding: 9px 11px; background: rgba(3, 13, 19, .68); color: var(--text); }
input::placeholder { color: #6f8c95; }
button { padding: 9px 13px; border-color: rgba(81, 230, 207, .34); background: rgba(81, 230, 207, .13); color: #c8fff7; font-size: .78rem; font-weight: 800; cursor: pointer; }
button:hover:not(:disabled) { background: rgba(81, 230, 207, .2); }
button:disabled { opacity: .55; cursor: wait; }
.button-secondary { border-color: var(--line); background: rgba(110, 216, 255, .05); color: #c9e9f0; }
.button-secondary[aria-pressed="true"] { border-color: rgba(255, 209, 102, .4); background: rgba(255, 209, 102, .09); color: var(--amber); }
.toolbar-actions { display: flex; gap: 8px; }
.filter-status { grid-column: 1 / -1; margin: 0; color: var(--muted); font-size: .75rem; }
.table-scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
th, td { padding: 13px 16px; border-bottom: 1px solid rgba(148, 188, 202, .12); text-align: left; font-size: .82rem; vertical-align: top; }
th { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(110, 216, 255, .035); }
.empty { padding: 34px 20px; color: var(--muted); text-align: center; }
.severity { display: inline-flex; padding: 4px 8px; border: 1px solid currentColor; border-radius: 999px; font-size: .68rem; font-weight: 850; letter-spacing: .04em; }
.CRITICAL { color: var(--rose); } .HIGH { color: var(--orange); } .MEDIUM { color: var(--amber); } .LOW { color: var(--cyan); } .UNKNOWN { color: var(--muted); }
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
progress { width: 100%; height: 8px; overflow: hidden; border: 0; border-radius: 999px; background: rgba(148, 188, 202, .12); }
progress::-webkit-progress-bar { border-radius: 999px; background: rgba(148, 188, 202, .12); }
progress::-webkit-progress-value { border-radius: 999px; background: linear-gradient(90deg, var(--aqua), var(--cyan)); }
progress::-moz-progress-bar { border-radius: 999px; background: linear-gradient(90deg, var(--aqua), var(--cyan)); }
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
@media (max-width: 880px) {
  .hero { grid-template-columns: 1fr; } .read-only { justify-self: start; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .toolbar { grid-template-columns: minmax(0, 1fr) minmax(150px, .45fr); }
  .toolbar-actions { grid-column: 1 / -1; }
  .offline-grid { grid-template-columns: 1fr; }
  .offline-side { border-top: 1px solid var(--line); border-left: 0; }
}
@media (max-width: 560px) {
  .shell { width: min(100% - 20px, 1240px); padding-top: 18px; }
  .topbar { align-items: flex-start; } .brand-subtitle { display: none; } .connection { max-width: 145px; }
  .metrics { grid-template-columns: 1fr 1fr; } .metric { min-height: 108px; padding: 14px; }
  .panel-head { display: block; } .timestamp { display: block; margin-top: 7px; }
  .toolbar { grid-template-columns: 1fr; padding: 14px; }
  .toolbar-actions, .filter-status { grid-column: 1; }
  .toolbar-actions { display: grid; grid-template-columns: 1fr 1fr; }
  th, td { padding: 11px 12px; } .facts { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
"""


DASHBOARD_JS = r"""
'use strict';

const metricSpec = [
  ['events', 'Events', 'Validated metadata records'],
  ['detections', 'Detections', 'Fixed-rule findings'],
  ['high_or_critical', 'High / critical', 'Priority review items'],
  ['actions', 'Actions', 'Planned or explicit records']
];
const knownSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const state = {
  events: [],
  paused: false,
  refreshing: false,
  timer: null,
  config: {event_limit: 50, refresh_seconds: 5}
};

function byId(value) { return document.getElementById(value); }
function textNode(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value);
  return node;
}
function formatNumber(value) { return new Intl.NumberFormat().format(Number(value)); }
function timeNode(value) {
  const parsed = new Date(value);
  const node = textNode('time', Number.isNaN(parsed.valueOf()) ? String(value) : parsed.toLocaleString());
  if (!Number.isNaN(parsed.valueOf())) node.dateTime = parsed.toISOString();
  return node;
}
function severityPresentation(value) {
  const normalized = String(value || '').toUpperCase();
  return knownSeverities.has(normalized) ? normalized : 'UNKNOWN';
}
async function requestJSON(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(path, {headers: {'Accept': 'application/json'}, cache: 'no-store', signal: controller.signal});
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    return await response.json();
  } finally {
    window.clearTimeout(timeout);
  }
}

function renderMetrics(summary) {
  const cards = metricSpec.map(([key, label, note]) => {
    const card = document.createElement('article'); card.className = 'metric';
    card.append(textNode('div', label, 'metric-label'), textNode('div', formatNumber(summary[key]), 'metric-value'), textNode('div', note, 'metric-note'));
    return card;
  });
  byId('live-metrics').replaceChildren(...cards);
}
function filteredEvents() {
  const severity = byId('filter-severity').value;
  const query = byId('filter-query').value.trim().toLocaleLowerCase();
  return state.events.filter(event => {
    if (severity !== 'ALL' && event.severity !== severity) return false;
    if (!query) return true;
    return [event.detected_at, event.severity, event.rule_id, event.src_ip, event.message]
      .some(value => String(value || '').toLocaleLowerCase().includes(query));
  });
}
function renderEvents(events) {
  const body = byId('events');
  if (!events.length) {
    const filtered = state.events.length && (byId('filter-query').value.trim() || byId('filter-severity').value !== 'ALL');
    const row = document.createElement('tr');
    const cell = textNode('td', filtered ? 'No detections match these filters.' : 'No detections recorded.', 'empty');
    cell.colSpan = 5; row.append(cell); body.replaceChildren(row); return;
  }
  const rows = events.map(event => {
    const row = document.createElement('tr');
    const timeCell = document.createElement('td');
    timeCell.append(timeNode(event.detected_at));
    const severityCell = document.createElement('td');
    const severity = severityPresentation(event.severity);
    severityCell.append(textNode('span', severity, `severity ${severity}`));
    row.append(timeCell, severityCell, textNode('td', event.rule_id || ''), textNode('td', event.src_ip || ''), textNode('td', event.message || ''));
    return row;
  });
  body.replaceChildren(...rows);
}
function applyFilters() {
  const visible = filteredEvents();
  renderEvents(visible);
  const noun = state.events.length === 1 ? 'detection' : 'detections';
  byId('filter-status').textContent = `${formatNumber(visible.length)} of ${formatNumber(state.events.length)} recent ${noun} shown · newest ${formatNumber(state.config.event_limit)} maximum`;
}
function fact(label, value) {
  const item = document.createElement('div'); item.className = 'fact';
  item.append(textNode('span', label), textNode('b', value)); return item;
}
function renderOffline(payload) {
  const empty = byId('offline-empty');
  const content = byId('offline-content');
  const status = byId('offline-status');
  if (!payload.available) { empty.hidden = false; content.hidden = true; status.textContent = 'Not selected'; return; }
  const data = payload.snapshot, run = data.run, summary = data.summary;
  empty.hidden = true; content.hidden = false; status.textContent = 'Validated summary snapshot';
  byId('offline-case').textContent = `${run.case_id} · ${run.record_kind} summary`;
  byId('offline-run-id').textContent = `Run ${run.run_id}`;
  byId('offline-facts').replaceChildren(
    fact('Accepted records', formatNumber(run.accepted_records)), fact('Review candidates', formatNumber(run.candidate_count)),
    fact('Source adapter', run.adapter), fact('Tool provenance', `${run.source} ${run.tool_version}`),
    fact('Relative window', `${formatNumber(summary.relative_window_minutes)} min`), fact('Metadata volume', `${formatNumber(summary.total_bytes)} bytes`)
  );
  const denominator = Math.max(summary.record_count, 1);
  const bars = summary.protocols.map(item => {
    const row = document.createElement('div'); row.className = 'bar-row';
    const progress = document.createElement('progress'); progress.max = denominator; progress.value = item.count;
    progress.setAttribute('aria-label', `${item.protocol}: ${item.count} of ${summary.record_count} records`);
    row.append(textNode('span', item.protocol), progress, textNode('b', formatNumber(item.count))); return row;
  });
  byId('protocols').replaceChildren(...(bars.length ? bars : [textNode('p', 'No accepted records.', 'offline-empty')]));
  const ports = summary.destination_ports.map(item => textNode('span', `${item.protocol}/${item.port} · ${item.count}`, 'chip'));
  if (summary.destination_ports_truncated) ports.push(textNode('span', `+${summary.destination_ports_total - summary.destination_ports.length} more`, 'chip'));
  byId('ports').replaceChildren(...(ports.length ? ports : [textNode('span', 'No TCP/UDP destination ports', 'chip')]));
  const candidates = data.candidates.map(item => {
    const entry = document.createElement('li');
    entry.append(textNode('span', item.rule.replaceAll('_', ' ')), textNode('b', formatNumber(item.count))); return entry;
  });
  if (!candidates.length) candidates.push(textNode('li', 'No review candidates in this run.'));
  byId('candidates').replaceChildren(...candidates);
  byId('limitations').replaceChildren(...data.limitations.map(value => textNode('li', value)));
}
function renderOfflineError() {
  byId('offline-content').hidden = true;
  const empty = byId('offline-empty'); empty.hidden = false;
  empty.textContent = 'The configured offline summary could not be loaded. Live telemetry remains available.';
  byId('offline-status').textContent = 'Unavailable';
}
function setConnection(label, className) {
  const connection = byId('connection'); connection.textContent = label; connection.className = `connection ${className}`;
}
function setUpdatedTime(value) {
  const updated = byId('updated'); updated.textContent = `Updated ${value.toLocaleTimeString()}`; updated.dateTime = value.toISOString();
}
function scheduleNext() {
  if (state.timer !== null) window.clearTimeout(state.timer);
  state.timer = null;
  if (state.paused) return;
  state.timer = window.setTimeout(async () => {
    if (!document.hidden) await refresh(false);
    scheduleNext();
  }, state.config.refresh_seconds * 1000);
}
async function refresh(announce = true) {
  if (state.refreshing) return;
  state.refreshing = true;
  const button = byId('refresh-button'); button.disabled = true; button.textContent = 'Refreshing…';
  try {
    const [summaryResult, eventsResult] = await Promise.allSettled([
      requestJSON('/api/summary'), requestJSON(`/api/events?limit=${state.config.event_limit}`)
    ]);
    if (summaryResult.status !== 'fulfilled' || eventsResult.status !== 'fulfilled') {
      throw new Error('dashboard refresh failed');
    }
    const summary = summaryResult.value;
    const events = eventsResult.value;
    if (!Array.isArray(events)) throw new Error('invalid events response');
    state.events = events;
    renderMetrics(summary); applyFilters(); setUpdatedTime(new Date());
    setConnection(state.paused ? 'Auto-refresh paused' : `Local data · ${state.config.refresh_seconds}s`, 'ok');
    if (announce) byId('refresh-announcement').textContent = 'Dashboard data refreshed.';
  } catch (_) {
    setConnection('Refresh unavailable', 'error');
    byId('refresh-announcement').textContent = 'Dashboard refresh failed. Existing rows were preserved.';
  } finally {
    state.refreshing = false; button.disabled = false; button.textContent = 'Refresh now';
  }
}
function togglePause() {
  state.paused = !state.paused;
  const button = byId('pause-button'); button.setAttribute('aria-pressed', String(state.paused));
  button.textContent = state.paused ? 'Resume refresh' : 'Pause refresh';
  setConnection(state.paused ? 'Auto-refresh paused' : `Local data · ${state.config.refresh_seconds}s`, 'ok');
  byId('refresh-announcement').textContent = state.paused ? 'Automatic refresh paused.' : 'Automatic refresh resumed.';
  if (state.paused) scheduleNext();
  else { refresh(false); scheduleNext(); }
}
function applyConfig(payload) {
  if (payload.schema !== 'dashboard-config-v1' || payload.read_only !== true) throw new Error('invalid dashboard config');
  const eventLimit = Number(payload.event_limit), refreshSeconds = Number(payload.refresh_seconds);
  if (!Number.isInteger(eventLimit) || eventLimit < 1 || eventLimit > 200) throw new Error('invalid event limit');
  if (!Number.isInteger(refreshSeconds) || refreshSeconds < 2 || refreshSeconds > 300) throw new Error('invalid refresh interval');
  state.config = {event_limit: eventLimit, refresh_seconds: refreshSeconds};
}
async function bootstrap() {
  try { applyConfig(await requestJSON('/api/config')); }
  catch (_) { setConnection('Using safe refresh defaults', 'error'); }
  try { renderOffline(await requestJSON('/api/offline-summary')); }
  catch (_) { renderOfflineError(); }
  await refresh(false); scheduleNext();
}

byId('filter-query').addEventListener('input', applyFilters);
byId('filter-severity').addEventListener('change', applyFilters);
byId('refresh-button').addEventListener('click', () => refresh(true));
byId('pause-button').addEventListener('click', togglePause);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !state.paused) { refresh(false); scheduleNext(); }
});
bootstrap();
"""


class DashboardHandler(BaseHTTPRequestHandler):
    store: DashboardReader
    offline_summary: dict[str, Any] | None = None
    refresh_seconds: int = 5
    event_limit: int = 50

    def do_GET(self) -> None:  # noqa: N802
        if not self._has_expected_host():
            self._send_json({"error": "invalid request host"}, status=400)
            return
        route = urlparse(self.path)
        if route.path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
            return
        if route.path == "/assets/dashboard.css":
            self._send(200, "text/css; charset=utf-8", DASHBOARD_CSS.encode())
            return
        if route.path == "/assets/dashboard.js":
            self._send(200, "text/javascript; charset=utf-8", DASHBOARD_JS.encode())
            return
        if route.path == "/api/config":
            self._send_json(
                {
                    "schema": "dashboard-config-v1",
                    "read_only": True,
                    "refresh_seconds": self.refresh_seconds,
                    "event_limit": self.event_limit,
                    "offline_summary_available": self.offline_summary is not None,
                }
            )
            return
        if route.path == "/api/summary":
            try:
                summary = self.store.summary()
            except StorageSchemaError:
                self._send_json(
                    {"error": "telemetry unavailable"}, status=503
                )
                return
            self._send_json(summary)
            return
        if route.path == "/api/events":
            params = parse_qs(route.query, keep_blank_values=True)
            if set(params) - {"limit"}:
                self._send_json({"error": "unsupported query parameter"}, status=400)
                return
            values = params.get("limit")
            if values is None:
                limit = self.event_limit
            elif len(values) != 1 or not values[0].isascii() or not values[0].isdigit():
                self._send_json({"error": "limit must be one decimal integer"}, status=400)
                return
            else:
                limit = int(values[0])
            if not 1 <= limit <= MAX_EVENT_LIMIT:
                self._send_json({"error": f"limit must be between 1 and {MAX_EVENT_LIMIT}"}, status=400)
                return
            try:
                events = _dashboard_events(self.store, limit)
            except StorageSchemaError:
                self._send_json(
                    {"error": "telemetry unavailable"}, status=503
                )
                return
            self._send_json(events)
            return
        if route.path == "/api/offline-summary":
            self._send_json(
                {"available": False}
                if self.offline_summary is None
                else {"available": True, "snapshot": self.offline_summary}
            )
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def _has_expected_host(self) -> bool:
        """Reject DNS-rebound and ambiguous requests before routing or store access."""
        values = self.headers.get_all("Host", [])
        if len(values) != 1:
            return False
        supplied = values[0]
        if not isinstance(supplied, str) or not 1 <= len(supplied) <= 64:
            return False
        if supplied != supplied.strip():
            return False

        bound_host, bound_port = self.server.server_address[:2]
        expected = {str(bound_host), f"{bound_host}:{bound_port}"}
        if bound_host == "127.0.0.1":
            expected.update({"localhost", f"localhost:{bound_port}"})
        return supplied in expected

    def _send_json(self, value: object, *, status: int = 200) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self._send(status, "application/json; charset=utf-8", payload)

    def _send(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "img-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'none'; worker-src 'none'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        return


def _dashboard_events(store: DashboardReader, limit: int) -> list[dict[str, Any]]:
    """Project stored detections onto the dashboard's minimal read-only contract."""
    return [
        {field: detection[field] for field in DASHBOARD_EVENT_FIELDS}
        for detection in store.recent(limit)
    ]


def _bounded_dashboard_integer(value: int, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def loopback_host(host: str, *, allow_remote: bool = False) -> str:
    """Return a numeric IPv4 loopback bind; never resolve a hostname.

    The legacy override is a refusal, not a way to weaken this boundary.
    IPv6 is intentionally refused by this IPv4 HTTP server.
    """
    if allow_remote is not False:
        raise ValueError("dashboard requires loopback; --allow-remote is no longer supported")
    if not isinstance(host, str) or not 1 <= len(host) <= 15:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost")
    if host == "localhost":
        return "127.0.0.1"
    try:
        address = IPv4Address(host)
    except AddressValueError:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost") from None
    if not address.is_loopback:
        raise ValueError("dashboard requires a numeric IPv4 loopback address or localhost")
    return str(address)


def serve(
    store: DashboardReader,
    host: str,
    port: int,
    *,
    enabled: bool = True,
    allow_remote: bool = False,
    offline_summary: dict[str, Any] | None = None,
    refresh_seconds: int = 5,
    event_limit: int = 50,
) -> None:
    if not enabled:
        raise ValueError("dashboard is disabled by configuration")
    refresh_seconds = _bounded_dashboard_integer(
        refresh_seconds, "dashboard refresh_seconds", MIN_REFRESH_SECONDS, MAX_REFRESH_SECONDS
    )
    event_limit = _bounded_dashboard_integer(event_limit, "dashboard event_limit", 1, MAX_EVENT_LIMIT)
    host = loopback_host(host, allow_remote=allow_remote)
    handler = type(
        "BoundDashboardHandler",
        (DashboardHandler,),
        {
            "store": store,
            "offline_summary": offline_summary,
            "refresh_seconds": refresh_seconds,
            "event_limit": event_limit,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    try:
        print(f"MEGALODON dashboard listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
