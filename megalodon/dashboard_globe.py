"""Local, presentation-only activity globe for the qualified traffic projection."""

from .dashboard_globe_land import LAND_MASK_BASE64

GLOBE_HTML = """
<section class="activity-globe" id="activity-globe" aria-labelledby="activity-globe-title">
  <div class="activity-globe-head">
    <div><p class="eyebrow">Rolling hour · stored metadata</p><h3 id="activity-globe-title">Activity globe</h3>
      <p class="activity-globe-hour-status" id="activity-globe-hour-status" role="status">Loading the past hour…</p></div>
    <div class="activity-globe-head-state"><span class="activity-globe-state" id="activity-globe-state">Waiting for traffic</span>
      <time id="activity-globe-updated">Awaiting hour view</time></div>
  </div>
  <div class="activity-globe-body">
    <div class="activity-globe-stage" id="activity-globe-stage">
      <canvas id="activity-globe-canvas" width="420" height="420" aria-hidden="true"></canvas>
      <span class="activity-globe-ping" id="activity-globe-ping" hidden aria-hidden="true"></span>
      <span class="activity-globe-caption">Natural Earth land · 30° grid</span>
    </div>
    <div class="activity-globe-readout">
      <p class="activity-globe-lead" id="activity-globe-lead" role="status" aria-live="polite">Waiting for qualified stored traffic.</p>
      <p class="activity-globe-list-heading" id="activity-globe-list-heading">Recent source IPs</p>
      <ul class="activity-globe-list" id="activity-globe-list" aria-label="Recent source IP mapping status"></ul>
      <p class="activity-globe-source-status" id="activity-globe-source-status">Checking offline location source…</p>
      <p class="activity-globe-note">Markers reflect offline database or CSV locations, rounded to about 5°. IP location may be wrong; this does not establish a device, person, or origin.</p>
    </div>
  </div>
  <section class="activity-globe-timeline" aria-labelledby="activity-globe-timeline-title">
    <div class="activity-globe-timeline-head"><div><p class="eyebrow">Time sweep</p><h4 id="activity-globe-timeline-title">Past 60 minutes</h4></div>
      <output id="activity-globe-selected-time" for="activity-globe-minute">Waiting for the hour view</output></div>
    <div class="activity-globe-histogram" id="activity-globe-histogram" role="img" aria-label="Waiting for the past-hour activity summary"></div>
    <div class="activity-globe-rail"><label for="activity-globe-minute">Review a minute</label>
      <input id="activity-globe-minute" type="range" min="0" max="59" step="1" value="59" aria-describedby="activity-globe-selected-time activity-globe-coverage">
      <button type="button" id="activity-globe-live" aria-pressed="true">Live · latest stored</button></div>
    <div class="activity-globe-axis"><span>60 min ago</span><span>Now · UTC</span></div>
    <div class="activity-globe-timeline-bottom"><dl class="activity-globe-counts">
      <div><dt>Selected minute</dt><dd id="activity-globe-selected-count">—</dd></div>
      <div><dt>Peak minute</dt><dd id="activity-globe-peak-count">—</dd></div>
    </dl><p class="activity-globe-legend"><span class="quiet">Returned records</span><span class="review">Review signal</span><span class="high">High priority signal</span></p></div>
    <p class="activity-globe-coverage" id="activity-globe-coverage">One bounded history page: at most 500 stored event candidates and 200 linked finding candidates. Empty minutes do not prove no traffic.</p>
  </section>
  <details class="activity-globe-controls">
    <summary>Offline location options <small>CSV override stays in this tab</small></summary>
    <div class="activity-globe-control-fields">
    <label for="activity-globe-file">Choose local IP map CSV <span>(up to 64 KiB, 500 rows)</span></label>
    <input id="activity-globe-file" type="file" accept=".csv,text/csv">
    <button type="button" id="activity-globe-clear" disabled>Clear map</button>
    <p id="activity-globe-file-status" role="status" aria-live="polite">No file selected. Mapping stays in this browser tab only.</p>
    <details><summary>CSV format</summary><code>ip,latitude,longitude,label<br>203.0.113.8,40,-75,Reviewed region</code><p>Exact IP match; IPv4 or plain IPv6. One unquoted row per address. Coordinates are rounded for display. The file is never uploaded or saved by the HUD.</p></details>
    </div>
  </details>
</section>
"""

GLOBE_CSS = r"""
.room-globe-entry { display: flex; justify-content: space-between; align-items: center; gap: 18px; margin: 15px 0; padding: 17px 19px; border: 1px solid #416875; border-left: 3px solid #66d9c6; border-radius: 8px; background: linear-gradient(100deg,#112d39,#0b212c); }
.room-globe-entry h3 { margin: 0 0 5px; font-size: 1.18rem; color: #f0fbfa; }
.room-globe-entry .eyebrow { margin: 0 0 4px; }
.room-globe-entry p:not(.eyebrow) { margin: 0; color: #bfd5db; font-size: .84rem; line-height: 1.45; }
.room-globe-entry #room-globe-entry-status { margin-top: 7px; color: #91e6d8; font-weight: 700; }
.room-globe-entry a { flex: none; min-height: 44px; display: inline-flex; align-items: center; gap: 8px; padding: 10px 12px; border: 1px solid #5b9d9c; border-radius: 6px; color: #eafffb; text-decoration: none; font-size: .84rem; font-weight: 700; }
.room-globe-entry a:hover { background: #173f48; }
.room-globe-entry a:focus-visible { outline: 3px solid #ffd16b; outline-offset: 2px; }
.activity-globe { margin: 18px 0; border: 1px solid #426779; border-radius: 12px; overflow: hidden; background: linear-gradient(125deg,#0c2633,#071b27 65%); color: #edf8fa; }
.activity-globe-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 15px 18px 10px; }
.activity-globe-head h3 { margin: 0; font-size: 1.25rem; letter-spacing: -.025em; }
.activity-globe-head .eyebrow { margin: 0 0 4px; }
.activity-globe-hour-status { margin: 7px 0 0; color: #bed4dd; font-size: .82rem; line-height: 1.4; }
.activity-globe-head-state { display: grid; justify-items: end; gap: 7px; text-align: right; }
.activity-globe-head-state time { color: #b5cdd6; font-size: .73rem; }
.activity-globe-state { flex: none; padding: 5px 9px; border: 1px solid #567484; border-radius: 6px; color: #d5e4ea; font-size: .73rem; font-weight: 700; }
.activity-globe-state.mapped { color: #94eedc; border-color: #389e90; }
.activity-globe-state.stale { color: #f4d58f; border-color: #9e8145; }
.activity-globe-body { display: grid; grid-template-columns: minmax(340px,.95fr) minmax(0,1fr); gap: 22px; align-items: center; padding: 4px 18px 18px; }
.activity-globe-stage { position: relative; width: min(100%,420px); aspect-ratio: 1; margin: 0 auto; }
.activity-globe-stage canvas { display: block; width: 100%; height: 100%; }
.activity-globe-caption { position: absolute; left: 0; right: 0; bottom: 2px; text-align: center; font-size: .68rem; color: #b6d4de; letter-spacing: .04em; }
.activity-globe-ping { position: absolute; width: 13px; height: 13px; border-radius: 50%; background: #ffd16b; border: 2px solid #fff2ce; box-shadow: 0 0 18px #ffd16b; transform: translate(-50%,-50%); pointer-events: none; }
.activity-globe-ping::after { content: ""; position: absolute; inset: -12px; border: 2px solid #ffd16b; border-radius: 50%; animation: globe-ping 1.8s ease-out infinite; }
.activity-globe.stale .activity-globe-ping, .activity-globe.hidden-page .activity-globe-ping { display: none; }
@keyframes globe-ping { 0% { opacity: .9; transform: scale(.35); } 100% { opacity: 0; transform: scale(1.4); } }
.activity-globe-readout { min-width: 0; }
.activity-globe-lead { margin: 0 0 10px; color: #e8f7fa; font-size: .9rem; line-height: 1.45; }
.activity-globe-list-heading { margin: 0 0 6px; color: #c5dbe1; font-size: .77rem; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.activity-globe-list { margin: 0; padding: 0; list-style: none; display: grid; gap: 5px; }
.activity-globe-list li { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: 10px; padding: 8px 10px; border: 1px solid #294957; border-radius: 6px; background: #0b2531; font-size: .78rem; }
.activity-globe-list code { overflow-wrap: anywhere; color: #f6fafb; }
.activity-globe-list span { color: #b1cbd3; text-align: right; }
.activity-globe-list .matched span { color: #94eedc; }
.activity-globe-list small { grid-column: 1 / -1; color: #b7cbd3; font-size: .72rem; font-weight: 700; }
.activity-globe-list small.review { color: #f1d18b; }
.activity-globe-list small.high { color: #ffb0a8; }
.activity-globe.stale .activity-globe-list li { border-color: #7f6a45; background: #28271e; }
.activity-globe.stale .activity-globe-list .matched span { color: #f4d58f; }
.activity-globe.stale .activity-globe-list-heading { color: #f4d58f; }
.activity-globe-source-status { margin: 12px 0 0; color: #91d9d1; font-size: .79rem; line-height: 1.45; }
.activity-globe-note { margin: 10px 0 0; color: #b8ced6; font-size: .82rem; line-height: 1.5; }
.activity-globe-timeline { padding: 15px 18px 17px; border-top: 1px solid #345967; background: linear-gradient(180deg,rgba(8,33,45,.66),rgba(5,23,33,.7)); }
.activity-globe-timeline-head { display: flex; align-items: end; justify-content: space-between; gap: 15px; }
.activity-globe-timeline-head .eyebrow { margin: 0 0 3px; }
.activity-globe-timeline h4 { margin: 0; color: #f0fbfb; font-size: 1rem; letter-spacing: -.02em; }
.activity-globe-timeline output { color: #d9edf0; font-size: .86rem; font-variant-numeric: tabular-nums; text-align: right; }
.activity-globe-histogram { display: grid; grid-template-columns: repeat(60,minmax(0,1fr)); align-items: end; gap: 2px; height: 82px; margin: 14px 0 5px; padding: 7px 4px 0; border: 1px solid #294c59; border-bottom-color: #6e9eaa; border-radius: 6px 6px 0 0; background: repeating-linear-gradient(to right,transparent,transparent calc(10% - 1px),rgba(111,171,180,.09) 10%),#081f2b; }
.activity-globe-bar { display: block; width: 100%; min-height: 2px; border-radius: 2px 2px 0 0; background: #4aaea8; opacity: .76; }
.activity-globe-bar.empty { height: 2px; opacity: .3; }
.activity-globe-bar.review { background: linear-gradient(to top,#4aaea8 65%,#e7bc6d 65%); }
.activity-globe-bar.high { background: linear-gradient(to top,#4aaea8 62%,#ee8b83 62%); }
.activity-globe-bar.selected { outline: 2px solid #ecf5e1; outline-offset: 1px; opacity: 1; }
.activity-globe-rail { display: grid; grid-template-columns: auto minmax(0,1fr) auto; align-items: center; gap: 10px; }
.activity-globe-rail label { color: #dcebee; font-size: .8rem; font-weight: 700; }
.activity-globe-rail input { width: 100%; min-width: 0; height: 30px; margin: 0; accent-color: #70e2d0; cursor: ew-resize; }
.activity-globe-rail button { min-height: 42px; padding: 8px 12px; border: 1px solid #6aa9a7; border-radius: 6px; background: #17414a; color: #edfffb; font: inherit; font-size: .78rem; font-weight: 800; cursor: pointer; }
.activity-globe-rail button[aria-pressed="false"] { background: #0e2935; color: #cae0e4; }
.activity-globe-rail button:focus-visible, .activity-globe-rail input:focus-visible { outline: 3px solid #ffd16b; outline-offset: 3px; }
.activity-globe-axis { display: flex; justify-content: space-between; margin: 0 0 11px; padding: 0 158px 0 109px; color: #b8ced6; font-size: .72rem; }
.activity-globe-timeline-bottom { display: flex; justify-content: space-between; align-items: end; gap: 14px; }
.activity-globe-counts { display: flex; gap: 16px; margin: 0; }
.activity-globe-counts div { min-width: 95px; }
.activity-globe-counts dt { color: #afc8d0; font-size: .7rem; text-transform: uppercase; letter-spacing: .07em; }
.activity-globe-counts dd { margin: 3px 0 0; color: #f0fbfb; font-size: 1.28rem; font-weight: 800; font-variant-numeric: tabular-nums; }
.activity-globe-legend { display: flex; flex-wrap: wrap; gap: 6px 12px; margin: 0; color: #c1d5da; font-size: .73rem; }
.activity-globe-legend span::before { content: ""; display: inline-block; width: 8px; height: 8px; margin-right: 5px; background: #4aaea8; }
.activity-globe-legend .review::before { background: #e7bc6d; }
.activity-globe-legend .high::before { background: #ee8b83; }
.activity-globe-coverage { margin: 11px 0 0; color: #b7d0d7; font-size: .77rem; line-height: 1.5; }
.activity-globe-controls { border-top: 1px solid #294957; background: #091f2b; }
.activity-globe-controls > summary { min-height: 48px; padding: 14px 18px; color: #e3f5f4; font-size: .84rem; font-weight: 800; cursor: pointer; }
.activity-globe-controls > summary small { margin-left: 8px; color: #adcbd1; font-size: .76rem; font-weight: 400; }
.activity-globe-controls > summary:focus-visible { outline: 3px solid #ffd16b; outline-offset: -4px; }
.activity-globe-control-fields { display: flex; flex-wrap: wrap; align-items: center; gap: 9px 13px; padding: 3px 18px 15px; }
.activity-globe-controls label { flex-basis: 100%; font-size: .78rem; font-weight: 700; }
.activity-globe-controls label span { color: #b8ced6; font-weight: 400; }
.activity-globe-controls input { max-width: min(100%,360px); font: inherit; font-size: .75rem; color: #eaf7fa; }
.activity-globe-controls input::file-selector-button, .activity-globe-controls button { padding: 8px 10px; border: 1px solid #5e8b98; border-radius: 6px; color: #eaf7fa; background: #153a46; font: inherit; font-size: .76rem; cursor: pointer; }
.activity-globe-controls button:disabled { opacity: .5; cursor: default; }
.activity-globe-controls :focus-visible { outline: 3px solid #ffd16b; outline-offset: 2px; }
.activity-globe-controls p { flex-basis: 100%; margin: 0; color: #b8ced6; font-size: .74rem; }
.activity-globe-controls details { flex-basis: 100%; color: #b8ced6; font-size: .74rem; }
.activity-globe-controls summary { width: fit-content; min-height: 34px; padding: 7px 0; cursor: pointer; }
.activity-globe-controls code { display: block; width: fit-content; max-width: 100%; overflow-wrap: anywhere; padding: 8px; border: 1px solid #365966; color: #eaf7fa; line-height: 1.5; }
@media (max-width: 900px) { .activity-globe-body { grid-template-columns: 1fr; gap: 8px; } .activity-globe-stage { width: min(100%,360px); } .activity-globe-head { align-items: flex-start; } .activity-globe-timeline-bottom { display: block; } .activity-globe-legend { margin-top: 12px; } }
@media (max-width: 680px) { .room-globe-entry { align-items: flex-start; flex-direction: column; } }
@media (max-width: 560px) {
  .activity-globe-stage { width: min(100%,306px); }
  .activity-globe-head { display: block; }
  .activity-globe-head .eyebrow { font-size: .75rem; }
  .activity-globe-state { display: inline-block; margin-top: 9px; }
  .activity-globe-list-heading { font-size: .82rem; }
  .activity-globe-list li { grid-template-columns: 1fr; gap: 3px; font-size: .875rem; }
  .activity-globe-list span { text-align: left; }
  .activity-globe-note { font-size: .875rem; }
  .activity-globe-head-state { justify-items: start; text-align: left; margin-top: 9px; }
  .activity-globe-timeline-head { display: block; }
  .activity-globe-timeline output { display: block; margin-top: 7px; text-align: left; }
  .activity-globe-rail { grid-template-columns: minmax(0,1fr) auto; }
  .activity-globe-rail label { grid-column: 1 / -1; }
  .activity-globe-axis { padding: 0 0 0 2px; }
  .activity-globe-histogram { gap: 1px; }
  .activity-globe-controls > summary small { display: block; margin: 4px 0 0; }
}
@media (prefers-reduced-motion: reduce) { .activity-globe-ping::after { animation: none; opacity: .65; transform: scale(.7); } }
@media (forced-colors: active) { .activity-globe-ping { background: Highlight; border-color: CanvasText; } .activity-globe-ping::after { border-color: Highlight; } }
"""

GLOBE_JS = r"""
const globeState = {mapping: null, backendMapping: null, locationStatus: 'checking', traffic: null,
  stale: false, latitude: 20, longitude: -20, frame: null, spinTimer: null, fileVersion: 0,
  focus: {id: null, until: 0, timer: null, seen: new Set(), selectionKey: null},
  hour: {page: null, start: null, end: null, selectedAt: null, selectedIndex: 59, live: true, fetchedAt: null,
    busy: false, failed: false, partial: false, capReached: false, started: false, timer: null, requestVersion: 0,
    locationVersion: 0, locationKey: null, notice: ''}};
const globeMaxBytes = 65536;
const globeMaxRows = 500;

function normalizeGlobeIp(value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 45) return null;
  if (value.includes('.')) {
    const parts = value.split('.');
    return parts.length === 4 && parts.every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)
      ? parts.join('.') : null;
  }
  if (!value.includes(':') || !/^[0-9a-f:]+$/i.test(value) || value.includes(':::')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = [...left, ...right];
  if (!groups.every(group => /^[0-9a-f]{1,4}$/i.test(group))) return null;
  if (halves.length === 1 && groups.length !== 8) return null;
  if (halves.length === 2 && groups.length >= 8) return null;
  return [...left, ...Array(8 - groups.length).fill('0'), ...right]
    .map(group => group.padStart(4, '0').toLowerCase()).join(':');
}
function parseGlobeMapping(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > globeMaxBytes || text.length === 0) throw new Error('Map file must be UTF-8 and no larger than 64 KiB.');
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  if (lines[0] !== 'ip,latitude,longitude,label' || lines.length < 2 || lines.length > globeMaxRows + 1) throw new Error('Use the exact four-column CSV header and 1–500 data rows.');
  const mapping = new Map();
  lines.slice(1).forEach((line, index) => {
    const columns = line.split(',');
    if (columns.length !== 4) throw new Error(`Invalid CSV row ${index + 2}.`);
    const [ip, latText, lonText, label] = columns;
    const address = normalizeGlobeIp(ip);
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
    const latitude = Number(latText), longitude = Number(lonText);
    if (!address || mapping.has(address) || !number.test(latText) || !number.test(lonText)
        || !Number.isFinite(latitude) || latitude < -90 || latitude > 90
        || !Number.isFinite(longitude) || longitude < -180 || longitude > 180
        || !label || label.length > 64 || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(label)
        || label !== label.trim() || line.includes('"') || line.includes('\r')) {
      throw new Error(`Invalid IP, coordinates, or label on CSV row ${index + 2}.`);
    }
    mapping.set(address, Object.freeze({latitude: Math.round(latitude / 5) * 5,
      longitude: Math.round(longitude / 5) * 5, label}));
  });
  return mapping;
}
function globeViewModel(traffic, mapping, stale = false, focusId = undefined) {
  if (!traffic || traffic.status !== 'available') return {kind: 'unavailable', entries: [], active: null};
  if (!traffic.events.length) return {kind: 'empty', entries: [], active: null};
  const ordered = [...traffic.events].sort((a, b) =>
    Date.parse(b.observed_at) - Date.parse(a.observed_at) ||
    (BigInt(b.id) > BigInt(a.id) ? 1 : BigInt(b.id) < BigInt(a.id) ? -1 : 0));
  const signals = ordered.filter(event => (traffic.signalByEvent?.get(event.id) || 'quiet') !== 'quiet')
    .sort((a, b) => (traffic.signalByEvent.get(b.id) === 'high') - (traffic.signalByEvent.get(a.id) === 'high'));
  const seen = new Set(), entries = [];
  for (const event of [...signals, ...ordered]) {
    const address = normalizeGlobeIp(event.src_ip);
    if (!address || seen.has(address)) continue;
    seen.add(address);
    entries.push({ip: event.src_ip, location: mapping ? mapping.get(address) || null : null,
      observed_at: event.observed_at, signal: traffic.signalByEvent?.get(event.id) || 'quiet'});
    if (entries.length === 5) break;
  }
  if (stale) return {kind: 'stale', entries, active: null};
  // Prioritize high severity, then the newest mapped signal, even if beyond the five listed IPs.
  const mappedSignal = signals.find(event => mapping?.has(normalizeGlobeIp(event.src_ip)));
  const mapped = focusId === undefined ? mappedSignal : signals.find(event => event.id === focusId && mapping?.has(normalizeGlobeIp(event.src_ip)));
  const kind = mapped ? 'mapped' : mappedSignal ? 'signal-waiting' : signals.length ? 'signal-unmapped' : !mapping ? 'no-map' : 'monitoring';
  return {kind, entries,
    active: mapped ? {ip: mapped.src_ip, observed_at: mapped.observed_at,
      signal: traffic.signalByEvent?.get(mapped.id) || 'quiet',
      location: mapping.get(normalizeGlobeIp(mapped.src_ip))} : null};
}
const globeSize = 420, globeCenter = 210, globeRadius = 182;
const globeLandMaskBase64 = '__GLOBE_LAND_MASK__';
let globeLandMask = null, globeImage = null;
function globeMask() {
  if (globeLandMask === null) {
    const binary = atob(globeLandMaskBase64);
    if (binary.length !== 32400) throw new Error('Invalid bundled globe land mask');
    globeLandMask = Uint8Array.from(binary, char => char.charCodeAt(0));
  }
  return globeLandMask;
}
function globeProject(latitude, longitude, centerLat, centerLon) {
  const rad = Math.PI / 180, phi = latitude * rad, phi0 = centerLat * rad;
  const delta = ((longitude - centerLon + 540) % 360 - 180) * rad;
  const depth = Math.sin(phi0) * Math.sin(phi) + Math.cos(phi0) * Math.cos(phi) * Math.cos(delta);
  return {visible: depth >= 0, x: globeCenter + globeRadius * Math.cos(phi) * Math.sin(delta),
    y: globeCenter - globeRadius * (Math.cos(phi0) * Math.sin(phi) - Math.sin(phi0) * Math.cos(phi) * Math.cos(delta))};
}
function drawGlobe(view) {
  const canvas = byId('activity-globe-canvas');
  if (typeof canvas.getContext !== 'function') return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const mask = globeMask();
  if (globeImage === null) globeImage = ctx.createImageData(globeSize, globeSize);
  const pixels = globeImage.data;
  pixels.fill(0);
  const phi0 = globeState.latitude * Math.PI / 180;
  const sin0 = Math.sin(phi0), cos0 = Math.cos(phi0);
  const lon0 = globeState.longitude * Math.PI / 180;
  const twoPi = Math.PI * 2;
  for (let y = globeCenter - globeRadius; y <= globeCenter + globeRadius; y += 1) {
    const north = (globeCenter - y) / globeRadius;
    for (let x = globeCenter - globeRadius; x <= globeCenter + globeRadius; x += 1) {
      const east = (x - globeCenter) / globeRadius;
      const distance = east * east + north * north;
      if (distance > 1) continue;
      const forward = Math.sqrt(1 - distance);
      const latitude = Math.asin(north * cos0 + forward * sin0);
      const longitude = lon0 + Math.atan2(east, forward * cos0 - north * sin0);
      let horizontal = longitude / twoPi + .5;
      horizontal -= Math.floor(horizontal);
      const landX = Math.min(719, Math.floor(horizontal * 720));
      const landY = Math.max(0, Math.min(359, Math.floor((.5 - latitude / Math.PI) * 360)));
      const bit = landY * 720 + landX;
      const isLand = (mask[bit >> 3] & (1 << (bit & 7))) !== 0;
      // Screen-fixed light gives volume while keeping the far side legible.
      const light = Math.max(0, -.28 * east + .37 * north + .88 * forward);
      const shade = .51 + .47 * light + .10 * forward;
      const relief = isLand ? 3 * Math.sin(latitude * 17 + longitude * 11) * Math.cos(longitude * 19) : 0;
      const index = (y * globeSize + x) * 4;
      pixels[index] = (isLand ? 72 : 16) * shade + relief;
      pixels[index + 1] = (isLand ? 135 : 81) * shade + relief;
      pixels[index + 2] = (isLand ? 113 : 116) * shade + relief;
      pixels[index + 3] = Math.min(255, Math.round(255 * Math.min(1, (1 - distance) * 95)));
    }
  }
  ctx.putImageData(globeImage, 0, 0);
  const atmosphere = ctx.createRadialGradient(globeCenter, globeCenter, globeRadius - 13,
    globeCenter, globeCenter, globeRadius + 24);
  atmosphere.addColorStop(0, 'rgba(112,205,218,0)');
  atmosphere.addColorStop(.42, 'rgba(112,205,218,.13)');
  atmosphere.addColorStop(.75, 'rgba(112,205,218,.21)');
  atmosphere.addColorStop(1, 'rgba(112,205,218,0)');
  ctx.fillStyle = atmosphere; ctx.fillRect(0, 0, globeSize, globeSize);
  ctx.save(); ctx.beginPath(); ctx.arc(globeCenter, globeCenter, globeRadius, 0, twoPi); ctx.clip();
  ctx.strokeStyle = 'rgba(185,231,226,.23)'; ctx.lineWidth = 1;
  function gridLine(points) {
    let drawing = false;
    ctx.beginPath();
    points.forEach(([lat, lon]) => {
      const point = globeProject(lat, lon, globeState.latitude, globeState.longitude);
      if (!point.visible) { drawing = false; return; }
      if (!drawing) ctx.moveTo(point.x, point.y); else ctx.lineTo(point.x, point.y);
      drawing = true;
    });
    ctx.stroke();
  }
  for (let lat = -60; lat <= 60; lat += 30)
    gridLine(Array.from({length: 145}, (_, i) => [lat, -180 + i * 2.5]));
  for (let lon = -180; lon < 180; lon += 30)
    gridLine(Array.from({length: 73}, (_, i) => [-90 + i * 2.5, lon]));
  ctx.restore();
  ctx.beginPath(); ctx.arc(globeCenter, globeCenter, globeRadius, 0, twoPi);
  ctx.strokeStyle = 'rgba(160,226,225,.75)'; ctx.lineWidth = 1.5; ctx.stroke();
  const ping = byId('activity-globe-ping');
  const point = view.active && globeProject(view.active.location.latitude, view.active.location.longitude,
    globeState.latitude, globeState.longitude);
  ping.hidden = !point || !point.visible || globeState.stale || document.hidden;
  if (!ping.hidden) { ping.style.left = `${point.x / globeSize * 100}%`; ping.style.top = `${point.y / globeSize * 100}%`; }
}
function orientGlobe(view) {
  stopGlobeSpin();
  if (globeState.frame !== null && typeof window.cancelAnimationFrame === 'function') window.cancelAnimationFrame(globeState.frame);
  globeState.frame = null;
  if (!view.active) { drawGlobe(view); return; }
  const targetLat = Math.max(-65, Math.min(65, view.active.location.latitude));
  const targetLon = ((view.active.location.longitude - 15 + 540) % 360) - 180;
  const motion = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (motion || document.hidden || byId('workspace-traffic').hidden || typeof window.requestAnimationFrame !== 'function') {
    globeState.latitude = targetLat; globeState.longitude = targetLon; drawGlobe(view); return;
  }
  const startLat = globeState.latitude, startLon = globeState.longitude;
  const deltaLon = ((targetLon - startLon + 540) % 360) - 180;
  if (Math.abs(deltaLon) < .1 && Math.abs(targetLat - startLat) < .1) { drawGlobe(view); return; }
  let started = null;
  function step(now) {
    if (document.hidden) { globeState.latitude = targetLat; globeState.longitude = targetLon; globeState.frame = null; drawGlobe(view); return; }
    if (started === null) started = now;
    const t = Math.min(1, (now - started) / 850), eased = 1 - Math.pow(1 - t, 3);
    globeState.latitude = startLat + (targetLat - startLat) * eased;
    globeState.longitude = startLon + deltaLon * eased;
    drawGlobe(view);
    globeState.frame = t < 1 ? window.requestAnimationFrame(step) : null;
  }
  globeState.frame = window.requestAnimationFrame(step);
}
function globeMotionMode(view, hidden, reducedMotion, paused, hasHour) {
  if (hidden || reducedMotion || paused || !hasHour || view.kind === 'stale' || view.kind === 'unavailable') return 'still';
  return view.active ? 'hold' : 'spin';
}
function stopGlobeSpin() {
  if (globeState.spinTimer !== null) window.clearTimeout(globeState.spinTimer);
  globeState.spinTimer = null;
}
function startGlobeSpin(view) {
  const reduced = () => typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const workspace = byId('workspace-traffic');
  if (globeMotionMode(view, document.hidden || workspace.hidden, reduced(), state.paused, Boolean(globeState.hour.page)) !== 'spin') return;
  const step = () => {
    if (globeMotionMode(view, document.hidden || workspace.hidden, reduced(), state.paused, Boolean(globeState.hour.page)) !== 'spin') {
      globeState.spinTimer = null; return;
    }
    globeState.longitude = ((globeState.longitude + 1.5 + 540) % 360) - 180;
    drawGlobe(view);
    globeState.spinTimer = window.setTimeout(step, 240);
  };
  globeState.spinTimer = window.setTimeout(step, 240);
}
function globeFocusDwell(count) { return count <= 1 ? 8000 : count <= 3 ? 4000 : 2500; }
function stopGlobeFocusTimer() {
  if (globeState.focus.timer !== null) window.clearTimeout(globeState.focus.timer);
  globeState.focus.timer = null;
}
function globeFocusCandidates(traffic, mapping) {
  const signals = traffic?.signalByEvent;
  if (!signals || !mapping) return [];
  const ordered = traffic.events.filter(event => signals.has(event.id) && mapping.has(normalizeGlobeIp(event.src_ip)))
    .sort((a, b) => (signals.get(b.id) === 'high') - (signals.get(a.id) === 'high')
      || Date.parse(b.observed_at) - Date.parse(a.observed_at));
  const ips = new Set();
  return ordered.filter(event => {
    const ip = normalizeGlobeIp(event.src_ip);
    if (ips.has(ip)) return false;
    ips.add(ip); return true;
  });
}
function syncGlobeFocus(mapping) {
  const focus = globeState.focus, hour = globeState.hour;
  if (!hour.page) return;
  const key = hour.live ? 'live' : `minute:${hour.selectedAt}`;
  if (key !== focus.selectionKey) {
    stopGlobeFocusTimer(); focus.id = null; focus.seen.clear(); focus.selectionKey = key;
  }
  const traffic = globeState.traffic;
  const validSignalIds = new Set(traffic?.events.filter(event => traffic.signalByEvent?.has(event.id)).map(event => event.id) || []);
  focus.seen = new Set([...focus.seen].filter(id => validSignalIds.has(id)));
  const candidates = globeFocusCandidates(traffic, mapping);
  const hidden = document.hidden || byId('workspace-traffic').hidden || state.paused || globeState.stale;
  const current = candidates.find(event => event.id === focus.id);
  const currentSignal = current && traffic.signalByEvent.get(current.id);
  const urgent = currentSignal === 'review' && candidates.some(event =>
    traffic.signalByEvent.get(event.id) === 'high' && !focus.seen.has(event.id));
  if (focus.id && (hidden || !current || Date.now() >= focus.until || urgent)) {
    focus.seen.add(focus.id); focus.id = null; stopGlobeFocusTimer();
  }
  if (hidden || focus.id) return;
  const next = candidates.find(event => !focus.seen.has(event.id));
  if (!next) return;
  focus.id = next.id; focus.until = Date.now() + globeFocusDwell(candidates.length);
  stopGlobeFocusTimer();
  focus.timer = window.setTimeout(() => {focus.timer = null; renderGlobeView();}, globeFocusDwell(candidates.length));
}
function globeEffectiveMapping() {
  if (!globeState.backendMapping && !globeState.mapping) return null;
  return new Map([...(globeState.backendMapping || []), ...(globeState.mapping || [])]);
}
function globeSignalLabel(signal) {
  return signal === 'high' ? 'High priority signal' : signal === 'review' ? 'Review signal'
    : 'No linked finding (safety unknown)';
}
function renderGlobeView() {
  const mapping = globeEffectiveMapping();
  syncGlobeFocus(mapping);
  const view = globeViewModel(globeState.traffic, mapping, globeState.stale,
    globeState.hour.page ? globeState.focus.id : undefined);
  const panel = byId('activity-globe'), badge = byId('activity-globe-state');
  panel.className = `activity-globe${view.kind === 'stale' ? ' stale' : ''}${document.hidden ? ' hidden-page' : ''}`;
  badge.className = `activity-globe-state${view.kind === 'mapped' ? ' mapped' : view.kind === 'stale' ? ' stale' : ''}`;
  const labels = {stale: 'Stale snapshot', unavailable: 'Unavailable', empty: 'No records',
    'no-map': 'No signal · no map', monitoring: 'No linked signal',
    'signal-unmapped': 'Signal · unmapped', 'signal-waiting': 'Signals listed', mapped: 'Signal located'};
  badge.textContent = labels[view.kind];
  const overviewStatus = byId('room-globe-entry-status');
  const overviewLabels = {stale: 'Previous traffic snapshot · no current marker',
    unavailable: 'Qualified traffic unavailable', empty: 'No qualified records yet',
    'no-map': 'Recent IPs available · no linked signal or map',
    monitoring: 'Recent IPs available · no linked finding',
    'signal-unmapped': 'Linked signal · source IP has no offline location',
    'signal-waiting': 'Linked signals listed · globe rotating', mapped: 'Mapped signal source context available'};
  if (overviewStatus.textContent !== overviewLabels[view.kind]) overviewStatus.textContent = overviewLabels[view.kind];
  const lead = byId('activity-globe-lead');
  const focusMinute = view.active && globeState.hour.start !== null
    ? Math.max(0, Math.min(59, Math.floor((Date.parse(view.active.observed_at) - globeState.hour.start) / 60000))) : null;
  const focusTime = view.active && globeState.hour.page
    ? ` Observed ${view.active.observed_at}${focusMinute !== globeState.hour.selectedIndex ? ' · recent signal beyond selected minute' : ''}.` : '';
  lead.textContent = view.kind === 'mapped'
    ? `Focused source: ${view.active.ip} · ${view.active.location.label}. ${globeSignalLabel(view.active.signal)}.${focusTime} Approximate region only.`
    : view.kind === 'stale' ? 'Hour refresh failed. Previous source IPs are shown; no current location ping.'
    : view.kind === 'unavailable' ? 'Qualified traffic is unavailable. No location is shown.'
    : view.kind === 'empty' ? 'No qualified stored events were returned for this minute.'
    : view.kind === 'no-map' ? 'Source IPs are available. No linked finding or offline location is available for this minute.'
    : view.kind === 'signal-unmapped' ? 'A detector-linked signal is present, but its source IP has no offline location. No dot is placed.'
    : view.kind === 'signal-waiting' ? 'Detector-linked source IPs are listed. The globe turns after each brief focus.'
    : 'No linked finding in this minute (safety unknown). The globe keeps turning.';
  const items = view.entries.map(entry => {
    const item = document.createElement('li'); item.className = entry.location ? 'matched' : '';
    item.append(textNode('code', entry.ip), textNode('span', entry.location ? entry.location.label : 'Unmapped'),
      textNode('small', `${view.kind === 'stale' ? 'Previous page · ' : ''}${globeSignalLabel(entry.signal)}`,
        entry.signal === 'quiet' ? '' : entry.signal));
    return item;
  });
  byId('activity-globe-list-heading').textContent = view.kind === 'stale'
    ? 'Previous snapshot · source IPs and map labels' : 'Recent source IPs';
  const list = byId('activity-globe-list');
  list.setAttribute('aria-label', view.kind === 'stale'
    ? 'Previous snapshot source IP mapping status' : 'Recent source IP mapping status');
  list.replaceChildren(...items);
  const sourceLabels = {checking: 'Checking same-host offline location database…', available: 'Offline database available. CSV overrides matching addresses in this tab.',
    unconfigured: 'Offline database unconfigured. A reviewed local CSV can supply locations.',
    unavailable: 'Offline location lookup unavailable. A reviewed local CSV can supply locations.'};
  byId('activity-globe-source-status').textContent = sourceLabels[globeState.locationStatus] || sourceLabels.unavailable;
  orientGlobe(view);
  startGlobeSpin(view);
}
function renderGlobe(traffic) { globeState.traffic = traffic; globeState.stale = false; renderGlobeView(); }
function renderGlobeUnavailable(preserve) {
  globeState.stale = preserve;
  if (!preserve) globeState.traffic = null;
  renderGlobeView();
}
function globePublicIp(value) {
  const address = normalizeGlobeIp(value);
  if (!address) return null;
  if (address.includes(':')) return /^[23]/.test(address) && !address.startsWith('2001:0db8:') ? value : null;
  const parts = address.split('.').map(Number), [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && c <= 2))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)) return null;
  return address;
}
function globeHourModel(page, start, end, selectedAt, live) {
  const bins = Array.from({length: 60}, () => ({count: 0, signal: 'quiet'}));
  const events = page?.traffic.events || [], findings = page?.traffic.findings || [];
  const signalByEvent = new Map();
  findings.forEach(finding => {
    const signal = ['HIGH', 'CRITICAL'].includes(finding.severity) ? 'high' : 'review';
    if (signal === 'high' || !signalByEvent.has(finding.event_id)) signalByEvent.set(finding.event_id, signal);
  });
  let latest = null;
  events.forEach(event => {
    const at = Date.parse(event.observed_at);
    const index = Math.max(0, Math.min(59, Math.floor((at - start) / 60000)));
    bins[index].count += 1;
    const signal = signalByEvent.get(event.id);
    if (signal === 'high' || (signal === 'review' && bins[index].signal === 'quiet')) bins[index].signal = signal;
    if (latest === null || at > latest) latest = at;
  });
  const at = live ? latest === null ? end : latest : Math.max(start, Math.min(end, selectedAt ?? end));
  const index = Math.max(0, Math.min(59, Math.floor((at - start) / 60000)));
  const selectedEvents = events.filter(event => Math.max(0, Math.min(59,
    Math.floor((Date.parse(event.observed_at) - start) / 60000))) === index);
  const recentSignals = live ? events.filter(event => signalByEvent.has(event.id)
    && Date.parse(event.observed_at) >= end - 300000) : [];
  const displayed = [...selectedEvents];
  const displayedIds = new Set(displayed.map(event => event.id));
  recentSignals.forEach(event => {if (!displayedIds.has(event.id)) displayed.push(event);});
  return {bins, index, peak: Math.max(0, ...bins.map(bin => bin.count)), latest,
    traffic: {status: 'available', events: displayed, signalByEvent}};
}
function globeHourTime(at) { return new Date(at).toISOString().slice(11, 16) + ' UTC'; }
function renderGlobeHour() {
  const hour = globeState.hour;
  if (!hour.page) {
    byId('activity-globe-hour-status').textContent = hour.failed
      ? 'Hour history unavailable · no current activity shown' : 'Loading the past hour of stored metadata…';
    byId('activity-globe-updated').textContent = hour.failed ? 'Refresh failed' : 'Awaiting hour view';
    byId('activity-globe-selected-time').textContent = hour.failed ? 'Hour unavailable' : 'Waiting for the hour view';
    byId('activity-globe-histogram').setAttribute('aria-label', 'No hour history available');
    byId('activity-globe-histogram').replaceChildren();
    byId('activity-globe-minute').disabled = true;
    byId('activity-globe-live').disabled = true;
    byId('activity-globe-selected-count').textContent = '—';
    byId('activity-globe-peak-count').textContent = '—';
    renderGlobeUnavailable(false);
    return;
  }
  const model = globeHourModel(hour.page, hour.start, hour.end, hour.selectedAt, hour.live);
  hour.selectedIndex = model.index;
  const binStart = hour.start + model.index * 60000;
  const counts = model.bins.map(bin => bin.count);
  const bars = model.bins.map((bin, index) => {
    const bar = document.createElement('span');
    bar.className = `activity-globe-bar${bin.count ? '' : ' empty'}${bin.signal === 'quiet' ? '' : ' ' + bin.signal}${index === model.index ? ' selected' : ''}`;
    bar.style.height = `${bin.count ? Math.max(8, bin.count / Math.max(1, model.peak) * 100) : 2}%`;
    bar.title = `${globeHourTime(hour.start + index * 60000)} · ${bin.count} returned record${bin.count === 1 ? '' : 's'} · ${globeSignalLabel(bin.signal)}`;
    return bar;
  });
  const histogram = byId('activity-globe-histogram'); histogram.replaceChildren(...bars);
  histogram.setAttribute('aria-label', `60 minute bins, oldest to newest, returned qualified metadata counts: ${counts.join(', ')}. Empty bins do not prove no traffic.`);
  const slider = byId('activity-globe-minute'); slider.disabled = false; slider.value = String(model.index);
  slider.setAttribute('aria-valuetext', `${globeHourTime(binStart)}, ${model.bins[model.index].count} returned records`);
  const live = byId('activity-globe-live'); live.disabled = false;
  live.setAttribute('aria-pressed', String(hour.live));
  byId('activity-globe-selected-time').textContent = `${hour.live ? 'Live · latest stored · ' : 'Selected · '}${globeHourTime(binStart)}–${globeHourTime(binStart + 60000)}`;
  byId('activity-globe-selected-count').textContent = String(model.bins[model.index].count);
  byId('activity-globe-peak-count').textContent = String(model.peak);
  byId('activity-globe-updated').textContent = `Refreshed ${globeHourTime(hour.fetchedAt)}`;
  const status = hour.failed ? 'Hour refresh failed · previous page shown'
    : hour.partial ? 'Partial hour · bounded page of returned records'
    : hour.capReached ? 'Candidate cap reached · coverage may be partial'
    : model.latest === null ? 'No returned records in this hour'
    : 'Rolling hour · returned qualified metadata';
  const details = [status, state.paused ? 'refresh paused' : null, hour.notice || null].filter(Boolean).join(' · ');
  if (byId('activity-globe-hour-status').textContent !== details) byId('activity-globe-hour-status').textContent = details;
  byId('activity-globe-coverage').textContent = `${hour.partial ? 'Partial view: the bounded result was paged or truncated. ' : hour.capReached ? 'A candidate cap was reached; more records may exist. ' : ''}One history page, at most 500 stored event candidates and 200 linked finding candidates. ${hour.live ? 'Live IP readout includes linked signals from the last five minutes of this page. ' : 'IP readout follows the selected minute. '}Counts cover returned qualified metadata only; empty bins do not prove no traffic or safety.`;
  globeState.traffic = model.traffic;
  globeState.stale = hour.failed;
  renderGlobeView();
  return model;
}
function validateGlobeLocations(value, requested) {
  const keys = item => item && typeof item === 'object' && !Array.isArray(item) ? Object.keys(item).sort().join('|') : '';
  if (keys(value) !== 'locations|schema|source|status' || value.schema !== 'dashboard-offline-locations-v1'
      || !['available', 'unconfigured'].includes(value.status)
      || value.source !== (value.status === 'available' ? 'offline database' : 'none')
      || !value.locations || typeof value.locations !== 'object' || Array.isArray(value.locations)) throw new Error('Invalid location response');
  const mapping = new Map(), allowed = new Set(requested);
  for (const [ip, location] of Object.entries(value.locations)) {
    if (!allowed.has(ip) || keys(location) !== 'label|latitude|longitude'
        || !Number.isFinite(location.latitude) || Math.abs(location.latitude) > 90
        || !Number.isFinite(location.longitude) || Math.abs(location.longitude) > 180
        || typeof location.label !== 'string' || !location.label || location.label.length > 64
        || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(location.label)) throw new Error('Invalid location');
    mapping.set(normalizeGlobeIp(ip), {latitude: Math.round(location.latitude / 5) * 5,
      longitude: Math.round(location.longitude / 5) * 5, label: location.label});
  }
  if (value.status === 'unconfigured' && mapping.size) throw new Error('Invalid unconfigured location response');
  return {status: value.status, mapping};
}
async function requestGlobeLocations(ips) {
  const response = await fetch('/api/offline-locations', {method: 'POST', cache: 'no-store',
    credentials: 'omit', mode: 'same-origin', redirect: 'error',
    headers: {'Content-Type': 'application/json', 'X-Megalodon-Location': '1'},
    body: JSON.stringify({ips}), signal: AbortSignal.timeout(5000)});
  if (!response.ok) throw new Error('Location lookup unavailable');
  const reader = response.body?.getReader(); if (!reader) throw new Error('Location lookup unavailable');
  let bytes = 0; const chunks = [];
  try {
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('Invalid location response');
      bytes += value.byteLength; if (bytes > 16384) throw new Error('Oversized location response');
      chunks.push(value);
    }
  } finally {try {await reader.cancel();} catch (_) {}}
  const merged = new Uint8Array(bytes); let offset = 0;
  chunks.forEach(chunk => {merged.set(chunk, offset); offset += chunk.length;});
  return validateGlobeLocations(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(merged)), ips);
}
function globeLocationIps(traffic) {
  const ordered = [...traffic.events].sort((a, b) => {
    const rank = event => traffic.signalByEvent.get(event.id) === 'high' ? 2
      : traffic.signalByEvent.get(event.id) === 'review' ? 1 : 0;
    return rank(b) - rank(a) || Date.parse(b.observed_at) - Date.parse(a.observed_at);
  });
  return [...new Set(ordered.map(event => globePublicIp(event.src_ip)).filter(Boolean))].slice(0, 20);
}
async function refreshGlobeLocations(model) {
  const hour = globeState.hour;
  const ips = globeLocationIps(model.traffic);
  const key = ips.join('|'); if (key === hour.locationKey) return;
  hour.locationKey = key;
  const version = ++hour.locationVersion;
  globeState.locationStatus = 'checking'; renderGlobeView();
  try {
    const result = await requestGlobeLocations(ips);
    if (version !== hour.locationVersion) return;
    globeState.backendMapping = result.mapping; globeState.locationStatus = result.status;
  } catch (_) {
    if (version !== hour.locationVersion) return;
    hour.locationKey = null; globeState.backendMapping = null; globeState.locationStatus = 'unavailable';
  }
  renderGlobeView();
}
async function refreshGlobeHour(force = false) {
  const hour = globeState.hour;
  if (hour.busy || (!force && (document.hidden || state.paused))) return;
  hour.busy = true; const version = ++hour.requestVersion;
  try {
    const end = Date.now(), start = end - 3600000;
    const path = `/api/traffic-history?start=${encodeURIComponent(new Date(start).toISOString())}&end=${encodeURIComponent(new Date(end).toISOString())}`;
    const page = validateHistory(await requestRoomSnapshot(path), {start, end, before: null});
    if (version !== hour.requestVersion) return;
    hour.page = page; hour.start = start; hour.end = end; hour.fetchedAt = Date.now();
    hour.failed = false; hour.partial = Boolean(page.next_before || page.traffic.truncated);
    hour.capReached = page.candidate_count === 500 || page.traffic.findings.length === 200;
    hour.notice = '';
    if (!hour.live && hour.selectedAt < start) {hour.selectedAt = start; hour.notice = 'Selection moved to earliest minute in the rolling hour';}
    const model = renderGlobeHour();
    if (model) refreshGlobeLocations(model);
  } catch (_) {
    if (version !== hour.requestVersion) return;
    hour.failed = true; renderGlobeHour();
  } finally {hour.busy = false;}
}
function startGlobeHour() {
  const hour = globeState.hour; if (hour.started) return;
  hour.started = true;
  const tick = async () => {
    if (!state.paused && !document.hidden) await refreshGlobeHour();
    hour.timer = window.setTimeout(tick, Math.max(2, state.config.refresh_seconds) * 1000);
  };
  tick();
}
async function loadGlobeFile(event) {
  const input = event.currentTarget;
  const file = input.files && input.files[0];
  if (!file) return;
  const version = ++globeState.fileVersion;
  globeState.mapping = null;
  byId('activity-globe-clear').disabled = true;
  renderGlobeView();
  try {
    if (file.size > globeMaxBytes || file.size === 0) throw new Error('Map file must be 1–64 KiB.');
    const bytes = await file.arrayBuffer();
    if (version !== globeState.fileVersion) return;
    if (bytes.byteLength > globeMaxBytes) throw new Error('Map file must be 1–64 KiB.');
    globeState.mapping = parseGlobeMapping(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    byId('activity-globe-file-status').textContent = `${globeState.mapping.size} offline address${globeState.mapping.size === 1 ? '' : 'es'} loaded for this tab.`;
    byId('activity-globe-clear').disabled = false;
  } catch (error) {
    if (version !== globeState.fileVersion) return;
    globeState.mapping = null;
    byId('activity-globe-file-status').textContent = `Map rejected: ${error instanceof Error ? error.message : 'invalid UTF-8 or file data'}`;
  } finally {
    if (version === globeState.fileVersion) {
      input.value = '';
      renderGlobeView();
    }
  }
}
function initializeGlobe() {
  byId('activity-globe-minute').addEventListener('input', event => {
    const hour = globeState.hour; if (!hour.page) return;
    const index = Number(event.currentTarget.value);
    if (!Number.isInteger(index) || index < 0 || index > 59) return;
    hour.live = false; hour.selectedAt = hour.start + index * 60000; hour.notice = '';
    const model = renderGlobeHour(); if (model) refreshGlobeLocations(model);
  });
  byId('activity-globe-live').addEventListener('click', () => {
    const hour = globeState.hour; if (!hour.page) return;
    hour.live = true; hour.selectedAt = null; hour.notice = '';
    const model = renderGlobeHour(); if (model) refreshGlobeLocations(model);
  });
  byId('activity-globe-file').addEventListener('change', loadGlobeFile);
  byId('activity-globe-clear').addEventListener('click', () => {
    globeState.fileVersion += 1;
    globeState.mapping = null;
    byId('activity-globe-clear').disabled = true;
    byId('activity-globe-file-status').textContent = 'Map cleared from this tab.';
    renderGlobeView();
  });
  document.addEventListener('visibilitychange', () => renderGlobeView());
  renderGlobeView();
}
"""

GLOBE_JS = GLOBE_JS.replace('__GLOBE_LAND_MASK__', LAND_MASK_BASE64)
