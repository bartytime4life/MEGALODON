"""Local, presentation-only activity globe for the qualified traffic projection."""

from .dashboard_globe_land import LAND_MASK_BASE64

GLOBE_HTML = """
<section class="activity-globe" id="activity-globe" aria-labelledby="activity-globe-title">
  <div class="activity-globe-head">
    <div><p class="eyebrow">Offline source context</p><h3 id="activity-globe-title">Activity globe</h3></div>
    <span class="activity-globe-state" id="activity-globe-state">Waiting for traffic</span>
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
      <p class="activity-globe-note">Markers reflect your offline IP mapping, rounded to about 5°. IP location may be wrong; this does not establish a device, person, or origin.</p>
    </div>
  </div>
  <div class="activity-globe-controls">
    <label for="activity-globe-file">Choose local IP map CSV <span>(up to 64 KiB, 500 rows)</span></label>
    <input id="activity-globe-file" type="file" accept=".csv,text/csv">
    <button type="button" id="activity-globe-clear" disabled>Clear map</button>
    <p id="activity-globe-file-status" role="status" aria-live="polite">No file selected. Mapping stays in this browser tab only.</p>
    <details><summary>CSV format</summary><code>ip,latitude,longitude,label<br>203.0.113.8,40,-75,Reviewed region</code><p>Exact IP match; IPv4 or plain IPv6. One unquoted row per address. Coordinates are rounded for display. The file is never uploaded or saved by the HUD.</p></details>
  </div>
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
.activity-globe.stale .activity-globe-list li { border-color: #7f6a45; background: #28271e; }
.activity-globe.stale .activity-globe-list .matched span { color: #f4d58f; }
.activity-globe.stale .activity-globe-list-heading { color: #f4d58f; }
.activity-globe-note { margin: 10px 0 0; color: #b8ced6; font-size: .73rem; line-height: 1.5; }
.activity-globe-controls { display: flex; flex-wrap: wrap; align-items: center; gap: 9px 13px; padding: 13px 18px 15px; border-top: 1px solid #294957; background: #091f2b; }
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
@media (max-width: 900px) { .activity-globe-body { grid-template-columns: 1fr; gap: 8px; } .activity-globe-stage { width: min(100%,360px); } .activity-globe-head { align-items: flex-start; } }
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
}
@media (prefers-reduced-motion: reduce) { .activity-globe-ping::after { animation: none; opacity: .65; transform: scale(.7); } }
@media (forced-colors: active) { .activity-globe-ping { background: Highlight; border-color: CanvasText; } .activity-globe-ping::after { border-color: Highlight; } }
"""

GLOBE_JS = r"""
const globeState = {mapping: null, traffic: null, stale: false, latitude: 20, longitude: -20, frame: null, fileVersion: 0};
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
function globeViewModel(traffic, mapping, stale = false) {
  if (!traffic || traffic.status !== 'available') return {kind: 'unavailable', entries: [], active: null};
  if (!traffic.events.length) return {kind: 'empty', entries: [], active: null};
  const ordered = [...traffic.events].sort((a, b) =>
    Date.parse(b.observed_at) - Date.parse(a.observed_at) ||
    (BigInt(b.id) > BigInt(a.id) ? 1 : BigInt(b.id) < BigInt(a.id) ? -1 : 0));
  const seen = new Set(), entries = [];
  for (const event of ordered) {
    const address = normalizeGlobeIp(event.src_ip);
    if (!address || seen.has(address)) continue;
    seen.add(address);
    entries.push({ip: event.src_ip, location: mapping ? mapping.get(address) || null : null, observed_at: event.observed_at});
    if (entries.length === 5) break;
  }
  if (stale) return {kind: 'stale', entries, active: null};
  if (!mapping) return {kind: 'no-map', entries, active: null};
  // The latest mapped event may fall beyond the five visible distinct addresses.
  const mapped = ordered.find(event => mapping.has(normalizeGlobeIp(event.src_ip)));
  return {kind: mapped ? 'mapped' : 'unmapped', entries,
    active: mapped ? {ip: mapped.src_ip, observed_at: mapped.observed_at,
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
function renderGlobeView() {
  const view = globeViewModel(globeState.traffic, globeState.mapping, globeState.stale);
  const panel = byId('activity-globe'), badge = byId('activity-globe-state');
  panel.className = `activity-globe${view.kind === 'stale' ? ' stale' : ''}${document.hidden ? ' hidden-page' : ''}`;
  badge.className = `activity-globe-state${view.kind === 'mapped' ? ' mapped' : view.kind === 'stale' ? ' stale' : ''}`;
  const labels = {stale: 'Stale snapshot', unavailable: 'Unavailable', empty: 'No records',
    'no-map': 'Map needed', unmapped: 'No match', mapped: 'Mapped context'};
  badge.textContent = labels[view.kind];
  const overviewStatus = byId('room-globe-entry-status');
  const overviewLabels = {stale: 'Previous traffic snapshot · no current marker',
    unavailable: 'Qualified traffic unavailable', empty: 'No qualified records yet',
    'no-map': 'Recent IPs available · choose a local map',
    unmapped: 'Recent IPs available · no map match', mapped: 'Mapped source context available'};
  if (overviewStatus.textContent !== overviewLabels[view.kind]) overviewStatus.textContent = overviewLabels[view.kind];
  const lead = byId('activity-globe-lead');
  lead.textContent = view.kind === 'mapped'
    ? `Latest mapped source: ${view.active.ip} · ${view.active.location.label}. Approximate region only.`
    : view.kind === 'stale' ? 'Traffic refresh failed. No current location ping is shown.'
    : view.kind === 'unavailable' ? 'Qualified traffic is unavailable. No location is shown.'
    : view.kind === 'empty' ? 'No qualified stored events are available for mapping.'
    : view.kind === 'no-map' ? 'Choose a reviewed local CSV to place source IPs on the globe.'
    : 'No recent source IP matches the selected offline map.';
  const items = view.entries.map(entry => {
    const item = document.createElement('li'); item.className = entry.location ? 'matched' : '';
    item.append(textNode('code', entry.ip), textNode('span', entry.location ? entry.location.label : 'Unmapped'));
    return item;
  });
  byId('activity-globe-list-heading').textContent = view.kind === 'stale'
    ? 'Previous snapshot · source IPs and map labels' : 'Recent source IPs';
  const list = byId('activity-globe-list');
  list.setAttribute('aria-label', view.kind === 'stale'
    ? 'Previous snapshot source IP mapping status' : 'Recent source IP mapping status');
  list.replaceChildren(...items);
  orientGlobe(view);
}
function renderGlobe(traffic) { globeState.traffic = traffic; globeState.stale = false; renderGlobeView(); }
function renderGlobeUnavailable(preserve) {
  globeState.stale = preserve;
  if (!preserve) globeState.traffic = null;
  renderGlobeView();
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
