"""HUD visual polish: supporting-app status dots, motion and one-click choices.

Presentation only; no side effects on import. The app status rail and the
Background tools tiles repaint from the existing tool heartbeat
(``heartbeatState``) and never fetch on their own. Choice chips mirror an
existing ``<select>`` or fill an existing input, then dispatch the same
``input``/``change`` events a person would, so every reviewed handler, bound
and validation rule stays the single source of truth.
"""

# Fixed order and short names match ``workflowToolIds`` and the heartbeat probes.
APP_RAIL_TOOLS = (
    ("core", "MEGALODON"), ("tshark", "TShark"), ("zeek", "Zeek"), ("suricata", "Suricata"),
    ("scapy", "Scapy"), ("nftables", "nftables"), ("clamav", "ClamAV"), ("osquery", "osquery"),
    ("qwen", "Ollama"), ("nmap", "Nmap"),
)


def _rail_items() -> str:
    return "".join(
        f'<li><a class="app-dot-chip" data-app-rail="{tool}" href="#setup-app-{tool}" data-state="unknown">'
        f'<i class="app-dot" aria-hidden="true"></i><span class="app-dot-name">{name}</span>'
        f'<span class="sr-only app-dot-state">status checking</span></a></li>'
        for tool, name in APP_RAIL_TOOLS
    )


def _tile_items() -> str:
    return "".join(
        f'<li><a class="app-tile" data-app-tile="{tool}" href="#setup-app-{tool}" data-state="unknown">'
        f'<i class="app-dot" aria-hidden="true"></i><span class="app-tile-name">{name}</span>'
        f'<span class="app-tile-state">Checking…</span></a></li>'
        for tool, name in APP_RAIL_TOOLS
    )


APP_RAIL_HTML = (
    '<nav class="app-rail" id="app-rail" aria-label="Supporting apps status">'
    '<span class="app-rail-label" aria-hidden="true">Apps</span>'
    f'<ul class="app-rail-items">{_rail_items()}</ul>'
    '<span class="app-rail-summary" id="app-rail-summary">Checking apps…</span>'
    '<button type="button" class="app-rail-recheck" id="app-rail-recheck" title="Check supporting apps now" '
    'aria-label="Check supporting apps now"><span aria-hidden="true">↻</span></button>'
    '</nav>'
)

APP_TILES_HTML = (
    '<div class="app-tiles" aria-labelledby="app-tiles-title">'
    '<p class="app-tiles-head"><span id="app-tiles-title">Supporting apps on this PC</span>'
    '<span class="app-tiles-legend" aria-hidden="true"><span><i class="app-dot" data-legend="running"></i>Running</span>'
    '<span><i class="app-dot" data-legend="ready"></i>Installed</span><span><i class="app-dot" data-legend="stopped"></i>Stopped</span>'
    '<span><i class="app-dot" data-legend="missing"></i>Not installed</span></span></p>'
    f'<ul class="app-tiles-grid">{_tile_items()}</ul></div>'
)


def compose_polish(html: str) -> str:
    """Place the status rail in the top bar and the tiles in Background tools."""
    html = html.replace(
        '    <div class="connection-state">',
        '    ' + APP_RAIL_HTML + '\n    <div class="connection-state">', 1)
    return html.replace(
        '  <div class="support-apps-feedback">',
        '  ' + APP_TILES_HTML + '\n  <div class="support-apps-feedback">', 1)


POLISH_CSS = r'''
/* ---- Polish layer: tokens, motion, depth. Loaded last; reduced motion disables all of it. ---- */
:root { --glow-teal: rgba(81,230,207,.55); --dot-running:#3ddc84; --dot-ready:#7fe0a8; --dot-stopped:#f5b642; --dot-missing:#ff5c5c; --dot-unknown:#6c7f8a; --ease-out:cubic-bezier(.2,.8,.2,1); }
body::after { content:""; position:fixed; inset:-20%; pointer-events:none; z-index:0; opacity:.55;
  background: radial-gradient(40rem 26rem at 20% 10%, rgba(42,180,190,.10), transparent 70%),
              radial-gradient(34rem 24rem at 85% 30%, rgba(70,120,210,.09), transparent 70%),
              radial-gradient(30rem 22rem at 50% 95%, rgba(61,220,132,.05), transparent 70%);
  animation: polish-aurora 38s ease-in-out infinite alternate; }
.shell { z-index:1; }
@keyframes polish-aurora { from { transform:translate3d(-2%,-1%,0) rotate(0deg); } to { transform:translate3d(2%,2%,0) rotate(4deg); } }

/* Links that no component styles fall back to the palette instead of the browser's lavender/purple.
   Zero specificity: every existing component link rule still wins. */
:where(.shell) :where(a:link, a:visited) { color:#8fe9e0; text-decoration-thickness:1px; text-underline-offset:3px; }
:where(.shell) :where(a:hover) { color:#c4fbf3; }
.ki-strip { align-items:center; }
.ki-strip a { font-size:.9rem; font-weight:650; text-decoration:none; padding:.35rem .1rem; border-bottom:1px solid rgba(143,233,224,.45); }
.ki-strip a:hover { border-bottom-color:#c4fbf3; }
.ki-strip a:focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }

/* Brand mark breathes softly; it is decorative. */
.mark { position:relative; overflow:hidden; animation: polish-breathe 6s ease-in-out infinite; }
.mark::after { content:""; position:absolute; inset:-40%; background:linear-gradient(115deg,transparent 40%,rgba(255,255,255,.22) 50%,transparent 60%); transform:translateX(-120%); animation: polish-sheen 7s ease-in-out infinite; }
@keyframes polish-breathe { 50% { box-shadow: inset 0 1px rgba(255,255,255,.1), 0 0 26px rgba(81,230,207,.32); } }
@keyframes polish-sheen { 0%,70% { transform:translateX(-120%); } 100% { transform:translateX(120%); } }

/* ---- Supporting-app status rail (top bar) ---- */
.topbar { gap:10px 14px; flex-wrap:wrap; }
.app-rail { order:3; display:flex; align-items:center; gap:.55rem; min-width:0; flex:1 1 100%; padding:.25rem .4rem .25rem .8rem; border:1px solid rgba(148,188,202,.18); border-radius:999px; background:linear-gradient(180deg,rgba(9,28,38,.78),rgba(4,14,20,.7)); box-shadow: inset 0 1px rgba(255,255,255,.05), 0 8px 26px -14px rgba(0,0,0,.7); }
.app-rail-label { color:var(--muted); font-size:.62rem; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
.app-rail-items { display:flex; flex:1 1 auto; flex-wrap:nowrap; gap:.15rem; margin:0; padding:0; list-style:none; overflow-x:auto; scrollbar-width:none; min-width:0; }
.app-rail-items::-webkit-scrollbar { display:none; }
.app-dot-chip { position:relative; display:inline-flex; align-items:center; gap:.35rem; min-height:30px; padding:.2rem .5rem; border-radius:999px; color:#c9dde5; font-size:.72rem; font-weight:700; text-decoration:none; white-space:nowrap; border:1px solid transparent; transition: background-color .2s, border-color .2s, color .2s, transform .15s var(--ease-out); }
.app-dot-chip:hover { background:rgba(81,230,207,.08); border-color:rgba(81,230,207,.28); color:#effffb; transform:translateY(-1px); }
.app-dot-chip:focus-visible { outline:2px solid #a6f4df; outline-offset:2px; }
.app-rail-summary { color:#b9cdd6; font-size:.7rem; font-weight:700; white-space:nowrap; }
.app-rail-recheck { display:inline-grid; place-items:center; width:30px; height:30px; min-height:30px; padding:0; border-radius:50%; border:1px solid rgba(148,188,202,.28); background:rgba(81,230,207,.06); color:#bff7ee; font:inherit; font-size:1rem; cursor:pointer; transition: transform .5s var(--ease-out), background-color .2s, border-color .2s; }
.app-rail-recheck:hover { background:rgba(81,230,207,.16); border-color:rgba(81,230,207,.5); }
.app-rail-recheck:focus-visible { outline:2px solid #a6f4df; outline-offset:2px; }
.app-rail-recheck[aria-busy="true"] span { display:inline-block; animation: polish-spin .9s linear infinite; }
@keyframes polish-spin { to { transform:rotate(360deg); } }

/* Shared dot: green running (pulsing), soft green installed, amber stopped, red missing, grey unknown. */
.app-dot { position:relative; display:inline-block; flex:none; box-sizing:border-box; width:.62rem; height:.62rem; border-radius:50%; background:var(--dot-unknown); box-shadow:0 0 0 2px rgba(0,0,0,.35); transition: background-color .35s, box-shadow .35s, border-radius .35s, transform .35s var(--ease-out); }
[data-state="running"] > .app-dot, .app-dot[data-legend="running"] { background:var(--dot-running); box-shadow:0 0 .5rem rgba(61,220,132,.85); }
[data-state="running"] > .app-dot::after { content:""; position:absolute; inset:-3px; border-radius:50%; border:2px solid rgba(61,220,132,.7); animation: polish-ping 2.2s var(--ease-out) infinite; }
[data-state="ready"] > .app-dot, .app-dot[data-legend="ready"] { background:var(--dot-ready); box-shadow:0 0 .35rem rgba(127,224,168,.55); }
[data-state="stopped"] > .app-dot, [data-state="attention"] > .app-dot, .app-dot[data-legend="stopped"] { background:var(--dot-stopped); box-shadow:0 0 .45rem rgba(245,182,66,.7); }
[data-state="missing"] > .app-dot, .app-dot[data-legend="missing"] { background:var(--dot-missing); box-shadow:0 0 .45rem rgba(255,92,92,.7); }
[data-state="unknown"] > .app-dot { animation: hb-pulse 1.6s ease-in-out infinite; }
#app-rail[data-stale="true"] .app-dot { animation:none; opacity:.55; }
/* Shape carries the state as well as hue, so red/green colour vision is never required:
   filled circle = running or installed, diamond = stopped or needs setup,
   hollow ring = not installed, dashed ring = unknown. */
[data-state="stopped"] > .app-dot, [data-state="attention"] > .app-dot, .app-dot[data-legend="stopped"] { border-radius:2px; transform:rotate(45deg) scale(.86); }
[data-state="missing"] > .app-dot, .app-dot[data-legend="missing"] { background:transparent; border:2px solid var(--dot-missing); box-shadow:0 0 .4rem rgba(255,92,92,.55); }
[data-state="unknown"] > .app-dot { background:transparent; border:2px dashed var(--dot-unknown); box-shadow:none; }
@keyframes polish-ping { 0% { transform:scale(.6); opacity:.9; } 80%,100% { transform:scale(1.9); opacity:0; } }

/* ---- Supporting-app tiles inside Background tools ---- */
.app-tiles { margin:.8rem 0 .2rem; }
.app-tiles-head { display:flex; flex-wrap:wrap; justify-content:space-between; gap:.4rem 1rem; margin:0 0 .5rem; color:#cfe2ea; font-size:.78rem; font-weight:700; letter-spacing:.02em; }
.app-tiles-legend { display:inline-flex; flex-wrap:wrap; gap:.75rem; color:#9fb7c2; font-weight:600; font-size:.7rem; }
.app-tiles-legend span { display:inline-flex; align-items:center; gap:.35rem; }
.support-apps .app-tiles-grid > li { display:block; grid-template-columns:none; padding:0; border:0; }
.app-tiles-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(max(10.5rem,calc(20% - .45rem)),1fr)); gap:.45rem; margin:0; padding:0; list-style:none; }
.app-tile { position:relative; display:grid; grid-template-columns:auto 1fr; grid-template-areas:"dot name" "dot state"; align-items:center; column-gap:.55rem; min-height:44px; padding:.45rem .65rem; border:1px solid #2c4c5b; border-radius:10px; background:linear-gradient(160deg,rgba(24,56,71,.55),rgba(8,26,35,.75)); color:#e6f3f7; text-decoration:none; overflow:hidden; transition: transform .2s var(--ease-out), border-color .2s, box-shadow .2s, background-color .2s; }
.app-tile > .app-dot { grid-area:dot; }
.app-tile-name { grid-area:name; font-size:.8rem; font-weight:750; line-height:1.25; }
.app-tile-state { grid-area:state; color:#9fb7c2; font-size:.68rem; line-height:1.3; }
.app-tile:hover { transform:translateY(-2px); border-color:rgba(81,230,207,.55); box-shadow:0 10px 24px -14px var(--glow-teal); }
.app-tile:focus-visible { outline:3px solid #a6f4df; outline-offset:2px; }
.app-tile[data-state="running"] { border-color:rgba(61,220,132,.38); }
.app-tile[data-state="running"] .app-tile-state { color:#9bf0c2; }
.app-tile[data-state="stopped"] .app-tile-state, .app-tile[data-state="attention"] .app-tile-state { color:#f2ce8b; }
.app-tile[data-state="missing"] .app-tile-state { color:#ffaaa0; }
.app-tile[data-state="missing"] { border-color:rgba(255,92,92,.28); }

/* Apps & connections cards carry the same dot in their heading. */
.apps-setup-card > summary .hb-light { margin-left:.15rem; }
.apps-setup .apps-setup-filters { padding:0 22px .9rem; margin:0; }

/* ---- Navigation: animated selection bar and hover glow ---- */
.section-nav { position:relative; backdrop-filter: blur(6px); }
.section-nav button { position:relative; overflow:hidden; transition: color .2s, background-color .2s, border-color .2s, box-shadow .25s; }
.section-nav button::after { content:""; position:absolute; left:18%; right:18%; bottom:4px; height:2px; border-radius:2px; background:linear-gradient(90deg,transparent,#a6f4df,transparent); transform:scaleX(0); opacity:0; transition: transform .35s var(--ease-out), opacity .35s; }
.section-nav button:hover::after { transform:scaleX(.5); opacity:.6; }
.section-nav button[aria-selected="true"]::after { transform:scaleX(1); opacity:1; }
.section-nav button[aria-selected="true"] { text-shadow:0 0 14px rgba(166,244,223,.45); }

/* ---- Views rise in when a tab opens ---- */
.workspace-view:not([hidden]) > *, .workspace-view:not([hidden]) > .ops-desk > * { animation: polish-rise .5s var(--ease-out) both; }
.workspace-view:not([hidden]) > :nth-child(2), .workspace-view:not([hidden]) > .ops-desk > :nth-child(2) { animation-delay:.04s; }
.workspace-view:not([hidden]) > :nth-child(3), .workspace-view:not([hidden]) > .ops-desk > :nth-child(3) { animation-delay:.08s; }
.workspace-view:not([hidden]) > :nth-child(4), .workspace-view:not([hidden]) > .ops-desk > :nth-child(4) { animation-delay:.12s; }
.workspace-view:not([hidden]) > :nth-child(n+5), .workspace-view:not([hidden]) > .ops-desk > :nth-child(n+5) { animation-delay:.16s; }
@keyframes polish-rise { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:none; } }

/* ---- Panels: glass depth and a soft hover edge ---- */
:is(.panel,.support-apps,.storage-panel,.network-panel,.live-globe,.support-config,.network-setup,.ops-location-setup,.companion-panel,.reports-desk,.analysis-window,.action-plane,.app-service-start,.setup-software,.setup-health,.hud-start,.pc-live,.ops-pulse,.ops-endpoints,.ops-defense) {
  transition: border-color .3s, box-shadow .3s; }
:is(.panel,.storage-panel,.network-panel,.support-config,.network-setup,.companion-panel,.reports-desk,.action-plane,.setup-software,.setup-health):hover { border-color:rgba(110,216,255,.34); box-shadow:0 18px 50px -30px rgba(81,230,207,.45); }
.workspace-view .support-apps, .ops-desk .support-apps { position:relative; overflow:hidden; border-radius:10px; background:linear-gradient(135deg,rgba(20,58,72,.72),rgba(9,30,40,.92) 55%,rgba(10,26,38,.95)); box-shadow:0 16px 40px -26px rgba(0,0,0,.8), inset 0 1px rgba(255,255,255,.05); }
.workspace-view .support-apps::before, .ops-desk .support-apps::before { content:""; position:absolute; inset:0 0 auto 0; height:1px; background:linear-gradient(90deg,transparent,rgba(117,230,225,.8),transparent); background-size:200% 100%; animation: polish-scan 6s linear infinite; pointer-events:none; }
@keyframes polish-scan { from { background-position:200% 0; } to { background-position:-200% 0; } }

/* ---- Buttons: rounded, lifted on hover, pressed on click, sheen on primary ---- */
.shell button:not(.app-rail-recheck):not([role="tab"]) { transition: background-color .18s, border-color .18s, box-shadow .2s, transform .14s var(--ease-out), color .18s; }
.shell :is(.ops-desk,.workspace-view) button:not(.app-rail-recheck):not(.polish-chip) { border-radius:8px; }
.shell button:not(:disabled):not([role="tab"]):not(.polish-chip):hover { transform:translateY(-1px); box-shadow:0 8px 20px -12px var(--glow-teal); border-color:rgba(117,230,225,.6); }
.shell button:not(:disabled):not([role="tab"]):active { transform:translateY(0) scale(.98); box-shadow:none; }
#support-apps-start:not(:disabled), #storage-preview:not(:disabled), .hb-install:not(:disabled) { position:relative; overflow:hidden; }
.ops-desk #support-apps-start, .support-apps #support-apps-start { background:linear-gradient(135deg,#7cf0e6,#4fcfd8); border-color:#7cf0e6; color:#04202a; box-shadow:0 6px 22px -10px rgba(117,230,225,.9); }
.ops-desk #support-apps-start:not(:disabled):hover, .support-apps #support-apps-start:not(:disabled):hover { background:linear-gradient(135deg,#a2f7ef,#68e0e6); }
:is(#support-apps-start,.hb-install):not(:disabled)::after { content:""; position:absolute; top:0; bottom:0; width:40%; left:-60%; background:linear-gradient(100deg,transparent,rgba(255,255,255,.45),transparent); transform:skewX(-18deg); pointer-events:none; }
:is(#support-apps-start,.hb-install):not(:disabled):hover::after { animation: polish-button-sheen .8s var(--ease-out); }
@keyframes polish-button-sheen { to { left:130%; } }

/* ---- Inputs and disclosure ---- */
.shell :is(input:not([type="checkbox"]):not([type="radio"]):not([type="range"]),select,textarea) { transition: border-color .2s, box-shadow .2s, background-color .2s; }
.shell :is(input:not([type="checkbox"]):not([type="radio"]):not([type="range"]),select,textarea):focus { border-color:#75e6e1; box-shadow:0 0 0 3px rgba(117,230,225,.18); }
.shell details > summary { transition: color .2s; }
.shell details > summary:hover { color:#bff7ee; }
.shell details[open] > :not(summary) { animation: polish-unfold .28s var(--ease-out) both; }
@keyframes polish-unfold { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }

/* ---- Numbers glow faintly so live values read first ---- */
:is(.ops-primary-strip strong,.metric-value,.pc-live strong) { text-shadow:0 0 18px rgba(117,230,225,.18); }

/* ---- Scrollbars ---- */
.workspace-scroll::-webkit-scrollbar { width:10px; }
.workspace-scroll::-webkit-scrollbar-thumb { background:linear-gradient(180deg,#2d5563,#1b3a46); border-radius:10px; border:2px solid #061017; }
.workspace-scroll::-webkit-scrollbar-thumb:hover { background:#3d6f80; }

/* ---- One-click choice chips and preset buttons ---- */
/* The mirrored select stays in the layout tree (transparent, inert to pointers) so automation and form state still reach it. */
.polish-native { position:absolute !important; width:2px !important; height:2px !important; min-height:0 !important; min-width:0 !important; padding:0 !important; margin:0 !important; border:0 !important; opacity:0 !important; pointer-events:none !important; }
.polish-chips { display:flex; flex-wrap:wrap; gap:.35rem; margin:.3rem 0; padding:0; }
.shell .polish-chip { display:inline-flex; align-items:center; gap:.3rem; min-height:34px; padding:.3rem .75rem; border:1px solid #3c6070; border-radius:999px; background:rgba(10,32,42,.85); color:#cfe4ec; font:inherit; font-size:.78rem; font-weight:650; line-height:1.2; cursor:pointer; transition: background-color .18s, border-color .18s, color .18s, box-shadow .2s, transform .14s var(--ease-out); }
.shell .polish-chip:hover:not(:disabled) { border-color:#75e6e1; color:#f2fffd; background:rgba(117,230,225,.1); transform:translateY(-1px); box-shadow:0 6px 16px -10px var(--glow-teal); }
.shell .polish-chip[aria-pressed="true"] { border-color:#75e6e1; background:linear-gradient(135deg,rgba(117,230,225,.3),rgba(110,216,255,.14)); color:#effffd; box-shadow:inset 0 1px rgba(255,255,255,.1), 0 0 0 1px rgba(117,230,225,.25); }
.shell .polish-chip[aria-pressed="true"]::before { content:"✓"; font-size:.72rem; color:#a6f4df; }
.shell .polish-chip:disabled { opacity:.5; cursor:default; }
.shell .polish-chip:focus-visible { outline:3px solid #a6f4df; outline-offset:2px; }
.polish-presets { display:flex; flex-wrap:wrap; align-items:center; gap:.3rem; margin:.4rem 0 .1rem; font-weight:400; letter-spacing:normal; text-transform:none; }
.reference-grid { grid-auto-flow:row dense; }
.reference-grid > .polish-presets { grid-column:1 / -1; margin:0; }
.polish-presets-label { color:#9fb7c2; font-size:.7rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase; margin-right:.15rem; }
.shell .polish-presets .polish-chip { min-height:30px; padding:.2rem .6rem; font-size:.74rem; }

/* Compact contexts keep chips on one line. */
.ops-unit-label .polish-chips, .live-motion-controls .polish-chips { flex-wrap:nowrap; margin:0; gap:.25rem; }
.shell .ops-unit-label .polish-chip { min-height:28px; padding:.15rem .55rem; font-size:.7rem; }

/* ---- Small screens: names stay visible; the rail scrolls sideways with a fading edge ---- */
@media (max-width: 900px) {
  .app-rail-items { scroll-snap-type:x proximity; scroll-padding-inline:.4rem; overscroll-behavior-x:contain;
    -webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 2rem),transparent); mask-image:linear-gradient(90deg,#000 calc(100% - 2rem),transparent); padding-right:1.6rem; }
  .app-dot-chip { scroll-snap-align:start; padding:.2rem .45rem; font-size:.7rem; }
}
@media (max-width: 560px) {
  .app-rail { flex-wrap:wrap; border-radius:16px; row-gap:.15rem; padding:.3rem .35rem .3rem .55rem; }
  .app-rail-label { display:none; } .app-rail-items { flex:1 1 100%; }
  .app-dot-chip { min-height:36px; }
  .app-rail-summary { flex:1 1 auto; font-size:.66rem; white-space:normal; }
  /* The header pill gets its own row instead of wrapping beside the wordmark. */
  .topbar > .connection-state { flex:1 1 100%; display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:4px 8px; }
  .topbar > .connection-state .connection { flex:1 1 15rem; min-width:0; }
}
@media (max-width: 600px) {
  .app-tiles-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .app-tiles-legend { display:none; }
  /* The primary action owns a full row so its label never breaks across three lines. */
  .support-apps #support-apps-start { flex:1 1 100%; }
}
@media (prefers-reduced-motion: reduce) {
  body::after, .mark, .mark::after, .app-dot, .app-dot::after, .app-rail-recheck span, .workspace-view > *, .ops-desk > *, .support-apps::before, .shell details[open] > * { animation:none !important; }
  .shell button, .app-tile, .app-dot-chip, .polish-chip { transition:none !important; transform:none !important; }
}
@media (prefers-contrast: more) {
  :root { --muted:#c6d8de; --line:rgba(170,205,216,.5); }
  body::after { display:none; }
  .app-dot { box-shadow:0 0 0 2px #000; }
  .app-tile, .app-rail, .shell .polish-chip { border-color:#7fa6b3; }
  .app-tile-state, .app-tiles-legend, .app-rail-summary, .polish-presets-label { color:#d6e6eb; }
}
@media (forced-colors: active) {
  /* System colours replace fills, so draw every dot as an outline; its shape still names the state. */
  .app-dot { border:2px solid CanvasText; background:Canvas; box-shadow:none; }
  [data-state="running"] > .app-dot, [data-state="ready"] > .app-dot, .app-dot[data-legend="running"], .app-dot[data-legend="ready"] { background:CanvasText; forced-color-adjust:none; }
  [data-state="unknown"] > .app-dot { border-style:dashed; }
  .app-dot-chip, .app-tile { border:1px solid CanvasText; }
}
@media print { .app-rail, .app-tiles, body::after { display:none !important; } }
'''

POLISH_JS = r'''
// ---- Supporting-app status rail and tiles: painted from the shared heartbeat. ----
const appRailLabels = {running: 'Running', ready: 'Installed', stopped: 'Stopped', attention: 'Needs setup', missing: 'Not installed', unknown: 'Status unknown'};
function appRailState(tool, stale) {
  if (!tool || stale) return 'unknown';
  if (tool.light === 'green') return tool.service === 'running' ? 'running' : 'ready';
  if (tool.light === 'amber') return tool.service === 'stopped' ? 'stopped' : 'attention';
  if (tool.light === 'red') return 'missing';
  return 'unknown';
}
function appRailDetail(tool, state) {
  if (state === 'running' && tool && tool.running_since && typeof heartbeatAge === 'function') return 'Running · up ' + heartbeatAge(tool.running_since);
  if (state === 'ready') return tool && tool.service === 'standalone' ? 'Installed · runs on demand' : 'Installed';
  if (state === 'attention' && tool && tool.model === 'missing') return 'Running · model missing';
  return appRailLabels[state];
}
function renderAppStatusRail() {
  if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function' || typeof heartbeatState === 'undefined') return;
  const stale = typeof heartbeatStale === 'function' && heartbeatStale();
  const counts = {running: 0, ready: 0, stopped: 0, attention: 0, missing: 0, unknown: 0};
  document.querySelectorAll('[data-app-rail],[data-app-tile]').forEach(node => {
    const id = node.getAttribute('data-app-rail') || node.getAttribute('data-app-tile');
    const tool = heartbeatState.byId.get(id);
    const state = appRailState(tool, stale);
    const detail = appRailDetail(tool, state);
    if (node.dataset) node.dataset.state = state;
    const full = typeof heartbeatText === 'function' ? heartbeatText(tool) : detail;
    node.title = full;
    if (node.hasAttribute('data-app-rail')) {
      counts[state] += 1;
      const label = node.querySelector('.app-dot-state'); if (label) label.textContent = detail;
    } else {
      const label = node.querySelector('.app-tile-state'); if (label) label.textContent = detail;
    }
  });
  if (typeof window !== 'undefined' && typeof window.megalodonAppsRefilter === 'function') window.megalodonAppsRefilter();
  const rail = document.getElementById('app-rail');
  if (rail && rail.dataset) rail.dataset.stale = stale ? 'true' : 'false';
  const summary = document.getElementById('app-rail-summary');
  if (summary) {
    if (!heartbeatState.report) summary.textContent = heartbeatState.failed ? 'Status unavailable' : 'Checking apps…';
    else if (stale) summary.textContent = 'Status stale · retrying';
    else {
      const parts = [counts.running + ' running'];
      if (counts.ready) parts.push(counts.ready + ' installed');
      if (counts.stopped + counts.attention) parts.push((counts.stopped + counts.attention) + ' stopped');
      if (counts.missing) parts.push(counts.missing + ' missing');
      summary.textContent = parts.join(' · ');
    }
  }
}
(() => {
  // Cosmetic enhancements need a real browser DOM; test harnesses with stub documents skip them.
  if (typeof document === 'undefined' || typeof document.querySelectorAll !== 'function'
      || typeof MutationObserver !== 'function' || typeof HTMLSelectElement === 'undefined') return;
  const recheck = document.getElementById('app-rail-recheck');
  if (recheck) recheck.addEventListener('click', async () => {
    if (typeof pollHeartbeat !== 'function' || recheck.getAttribute('aria-busy') === 'true') return;
    recheck.setAttribute('aria-busy', 'true');
    try { await pollHeartbeat(true); } finally { recheck.setAttribute('aria-busy', 'false'); renderAppStatusRail(); }
  });
  renderAppStatusRail();

  const make = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const fire = node => { node.dispatchEvent(new Event('input', {bubbles: true})); node.dispatchEvent(new Event('change', {bubbles: true})); };
  const labelFor = node => { const label = node.id && document.querySelector('label[for="' + node.id + '"]'); return (label ? label.textContent : node.closest('label')?.textContent || node.getAttribute('aria-label') || '').trim().slice(0, 80); };

  // Reviewed code often sets .value directly without events; keep chips in step with it.
  function watchValue(node, proto, sync) {
    const native = Object.getOwnPropertyDescriptor(proto, 'value');
    try { Object.defineProperty(node, 'value', {configurable: true, get() { return native.get.call(this); }, set(v) { native.set.call(this, v); sync(); }}); } catch (_) { /* chips still follow input and change events */ }
  }
  // Segmented chips mirror a short <select>; the select stays the source of truth.
  function chipSelect(select, maxLabel = 26) {
    if (!select || select.dataset.polished || select.multiple) return;
    const group = make('div', 'polish-chips'); group.setAttribute('role', 'group');
    const name = labelFor(select); if (name) group.setAttribute('aria-label', name);
    select.dataset.polished = 'true';
    select.insertAdjacentElement('afterend', group);
    const build = () => {
      const options = [...select.options];
      const usable = options.length >= 2 && options.length <= 8 && options.every(o => o.textContent.trim().length <= maxLabel && o.value !== '');
      select.classList.toggle('polish-native', usable); group.hidden = !usable;
      if (usable) { select.tabIndex = -1; select.setAttribute('aria-hidden', 'true'); }
      else { select.removeAttribute('tabindex'); select.removeAttribute('aria-hidden'); }
      group.replaceChildren(...(usable ? options.map(option => {
        const chip = make('button', 'polish-chip', option.textContent.trim()); chip.type = 'button'; chip.dataset.value = option.value;
        chip.addEventListener('click', () => { if (select.disabled || select.value === option.value) return; select.value = option.value; fire(select); sync(); });
        return chip;
      }) : []));
      sync();
    };
    const sync = () => group.querySelectorAll('.polish-chip').forEach(chip => {
      chip.setAttribute('aria-pressed', chip.dataset.value === select.value ? 'true' : 'false');
      chip.disabled = select.disabled || [...select.options].some(o => o.value === chip.dataset.value && o.disabled);
    });
    watchValue(select, HTMLSelectElement.prototype, sync);
    select.addEventListener('change', sync);
    new MutationObserver(build).observe(select, {childList: true, subtree: true, characterData: true});
    new MutationObserver(sync).observe(select, {attributes: true, attributeFilter: ['disabled']});
    build();
  }
  ['room-range', 'ops-speed-unit', 'live-globe-camera', 'network-view', 'network-page-size', 'filter-severity', 'ingestion-source',
   'reports-range', 'reports-frequency', 'storage-profile', 'support-config-scan-folder',
   'action-schedule-preset', 'integrations-platform', 'integrations-presence-filter', 'support-model-compute', 'setup-software-workflow']
    .forEach(id => { try { chipSelect(document.getElementById(id), id === 'support-model-compute' || id === 'setup-software-workflow' ? 34 : 26); } catch (_) { /* leave the native control */ } });

  // Preset buttons fill an input with a common value; bounds and validation stay with the input.
  function presets(id, title, values, submit = false) {
    const input = document.getElementById(id);
    if (!input || input.dataset.polished) return;
    input.dataset.polished = 'true';
    const row = make('div', 'polish-presets'); row.setAttribute('role', 'group'); row.setAttribute('aria-label', title + ' for ' + (labelFor(input) || id));
    row.append(make('span', 'polish-presets-label', title));
    const chips = values.map(([value, text]) => {
      const chip = make('button', 'polish-chip', text); chip.type = 'button'; chip.dataset.value = typeof value === 'function' ? '' : String(value);
      chip.addEventListener('click', () => {
        if (input.disabled || input.readOnly) return;
        const next = typeof value === 'function' ? value() : String(value); if (!next) return;
        input.value = next; fire(input); sync();
        // A lookup preset submits its own form, exactly as pressing its submit button would.
        if (submit && input.form && typeof input.form.requestSubmit === 'function') input.form.requestSubmit();
        else input.focus({preventScroll: true});
      });
      return chip;
    });
    const sync = () => chips.forEach(chip => { chip.disabled = input.disabled; chip.setAttribute('aria-pressed', chip.dataset.value !== '' && chip.dataset.value === input.value ? 'true' : 'false'); });
    row.append(...chips);
    // Lookup presets sit after their form so the form keeps exactly one submit button.
    (submit && input.form ? input.form : input).insertAdjacentElement('afterend', row);
    watchValue(input, HTMLInputElement.prototype, sync);
    input.addEventListener('input', sync); input.addEventListener('change', sync);
    new MutationObserver(sync).observe(input, {attributes: true, attributeFilter: ['disabled', 'readonly']});
    sync();
  }
  const zone = () => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) { return ''; } };
  [
    ['storage-days', 'Quick', [[7, '7 days'], [14, '14 days'], [30, '30 days']]],
    ['storage-cap', 'Quick', [[5, '5 GiB'], [20, '20 GiB'], [100, '100 GiB'], [500, '500 GiB']]],
    ['support-model-timeout', 'Quick', [[60, '1 min'], [300, '5 min'], [900, '15 min']]],
    ['reference-port', 'Look up', [[22, '22 SSH'], [53, '53 DNS'], [80, '80 HTTP'], [443, '443 HTTPS'], [3389, '3389 RDP'], [445, '445 SMB']], true],
    ['reports-time', 'Quick', [['07:00', '7:00'], ['09:00', '9:00'], ['12:00', '12:00'], ['18:00', '18:00']]],
    ['action-schedule-zone', 'Quick', [[zone, 'This PC’s time zone'], ['UTC', 'UTC']]],
    ['ki-search', 'Try', [['prompt injection', 'Prompt injection'], ['ransomware', 'Ransomware'], ['phishing', 'Phishing'], ['port scan', 'Port scan'], ['DNS tunneling', 'DNS tunneling']]],
    ['setup-port', 'Quick', [[8788, '8788'], [8789, '8789'], [8790, '8790']]]
  ].forEach(([id, title, values, submit]) => { try { presets(id, title, values, submit); } catch (_) { /* leave the input as typed-only */ } });

})();
'''
