"""Anchored control-room presentation; all traffic comes from the local reader."""

from .dashboard_setup import SETUP_HTML
from .status_glossary import STATUS_GLOSSARY_CSS, STATUS_GLOSSARY_HTML

STATUS_HTML = """
<section class="room-status" aria-label="Control room status">
  <div class="room-status-headline"><span>Evidence Status</span><strong id="room-overall">Unknown</strong></div>
  <details class="room-status-details">
    <summary>More status fields</summary>
    <div class="room-status-grid">
      <div><span>Local Service</span><strong id="room-connection">Not checked</strong></div>
      <div><span>Data Coverage</span><strong id="room-coverage">Unavailable</strong></div>
      <div><span>Last Fetched</span><strong id="room-updated">Not fetched</strong></div>
      <div><span>Stored Sources</span><strong id="room-sources">Unknown</strong></div>
      <div><span>Findings</span><strong id="room-count">Unavailable</strong></div>
    </div>
  </details>
</section>
<p id="room-notice" class="room-notice" role="status" aria-live="polite">No qualified data available until the local metadata check succeeds.</p>
<div class="room-range" aria-label="Shared time range">
  <label>When?<select id="room-range"><option value="recorded">Recorded window</option><option value="now">Now (last 5 minutes)</option><option value="hour">Last hour</option><option value="today">Today (UTC)</option><option value="custom">Custom UTC</option></select></label>
  <label id="room-start-label" hidden>Start (UTC)<input id="room-start" type="datetime-local" step="1"></label>
  <label id="room-end-label" hidden>End (UTC)<input id="room-end" type="datetime-local" step="1"></label>
  <button type="button" id="room-apply">Apply time range</button><button type="button" id="room-refresh">Refresh metadata</button>
  <button type="button" id="room-pause" aria-pressed="false">Pause refresh</button>
  <button type="button" id="room-newer" hidden>Newer page</button><button type="button" id="room-older" hidden>Older page</button>
  <button type="button" id="room-latest" hidden>Return to latest</button>
  <details class="room-feed-details">
    <summary>Data scope and refresh details</summary>
    <p id="room-feed-status" role="status">Automatic refresh is waiting for configuration.</p>
    <p id="room-history-status" role="status"></p>
    <p id="room-range-description">Time range unavailable</p>
  </details>
</div>
"""

HOME_HTML = """
<section class="room-home panel" aria-labelledby="room-home-title">
  <p class="eyebrow">Continue exploring</p><h2 id="room-home-title" tabindex="-1">Review your saved evidence</h2>
  <p id="room-home-summary">No qualified data available. Your saved audit data and optional tools are checked separately.</p>
  <div class="room-actions"><a href="#setup-title">Data and tools</a><a href="#room-traffic-title">See traffic</a><a href="#room-findings-title">Review findings</a><a href="#integrations-title">Open Apps</a><a href="#room-reports-title">Make a report</a></div>
  <details><summary>How do we know?</summary><p>Only validated, bounded metadata linked to a non-sample ingestion run appears in Traffic and Findings. Imported JSONL provenance is unverified. Open Evidence for separate saved reports and audit history.</p></details>
</section>
"""

TRAFFIC_HTML = """
<section class="workspace-view" id="workspace-traffic" role="tabpanel" aria-labelledby="workspace-tab-traffic" hidden>
  <h2 id="room-traffic-title" tabindex="-1">Traffic</h2><p>Saved metadata in the shared time range. No capture starts here.</p>
  <div id="room-traffic-grid" class="room-grid"></div>
  <h3>Activity detail</h3><p>Every qualified event in this page, with its recorded source and import status. Times are UTC; imported event order can differ from capture time.</p>
  <div id="room-activity-table" class="room-table" tabindex="0" role="region" aria-label="Scrollable activity detail"></div>
</section>
<section class="workspace-view" id="workspace-findings" role="tabpanel" aria-labelledby="workspace-tab-findings" hidden>
  <h2 id="room-findings-title" tabindex="-1">Findings</h2><p>Fixed detector results linked to the qualified event set. A finding is a reason to review, not proof of malware.</p>
  <div id="room-findings-visual" class="room-grid"></div><div id="room-findings-table" class="room-table"></div>
</section>
<section class="workspace-view" id="workspace-reports" role="tabpanel" aria-labelledby="workspace-tab-reports" hidden>
  <h2 id="room-reports-title" tabindex="-1">Make a local report</h2>
  <p>Preview the exact metadata-only JSON before downloading it. Nothing is uploaded, sent, or written by the server.</p>
  <div id="room-report-flow" class="room-report-flow">
    <ol class="room-report-steps">
      <li><strong>1. Confirm range</strong><span>The shared UTC range controls the next preview.</span></li>
      <li><strong>2. Preview locally</strong><span>Review the complete bounded JSON in this browser tab.</span></li>
      <li><strong>3. Download explicitly</strong><span>Save only after the preview is ready.</span></li>
    </ol>
    <div class="room-report-actions">
      <button type="button" id="room-report-create">Preview local report</button>
      <button type="button" id="room-report-download" disabled>Download JSON report</button>
      <button type="button" id="room-report-discard" disabled>Discard preview</button>
    </div>
    <p id="room-report-context" class="room-meta">A preview holds its original range and data until you replace or discard it.</p>
    <p id="room-report-status" class="room-meta" role="status" aria-live="polite">No preview is ready.</p>
    <pre id="room-report-preview" class="room-report-preview" tabindex="0" hidden aria-label="Exact local report preview"></pre>
  </div>
</section>
<section class="workspace-view" id="workspace-help" role="tabpanel" aria-labelledby="workspace-tab-help" hidden>
  <p class="eyebrow">A little guidance</p><h2 id="room-help-title" tabindex="-1">Make yourself at home</h2>
  <p>Start with a check. Add software when you need it. Review evidence when it is available.</p>
  <div class="room-help-grid">
    <section aria-labelledby="help-here"><h3 id="help-here">You can do this here</h3>
      <ul><li>Check the local service, runtime versions, data readability, executables, and process names.</li><li>Find official downloads by workflow and check availability again after installing.</li><li>Review saved traffic and findings, filter by time, and export a local report.</li><li>Save a companion console link in Apps and open that app in its own tab.</li></ul>
      <div class="room-actions"><a href="#setup-title">Check this computer →</a><a href="#setup-software-title">Find software →</a></div>
    </section>
    <section aria-labelledby="help-terminal"><h3 id="help-terminal">Use a terminal or another app</h3>
      <p>Installing software, starting or stopping the HUD, selecting a new data source, and importing metadata happen outside this page. Downloads open the official publisher instructions.</p>
      <p>Under <a href="#setup-title">Data and tools</a>, expand “Change data for the next launch” to prepare and copy a command. In Apps, advanced checks and maintenance commands are available to copy.</p>
      <details><summary>Reopen or stop MEGALODON</summary><p id="help-launch-intro">Reading the launch method for this HUD…</p><code id="help-reopen-command">Launch command unavailable</code><p>The terminal window owns the running session. Keep it open, and press Ctrl+C there to stop the HUD. Launching does not create sample data or start a sensor.</p><p id="help-source-launch" hidden>From your reviewed repository folder, you can also run <code>./scripts/start-local.sh --check</code>, then <code>./scripts/start-local.sh</code>.</p></details>
    </section>
    <section aria-labelledby="help-data"><h3 id="help-data">Why is there no traffic?</h3>
      <p>A working HUD and tools found on your PC do not mean evidence has been collected. Traffic and Findings need qualified metadata in the selected audit store.</p>
      <p>Check the selected store in Home. To import authorized metadata, run <code>python -m megalodon run --help</code> in your terminal. For an existing completed offline run, prepare a launch command in Data and tools and review its snapshots under Evidence.</p>
      <details><summary>I imported data and still see nothing</summary><p>Refresh reads the selected store. After the first import into a previously missing store, restart the HUD. If a store is unsafe or incompatible, inspect the terminal refusal and follow the setup guide; do not weaken permissions to force it open.</p></details>
      <a href="https://github.com/bartytime4life/MEGALODON/blob/main/docs/local-pc-setup.md" target="_blank" rel="noopener noreferrer">Local PC setup and troubleshooting ↗</a>
    </section>
    <section aria-labelledby="help-language"><h3 id="help-language">Read the status with confidence</h3>
      <p>MEGALODON uses many narrow, truthful status words instead of one collapsed health signal, because each check answers a different question. The same word can still mean different things on different pages &mdash; the glossary below groups them by what each check actually does.</p>
      <p>Home shows the latest check you requested. Apps keeps its startup observations until you reopen the HUD. <strong>Stale</strong> means the saved view is old or a refresh failed; it does not by itself establish network safety.</p>
      <details><summary>Full status glossary (every page)</summary>
        __STATUS_GLOSSARY__
      </details>
      <details><summary>What stays on this computer?</summary><p>Traffic, findings, tool checks, and reports stay local. Official download links open external publisher websites. MEGALODON does not send local evidence to the hosted reference console. Qwen is optional and cannot create findings, commands, or reports.</p></details>
    </section>
  </div>
</section>
"""
if "__STATUS_GLOSSARY__" not in TRAFFIC_HTML:
    raise AssertionError("status glossary placeholder missing from TRAFFIC_HTML")
TRAFFIC_HTML = TRAFFIC_HTML.replace("__STATUS_GLOSSARY__", STATUS_GLOSSARY_HTML)


def compose_control_room(html: str) -> str:
    start = html.index('  <nav class="section-nav"')
    end = html.index('  <div class="workspace-scroll"', start)
    tabs = (("live", "Home"), ("traffic", "Traffic"), ("findings", "Findings"), ("interfaces", "Apps"),
            ("reports", "Reports"), ("analysis", "Evidence"), ("help", "Help"))
    nav = '<nav class="section-nav" aria-label="Command center workspaces" role="tablist">'
    for key, name in tabs:
        nav += f'<button id="workspace-tab-{key}" type="button" role="tab" aria-controls="workspace-{key}" aria-selected="{"true" if key == "live" else "false"}" tabindex="{0 if key == "live" else -1}">{name}</button>'
    nav += '</nav><a class="room-back" href="#page-title">← Back to Home</a>'
    html = html[:start] + '<div class="room-chrome">' + STATUS_HTML + '</div>' + nav + html[end:]
    # Preserve the older audit inspector and its IDs in the Evidence workspace.
    start = html.index('  <section class="trust-strip')
    end = html.index('  <section class="workspace-view" id="workspace-analysis"', start)
    legacy = html[start:end]
    legacy = legacy[:legacy.rfind('  </section>')].replace(SETUP_HTML, '', 1)
    # Setup describes the current launch, so keep it on Home rather than inside
    # the historical audit inspector. Its IDs and handlers stay unchanged.
    html = html[:start] + SETUP_HTML + HOME_HTML + '</section>\n' + html[end:]
    marker = '<section class="workspace-view" id="workspace-analysis" role="tabpanel" aria-labelledby="workspace-tab-analysis" hidden>'
    html = html.replace(marker, marker + '<details class="room-audit-history"><summary>Audit history — may include sample and unlinked rows</summary>' + legacy + '</details>')
    html = html.replace('  <noscript>', TRAFFIC_HTML + '  <noscript>')
    return html


ROOM_CSS = r"""
.shell { display:flex; flex-direction:column; }
.shell > .topbar,.shell > .section-nav,.room-back { flex-shrink:0; }
.room-chrome { max-height:45vh; overflow:auto; flex-shrink:1; }
.workspace-scroll { flex:1; min-height:80px; }
.section-nav { grid-template-columns:repeat(7,minmax(0,1fr)); margin:0; }
.section-nav button[aria-selected="true"] { box-shadow:inset 0 -3px 0 #a6f4df; }
.section-nav button:focus-visible { outline:3px solid #a6f4df; outline-offset:-3px; }
.room-status { margin:.7rem 0; }
.room-status-headline,.room-status-grid > div { background:#102632; border:1px solid #325061; border-radius:10px; padding:.75rem; min-width:0; }
.room-status-headline { max-width:22rem; }
.room-status-headline span,.room-status-grid span { display:block; font-size:.8rem; color:#b7cbd4; margin-bottom:.4rem; }
.room-status-headline strong,.room-status-grid strong { display:block; font-size:.96rem; overflow-wrap:anywhere; color:#f2f7f9; }
.room-status-details { margin-top:.5rem; }
.room-status-details > summary { min-height:44px; padding:.5rem 0; color:#b7cbd4; font-size:.82rem; line-height:1.5; cursor:pointer; overflow-wrap:anywhere; }
.room-status-details[open] { padding-bottom:.3rem; }
.room-status-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:.6rem; margin-top:.5rem; }
.room-notice { color:#e2d298; font-size:.88rem; margin:.35rem 0 .7rem; }
.room-range { display:flex; flex-wrap:wrap; gap:.6rem; align-items:end; }
.room-range label { display:grid; gap:.25rem; font-size:.85rem; }
.room-range select,.room-range input,.room-range button,.room-back,.room-actions a { min-height:44px; font:inherit; border:1px solid #426173; border-radius:7px; padding:.65rem .8rem; color:#e9f5f9; background:#112b38; }
.room-range p { flex-basis:100%; font-size:.78rem; color:#b7cbd4; margin:.1rem 0 .6rem; overflow-wrap:anywhere; }
.room-range button { cursor:pointer; }
.room-feed-details { flex-basis:100%; min-width:0; }
.room-feed-details > summary { min-height:44px; padding:.65rem 0; color:#b7cbd4; font-size:.82rem; line-height:1.5; cursor:pointer; overflow-wrap:anywhere; }
.room-feed-details[open] { padding-bottom:.3rem; }
.room-back { display:inline-flex; align-items:center; text-decoration:none; align-self:start; margin:.35rem 0; }
.section-nav { flex-wrap:wrap; }
.room-actions { display:flex; gap:.6rem; flex-wrap:wrap; }
.room-actions a { text-decoration:none; }
.room-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1rem; margin:1rem 0; }
.room-visual { min-width:0; background:#0e2330; border:1px solid #335064; border-radius:12px; padding:1rem; }
.room-visual h3 { font-size:1.05rem; margin:0 0 .5rem; color:#f2f7f9; }
.room-meta,.room-empty { font-size:.85rem; color:#bfd0d9; line-height:1.6; overflow-wrap:anywhere; }
.room-bars { list-style:none; padding:0; margin:.7rem 0; }
.room-bars li { display:grid; grid-template-columns:minmax(0,1fr) 5rem; gap:.2rem .5rem; margin:.6rem 0; font-size:.85rem; overflow-wrap:anywhere; }
.room-bars meter { grid-column:1/-1; width:100%; height:12px; }
.room-bars strong { text-align:right; }
.room-table { overflow:auto; max-height:50vh; }
.room-table table { min-width:580px; }
.room-table caption { text-align:left; color:#e6f3f8; padding:.6rem; }
.room-flow { display:grid; gap:.5rem; }
.room-flow p { border-left:3px solid #62d6c6; padding:.6rem; margin:0; font-family:ui-monospace,monospace; font-size:.8rem; overflow-wrap:anywhere; }
.room-visual svg { width:100%; height:140px; }
.room-visual svg rect { fill:#67dfcc; }
.room-visual svg text { fill:#c3d2da; font-size:10px; }
.room-audit-history > summary { min-height:44px; padding:1rem; color:#d9e8ef; cursor:pointer; }
.room-home p,.workspace-view > p { color:#bfd0d9; line-height:1.6; }
.room-home summary { min-height:44px; padding:.8rem 0; cursor:pointer; }
#setup-title { scroll-margin-top:2.25rem; }
.setup-journey { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1.2rem; margin:1rem 0; padding:0; list-style:none; }
.setup-journey li { min-width:0; border-left:2px solid #426173; padding-left:.8rem; }
.setup-journey strong { display:block; color:#a6f4df; font-size:.88rem; }
.setup-journey span { display:block; margin-top:.3rem; color:#bfd0d9; font-size:.82rem; line-height:1.6; }
.hud-start .setup-launch-help { border-top:1px solid var(--line); }
.hud-start .setup-launch-help code { margin:.5rem 0; }
.hud-start .setup-launch-help a { text-underline-offset:.2rem; }
.room-report-flow { display:grid; gap:1rem; max-width:900px; }
.room-report-steps { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.75rem; margin:0; padding:0; list-style:none; counter-reset:none; }
.room-report-steps li { display:grid; gap:.4rem; border:1px solid #335064; border-radius:10px; padding:.85rem; background:#0e2330; }
.room-report-steps span { color:#bfd0d9; font-size:.82rem; line-height:1.5; }
.room-report-actions { display:flex; flex-wrap:wrap; gap:.6rem; }
.room-report-actions button { min-height:44px; font:inherit; border:1px solid #426173; border-radius:7px; padding:.65rem .8rem; color:#e9f5f9; background:#112b38; cursor:pointer; }
.room-report-actions button:disabled { cursor:not-allowed; opacity:.58; }
.room-report-preview { max-height:48vh; overflow:auto; margin:0; padding:1rem; border:1px solid #335064; border-radius:10px; background:#071923; color:#dcebf0; white-space:pre-wrap; overflow-wrap:anywhere; font-size:.78rem; line-height:1.5; }
:is(.room-range,.room-actions,.room-visual,.room-table,.room-report-actions) :focus-visible,.room-report-preview:focus-visible,.room-back:focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }
@media(max-width:760px) { .section-nav { grid-template-columns:repeat(4,minmax(0,1fr)); } .room-report-steps,.setup-journey { grid-template-columns:1fr; } .room-grid { grid-template-columns:1fr; } .room-status-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .room-status-headline { max-width:none; } .room-range label { flex:1 1 140px; } .room-range select,.room-range input { max-width:100%; min-width:0; } }
@media(max-width:560px) { .room-status-grid { gap:.35rem; } .room-status-headline,.room-status-grid > div { padding:.5rem; } .room-status-headline span,.room-status-grid span { font-size:.68rem; } .room-status-headline strong,.room-status-grid strong { font-size:.78rem; } .room-range { gap:.4rem; } .room-range button { flex:1 1 130px; font-size:.82rem; } .room-notice { font-size:.78rem; } }
@media(max-height:500px) { .shell { padding-top:4px; } .topbar { display:none; } .room-chrome { max-height:25vh; } .workspace-scroll { min-height:44px; } }
@media(max-width:560px), (max-height:500px) {
  html { height:auto; overflow:auto; }
  body { height:auto; min-height:100dvh; overflow:visible; }
  .shell { height:auto; min-height:100dvh; }
  .room-chrome { max-height:none; overflow:visible; flex-shrink:0; }
  .workspace-scroll { flex:none; overflow:visible; overscroll-behavior:auto; }
  .workspace-view { min-height:0; }
}
@media(prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none!important; transition:none!important; scroll-behavior:auto!important; } }
"""

ROOM_CSS += r"""
/* Guided setup: one clear check, then software chosen by purpose. */
.hud-start { padding:clamp(16px,2.3vw,28px); gap:24px; margin:0 0 20px; border-color:#365766; background:#0c202b; }
.hud-start .setup-heading { display:flex; justify-content:space-between; align-items:flex-start; gap:20px; padding-bottom:20px; border-bottom:1px solid #304953; }
.hud-start .setup-heading h2 { font-size:clamp(1.6rem,3vw,2.15rem); letter-spacing:-.035em; line-height:1.15; }
.hud-start .setup-heading p:not(.eyebrow) { font-size:.94rem; margin:9px 0 0; }
.hud-start .setup-heading .eyebrow { color:#8cdfce; font-size:.68rem; letter-spacing:.13em; margin:0 0 9px; }
.hud-start .setup-help-link { flex-shrink:0; padding:11px 0; color:#c4e7ef; font-size:.85rem; text-underline-offset:4px; }
.setup-main { display:grid; grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr); gap:32px; align-items:start; }
.setup-main > section { min-width:0; }
.hud-start .setup-step { color:#8cdfce; font-size:.65rem; font-weight:750; letter-spacing:.14em; margin:0 0 10px; }
.hud-start .setup-main h3 { font-size:1.16rem; letter-spacing:-.025em; line-height:1.35; }
.hud-start .setup-main > section > p { font-size:.85rem; line-height:1.6; }
.setup-health { border-right:1px solid #304953; padding-right:32px; }
.setup-check-actions { display:flex; gap:9px; flex-wrap:wrap; margin:20px 0 12px; }
.hud-start .setup-primary { display:inline-flex; align-items:center; justify-content:space-between; gap:18px; background:#a6f4df; border-color:#a6f4df; color:#092c2b; font-weight:750; box-shadow:0 3px 0 #285e55; transition:background .15s,transform .15s; }
.hud-start .setup-primary:hover:not(:disabled) { background:#c5ffef; transform:translateY(-1px); }
.hud-start button:active:not(:disabled) { transform:translateY(1px); }
.hud-start button:disabled { opacity:.6; cursor:not-allowed; }
.hud-start .setup-report-button { background:transparent; font-size:.78rem; padding:.65rem .7rem; }
.hud-start .setup-check-status { min-height:40px; color:#d6ebe9; font-size:.8rem; }
.setup-check-results { border-top:1px solid #304953; border-bottom:1px solid #304953; margin:12px 0; padding:6px 0; }
.hud-start .setup-check-empty { font-size:.83rem; padding:16px 2px; color:#aebfc7; }
.setup-check-row { display:grid; grid-template-columns:24px minmax(0,1fr); gap:11px; padding:13px 0; transition:background-color .16s,opacity .16s; animation:setup-result-in .16s ease-out; }
.setup-check-results[aria-busy="true"] .setup-check-row { opacity:.65; }
@keyframes setup-result-in { from { opacity:.8; } to { opacity:1; } }
.setup-check-row + .setup-check-row { border-top:1px solid #243b46; }
.setup-check-indicator { width:22px; height:22px; display:grid; place-items:center; font-size:.78rem; font-weight:800; border:1px solid #7e7148; color:#e9d495; border-radius:6px; margin-top:2px; }
.setup-check-indicator.is-ready { color:#a6f4df; border-color:#356d63; background:#133d37; }
.setup-check-indicator.is-neutral { color:#bdd0da; border-color:#48616f; background:#112934; }
.setup-check-row strong { display:block; font-size:.69rem; font-weight:600; color:#b1c7d0; }
.setup-check-row b { display:block; margin:4px 0 5px; font-size:.89rem; font-weight:650; color:#eff8f6; overflow-wrap:anywhere; }
.hud-start .setup-check-row p { margin:0; font-size:.77rem; line-height:1.55; }
.hud-start .setup-health > .setup-check-boundary { font-size:.72rem; color:#b3cad2; padding-top:7px; }
.hud-start .setup-status-grid { margin:14px 0 8px; grid-template-columns:repeat(2,minmax(0,1fr)); }
.hud-start .setup-status-grid > div { background:#0a1a24; border-radius:7px; }
.hud-start .setup-status-grid span { font-size:.64rem; }
.hud-start .setup-status-grid b { font-size:1.05rem; font-weight:600; }
.hud-start #setup-readiness { font-size:.73rem; line-height:1.6; }
.setup-software-filters { display:grid; grid-template-columns:minmax(0,1.2fr) minmax(0,1fr); gap:12px; margin:20px 0 12px; }
.setup-software-filters label { display:grid; gap:7px; font-size:.74rem; font-weight:650; color:#d0e2e8; min-width:0; }
.setup-software-filters input,.setup-software-filters select { min-width:0; width:100%; min-height:44px; background:#081a25; color:#edf6f7; border:1px solid #426173; padding:10px 12px; border-radius:6px; font:inherit; font-size:.8rem; }
.setup-software-filters input::placeholder { color:#a7bcc6; opacity:1; }
.hud-start .setup-software-count { font-size:.73rem; margin:0 0 11px; color:#afc7d0; }
.setup-software-list { display:grid; gap:0; border-top:1px solid #36515f; }
.software-row { min-width:0; padding:18px 12px 15px; border-bottom:1px solid #36515f; transition:background-color .16s,box-shadow .16s; }
.software-row.software-checked { box-shadow:inset 3px 0 0 #a6f4df; background:#112d35; }
.software-heading { display:flex; align-items:center; gap:12px; }
.software-mark { display:grid; place-items:center; width:38px; height:38px; flex:0 0 38px; font-size:.82rem; font-weight:750; letter-spacing:-.04em; color:#a6f4df; background:#16332e; border:1px solid #31554f; border-radius:8px; }
.software-identity { min-width:0; }
.hud-start .software-identity h4 { margin:0; font-size:1rem; line-height:1.3; color:#f1f7f6; }
.software-requirement { display:block; font-size:.68rem; color:#b2c6ce; margin-top:4px; }
.hud-start .software-purpose { margin:12px 0 6px; font-size:.84rem; }
.hud-start .software-presence { font-size:.7rem; color:#bddbd8; margin:6px 0 12px; }
.software-actions { display:flex; gap:8px; flex-wrap:wrap; }
.software-actions > [data-heartbeat-install] { min-width:0; max-width:100%; overflow-wrap:anywhere; }
.hud-start .software-actions > a,.hud-start .software-actions > button { display:inline-flex; align-items:center; justify-content:center; padding:10px 12px; min-height:44px; border:1px solid #416674; border-radius:6px; font-size:.76rem; font-weight:600; text-decoration:none; color:#e2f5f4; background:#183845; }
.hud-start .software-actions > button { background:transparent; color:#c4dfeb; }
.hud-start .software-actions > .software-check { min-width:148px; }
.hud-start .software-actions > a:hover,.hud-start .software-actions > button:hover:not(:disabled) { border-color:#a6f4df; background:#204654; }
.hud-start .software-details { margin-top:6px; }
.hud-start .software-details > summary { font-size:.73rem; min-height:38px; padding:10px 0; }
.hud-start .software-details p { font-size:.77rem; line-height:1.65; margin:2px 0 10px; }
.hud-start .software-details a { font-size:.77rem; display:inline-block; padding:8px 0; min-height:36px; }
.hud-start .setup-download-note { font-size:.74rem; line-height:1.7; margin:15px 0 0; }
.setup-download-note a { display:block; margin-top:8px; text-underline-offset:4px; }
.setup-bottom { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:24px; border-top:1px solid #304953; padding-top:7px; }
.hud-start .setup-bottom > details { border:0; margin:0; }
.hud-start .setup-bottom summary { font-size:.84rem; font-weight:600; padding:12px 0; }
.hud-start .setup-bottom p,.hud-start .setup-bottom label { font-size:.8rem; line-height:1.7; }
.hud-start .setup-bottom code { font-size:.79rem; padding:12px; white-space:pre-wrap; }
.hud-start :focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }
.room-home { padding:20px 0; margin:0 0 12px; border:0; background:transparent; box-shadow:none; }
.room-home h2 { font-size:1.2rem; margin:0; }
.room-home .eyebrow { font-size:.67rem; }
.room-home .room-actions a { background:transparent; font-size:.8rem; }
.room-home > p:not(.eyebrow) { font-size:.84rem; }
.room-help-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:20px; }
.room-help-grid > section { padding:20px; background:#0c202b; border:1px solid #36515f; border-radius:10px; min-width:0; }
.room-help-grid h3 { margin:0 0 12px; font-size:1.05rem; }
.room-help-grid p,.room-help-grid li { font-size:.87rem; line-height:1.7; color:#bfd0d9; }
.room-help-grid ul { padding-left:20px; }
.room-help-grid a { color:#a6f4df; text-underline-offset:3px; }
.room-help-grid details { border-top:1px solid #36515f; margin-top:14px; }
.room-help-grid summary { cursor:pointer; min-height:44px; padding:12px 0; color:#deeeed; font-size:.87rem; }
.room-help-grid code { font-size:.78rem; overflow-wrap:anywhere; }
.room-help-grid #help-reopen-command { display:block; padding:12px; border:1px solid #36515f; border-radius:6px; background:#071923; white-space:pre-wrap; }
@media(prefers-reduced-motion:reduce) { .setup-check-row,.software-row { animation:none; transition:none; } }
@media(max-width:940px) { .setup-main { gap:22px; } .setup-health { padding-right:22px; } .setup-software-filters { grid-template-columns:1fr; } .setup-check-actions { flex-direction:column; align-items:stretch; } }
@media(max-width:760px) { .setup-main,.setup-bottom,.room-help-grid { grid-template-columns:1fr; } .setup-health { padding-right:0; border-right:0; padding-bottom:22px; border-bottom:1px solid #304953; } .setup-check-actions { flex-direction:row; } .setup-software-filters { grid-template-columns:minmax(0,1.2fr) minmax(0,1fr); } .hud-start .setup-heading { gap:12px; flex-direction:column; } .hud-start .setup-help-link { padding:0; min-height:32px; } .setup-bottom { gap:0; } .hud-start .setup-bottom > details + details { border-top:1px solid #304953; } }
@media(max-width:440px) { .hud-start { padding:17px; } .setup-software-filters { grid-template-columns:1fr; } .hud-start .setup-heading h2 { font-size:1.7rem; } .setup-check-actions { flex-direction:column; } .software-actions { flex-direction:column; align-items:stretch; } .hud-start .tool-status-row { grid-template-columns:1fr; } .hud-start .tool-status-badges { justify-content:flex-start; } }
"""
ROOM_CSS += STATUS_GLOSSARY_CSS

ROOM_JS = r"""
const roomState = {snapshot:null, failed:false, connected:null, busy:false, range:'recorded', custom:null, selection:null, report:null, history:null};
const roomProtocols = ['TCP','UDP','ICMP','ICMPV6','DNS','HTTP','TLS','OTHER'];
const roomRules = ['SYN_FLOOD','PORT_SCAN','DNS_TUNNELING'];
const roomFlags = ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'];
const roomId = value => typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value) && Number.isSafeInteger(Number(value));
function roomStamp(value) {
  if(typeof value!=='string') return false;
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(value);
  if(!match) return false;
  const [year,month,day,hour,minute,second]=match.slice(1,7).map(Number);
  if(year<1 || month<1 || month>12 || hour>23 || minute>59 || second>59) return false;
  const instant=new Date(0);
  instant.setUTCFullYear(year,month-1,day);
  instant.setUTCHours(hour,minute,second,Number((match[7]||'').padEnd(3,'0').slice(0,3)));
  return Number.isFinite(instant.valueOf())
    && instant.getUTCFullYear()===year && instant.getUTCMonth()===month-1 && instant.getUTCDate()===day
    && instant.getUTCHours()===hour && instant.getUTCMinutes()===minute && instant.getUTCSeconds()===second;
}
function validateTraffic(value) {
  if (!referenceExactKeys(value, ['schema','status','reason','generated_at','unit','vantage','quality','window','limits','truncated','excluded_event_candidates','events','findings','limitations','build'])
    || value.schema !== 'dashboard-traffic-v1' || !['available','unavailable'].includes(value.status)
    || !roomStamp(value.generated_at) || Date.parse(value.generated_at)>Date.now()+60000
    || !['unknown','degraded'].includes(value.quality) || typeof value.truncated !== 'boolean'
    || !Number.isInteger(value.excluded_event_candidates) || value.excluded_event_candidates<0 || value.excluded_event_candidates>500
    || !Array.isArray(value.events) || value.events.length>500 || !Array.isArray(value.findings) || value.findings.length>200
    || !referenceExactKeys(value.limits,['events','findings','bytes']) || value.limits.events!==500 || value.limits.findings!==200 || value.limits.bytes!==262144
    || !referenceExactKeys(value.window,['start','end']) || !referenceExactKeys(value.build,['package_version','base_commit','projection_sha256','commit'])
    || !/^[0-9a-f]{64}$/.test(value.build.projection_sha256) || !/^[0-9a-f]{40}$/.test(value.build.base_commit)
    || !Array.isArray(value.limitations) || value.limitations.length!==7
    || ![value.reason,value.unit,value.vantage,...value.limitations,...Object.values(value.build)].every(x=>typeof x==='string' && x.length<=256 && !/[\x00-\x1f\x7f]/.test(x))) throw new Error('Invalid traffic envelope');
  const ids = new Set();
  value.events.forEach(e=>{
    if(!referenceExactKeys(e,['id','observed_at','src_ip','dst_ip','protocol','src_port','dst_port','tcp_flags','byte_count','run_id','source','run_status','termination_reason'])
      || !roomId(e.id) || ids.has(e.id) || !roomId(e.run_id) || !roomStamp(e.observed_at)
      || ![e.src_ip,e.dst_ip].every(ip=>typeof ip==='string' && ip.length<=45 && /^[0-9a-f:.]+$/i.test(ip))
      || !roomProtocols.includes(e.protocol) || !['jsonl','scapy'].includes(e.source)
      || !['running','completed','incomplete','failed'].includes(e.run_status)
      || ![null,'source_exhausted','event_limit_reached','failed','interrupted'].includes(e.termination_reason)
      || !({running:[null],completed:['source_exhausted'],incomplete:['event_limit_reached'],failed:['failed','interrupted']}[e.run_status]||[]).includes(e.termination_reason)
      || ![e.src_port,e.dst_port].every(p=>p===null || (Number.isInteger(p)&&p>=0&&p<=65535))
      || !Array.isArray(e.tcp_flags) || e.tcp_flags.length>8 || new Set(e.tcp_flags).size!==e.tcp_flags.length || !e.tcp_flags.every(f=>roomFlags.includes(f))
      || typeof e.byte_count!=='string' || !/^(0|[1-9][0-9]{0,18})$/.test(e.byte_count) || BigInt(e.byte_count)>9223372036854775807n) throw new Error('Invalid event');
    ids.add(e.id);
  });
  const findings = new Set();
  value.findings.forEach(f=>{
    if(!referenceExactKeys(f,['id','event_id','detected_at','rule_id','severity','detector_version']) || !roomId(f.id) || findings.has(f.id) || !ids.has(f.event_id)
      || !roomStamp(f.detected_at) || !roomRules.includes(f.rule_id) || !knownSeverities.has(f.severity)
      || f.detector_version!=='unknown; not stored on historical finding') throw new Error('Invalid finding');
    findings.add(f.id);
  });
  const times=value.events.map(e=>e.observed_at).sort();
  if(value.window.start!==(times[0]||null) || value.window.end!==(times.at(-1)||null) || (value.status==='available')!==(value.events.length>0)) throw new Error('Invalid coverage');
  return value;
}
function validateHistory(value, request) {
  if(!referenceExactKeys(value,['schema','traffic','range','next_before','candidate_count']) || value.schema!=='dashboard-traffic-history-v1'
    || !referenceExactKeys(value.range,['start','end']) || !roomStamp(value.range.start) || !roomStamp(value.range.end)
    || Date.parse(value.range.start)!==request.start || Date.parse(value.range.end)!==request.end
    || !Number.isInteger(value.candidate_count) || value.candidate_count<0 || value.candidate_count>500
    || !(value.next_before===null || roomId(value.next_before))) throw new Error('Invalid history page');
  validateTraffic(value.traffic);
  if(value.traffic.events.length+value.traffic.excluded_event_candidates!==value.candidate_count
    || (value.next_before!==null && (value.candidate_count!==500 || !value.traffic.truncated || (request.before!==null && BigInt(value.next_before)>=BigInt(request.before))))
    || value.traffic.events.some(e=>Date.parse(e.observed_at)<request.start || Date.parse(e.observed_at)>request.end || (request.before!==null && BigInt(e.id)>=BigInt(request.before)) || (value.next_before!==null && BigInt(e.id)<BigInt(value.next_before)))) throw new Error('Invalid history coverage');
  return value;
}
function roomSelection(snapshot, range, custom, now=Date.now()) {
  let start,end;
  if(range==='recorded') { end=snapshot?.window.end ? Date.parse(snapshot.window.end) : now; start=Math.max(end-31*86400000,snapshot?.window.start ? Date.parse(snapshot.window.start) : end); }
  else if(range==='now') {end=now;start=end-300000;}
  else if(range==='hour') {end=now;start=end-3600000;}
  else if(range==='today') {end=now;start=Date.parse(new Date(now).toISOString().slice(0,10)+'T00:00:00Z');}
  else if(range==='custom' && custom) {start=custom.start;end=custom.end;}
  else throw new Error('Choose a valid time range.');
  if(!Number.isFinite(start)||!Number.isFinite(end)||start>end||end-start>31*86400000||(range!=='recorded' && end>now+60000)) throw new Error('Choose an ordered UTC range of at most 31 days, ending no later than now.');
  const events=(snapshot?.events||[]).filter(e=>Date.parse(e.observed_at)>=start&&Date.parse(e.observed_at)<=end);
  const ids=new Set(events.map(e=>e.id));
  const findings=(snapshot?.findings||[]).filter(f=>ids.has(f.event_id)&&Date.parse(f.detected_at)>=start&&Date.parse(f.detected_at)<=end);
  return {start,end,events,findings};
}
function roomCounts(values) {const counts=new Map();values.forEach(v=>counts.set(v,(counts.get(v)||0)+1));return [...counts].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,10);}
function roomEndpoint(address,port) {return port===null?address:`${address.includes(':')?`[${address}]`:address}:${port}`;}
function roomMeta(selection) {
  const value=roomState.snapshot;
  return `${new Date(selection.start).toISOString()} → ${new Date(selection.end).toISOString()} · source: ${[...new Set(selection.events.map(e=>e.source))].join(', ')||'unavailable'} · vantage: unknown · last update: ${value?.generated_at||'unavailable'} · unit: metadata events / reported bytes · quality: ${roomState.failed?'stale':value?.quality||'unavailable'} · bounded candidate window (top lists omit lower-ranked rows)`;
}
function roomVisual(parent,title,selection) {
  const article=textNode('article','','room-visual');
  const details=textNode('details');details.append(textNode('summary','Source and coverage details'),textNode('p',roomMeta(selection),'room-meta'));
  article.append(textNode('h3',title),details);parent.append(article);return article;
}
function roomBars(parent,rows,unit='events') {
  if(!rows.length) {parent.append(textNode('p','No qualified data available in this time range. Use Help to select or import authorized metadata.','room-empty'));return;}
  const list=textNode('ul','','room-bars'),max=Math.max(...rows.map(r=>r[1]));
  rows.forEach(([label,count])=>{const item=textNode('li'),meter=document.createElement('meter');meter.min=0;meter.max=max;meter.value=count;meter.setAttribute('aria-label',`${label}: ${count} ${unit}`);item.append(textNode('span',label),textNode('strong',`${count}`),meter);list.append(item);});parent.append(list);
}
function roomTimeline(parent,selection,rows,stamp) {
  if(!rows.length){roomBars(parent,[]);return;}
  const bins=Array.from({length:12},()=>0),span=Math.max(1,selection.end-selection.start);
  rows.forEach(row=>bins[Math.min(11,Math.floor((Date.parse(row[stamp])-selection.start)/span*12))]++);
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 480 140');svg.setAttribute('role','img');svg.setAttribute('aria-label',`12 equal time bins, metadata record counts: ${bins.join(', ')}. Gaps do not prove no traffic.`);
  const max=Math.max(1,...bins);
  bins.forEach((count,i)=>{const bar=document.createElementNS(svg.namespaceURI,'rect');bar.setAttribute('x',String(i*40+4));bar.setAttribute('y',String(115-count/max*105));bar.setAttribute('width','30');bar.setAttribute('height',String(count/max*105));svg.append(bar);const label=document.createElementNS(svg.namespaceURI,'text');label.setAttribute('x',String(i*40+8));label.setAttribute('y','134');label.textContent=String(count);svg.append(label);});parent.append(svg);
  parent.append(textNode('p','12 equal time bins, left to right. An empty bin means no returned records; sensor gaps and drops are unknown.','room-meta'));
}
const roomReportFields = ['schema','generated_at','title','range','sources','vantage','quality','freshness','unit','counts','findings','limitations','build'];
const roomReportLimitations = [
  'Saved metadata only; no packet bodies, raw logs, messages, model output, addresses, ports, IDs, or commands.',
  'Source authenticity, sensor health, installed-tool qualification, drops, and whole-network completeness remain unknown.',
  'Direction, local-subnet scope, connection state, and observed service identities are unavailable.',
  'Counts cover only the validated events in the selected bounded range.',
  'A missing finding or empty range does not prove safety or absence of traffic.',
  'Imported source labels are provenance, not independent authentication.',
  'This report was created locally in the browser and was not uploaded by MEGALODON.'
];
function roomReportDocument(now=Date.now()) {
  const snapshot=roomState.snapshot,selection=roomState.selection;
  if(!snapshot || !selection || !selection.events.length) throw new Error('No qualified data is available in the selected range. No report was created.');
  const findings=new Map();
  selection.findings.forEach(item=>{
    const key=item.rule_id+'\n'+item.severity;
    findings.set(key,(findings.get(key)||0)+1);
  });
  const document={
    schema:'megalodon-local-report-v1',
    generated_at:new Date(now).toISOString(),
    title:'MEGALODON local metadata report',
    range:{start:new Date(selection.start).toISOString(),end:new Date(selection.end).toISOString()},
    sources:[...new Set(selection.events.map(item=>item.source))].sort(),
    vantage:'unknown',
    quality:snapshot.quality,
    freshness:roomState.failed || now-Date.parse(snapshot.generated_at)>300000 || Date.parse(snapshot.generated_at)>now+60000 ? 'stale' : 'current_by_five_minute_ui_threshold',
    unit:'metadata events / linked findings / reported bytes',
    counts:{
      events:selection.events.length,
      findings:selection.findings.length,
      reported_bytes:selection.events.reduce((sum,item)=>sum+BigInt(item.byte_count),0n).toString()
    },
    findings:[...findings].sort((a,b)=>a[0].localeCompare(b[0])).map(([key,count])=>{
      const [rule_id,severity]=key.split('\n');return {rule_id,severity,count};
    }),
    limitations:[...roomReportLimitations],
    build:{
      package_version:snapshot.build.package_version,
      base_commit:snapshot.build.base_commit,
      projection_sha256:snapshot.build.projection_sha256,
      commit:snapshot.build.commit
    }
  };
  if(!referenceExactKeys(document,roomReportFields)
      || !referenceExactKeys(document.range,['start','end'])
      || !referenceExactKeys(document.counts,['events','findings','reported_bytes'])
      || !referenceExactKeys(document.build,['package_version','base_commit','projection_sha256','commit'])
      || document.findings.some(item=>!referenceExactKeys(item,['rule_id','severity','count']))) throw new Error('The local report contract could not be satisfied.');
  const json=JSON.stringify(document,null,2)+'\n';
  if(new TextEncoder().encode(json).byteLength>65536) throw new Error('The local report exceeded its 64 KiB limit. No report was created.');
  return {document,json};
}
function invalidateRoomReport() {
  roomState.report=null;
  byId('room-report-download').disabled=true;
  byId('room-report-discard').disabled=true;
  byId('room-report-context').textContent='A preview holds its original range and data until you replace or discard it.';
  const preview=byId('room-report-preview');preview.replaceChildren();preview.hidden=true;
  byId('room-report-status').textContent=roomState.selection && roomState.selection.events.length
    ? 'No preview is ready. Preview the current selected range before downloading.'
    : 'No qualified data is available in the selected range. No report can be created.';
}
function previewRoomReport() {
  try {
    const report=roomReportDocument();roomState.report=report;
    const preview=byId('room-report-preview');preview.replaceChildren(textNode('code',report.json));preview.hidden=false;
    byId('room-report-download').disabled=false;
    byId('room-report-discard').disabled=false;
    byId('room-report-context').textContent=`Held preview created ${report.document.generated_at}. Range: ${report.document.range.start} → ${report.document.range.end}. Freshness at creation: ${report.document.freshness}. Refreshes and range changes do not update this preview; preview again to replace it.`;
    byId('room-report-status').textContent='Preview ready in this browser. Review it, then download explicitly.';
    return true;
  } catch(_) {
    invalidateRoomReport();
    byId('room-report-status').textContent='No qualified data is available in the selected range. No report was created.';
    return false;
  }
}
function downloadRoomReport() {
  if(!roomState.report) {byId('room-report-status').textContent='Preview the current selected range before downloading.';return false;}
  let url;
  try {
    url=URL.createObjectURL(new Blob([roomState.report.json],{type:'application/json'}));
    const link=document.createElement('a');
    link.href=url;link.download='megalodon-local-report-'+roomState.report.document.generated_at.replace(/[:.]/g,'-')+'.json';
    link.click();
    byId('room-report-status').textContent='Local JSON download requested for the held preview. MEGALODON did not upload it.';
    return true;
  } catch(_) {
    byId('room-report-status').textContent='The browser could not request the download. Your preview is preserved; retry or copy the JSON shown below.';
    return false;
  } finally {if(url)setTimeout(()=>URL.revokeObjectURL(url),0);}
}
function renderRoom() {
  let selected;
  try {selected=roomSelection(roomState.snapshot,roomState.history?'custom':roomState.range,roomState.history||roomState.custom);} catch(error) {byId('room-notice').textContent=error.message;return;}
  roomState.selection=selected;
  const snapshot=roomState.snapshot,has=selected.events.length>0;
  const stale=roomState.failed || (snapshot && Date.now()-Date.parse(snapshot.generated_at)>300000);
  const old=has && Date.now()-Math.max(...selected.events.map(e=>Date.parse(e.observed_at)))>300000;
  const future=has && selected.events.some(e=>Date.parse(e.observed_at)>Date.now()+60000);
  byId('room-overall').textContent=stale?'Stale view':!has?'No qualified data':future?'Clock uncertain':selected.findings.length?'Review findings':roomState.history||old?'Historical view':snapshot?.truncated?'Limited window':'Metadata available';
  byId('room-connection').textContent=roomState.connected===true?'Connected · read-only':roomState.connected===false?(snapshot?'Unavailable · preserved view':'Unavailable'):'Not checked';
  byId('room-coverage').textContent=stale?'Stale':future?'Clock uncertain':has?'Partial · quality unknown':'Unavailable';
  byId('room-updated').textContent=snapshot?new Date(snapshot.generated_at).toISOString().slice(0,19).replace('T',' ')+' UTC':'Not fetched';
  byId('room-updated').title=snapshot?.generated_at||'';
  byId('room-sources').textContent=has?[...new Set(selected.events.map(e=>e.source==='jsonl'?'JSONL import':'Scapy'))].join(', '):'Unknown';
  byId('room-count').textContent=has?`${selected.findings.length} in returned set`:'Unavailable';
  const note=stale?(snapshot?'Refresh failed or snapshot expired. Preserved metadata is stale.':'No qualified data available. The metadata check failed; use Help for the safe next step.'):!has?'No qualified data available in this time range.':future?'Clock uncertainty: future timestamps are present.':old?'Historical metadata only. Current sensor activity is unknown.':'Showing saved metadata. Sensor health and full coverage are unknown.';
  byId('room-notice').textContent=note;
  byId('room-home-summary').textContent=has?`${selected.events.length} stored metadata events and ${selected.findings.length} linked findings are available. ${note}`:note+' Open Data and tools to check your source and choose the next step.';
  byId('room-range-description').textContent=roomMeta(selected);
  renderRoomControls();
  const activity=textNode('table');activity.append(textNode('caption',`${selected.events.length} qualified events in this page`));
  const activityHead=textNode('tr');['Observed (UTC)','Source → destination','Protocol / flags','Reported bytes','Source / run / state','Event ID'].forEach(label=>{const th=textNode('th',label);th.scope='col';activityHead.append(th);});
  const activityHeader=textNode('thead');activityHeader.append(activityHead);activity.append(activityHeader);
  const activityBody=textNode('tbody');
  [...selected.events].sort((a,b)=>Date.parse(b.observed_at)-Date.parse(a.observed_at)||Number(b.id)-Number(a.id)).forEach(e=>{
    const row=textNode('tr');[e.observed_at,roomEndpoint(e.src_ip,e.src_port)+' → '+roomEndpoint(e.dst_ip,e.dst_port),e.protocol+' / '+(e.tcp_flags.join(', ')||'—'),e.byte_count,e.source+' / '+e.run_id+' / '+e.run_status,e.id].forEach(value=>row.append(textNode('td',value)));activityBody.append(row);
  });activity.append(activityBody);byId('room-activity-table').replaceChildren(activity);
  const grid=byId('room-traffic-grid');grid.replaceChildren();
  let panel=roomVisual(grid,'Traffic volume over time',selected);roomTimeline(panel,selected,selected.events,'observed_at');
  if(has) panel.append(textNode('p',`${selected.events.reduce((sum,e)=>sum+BigInt(e.byte_count),0n)} reported bytes in this returned set. No packets-per-second or link-speed claim.`,'room-meta'));
  panel=roomVisual(grid,'Protocol mix',selected);roomBars(panel,roomCounts(selected.events.map(e=>e.protocol)));panel.append(textNode('p','Recorded labels only. A port number does not prove DNS, HTTP or TLS.','room-meta'));
  panel=roomVisual(grid,'Inbound, outbound and internal',selected);panel.append(textNode('p','Unavailable — no qualified local-subnet or sensor-vantage contract. Private addresses alone do not establish direction.','room-empty'));
  panel=roomVisual(grid,'Top observed endpoints',selected);roomBars(panel,roomCounts(selected.events.flatMap(e=>[e.src_ip,e.dst_ip])),'endpoint appearances');panel.append(textNode('p','Which endpoints are local is unknown. Each event contributes both endpoint appearances.','room-meta'));
  panel=roomVisual(grid,'Top conversations',selected);roomBars(panel,roomCounts(selected.events.map(e=>`${roomEndpoint(e.src_ip,e.src_port)} → ${roomEndpoint(e.dst_ip,e.dst_port)} · ${e.protocol}`)));
  panel=roomVisual(grid,'Ports and connection indicators',selected);roomBars(panel,roomCounts(selected.events.map(e=>`${e.protocol} / source ${e.src_port===null?'not recorded':e.src_port}`)));roomBars(panel,roomCounts(selected.events.map(e=>`${e.protocol} / destination ${e.dst_port===null?'not recorded':e.dst_port}`)));roomBars(panel,roomCounts(selected.events.filter(e=>e.protocol==='TCP').map(e=>'Flags: '+(e.tcp_flags.join(', ')||'none recorded'))));panel.append(textNode('p','TCP flags are indicators; connection state and actual service identity are unavailable.','room-meta'));
  panel=roomVisual(grid,'Source → destination → protocol / port',selected);const flow=textNode('div','','room-flow');roomCounts(selected.events.map(e=>`${roomEndpoint(e.src_ip,e.src_port)} → ${roomEndpoint(e.dst_ip,e.dst_port)} → ${e.protocol}`)).slice(0,8).forEach(([label,count])=>flow.append(textNode('p',`${label} · ${count} events`)));panel.append(flow);if(!has)roomBars(panel,[]);
  panel=roomVisual(grid,'Coverage and gaps',selected);panel.append(textNode('p',`Candidate window limited: ${snapshot?.truncated?'Yes':'Unknown beyond returned window'}. Excluded sample/unlinked/legacy/held event candidates: ${snapshot?snapshot.excluded_event_candidates:'Unknown'}. Drops: Unknown. Rejected records: Unknown. Missing intervals: Unknown. Clock accuracy: Unknown.`,'room-meta'));
  const findings=byId('room-findings-visual');findings.replaceChildren();panel=roomVisual(findings,'Findings over time',selected);roomTimeline(panel,selected,selected.findings,'detected_at');panel=roomVisual(findings,'Detector and severity',selected);roomBars(panel,roomCounts(selected.findings.map(f=>`${f.rule_id} · ${f.severity}`)),'findings');
  const tableRoot=byId('room-findings-table');tableRoot.replaceChildren();tableRoot.setAttribute('tabindex','0');tableRoot.setAttribute('role','region');tableRoot.setAttribute('aria-label','Scrollable qualified findings');
  const table=textNode('table'),caption=textNode('caption','Qualified findings in the shared time range');table.append(caption);const head=textNode('tr');['Time','Detector','Severity','Finding / event ID','Detector version'].forEach(label=>{const th=textNode('th',label);th.scope='col';head.append(th);});const thead=textNode('thead');thead.append(head);table.append(thead);const body=textNode('tbody');selected.findings.forEach(f=>{const row=textNode('tr');[f.detected_at,f.rule_id,f.severity,`${f.id} / ${f.event_id}`,f.detector_version].forEach(value=>row.append(textNode('td',value)));body.append(row);});table.append(body);tableRoot.append(table);if(!selected.findings.length)tableRoot.append(textNode('p',has?'No linked findings in this bounded set. This does not prove no threat.':'No qualified data available.','room-empty'));
  if(!roomState.report)invalidateRoomReport();
}
const roomRequests=new Map();
function requestRoomSnapshot(path='/api/traffic') {
  if(roomRequests.has(path))return roomRequests.get(path);
  const pending=(async()=>{
    const response=await fetch(path,{method:'GET',cache:'no-store',credentials:'omit',mode:'same-origin',redirect:'error',signal:AbortSignal.timeout(5000)});
    const reader=response.body?.getReader();if(!reader)throw new Error('Unavailable');let bytes=0,chunks=[];
    try {
      while(true){const {done,value}=await reader.read();if(done)break;if(!(value instanceof Uint8Array))throw new Error('Invalid response');bytes+=value.byteLength;if(bytes>262144)throw new Error('Oversized');chunks.push(value);}
      const declared=response.headers?.get('Content-Length');
      if(declared!==null && declared!==undefined && (!/^(0|[1-9][0-9]*)$/.test(declared)||Number(declared)!==bytes))throw new Error('Partial response');
    } finally {try{await reader.cancel();}catch(_){}}
    const merged=new Uint8Array(bytes);let offset=0;chunks.forEach(chunk=>{merged.set(chunk,offset);offset+=chunk.length;});
    const payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(merged));
    if(!response.ok){const error=new Error('Unavailable');error.status=response.status;error.payload=payload;throw error;}
    return payload;
  })();
  roomRequests.set(path,pending);pending.then(()=>roomRequests.delete(path),()=>roomRequests.delete(path));return pending;
}
function acceptRoomResult(result) {
  if(roomState.history||roomState.busy)return;
  try {
    const value=result.status==='fulfilled'?result.value:result.reason?.status===503?result.reason.payload:null;
    const snapshot=validateTraffic(value);
    if(result.status!=='fulfilled' && snapshot.status!=='unavailable')throw new Error('Unavailable');
    roomState.snapshot=snapshot;roomState.failed=false;roomState.connected=true;
  } catch(_) {roomState.failed=true;roomState.connected=false;}
  renderRoom();
}
function renderRoomControls() {
  const history=roomState.history,busy=roomState.busy;
  ['room-apply','room-refresh','room-older','room-newer','room-latest'].forEach(id=>byId(id).disabled=busy);
  byId('room-older').hidden=!history;byId('room-newer').hidden=!history;byId('room-latest').hidden=!history;
  if(history){byId('room-older').disabled=busy||history.next===null;byId('room-newer').disabled=busy||!history.previous.length;}
  const paused=typeof state!=='undefined' && state.paused;
  const interval=typeof state!=='undefined'?state.config.refresh_seconds:5;
  byId('room-pause').textContent=paused?'Resume refresh':'Pause refresh';byId('room-pause').setAttribute('aria-pressed',String(Boolean(paused)));
  const last=roomState.snapshot?.window.end;
  byId('room-feed-status').textContent=(history?'History page held for review.':paused?'Automatic refresh paused.':`Automatic refresh every ${interval}s while this tab is visible.`)+(last?' Latest observation in this page: '+last+'.':' No observation available.')+' Sensor liveness and network-wide coverage are unknown.';
  byId('room-history-status').textContent=history?`History page ${history.previous.length+1} · ${history.candidates} stored candidates checked · ${history.next===null?'End of stored candidates in this range.':'More stored candidates available.'} Findings are capped at 200 per page; pages reflect the store when read.`:'Latest 500 stored candidates. Choose Last hour, Today or Custom UTC to browse database history.';
}
async function refreshRoom(request=undefined) {
  if(roomState.busy)return;
  // Event listeners pass an Event; only source-owned request objects select a page.
  const history=request?.history===null?null:request?.history||roomState.history;
  roomState.busy=true;renderRoomControls();
  try {
    const path=history?`/api/traffic-history?start=${encodeURIComponent(new Date(history.start).toISOString())}&end=${encodeURIComponent(new Date(history.end).toISOString())}`+(history.before?'&before='+history.before:''):'/api/traffic';
    const payload=await requestRoomSnapshot(path);
    if(history){const page=validateHistory(payload,history);roomState.history={...history,next:page.next_before,candidates:page.candidate_count};roomState.snapshot=page.traffic;}
    else {roomState.snapshot=validateTraffic(payload);roomState.history=null;}
    if(request?.range){roomState.range=request.range;roomState.custom=request.custom||null;}
    roomState.failed=false;roomState.connected=true;
  } catch(error) {
    if(!history && error.status===503){try{const snapshot=validateTraffic(error.payload);if(snapshot.status!=='unavailable')throw Error();roomState.snapshot=snapshot;roomState.history=null;roomState.failed=false;roomState.connected=true;}catch(_){roomState.failed=true;roomState.connected=false;}}
    else {roomState.failed=true;roomState.connected=false;}
  } finally {roomState.busy=false;renderRoom();}
}
function applyRoomRange() {
  try {
    const range=byId('room-range').value;
    const utcInput=id=>{const raw=byId(id).value;const value=raw.length===16?raw+':00Z':raw+'Z';if(!roomStamp(value))throw Error('Choose valid UTC start and end times.');return Date.parse(value);};
    const custom=range==='custom'?{start:utcInput('room-start'),end:utcInput('room-end')}:null;
    const selection=roomSelection(roomState.snapshot,range,custom);
    const history=['hour','today','custom'].includes(range)?{start:selection.start,end:selection.end,before:null,next:null,candidates:0,previous:[]}:null;
    return refreshRoom({history,range,custom});
  }catch(error){byId('room-notice').textContent=error.message;}
}
byId('room-range').addEventListener('change',()=>{const custom=byId('room-range').value==='custom';byId('room-start-label').hidden=!custom;byId('room-end-label').hidden=!custom;});
byId('room-apply').addEventListener('click',applyRoomRange);
byId('room-older').addEventListener('click',()=>{const h=roomState.history;if(h?.next)refreshRoom({history:{...h,before:h.next,previous:[...h.previous,h.before]}});});
byId('room-newer').addEventListener('click',()=>{const h=roomState.history;if(h?.previous.length)refreshRoom({history:{...h,before:h.previous.at(-1),previous:h.previous.slice(0,-1)}});});
byId('room-latest').addEventListener('click',()=>{byId('room-range').value='recorded';byId('room-start-label').hidden=true;byId('room-end-label').hidden=true;refreshRoom({history:null,range:'recorded'});});
byId('room-pause').addEventListener('click',()=>{if(typeof togglePause==='function'){togglePause();renderRoomControls();}});
byId('room-refresh').addEventListener('click',refreshRoom);
byId('room-report-create').addEventListener('click',previewRoomReport);
byId('room-report-download').addEventListener('click',downloadRoomReport);
byId('room-report-discard').addEventListener('click',invalidateRoomReport);
"""
