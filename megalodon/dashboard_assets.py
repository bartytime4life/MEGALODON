"""Same-origin dashboard assets, kept separate from HTTP request handling.

This module contains presentation only. Importing it cannot read telemetry,
probe a host, or start an integration. The dashboard module re-exports these
constants to preserve the existing public/test interface.
"""

from .dashboard_integrations import INTEGRATIONS_HTML, INTEGRATIONS_CSS, INTEGRATIONS_JS
from .dashboard_reference_contract import REFERENCE_CONTRACT_JS, REFERENCE_CONTRACT_CSS
from .dashboard_setup import SETUP_HTML, SETUP_JS
from .dashboard_tool_assets import LIFECYCLE_JS, READINESS_JS, CONTROLS_JS, CONTROLS_CSS
from .status_glossary import GLOSSARY_ANCHOR_ID


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
<a class="skip-link" id="skip-link" href="#detections-title">Skip to findings</a>
<main class="shell">
  <header class="topbar">
    <div class="brand" aria-label="MEGALODON">
      <div class="mark" aria-hidden="true">M</div>
      <div><p class="brand-name">MEGALODON</p><p class="brand-subtitle">Local defense telemetry</p></div>
    </div>
    <div class="connection-state"><div class="connection" id="connection">Dashboard API · connecting</div><span>Capture health unknown</span></div>
    <p class="sr-only" id="refresh-announcement" aria-live="polite"></p>
  </header>

  <nav class="section-nav" aria-label="Command center workspaces" role="tablist">
    <button id="workspace-tab-live" type="button" role="tab" aria-controls="workspace-live" aria-selected="true" tabindex="0">Overview</button>
    <button id="workspace-tab-analysis" type="button" role="tab" aria-controls="workspace-analysis" aria-selected="false" tabindex="-1">Investigate</button>
    <button id="workspace-tab-interfaces" type="button" role="tab" aria-controls="workspace-interfaces" aria-selected="false" tabindex="-1">Tools</button>
  </nav>

  <div class="workspace-scroll" id="workspace-content">
  <section class="workspace-view" id="workspace-live" role="tabpanel" aria-labelledby="workspace-tab-live">
  <section class="hero" aria-labelledby="page-title">
    <div>
      <p class="eyebrow">Overview</p>
      <h1 id="page-title" tabindex="-1">What MEGALODON has stored</h1>
      <p class="lede">A read-only view of recent metadata, alerts, and tools on this computer.</p>
    </div>
    <div class="read-only">Local and read only</div>
  </section>

  <section class="trust-strip waiting" id="trust-strip" aria-labelledby="trust-title">
    <div class="trust-summary">
      <p class="eyebrow" id="trust-title">Data status</p>
      <p class="trust-message" id="snapshot-status" role="status" aria-live="polite" aria-atomic="true">Waiting for the first dashboard update. API status does not prove capture health.</p>
    </div>
    <p class="snapshot-scope"><span id="scope-status">Newest 50 detections maximum</span><span>No changes made</span></p>
  </section>

  <section class="metrics" id="live-metrics" aria-label="Stored telemetry summary">
    <article class="metric"><div class="metric-label">Stored events</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Findings</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">High priority</div><div class="metric-value">—</div></article>
    <article class="metric"><div class="metric-label">Recorded decisions</div><div class="metric-value">—</div></article>
  </section>

  <div class="command-overview">
  <section class="panel traffic-panel" id="traffic-panel" aria-labelledby="traffic-title" aria-busy="true">
    <div class="traffic-heading">
      <div>
        <p class="eyebrow">Recent activity</p>
        <h2 id="traffic-title">Recent network metadata</h2>
        <p id="traffic-status" role="status" aria-live="polite">Loading a bounded view of recorded events…</p>
      </div>
      <span class="traffic-freshness" id="traffic-freshness">Awaiting data</span>
    </div>
    <div class="traffic-layout">
      <div class="traffic-plot-wrap">
        <div class="traffic-chart" id="traffic-chart" role="img" aria-label="No stored traffic data loaded yet"></div>
        <div class="traffic-axis"><span>Earlier</span><span>Most recent</span></div>
        <p class="traffic-explainer">Each bar groups records by time. Taller bars contain more stored metadata bytes.</p>
      </div>
      <dl class="traffic-facts">
        <div><dt>Records shown</dt><dd id="traffic-events">—</dd></div>
        <div><dt>Stored volume</dt><dd id="traffic-bytes">—</dd></div>
        <div><dt>Sample window</dt><dd id="traffic-window">—</dd></div>
        <div><dt>Last observed</dt><dd id="traffic-last">—</dd></div>
      </dl>
    </div>
    <div class="protocol-mix" id="protocol-mix" aria-label="Protocol mix"></div>
    <p class="traffic-boundary">Shows at most 500 source-qualified records tied to ingestion receipts. This is bounded saved metadata, not network speed or proof that capture is complete.</p>
  </section>

  <!-- HUD_SETUP -->
  </div>

  <nav class="next-actions" aria-label="Common tasks">
    <a href="#detections-title"><strong>Review findings</strong><span>Open the newest stored findings.</span></a>
    <button id="open-report-studio" type="button"><strong>Create a report</strong><span>Export an overview, alert review, or ingestion summary.</span></button>
    <a href="#integrations-title"><strong>Open tools</strong><span>Review companion apps and their setup instructions.</span></a>
  </nav>

  <details class="panel report-studio" id="report-studio">
    <summary><span><strong id="report-title">Create a report</strong><small>Choose a purpose, preview the result, then export it locally.</small></span><span class="summary-action" id="report-studio-action">Open report builder</span></summary>
    <div class="report-layout">
      <div class="report-controls">
        <label class="field" for="report-scope"><span>Report purpose</span>
          <select id="report-scope">
            <option value="overview">Operations overview</option>
            <option value="detections">Detection review</option>
            <option value="ingestion">Ingestion health</option>
          </select>
        </label>
        <label class="field" for="report-title-input"><span>Report title</span><input id="report-title-input" maxlength="80" value="MEGALODON local telemetry report"></label>
        <div class="report-actions">
          <button id="report-preview" type="button">Update preview</button>
          <button id="report-copy" type="button" class="button-secondary">Copy summary</button>
          <button id="report-json" type="button" class="button-secondary">Download JSON</button>
          <button id="report-csv" type="button" class="button-secondary">Download CSV</button>
          <button id="report-print" type="button" class="button-secondary">Print / save PDF</button>
        </div>
        <p class="report-feedback" id="report-feedback" role="status" aria-live="polite">Choose a purpose, then update the preview.</p>
      </div>
      <article class="report-preview" id="report-preview-card" aria-live="polite">
        <p class="eyebrow">Preview</p>
        <h3>MEGALODON local telemetry report</h3>
        <p>No successful dashboard snapshot is available yet.</p>
      </article>
    </div>
  </details>

  <section class="panel" id="triage-panel" aria-labelledby="detections-title" aria-busy="true">
    <div class="panel-head">
      <div><p class="eyebrow">Needs attention</p><h2 id="detections-title" tabindex="-1">Stored findings</h2><p>The newest fixed-rule findings. MEGALODON has not changed the host or network.</p></div>
      <time class="timestamp" id="updated">Awaiting first refresh</time>
    </div>
    <details class="triage-tools" id="triage-tools">
      <summary><span><strong>Filter and inspect timing</strong><small>Optional controls for a longer alert list.</small></span><span class="summary-action" id="triage-tools-action">Show controls</span></summary>
    <div class="priority-pulse" aria-labelledby="priority-title">
      <div>
        <p class="eyebrow" id="priority-title">Stored priority counter</p>
        <p class="priority-change" id="priority-change">Waiting for the first successful summary fetch.</p>
      </div>
      <p class="priority-boundary">Sequential count-change signal only · not unique alerts, incident state, or capture health</p>
      <p class="sr-only" id="priority-announcement" aria-live="polite" aria-atomic="true"></p>
    </div>
    <fieldset class="toolbar" id="triage-controls" disabled>
      <legend class="sr-only">Detection triage filters and refresh controls</legend>
      <label class="field field-search" for="filter-query">
        <span>Search detections</span>
        <input id="filter-query" type="search" maxlength="160" autocomplete="off" placeholder="Rule, source, or message">
      </label>
      <label class="field" for="filter-severity">
        <span>Review priority</span>
        <select id="filter-severity">
          <option value="ALL">All priorities</option>
          <option value="PRIORITY">High + critical</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </label>
      <label class="field" for="filter-rule">
        <span>Rule</span>
        <select id="filter-rule"><option value="">All rules</option></select>
      </label>
      <div class="toolbar-actions">
        <button id="clear-filters" type="button" class="button-secondary">Clear filters</button>
        <button id="refresh-button" type="button">Refresh now</button>
        <button id="pause-button" type="button" class="button-secondary" aria-pressed="false">Pause refresh</button>
      </div>
      <p class="filter-status" id="filter-status" role="status" aria-live="polite">Waiting for recent detections.</p>
    </fieldset>
    <div class="triage-summary" role="group" aria-label="Returned detection view summary">
      <span class="summary-chip" id="returned-status">No returned rows yet</span>
      <span class="summary-chip" id="priority-status">Priority rows unavailable</span>
      <span class="summary-chip" id="rule-status">Rule count unavailable</span>
    </div>
    <section class="timeline-section" aria-labelledby="timeline-title">
      <div class="timeline-head">
        <div><h3 id="timeline-title">Detection timing</h3><p>Up to 12 chronological bins from valid timestamps in the returned, non-time-filtered view.</p></div>
        <button id="clear-time-filter" type="button" class="button-secondary" hidden>Clear time filter</button>
      </div>
      <div class="timeline" id="timeline" role="group" aria-label="Filter detections by returned timestamp range"></div>
      <p class="timeline-status" id="timeline-status" role="status" aria-live="polite">Waiting for returned timestamps.</p>
    </section>
    </details>
    <p class="sr-only" id="table-scroll-help">The recent detections table may scroll horizontally on narrow screens.</p>
    <div class="table-scroll" role="region" aria-label="Scrollable recent detections table" aria-describedby="table-scroll-help" tabindex="0">
      <table aria-describedby="filter-status">
        <caption>Recent MEGALODON detections</caption>
        <thead><tr><th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Rule</th><th scope="col">Source</th><th scope="col">Message</th></tr></thead>
        <tbody id="events"><tr><td class="empty" colspan="5">Loading local detections…</td></tr></tbody>
      </table>
    </div>
  </section>
  </section>

  <section class="workspace-view" id="workspace-analysis" role="tabpanel" aria-labelledby="workspace-tab-analysis" hidden>
  <section class="section-intro deep-analysis-intro" aria-labelledby="deep-analysis-title">
    <p class="eyebrow">Investigate</p>
    <div><h2 id="deep-analysis-title" tabindex="-1">Inspect one source at a time</h2><p>Open only the evidence or reference source you need. These panels are read only and do not start a tool or create a verdict.</p></div>
  </section>

  <section class="analysis-window" aria-labelledby="analysis-window-title">
    <div>
      <p class="eyebrow">AI advisory status</p>
      <h3 id="analysis-window-title" tabindex="-1">Qwen advisory receipt · checking</h3>
      <p id="analysis-summary">Checking for one startup-supplied, display-only legacy advisory receipt. Explicit local requests use the separate control above.</p>
      <p class="analysis-trust" role="note">AI advisory; not evidence or an action.</p>
      <ul class="analysis-limitations" id="analysis-limitations" aria-label="Advisory limitations"></ul>
    </div>
    <dl class="analysis-facts">
      <div><dt>Outcome</dt><dd id="analysis-outcome">Checking</dd></div>
      <div><dt>Model</dt><dd id="analysis-model">Not supplied</dd></div>
      <div><dt>Artifact SHA-256</dt><dd id="analysis-digest" class="receipt-digest">Not supplied</dd></div>
      <div><dt>Policy</dt><dd id="analysis-policy">local-model-advisory-v1</dd></div>
    </dl>
  </section>

  <details class="panel investigation-panel" id="suricata-panel" aria-labelledby="suricata-title" aria-busy="true">
    <summary class="panel-head">
      <div><h2 id="suricata-title" tabindex="-1">Suricata evidence</h2><p>Startup snapshot of the separately selected durable alert store. Signature matches remain external evidence and never increase MEGALODON’s detection or action counters.</p></div>
      <span class="timestamp" id="suricata-status">Checking startup snapshot…</span>
    </summary>
    <p class="ingestion-runs-note" id="suricata-message" role="status" aria-live="polite" aria-atomic="true">Checking for an explicitly selected Suricata store.</p>
    <div id="suricata-content" hidden>
      <dl class="ingestion-run-facts suricata-summary" id="suricata-summary"></dl>
      <p class="ingestion-runs-note">Newest 5 publications, at most 50 signature alerts in publication order. Producer-reported “blocked” is a Suricata observation; MEGALODON performed no response. Restart the dashboard to take a new snapshot.</p>
      <div class="table-scroll" role="region" aria-label="Scrollable Suricata signature alerts" tabindex="0">
        <table><caption>External signature evidence · startup snapshot</caption>
          <thead><tr><th scope="col">Observed time</th><th scope="col">Endpoints</th><th scope="col">Rule</th><th scope="col">Producer action</th><th scope="col">Source provenance</th></tr></thead>
          <tbody id="suricata-alerts"></tbody>
        </table>
      </div>
      <div class="panel-head"><div><h3 id="suricata-provenance" tabindex="-1">Publication provenance</h3><p>Sensor, run, ruleset, and version are recorded operator declarations. They do not establish a live sensor, independent verification, or maliciousness.</p></div></div>
      <div class="ingestion-runs-list" id="suricata-runs" role="list"></div>
    </div>
  </details>

  <details class="panel investigation-panel ingestion-runs-panel" id="ingestion-runs-panel" aria-labelledby="ingestion-runs-title" aria-busy="true">
    <summary class="panel-head">
      <div><h2 id="ingestion-runs-title" tabindex="-1">Ingestion run receipts</h2><p>Bounded read-only evidence for the newest local ingestion attempts. A completed receipt describes stored work; it does not prove sensor liveness or full network coverage.</p></div>
      <span class="timestamp" id="ingestion-runs-status">Loading receipts…</span>
    </summary>
    <div class="ingestion-runs-note" role="note">Select one stored source to review its attempts. This filters this panel only; the report builder and Traffic label use the separate all-source snapshot. Stored events, findings, and action records are different units; action records are plans, not host changes. Adapter identity and accepted/rejected counts are not recorded. A running receipt does not prove a process is still active; a completed run does not prove sensor liveness or complete coverage. <a href="#__GLOSSARY_ANCHOR__">What do these receipt statuses mean? →</a></div>
    <div class="ingestion-runs-list" id="ingestion-runs-list" role="list" aria-live="polite" aria-atomic="true">
      <p class="ingestion-runs-empty">Loading bounded ingestion receipts…</p>
    </div>
    <div class="ingestion-runs-actions">
      <label class="ingestion-source-control" for="ingestion-source">Stored source
        <select id="ingestion-source">
          <option value="all">All stored runs</option>
          <option value="sample">Sample</option>
          <option value="jsonl">JSONL</option>
          <option value="scapy">Scapy</option>
        </select>
      </label>
      <button id="ingestion-runs-retry" type="button" class="button-secondary">Reload receipts</button>
    </div>
  </details>

  <details class="panel investigation-panel reference-panel" id="reference-panel" aria-labelledby="reference-title" aria-busy="true">
    <summary class="panel-head">
      <div><h2 id="reference-title" tabindex="-1">Reference Library</h2><p>Manual context lookup against the installed, manifest-verified IANA snapshot. It never classifies traffic or changes stored records.</p></div>
      <span class="timestamp" id="reference-bundle-label">Loading pinned snapshot…</span>
    </summary>
    <div class="reference-warning" role="note">
      Registration is analyst context, not proof of what was observed or whether an endpoint is safe or malicious.
    </div>
    <div class="reference-grid">
      <form class="reference-form" id="reference-port-form">
        <h3>Service and port</h3>
        <p>Look up one normalized transport and decimal port.</p>
        <label class="field" for="reference-transport"><span>Transport</span>
          <select id="reference-transport">
            <option value="tcp">TCP</option><option value="udp">UDP</option><option value="sctp">SCTP</option><option value="dccp">DCCP</option>
          </select>
        </label>
        <label class="field" for="reference-port"><span>Port</span>
          <input id="reference-port" name="port" type="text" inputmode="numeric" autocomplete="off" maxlength="5" pattern="[0-9]{1,5}" placeholder="443" required>
        </label>
        <button type="submit">Look up service</button>
      </form>
      <form class="reference-form" id="reference-protocol-form">
        <h3>IP protocol number</h3>
        <p>Look up one decimal protocol number from 0 through 255.</p>
        <label class="field" for="reference-protocol"><span>Number</span>
          <input id="reference-protocol" name="number" type="text" inputmode="numeric" autocomplete="off" maxlength="3" pattern="[0-9]{1,3}" placeholder="6" required>
        </label>
        <button type="submit">Look up protocol</button>
      </form>
    </div>
    <div class="reference-actions" role="group" aria-label="Reference Library recovery and display controls">
      <button id="reference-retry" type="button" class="button-secondary" disabled>Recheck local snapshot</button>
      <button id="reference-clear" type="button" class="button-secondary" disabled>Clear displayed context</button>
    </div>
    <p class="reference-status" id="reference-status" role="status" aria-live="polite" aria-atomic="true">Loading the verified reference snapshot…</p>
    <details class="reference-provenance">
      <summary>Snapshot provenance and verification limits</summary>
      <div id="reference-provenance" hidden></div>
    </details>
    <div class="reference-result" id="reference-result" aria-live="polite" aria-atomic="true">
      <p class="reference-empty" id="reference-empty">Enter a value to inspect registration context.</p>
      <div id="reference-meta" hidden></div>
      <div id="reference-results" hidden></div>
    </div>
  </details>

  <details class="panel investigation-panel" aria-labelledby="offline-title">
    <summary class="panel-head">
      <div><h2 id="offline-title" tabindex="-1">Offline analysis snapshot</h2><p>Validated, source-qualified, privacy-bounded summary loaded once at dashboard startup.</p></div>
      <span class="timestamp" id="offline-status">Checking</span>
    </summary>
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
  </details>
  </section>

  <section class="workspace-view" id="workspace-interfaces" role="tabpanel" aria-labelledby="workspace-tab-interfaces" hidden>
""" + INTEGRATIONS_HTML + """
  </section>
  <noscript><p class="offline-empty">JavaScript is required to render this local dashboard.</p></noscript>
  </div>
</main>
</body>
</html>"""
if "__GLOSSARY_ANCHOR__" not in INDEX_HTML:
    raise AssertionError("glossary anchor placeholder missing from INDEX_HTML")
INDEX_HTML = INDEX_HTML.replace("__GLOSSARY_ANCHOR__", GLOSSARY_ANCHOR_ID)


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
html { height: 100%; overflow: hidden; }
body {
  margin: 0; min-width: 300px; height: 100vh; height: 100dvh; overflow: hidden; color: var(--text);
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
.shell { position: relative; display: grid; grid-template-rows: auto auto minmax(0, 1fr); width: min(1240px, calc(100% - 32px)); height: 100%; margin: 0 auto; padding: 20px 0 16px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 14px; }
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
.connection-state { display: grid; justify-items: end; gap: 3px; }
.connection-state > span { color: var(--muted); font-size: .62rem; font-weight: 750; letter-spacing: .04em; text-transform: uppercase; }
.section-nav { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0 0 12px; padding: 5px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .68); }
.section-nav button { min-height: 44px; border: 1px solid transparent; border-radius: 10px; background: transparent; color: var(--muted); font-size: .78rem; font-weight: 800; }
.section-nav button:hover:not(:disabled) { border-color: rgba(81, 230, 207, .28); color: #c8fff7; background: rgba(81, 230, 207, .06); }
.section-nav button[aria-selected="true"] { border-color: rgba(81, 230, 207, .42); color: #c8fff7; background: linear-gradient(145deg, rgba(81, 230, 207, .17), rgba(110, 216, 255, .07)); box-shadow: inset 0 1px rgba(255, 255, 255, .08); }
.section-nav button[aria-selected="true"]:hover:not(:disabled) { background: linear-gradient(145deg, rgba(81, 230, 207, .2), rgba(110, 216, 255, .09)); }
.workspace-scroll { min-height: 0; overflow: auto; overscroll-behavior: contain; padding: 10px 4px 32px; scrollbar-color: var(--muted) rgba(3, 13, 19, .42); }
.workspace-view { min-height: 100%; }
.hero { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: 24px; margin-bottom: 24px; }
.eyebrow { margin: 0 0 9px; color: var(--aqua); font-size: .75rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
h1 { max-width: 760px; margin: 0; font-size: clamp(2rem, 5vw, 4.25rem); line-height: .98; letter-spacing: -.055em; }
.lede { max-width: 720px; margin: 16px 0 0; color: var(--muted); font-size: clamp(.95rem, 1.7vw, 1.08rem); line-height: 1.65; }
.read-only {
  align-self: start; padding: 12px 15px; border: 1px solid rgba(81, 230, 207, .25);
  border-radius: 14px; background: rgba(81, 230, 207, .07); color: #b7fff2;
  font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; white-space: nowrap;
}
.section-intro { display: grid; grid-template-columns: 144px minmax(0, 1fr); gap: 18px; align-items: start; margin: 30px 0 14px; padding: 0 4px; }
.section-intro .eyebrow { margin-top: 5px; }
.section-intro h2 { margin: 0; font-size: 1.08rem; letter-spacing: -.01em; }
.section-intro p:not(.eyebrow) { max-width: 780px; margin: 6px 0 0; color: var(--muted); font-size: .83rem; line-height: 1.55; }
.deep-analysis-intro { margin-top: 40px; }
.analysis-window { display: grid; grid-template-columns: minmax(0, 1fr) minmax(330px, .7fr); gap: 18px; align-items: center; margin: 0 0 18px; padding: 18px 20px; border: 1px solid rgba(255, 209, 102, .28); border-radius: var(--radius); background: linear-gradient(145deg, rgba(65, 54, 23, .24), rgba(8, 24, 33, .88)); box-shadow: var(--shadow); }
.analysis-window h3 { margin: 0; font-size: .94rem; }
.analysis-window p:not(.eyebrow) { max-width: 720px; margin: 7px 0 0; color: var(--muted); font-size: .8rem; line-height: 1.55; }
.analysis-window p.analysis-trust { color: var(--amber); font-weight: 700; }
.analysis-limitations { margin: 10px 0 0; padding-left: 18px; color: var(--muted); font-size: .76rem; line-height: 1.5; }
.receipt-digest { overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.analysis-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; margin: 0; }
.analysis-facts div { padding: 10px 11px; border: 1px solid var(--line); border-radius: 11px; background: rgba(3, 13, 19, .42); }
.analysis-facts dt { color: var(--muted); font-size: .65rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.analysis-facts dd { margin: 5px 0 0; color: #ffe5a1; font-size: .74rem; font-weight: 750; line-height: 1.35; }
.ingestion-runs-panel { margin-bottom: 18px; }
.ingestion-runs-note { margin: 16px 22px 0; padding: 12px 14px; border: 1px solid rgba(110, 216, 255, .2); border-radius: 12px; background: rgba(110, 216, 255, .045); color: var(--muted); font-size: .78rem; line-height: 1.5; }
.ingestion-runs-list { display: grid; gap: 10px; padding: 16px 22px 0; }
.ingestion-run { padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .34); }
.ingestion-run-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
.ingestion-run h3 { margin: 0; font-size: .86rem; }
.ingestion-run-status { padding: 4px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
.ingestion-run-status.completed { border-color: rgba(75, 227, 176, .35); color: var(--aqua); }
.ingestion-run-status.incomplete, .ingestion-run-status.failed, .ingestion-run-status.reconciliation_required { border-color: rgba(255, 209, 102, .35); color: var(--amber); }
.ingestion-run-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 12px 0 0; }
.ingestion-run-facts div { min-width: 0; padding: 9px 10px; border-radius: 10px; background: rgba(110, 216, 255, .035); }
.ingestion-run-facts dt { color: var(--muted); font-size: .64rem; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
.ingestion-run-facts dd { margin: 4px 0 0; overflow-wrap: anywhere; font-size: .75rem; }
.ingestion-run-reason { margin: 10px 0 0; color: var(--muted); font-size: .74rem; line-height: 1.45; }
.ingestion-run-evidence { margin: 8px 0 0; color: var(--muted); font-size: .74rem; line-height: 1.45; }
.evidence-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--line); font-weight: 800; font-size: .68rem; letter-spacing: .03em; text-transform: uppercase; white-space: nowrap; }
.evidence-badge.contract-only { border-color: rgba(110, 216, 255, .35); color: var(--cyan); }
.ingestion-runs-empty { margin: 0; padding: 14px; border: 1px dashed var(--line); border-radius: 12px; color: var(--muted); font-size: .78rem; }
.ingestion-runs-actions { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; padding: 14px 22px 20px; }
.ingestion-source-control { display: grid; gap: 5px; width: min(100%, 230px); color: var(--muted); font-size: .75rem; font-weight: 700; }
.trust-strip {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px;
  align-items: center; margin: 0 0 10px; padding: 12px 14px; border: 1px solid var(--line);
  border-left: 4px solid var(--muted); border-radius: 15px; background: rgba(5, 18, 25, .62);
}
.trust-strip.current { border-left-color: var(--aqua); }
.trust-strip.paused, .trust-strip.checking { border-left-color: var(--amber); background: rgba(255, 209, 102, .035); }
.trust-strip.stale { border-left-color: var(--rose); background: rgba(255, 117, 143, .04); }
.trust-summary .eyebrow { margin-bottom: 6px; }
.trust-message { margin: 0; color: var(--text); font-size: .82rem; line-height: 1.55; }
.snapshot-scope { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 7px; margin: 0; }
.snapshot-scope span { padding: 5px 8px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: .66rem; font-weight: 750; }
.trust-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; margin: 0; }
.trust-facts div { padding: 10px 11px; border: 1px solid var(--line); border-radius: 11px; background: rgba(3, 13, 19, .42); }
.trust-facts dt { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.trust-facts dd { margin: 5px 0 0; color: #d8ebee; font-size: .78rem; font-weight: 750; line-height: 1.35; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 0 0 12px; }
.metric, .panel {
  border: 1px solid var(--line); background: linear-gradient(145deg, rgba(18, 45, 59, .92), rgba(8, 24, 33, .9));
  box-shadow: var(--shadow);
}
.metric { min-height: 76px; padding: 12px 14px; border-radius: 13px; box-shadow: none; }
.metric-label { color: var(--muted); font-size: .66rem; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
.metric-value { margin-top: 7px; font-size: 1.45rem; font-variant-numeric: tabular-nums; font-weight: 800; letter-spacing: -.03em; }
.metric-note { margin-top: 3px; color: var(--muted); font-size: .68rem; line-height: 1.35; }
.panel { overflow: hidden; border-radius: var(--radius); }
.panel + .panel { margin-top: 18px; }
.panel-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 22px; border-bottom: 1px solid var(--line); }
.panel-head h2 { margin: 0; font-size: 1rem; letter-spacing: -.01em; }
.panel-head p { margin: 6px 0 0; color: var(--muted); font-size: .82rem; line-height: 1.5; }
.panel-head .eyebrow { margin: 0 0 5px; }
.investigation-panel > summary { cursor: pointer; list-style: none; }
.investigation-panel > summary::-webkit-details-marker { display: none; }
.investigation-panel > summary::after { content: "Open"; color: var(--aqua); font-size: .7rem; font-weight: 800; }
.investigation-panel[open] > summary::after { content: "Close"; }
.investigation-panel:not([open]) > summary { border-bottom: 0; }
.timestamp { color: var(--muted); font-size: .75rem; white-space: nowrap; }
.priority-pulse { display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 14px 22px; border-bottom: 1px solid var(--line); background: rgba(81, 230, 207, .035); }
.priority-pulse .eyebrow { margin-bottom: 5px; }
.priority-change { margin: 0; color: var(--text); font-size: .86rem; font-weight: 800; line-height: 1.45; }
.priority-boundary { max-width: 510px; margin: 0; color: var(--muted); font-size: .72rem; line-height: 1.5; text-align: right; }
.toolbar { display: grid; grid-template-columns: minmax(210px, 1fr) repeat(2, minmax(145px, .42fr)) auto; align-items: end; gap: 12px; min-width: 0; margin: 0; padding: 16px 22px; border: 0; border-bottom: 1px solid var(--line); background: rgba(4, 15, 21, .26); }
.toolbar:disabled { opacity: .76; }
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
.triage-summary { display: flex; flex-wrap: wrap; gap: 8px; padding: 13px 22px 0; }
.summary-chip { padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; background: rgba(110, 216, 255, .045); color: #c9e9f0; font-size: .7rem; font-weight: 750; }
.timeline-section { padding: 14px 22px 18px; border-bottom: 1px solid var(--line); }
.timeline-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; }
.timeline-head h3 { margin: 0; font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; }
.timeline-head p { margin: 5px 0 0; color: var(--muted); font-size: .72rem; line-height: 1.45; }
.timeline { display: grid; grid-template-columns: repeat(auto-fit, minmax(54px, 1fr)); align-items: end; gap: 6px; min-height: 94px; margin-top: 13px; }
.timeline-bin { display: grid; grid-template-rows: 54px auto; align-items: end; gap: 6px; min-width: 0; min-height: 82px; padding: 6px; border-color: var(--line); background: rgba(110, 216, 255, .035); color: var(--muted); }
.timeline-bin:hover:not(:disabled) { background: rgba(110, 216, 255, .09); }
.timeline-bin[aria-pressed="true"] { border-color: var(--aqua); background: rgba(81, 230, 207, .14); color: var(--text); }
.timeline-bar { display: block; width: 100%; border-radius: 6px 6px 3px 3px; background: var(--cyan); opacity: .78; }
.timeline-bar.level-0 { height: 0; }
.timeline-bar:not(.level-0) { min-height: 5px; }
.timeline-bar.level-1 { height: 10%; } .timeline-bar.level-2 { height: 20%; } .timeline-bar.level-3 { height: 30%; }
.timeline-bar.level-4 { height: 40%; } .timeline-bar.level-5 { height: 50%; } .timeline-bar.level-6 { height: 60%; }
.timeline-bar.level-7 { height: 70%; } .timeline-bar.level-8 { height: 80%; } .timeline-bar.level-9 { height: 90%; } .timeline-bar.level-10 { height: 100%; }
.timeline-count { overflow: hidden; font-size: .68rem; font-variant-numeric: tabular-nums; font-weight: 850; text-overflow: ellipsis; }
.timeline-status { margin: 9px 0 0; color: var(--muted); font-size: .72rem; line-height: 1.45; }
.triage-tools { border-bottom: 1px solid var(--line); background: rgba(3, 13, 19, .2); }
.triage-tools > summary { border-bottom: 0; }
.triage-tools[open] > summary { border-bottom: 1px solid var(--line); }
.table-scroll { overflow-x: auto; scrollbar-color: var(--muted) rgba(3, 13, 19, .42); }
.table-scroll:focus-visible { outline-offset: -3px; }
table { width: 100%; border-collapse: collapse; }
caption { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
th, td { padding: 13px 16px; border-bottom: 1px solid rgba(148, 188, 202, .12); overflow-wrap: anywhere; text-align: left; font-size: .82rem; vertical-align: top; }
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
.reference-warning { margin: 16px 22px 0; padding: 12px 14px; border: 1px solid rgba(255, 209, 102, .26); border-radius: 12px; background: rgba(255, 209, 102, .06); color: #ffe5a1; font-size: .78rem; line-height: 1.5; }
.reference-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 16px 22px 0; }
.reference-form { display: grid; align-content: start; gap: 10px; padding: 15px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .34); }
.reference-form h3 { margin: 0; font-size: .86rem; }
.reference-form p { min-height: 34px; margin: -3px 0 1px; color: var(--muted); font-size: .74rem; line-height: 1.45; }
.reference-form button { justify-self: start; }
.reference-status { margin: 16px 22px 0; color: var(--muted); font-size: .78rem; line-height: 1.5; }
.reference-status.ready { color: var(--aqua); }
.reference-status.empty { color: var(--muted); }
.reference-status.stale, .reference-status.integrity_failure, .reference-status.unavailable { color: var(--amber); }
.reference-result { margin: 12px 22px 22px; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .28); }
.reference-empty { margin: 0; color: var(--muted); font-size: .78rem; }
.reference-meta { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 12px; }
.reference-meta .summary-chip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .68rem; }
.reference-records { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
.reference-record { display: grid; grid-template-columns: minmax(105px, .38fr) minmax(0, 1fr); gap: 12px; padding: 11px 12px; border: 1px solid var(--line); border-radius: 11px; background: rgba(110, 216, 255, .035); }
.reference-record dt { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
.reference-record dd { margin: 0; overflow-wrap: anywhere; font-size: .78rem; }
.reference-record dd + dt { margin-top: 6px; }
.suricata-summary { margin: 16px 22px; }
#suricata-alerts td { overflow-wrap: anywhere; }
code { padding: 2px 5px; border: 1px solid var(--line); border-radius: 6px; background: rgba(0, 0, 0, .2); color: #c8f7ef; font-size: .85em; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
[hidden] { display: none !important; }
@media (max-width: 880px) {
  .hero { grid-template-columns: 1fr; } .read-only { justify-self: start; }
  .section-intro, .analysis-window { grid-template-columns: 1fr; }
  .trust-strip { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .toolbar { grid-template-columns: minmax(0, 1fr) minmax(150px, .45fr); }
  .toolbar-actions { grid-column: 1 / -1; }
  .offline-grid { grid-template-columns: 1fr; }
  .offline-side { border-top: 1px solid var(--line); border-left: 0; }
  .reference-grid { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
  .shell { width: min(100% - 20px, 1240px); padding: 12px 0 10px; }
  .topbar { align-items: flex-start; } .brand-subtitle { display: none; } .connection { max-width: 145px; }
  .trust-strip { padding: 14px; } .trust-facts { grid-template-columns: 1fr; }
  .section-nav { gap: 4px; padding: 4px; } .section-nav button { padding: 7px 5px; font-size: .72rem; } .workspace-scroll { padding-top: 6px; } .section-intro { gap: 4px; margin-top: 24px; } .analysis-window { padding: 15px; } .analysis-facts { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: 1fr 1fr; } .metric { min-height: 108px; padding: 14px; }
  .panel-head { display: block; } .timestamp { display: block; margin-top: 7px; }
  .priority-pulse { display: block; padding: 14px; } .priority-boundary { margin-top: 8px; text-align: left; }
  .toolbar { grid-template-columns: 1fr; padding: 14px; }
  .toolbar-actions, .filter-status { grid-column: 1; }
  .toolbar-actions { display: grid; grid-template-columns: 1fr 1fr; }
  #clear-filters { grid-column: 1 / -1; }
  .triage-summary, .timeline-section { padding-right: 14px; padding-left: 14px; }
  .ingestion-runs-note, .reference-warning, .reference-grid, .reference-status, .reference-result { margin-right: 14px; margin-left: 14px; }
  .ingestion-runs-list { padding-right: 14px; padding-left: 14px; }
  .ingestion-run-facts { grid-template-columns: 1fr; }
  .reference-grid { padding-right: 0; padding-left: 0; }
  th, td { padding: 11px 12px; } .facts { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; } }
@media (forced-colors: active) {
  .timeline-bin[aria-pressed="true"] { border-width: 3px; }
  .timeline-bar { background: CanvasText; forced-color-adjust: none; }
}
"""


DASHBOARD_CSS += INTEGRATIONS_CSS
DASHBOARD_CSS += CONTROLS_CSS + "\n.hero {padding: 18px 0;} .hero h1 {font-size: 2rem;} .integration-card h3 {font-size: 1.1rem;} .integration-card dd, .integration-gate {font-size: .875rem;}\n"
DASHBOARD_CSS += r"""
.command-overview { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(310px, .62fr); gap: 12px; align-items: stretch; margin-bottom: 12px; }
.traffic-panel { margin: 0; border-color: rgba(81, 230, 207, .28); background: linear-gradient(145deg, rgba(14, 49, 61, .96), rgba(6, 23, 32, .96)); }
.traffic-heading { display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; padding: 16px 18px 10px; }
.traffic-heading h2 { margin: 0; font-size: clamp(1.25rem, 2.5vw, 1.8rem); letter-spacing: -.03em; }
.traffic-heading p:not(.eyebrow) { margin: 7px 0 0; color: var(--muted); font-size: .8rem; line-height: 1.5; }
.traffic-freshness { padding: 6px 10px; border: 1px solid rgba(81, 230, 207, .28); border-radius: 999px; color: var(--aqua); background: rgba(81, 230, 207, .07); font-size: .7rem; font-weight: 800; white-space: nowrap; }
.traffic-freshness.sample { border-color: rgba(255, 209, 102, .32); color: var(--amber); background: rgba(255, 209, 102, .07); }
.traffic-layout { display: grid; grid-template-columns: minmax(0, 1.5fr) minmax(250px, .58fr); gap: 12px; padding: 0 18px 12px; }
.traffic-plot-wrap { min-width: 0; padding: 12px 14px 9px; border: 1px solid var(--line); border-radius: 12px; background: rgba(1, 12, 18, .48); }
.traffic-chart { display: grid; grid-template-columns: repeat(24, minmax(0, 1fr)); align-items: end; gap: clamp(2px, .55vw, 7px); width: 100%; height: 112px; overflow: hidden; }
.traffic-bar { display: block; inline-size: 100%; min-inline-size: 0; max-inline-size: 100%; min-height: 3px; justify-self: stretch; overflow: hidden; border-radius: 5px 5px 2px 2px; background: linear-gradient(to top, rgba(81, 230, 207, .35), var(--aqua)); box-shadow: 0 0 14px rgba(81, 230, 207, .12); }
.traffic-bar.traffic-empty { width: 1px; min-width: 0; max-width: 1px; padding: 0; justify-self: center; opacity: .2; box-shadow: none; }
.traffic-bar.level-0 { height: 2%; } .traffic-bar.level-1 { height: 10%; } .traffic-bar.level-2 { height: 20%; }
.traffic-bar.level-3 { height: 30%; } .traffic-bar.level-4 { height: 40%; } .traffic-bar.level-5 { height: 50%; }
.traffic-bar.level-6 { height: 60%; } .traffic-bar.level-7 { height: 70%; } .traffic-bar.level-8 { height: 80%; }
.traffic-bar.level-9 { height: 90%; } .traffic-bar.level-10 { height: 100%; }
.traffic-axis { display: flex; justify-content: space-between; margin-top: 8px; color: var(--muted); font-size: .64rem; text-transform: uppercase; letter-spacing: .08em; }
.traffic-explainer { margin: 8px 0 0; color: var(--muted); font-size: .68rem; line-height: 1.4; }
.traffic-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 0; }
.traffic-facts div { display: flex; flex-direction: column; justify-content: center; min-width: 0; padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; background: rgba(3, 13, 19, .38); }
.traffic-facts dt { color: var(--muted); font-size: .65rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.traffic-facts dd { margin: 5px 0 0; overflow-wrap: anywhere; font-size: .88rem; font-weight: 800; font-variant-numeric: tabular-nums; }
.protocol-mix { display: flex; flex-wrap: wrap; gap: 7px; padding: 0 18px 12px; }
.protocol-pill { display: inline-flex; gap: 7px; align-items: center; padding: 6px 9px; border: 1px solid var(--line); border-radius: 999px; background: rgba(110, 216, 255, .045); color: #d9f5f7; font-size: .7rem; }
.protocol-pill b { color: var(--aqua); font-variant-numeric: tabular-nums; }
.traffic-boundary { margin: 0; padding: 9px 18px; border-top: 1px solid var(--line); color: var(--muted); background: rgba(3, 13, 19, .26); font-size: .66rem; line-height: 1.4; }
.hud-start { display: grid; grid-template-columns: 1fr; align-content: start; margin: 0; padding: 16px; border-color: var(--line); border-radius: var(--radius); background: linear-gradient(145deg, rgba(15, 38, 50, .9), rgba(7, 22, 31, .9)); }
.hud-start h2, .hud-start h3 { margin: 0; font-size: 1rem; }
.hud-start p { margin: 7px 0; color: var(--muted); font-size: .78rem; line-height: 1.5; }
.setup-status-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin: 12px 0 8px; }
.setup-status-grid div { padding: 10px; border: 1px solid var(--line); border-radius: 11px; background: rgba(3, 13, 19, .42); }
.setup-status-grid span { display: block; color: var(--muted); font-size: .62rem; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; }
.setup-status-grid b { display: block; margin-top: 4px; font-size: .82rem; }
.setup-actions-card { margin-top: 10px; border-top: 1px solid var(--line); }
.setup-form { display: grid; gap: 10px; padding-top: 10px; }
.tool-status-details { border-top: 1px solid var(--line); }
.setup-boundary { margin-bottom: 10px !important; }
.tool-status-list { display: grid; gap: 7px; max-height: 290px; overflow: auto; padding-right: 4px; }
.tool-status-row { display: grid; grid-template-columns: minmax(110px, .6fr) minmax(0, 1.4fr); gap: 10px; align-items: center; padding: 8px 9px; border: 1px solid var(--line); border-radius: 9px; background: rgba(3, 13, 19, .32); }
.tool-status-row strong { font-size: .72rem; }
.tool-status-badges { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 5px; }
.status-badge { padding: 3px 7px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: .62rem; font-weight: 750; }
.status-badge.executable_found, .status-badge.running { border-color: rgba(81, 230, 207, .3); color: var(--aqua); }
.status-badge.not_found, .status-badge.not_running { color: #bdd0d6; }
.status-badge.not_checked { border-color: rgba(255, 209, 102, .28); color: var(--amber); }
.next-actions { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0 0 12px; }
.next-actions a, .next-actions button { display: grid; gap: 4px; min-height: 70px; padding: 12px 14px; text-align: left; text-decoration: none; border: 1px solid var(--line); border-radius: 13px; background: rgba(7, 25, 34, .74); color: var(--text); box-shadow: none; }
.next-actions a:hover, .next-actions button:hover { border-color: rgba(81, 230, 207, .38); background: rgba(81, 230, 207, .08); }
.next-actions strong { font-size: .8rem; }
.next-actions span { color: var(--muted); font-size: .7rem; line-height: 1.35; }
.report-studio { margin: 0 0 12px; }
.report-studio:not([open]) { display: none; }
.report-studio > summary, .triage-tools > summary { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 58px; padding: 12px 16px; cursor: pointer; list-style: none; }
.report-studio > summary::-webkit-details-marker, .triage-tools > summary::-webkit-details-marker { display: none; }
.report-studio > summary span:first-child, .triage-tools > summary span:first-child { display: grid; gap: 3px; }
.report-studio > summary strong, .triage-tools > summary strong { font-size: .82rem; }
.report-studio > summary small, .triage-tools > summary small { color: var(--muted); font-size: .7rem; line-height: 1.35; }
.summary-action { color: var(--aqua); font-size: .7rem; font-weight: 800; white-space: nowrap; }
.report-studio[open] > summary { border-bottom: 1px solid var(--line); }
.report-layout { display: grid; grid-template-columns: minmax(280px, .72fr) minmax(0, 1.28fr); }
.report-controls { display: grid; gap: 12px; align-content: start; padding: 18px 22px 22px; border-right: 1px solid var(--line); }
.report-actions { display: flex; flex-wrap: wrap; gap: 8px; }
.report-feedback { margin: 0; color: var(--muted); font-size: .72rem; line-height: 1.45; }
.report-preview { min-height: 230px; padding: 20px 22px; background: rgba(3, 13, 19, .3); }
.report-preview h3 { margin: 0; font-size: 1.1rem; }
.report-preview p, .report-preview li { color: var(--muted); font-size: .78rem; line-height: 1.55; }
.report-preview dl { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.report-preview dl div { padding: 9px; border: 1px solid var(--line); border-radius: 9px; }
.report-preview dt { color: var(--muted); font-size: .62rem; font-weight: 800; text-transform: uppercase; }
.report-preview dd { margin: 4px 0 0; font-size: .8rem; font-weight: 800; overflow-wrap: anywhere; }
@media (max-width: 880px) {
  .command-overview, .traffic-layout, .report-layout, .hud-start { grid-template-columns: 1fr; }
  .traffic-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); grid-template-rows: auto; }
  .report-controls { padding-left: 18px; border-right: 0; border-bottom: 1px solid var(--line); }
}
@media (max-width: 560px) {
  .hero { margin-bottom: 14px; }
  .connection-state > span { max-width: 145px; text-align: right; }
  .traffic-heading { display: block; padding: 16px 14px 10px; }
  .traffic-freshness { display: inline-flex; margin-top: 10px; }
  .traffic-layout { padding: 0 14px 12px; }
  .traffic-chart { height: 96px; }
  .traffic-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .protocol-mix, .traffic-boundary { padding-right: 14px; padding-left: 14px; }
  .setup-status-grid, .report-preview dl { grid-template-columns: 1fr; }
  .next-actions { grid-template-columns: 1fr; }
  .next-actions a, .next-actions button { min-height: 60px; }
  .metric { min-height: 72px; padding: 10px 11px; }
  .tool-status-row { grid-template-columns: 1fr; }
  .tool-status-badges { justify-content: flex-start; }
  .report-controls, .report-preview { padding: 16px 14px; }
}
@media print {
  body { height: auto; overflow: visible; background: white; color: black; }
  body::before, .topbar, .section-nav, .hero, .traffic-panel, .hud-start, .section-intro, .trust-strip, .metrics, .triage-panel, .next-actions, .report-studio > summary,
  #workspace-analysis, #workspace-interfaces, .report-studio .panel-head, .report-controls { display: none !important; }
  .shell, .workspace-scroll, .workspace-view, .report-studio { display: block !important; width: 100%; height: auto; overflow: visible; margin: 0; padding: 0; border: 0; box-shadow: none; }
  .report-layout { display: block; }
  .report-preview { color: black; background: white; }
  .report-preview p, .report-preview li, .report-preview dt { color: #333; }
}
"""

DASHBOARD_JS = r"""
'use strict';

const metricSpec = [
  ['events', 'Stored events', 'Metadata rows'],
  ['detections', 'Findings', 'Fixed-rule matches'],
  ['high_or_critical', 'High priority', 'Stored high or critical findings'],
  ['actions', 'Recorded decisions', 'Audit records only']
];
const summaryFields = ['actions', 'detections', 'events', 'high_or_critical'];
const eventFields = ['detected_at', 'message', 'rule_id', 'severity', 'src_ip'];
const knownSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const prioritySeverities = new Set(['CRITICAL', 'HIGH']);
const maxTimelineBins = 12;
const workspaceIds = ['live', 'traffic', 'findings', 'interfaces', 'reports', 'analysis', 'help'];
const workspaceNavigation = {active: 'live', scroll: Object.create(null), pageScroll: Object.create(null)};
const workspaceTargets = {
  'workspace-traffic': 'traffic', 'workspace-findings': 'findings',
  'workspace-reports': 'reports', 'workspace-help': 'help',
  '': 'live', 'page-title': 'live', 'live-review-title': 'live', 'detections-title': 'analysis',
  'room-home-title': 'live', 'setup-title': 'live', 'tool-management-controls': 'live', 'room-traffic-title': 'traffic', 'room-findings-title': 'findings',
  'room-reports-title': 'reports', 'room-help-title': 'help', 'setup-software-title': 'live',
  'workspace-live': 'live', 'deep-analysis-title': 'analysis', 'suricata-title': 'analysis', 'suricata-provenance': 'analysis', 'ingestion-runs-title': 'analysis', 'reference-title': 'analysis',
  'offline-title': 'analysis', 'workspace-analysis': 'analysis', 'integrations-title': 'interfaces',
  'workspace-interfaces': 'interfaces', 'analysis-window-title': 'analysis',
  'help-language': 'help', 'status-glossary': 'help'
};
const state = {
  events: [],
  summary: null,
  traffic: null,
  ingestionRuns: [],
  ingestionRunsFetchedAt: null,
  activeBin: null,
  timelineBins: [],
  timelineNotice: '',
  lastPriorityTotal: null,
  paused: false,
  refreshing: false,
  timer: null,
  lastSuccessfulRefresh: null,
  lastRefreshFailed: false,
  telemetryNotConfigured: false,
  configDegraded: false,
  config: {event_limit: 50, refresh_seconds: 5}
};
const referenceState = {
  available: null,
  status: 'loading',
  loading: false,
  statusLoading: false,
  snapshot: null,
  lastResult: null,
  lastQuery: null
};
const referenceSourceFields = ['id', 'registry_url', 'registry_last_updated', 'retrieved_at', 'retrieved_at_basis'];
const referencePortFields = ['service_name', 'transport', 'port_start', 'port_end', 'record_kind', 'description', 'registration_date', 'modification_date', 'source_row'];
const referenceProtocolFields = ['keyword', 'protocol_name', 'decimal_start', 'decimal_end', 'record_kind', 'ipv6_extension_header', 'source_row'];
const advisoryReceiptFields = ['code', 'limitations', 'model_receipt', 'outcome', 'summary'];
const advisoryModelFields = ['model_artifact_sha256', 'model_id', 'policy_version', 'provider_class'];
const advisoryCodes = Object.freeze({
  ANSWER: 'ADVISORY_ANSWER', ABSTAIN: 'INSUFFICIENT_ALLOWED_CONTEXT',
  DENY: 'POLICY_DENIED', ERROR: 'LOCAL_PROVIDER_ERROR'
});
const maxAdvisoryResponseBytes = 8 * 1024;
const maxIngestionRunsResponseBytes = 32 * 1024;
const maxSuricataResponseBytes = 64 * 1024;
let ingestionRunsLoading = false;
const ingestionRunFields = [
  'action_count', 'detection_count', 'failure_code', 'finished_at', 'processed_count',
  'receipt_version', 'run_id', 'source', 'started_at', 'status', 'termination_reason'
];
const ingestionRunSources = new Set(['sample', 'jsonl', 'scapy']);
const ingestionRunStatuses = new Set(['running', 'completed', 'incomplete', 'failed', 'reconciliation_required']);
const ingestionFailureCodes = new Set(['CAPTURE_ERROR', 'INTERRUPTED', 'IO_ERROR', 'STORAGE_ERROR', 'VALIDATION_ERROR']);
const ingestionTerminationReasons = new Set(['source_exhausted', 'event_limit_reached', 'interrupted', 'failed', 'reconciliation_required']);

function byId(value) { return document.getElementById(value); }
function activateWorkspace(nextWorkspace, moveFocus = false) {
  if (!workspaceIds.includes(nextWorkspace)) return;
  const pageScroll = typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 560px), (max-height: 500px)').matches;
  const scroller = pageScroll ? document.scrollingElement || document.documentElement : byId('workspace-content');
  const positions = pageScroll ? workspaceNavigation.pageScroll : workspaceNavigation.scroll;
  positions[workspaceNavigation.active] = scroller.scrollTop;
  workspaceIds.forEach(workspace => {
    const selected = workspace === nextWorkspace;
    const tab = byId(`workspace-tab-${workspace}`);
    tab.setAttribute('aria-selected', selected ? 'true' : 'false');
    tab.tabIndex = selected ? 0 : -1;
    byId(`workspace-${workspace}`).hidden = !selected;
  });
  scroller.scrollTop = positions[nextWorkspace] || 0;
  workspaceNavigation.active = nextWorkspace;
  if (nextWorkspace === 'interfaces' && typeof maybeLoadIntegrationMap === 'function') maybeLoadIntegrationMap();
  if (moveFocus) {
    const tab = byId(`workspace-tab-${nextWorkspace}`);
    if (typeof tab.focus === 'function') tab.focus();
  }
}
function navigateWorkspace(workspace, moveFocus = false) {
  if (!workspaceIds.includes(workspace)) return;
  activateWorkspace(workspace, moveFocus);
  const hash = `#workspace-${workspace}`;
  if (window.location && window.location.hash !== hash && window.history) {
    try { window.history.pushState(null, '', hash); } catch { /* Navigation still works without history. */ }
  }
}
function workspaceFromHash(value) {
  if (typeof value !== 'string' || value.length > 128 || (value && !value.startsWith('#'))) return null;
  const target = value.startsWith('#') ? value.slice(1) : '';
  return Object.prototype.hasOwnProperty.call(workspaceTargets, target) ? workspaceTargets[target] : null;
}
function revealTargetDisclosure(target) {
  for (let parent = target; parent; parent = parent.parentElement) {
    if (parent.tagName === 'DETAILS') parent.open = true;
  }
}
function restoreWorkspaceFromHash() {
  const hash = window.location && typeof window.location.hash === 'string' ? window.location.hash : '';
  const workspace = workspaceFromHash(hash);
  if (!workspace) return;
  activateWorkspace(workspace);
  const targetId = hash.startsWith('#') ? hash.slice(1) : '';
  const target = targetId ? byId(targetId) : null;
  revealTargetDisclosure(target);
  if (target && !targetId.startsWith('workspace-') && typeof target.scrollIntoView === 'function') target.scrollIntoView({block: 'start'});
}
workspaceIds.forEach((workspace, index) => {
  const tab = byId(`workspace-tab-${workspace}`);
  tab.addEventListener('click', () => navigateWorkspace(workspace));
  tab.addEventListener('keydown', event => {
    let nextIndex = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % workspaceIds.length;
    if (event.key === 'ArrowLeft') nextIndex = (index - 1 + workspaceIds.length) % workspaceIds.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = workspaceIds.length - 1;
    if (nextIndex === null) return;
    event.preventDefault(); navigateWorkspace(workspaceIds[nextIndex], true);
  });
});
document.addEventListener('click', event => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const link = event.target && typeof event.target.closest === 'function' ? event.target.closest('a[href^="#"]') : null;
  if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
  const hash = link.getAttribute('href');
  const workspace = workspaceFromHash(hash);
  if (!workspace) return;
  // A tab change can hide the current hash target. Reveal it on every link
  // activation, including repeated fragments that do not fire hashchange.
  activateWorkspace(workspace);
  const target = byId(hash.slice(1));
  revealTargetDisclosure(target);
  if (target && typeof target.focus === 'function') target.focus({preventScroll: true});
  // Keep native fragment history and scrolling after exposing the target.
});
if (typeof window.addEventListener === 'function') {
  window.addEventListener('hashchange', restoreWorkspaceFromHash);
  window.addEventListener('popstate', restoreWorkspaceFromHash);
}
function textNode(tag, value = '', className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = String(value);
  return node;
}
// Fixed five-level evidence taxonomy from ADR-0006 (docs/adr/0006-evidence-status-badges.md).
// The glyph is decorative and always aria-hidden; the label is the only thing a screen
// reader announces, so a badge is never rendered with the glyph alone.
const evidenceGlyphs = Object.freeze({
  'implemented': '●', 'proposed': '◐', 'contract-only': '◇',
  'synthetic': '▽', 'native-receipt-required': '◆'
});
function evidenceBadge(level, label) {
  const badge = document.createElement('span'); badge.className = `evidence-badge ${level}`;
  const glyph = textNode('span', evidenceGlyphs[level]); glyph.setAttribute('aria-hidden', 'true');
  badge.append(glyph, document.createTextNode(` ${label}`));
  return badge;
}
function formatNumber(value) { return new Intl.NumberFormat().format(Number(value)); }
const displayTimeFormatter = new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  second: '2-digit', fractionalSecondDigits: 3, timeZoneName: 'short'
});
function displayTime(value) { return displayTimeFormatter.format(value); }
function timeNode(value) {
  const parsed = new Date(value);
  const node = textNode('time', Number.isNaN(parsed.valueOf()) ? String(value) : displayTime(parsed));
  if (!Number.isNaN(parsed.valueOf())) node.dateTime = parsed.toISOString();
  return node;
}
function severityPresentation(value) {
  const normalized = String(value || '').toUpperCase();
  return knownSeverities.has(normalized) ? normalized : 'UNKNOWN';
}
function validatedSummary(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid summary response');
  const keys = Object.keys(value).sort();
  if (keys.length !== summaryFields.length || !summaryFields.every((field, index) => keys[index] === field)) {
    throw new Error('invalid summary response');
  }
  if (!summaryFields.every(field => Number.isSafeInteger(value[field]) && value[field] >= 0)
      || value.high_or_critical > value.detections) {
    throw new Error('invalid summary response');
  }
  return value;
}
function validatedEvents(value) {
  if (!Array.isArray(value) || value.length > state.config.event_limit) throw new Error('invalid events response');
  const valid = value.every(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
    const keys = Object.keys(event).sort();
    if (keys.length !== eventFields.length || !eventFields.every((field, index) => keys[index] === field)) return false;
    return eventFields.every(field => typeof event[field] === 'string') && knownSeverities.has(event.severity);
  });
  if (!valid) throw new Error('invalid events response');
  return value;
}
function validatedTraffic(value) {
  const source = validateTraffic(value);
  const events = source.events.map(event => Object.freeze({
    observed_at: event.observed_at,
    protocol: event.protocol,
    byte_count: event.byte_count
  }));
  const protocolMap = new Map();
  let totalBytes = 0n;
  events.forEach(event => {
    const byteCount = BigInt(event.byte_count);
    totalBytes += byteCount;
    const item = protocolMap.get(event.protocol) || {protocol: event.protocol, events: 0, bytes: 0n};
    item.events += 1; item.bytes += byteCount; protocolMap.set(event.protocol, item);
  });
  const protocols = [...protocolMap.values()]
    .sort((left, right) => right.events - left.events || left.protocol.localeCompare(right.protocol))
    .map(item => Object.freeze({...item, bytes: item.bytes.toString()}));
  return Object.freeze({
    schema: source.schema,
    status: source.status,
    sample_limit: source.limits.events,
    sampled_events: events.length,
    total_bytes: totalBytes.toString(),
    first_observed_at: source.window.start,
    last_observed_at: source.window.end,
    protocols: Object.freeze(protocols),
    events: Object.freeze(events)
  });
}
function unavailableTrafficResponse(value) {
  try { return validateTraffic(value).status === 'unavailable'; }
  catch (_) { return false; }
}
function boundedAdvisoryText(value) {
  return typeof value === 'string' && [...value].length >= 1 && [...value].length <= 1200
    && value.trim().length > 0
    && !/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff\ufeff]/u.test(value);
}
function validatedAdvisoryEnvelope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.schema !== 'dashboard-advisory-receipt-v1' || typeof value.available !== 'boolean') {
    throw new Error('invalid advisory receipt');
  }
  const envelopeKeys = Object.keys(value).sort();
  const expectedEnvelopeKeys = value.available ? ['available', 'receipt', 'schema'] : ['available', 'schema'];
  if (envelopeKeys.length !== expectedEnvelopeKeys.length
      || !expectedEnvelopeKeys.every((field, index) => envelopeKeys[index] === field)) {
    throw new Error('invalid advisory receipt');
  }
  if (!value.available) return null;
  const receipt = value.receipt;
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) throw new Error('invalid advisory receipt');
  const receiptKeys = Object.keys(receipt).sort();
  if (receiptKeys.length !== advisoryReceiptFields.length
      || !advisoryReceiptFields.every((field, index) => receiptKeys[index] === field)
      || !Object.prototype.hasOwnProperty.call(advisoryCodes, receipt.outcome)
      || advisoryCodes[receipt.outcome] !== receipt.code
      || !boundedAdvisoryText(receipt.summary)
      || !Array.isArray(receipt.limitations) || receipt.limitations.length < 1 || receipt.limitations.length > 8
      || !receipt.limitations.every(boundedAdvisoryText)
      || new Set(receipt.limitations).size !== receipt.limitations.length) {
    throw new Error('invalid advisory receipt');
  }
  const model = receipt.model_receipt;
  if (!model || typeof model !== 'object' || Array.isArray(model)) throw new Error('invalid advisory receipt');
  const modelKeys = Object.keys(model).sort();
  if (modelKeys.length !== advisoryModelFields.length
      || !advisoryModelFields.every((field, index) => modelKeys[index] === field)
      || model.provider_class !== 'local_loopback'
      || model.policy_version !== 'local-model-advisory-v1'
      || typeof model.model_id !== 'string'
      || !/^local:qwen-[A-Za-z0-9._-]{1,96}(?![\s\S])/u.test(model.model_id)
      || typeof model.model_artifact_sha256 !== 'string'
      || !/^[a-f0-9]{64}(?![\s\S])/u.test(model.model_artifact_sha256)) {
    throw new Error('invalid advisory receipt');
  }
  const ownedModel = Object.freeze({
    provider_class: model.provider_class, model_id: model.model_id,
    model_artifact_sha256: model.model_artifact_sha256, policy_version: model.policy_version
  });
  return Object.freeze({
    outcome: receipt.outcome, code: receipt.code, summary: receipt.summary,
    limitations: Object.freeze([...receipt.limitations]), model_receipt: ownedModel
  });
}
function renderAdvisoryUnavailable(message) {
  byId('analysis-window-title').textContent = 'Qwen advisory receipt · unavailable';
  byId('analysis-summary').textContent = message;
  byId('analysis-outcome').textContent = 'Unavailable';
  byId('analysis-model').textContent = 'Not supplied';
  byId('analysis-digest').textContent = 'Not supplied';
  byId('analysis-policy').textContent = 'local-model-advisory-v1';
  byId('analysis-limitations').replaceChildren();
}
function renderAdvisoryReceipt(receipt) {
  byId('analysis-window-title').textContent = 'Qwen advisory receipt · display only';
  byId('analysis-summary').textContent = receipt.summary;
  byId('analysis-outcome').textContent = `${receipt.outcome} · ${receipt.code}`;
  byId('analysis-model').textContent = receipt.model_receipt.model_id;
  byId('analysis-digest').textContent = receipt.model_receipt.model_artifact_sha256;
  byId('analysis-policy').textContent = receipt.model_receipt.policy_version;
  byId('analysis-limitations').replaceChildren(
    ...receipt.limitations.map(value => textNode('li', value))
  );
}
function validRecordedTime(value) {
  if (typeof value !== 'string' || value.length < 20 || value.length > 64) return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})(?![\s\S])/u.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offset = match[7];
  if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month - 1]) return false;
  if (offset !== 'Z' && (Number(offset.slice(1, 3)) > 23 || Number(offset.slice(4, 6)) > 59)) return false;
  return !Number.isNaN(new Date(value).valueOf());
}
function validIngestionRunSemantics(run) {
  const finished = run.finished_at !== null;
  if (run.receipt_version === 2) {
    if (run.termination_reason !== null || !['running', 'completed', 'failed'].includes(run.status)) return false;
    if (run.status === 'running') return !finished && run.failure_code === null;
    if (run.status === 'completed') return finished && run.failure_code === null;
    return finished && ingestionFailureCodes.has(run.failure_code);
  }
  if (run.status === 'running') return !finished && run.failure_code === null && run.termination_reason === null;
  if (run.status === 'completed') return finished && run.failure_code === null && run.termination_reason === 'source_exhausted';
  if (run.status === 'incomplete') return finished && run.failure_code === null && run.termination_reason === 'event_limit_reached';
  if (run.status === 'reconciliation_required') return !finished && run.failure_code === null && run.termination_reason === 'reconciliation_required';
  if (!finished || !ingestionFailureCodes.has(run.failure_code)) return false;
  return run.failure_code === 'INTERRUPTED'
    ? run.termination_reason === 'interrupted'
    : run.termination_reason === 'failed';
}
function validatedIngestionRuns(value, expectedSource) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.schema !== 'dashboard-ingestion-runs-v2'
      || value.limit !== 8
      || value.max_runs !== 25 || value.max_response_bytes !== maxIngestionRunsResponseBytes
      || !['adapter_identity', 'accepted_count', 'rejected_count'].every((item, index) =>
        Array.isArray(value.not_recorded) && value.not_recorded[index] === item)
      || value.not_recorded.length !== 3
      || value.source_filter !== expectedSource
      || !Array.isArray(value.runs) || value.runs.length > value.limit
      || Object.keys(value).sort().join(',') !== 'limit,max_response_bytes,max_runs,not_recorded,runs,schema,source_filter') {
    throw new Error('invalid ingestion run response');
  }
  return Object.freeze(value.runs.map(run => {
    if (!run || typeof run !== 'object' || Array.isArray(run)
        || Object.keys(run).sort().join(',') !== ingestionRunFields.join(',')
        || !Number.isSafeInteger(run.run_id) || run.run_id < 1
        || ![run.processed_count, run.detection_count, run.action_count].every(item => Number.isSafeInteger(item) && item >= 0)
        || ![2, 3].includes(run.receipt_version)
        || !ingestionRunSources.has(run.source) || !ingestionRunStatuses.has(run.status)
        || (expectedSource !== 'all' && run.source !== expectedSource)
        || !validRecordedTime(run.started_at)
        || (run.finished_at !== null && !validRecordedTime(run.finished_at))
        || (run.failure_code !== null && !ingestionFailureCodes.has(run.failure_code))
        || (run.termination_reason !== null && !ingestionTerminationReasons.has(run.termination_reason))
        || !validIngestionRunSemantics(run)) {
      throw new Error('invalid ingestion run response');
    }
    return Object.freeze({...run});
  }));
}
function ingestionFact(label, value) {
  const wrapper = document.createElement('div');
  wrapper.append(textNode('dt', label), textNode('dd', value));
  return wrapper;
}
function renderIngestionRuns(runs, selectedSource = 'all') {
  if (selectedSource === 'all') {
    state.ingestionRuns = [...runs];
    state.ingestionRunsFetchedAt = new Date().toISOString();
    if (state.traffic) updateTrafficFreshness();
  }
  const panel = byId('ingestion-runs-panel');
  const list = byId('ingestion-runs-list');
  panel.setAttribute('aria-busy', 'false');
  byId('ingestion-runs-status').textContent = runs.length === 0
    ? `No recorded ${selectedSource === 'all' ? '' : `${selectedSource} `}runs`
    : `${formatNumber(runs.length)} newest ${selectedSource === 'all' ? '' : `${selectedSource} `}receipt${runs.length === 1 ? '' : 's'}`;
  if (runs.length === 0) {
    list.replaceChildren(textNode('p', selectedSource === 'all'
      ? 'No ingestion run receipt is recorded in this database.'
      : `No ${selectedSource} ingestion run receipt is recorded in this bounded result.`, 'ingestion-runs-empty'));
    return;
  }
  const cards = runs.map(run => {
    const card = document.createElement('article'); card.className = 'ingestion-run'; card.setAttribute('role', 'listitem');
    const head = document.createElement('div'); head.className = 'ingestion-run-head';
    head.append(
      textNode('h3', `Run ${run.run_id} · ${run.source}`),
      textNode('span', run.status.replaceAll('_', ' '), `ingestion-run-status ${run.status}`)
    );
    const facts = document.createElement('dl'); facts.className = 'ingestion-run-facts';
    facts.append(
      ingestionFact('Stored events', formatNumber(run.processed_count)),
      ingestionFact('Stored findings', formatNumber(run.detection_count)),
      ingestionFact('Action records', formatNumber(run.action_count)),
      ingestionFact('Started', displayTime(new Date(run.started_at))),
      ingestionFact('Finished', run.finished_at === null ? 'Not recorded' : displayTime(new Date(run.finished_at))),
      ingestionFact('Receipt', `v${run.receipt_version}`)
    );
    const reason = run.termination_reason === null ? 'No terminal reason recorded' : run.termination_reason.replaceAll('_', ' ');
    const failure = run.failure_code === null ? '' : ` · ${run.failure_code}`;
    const evidence = document.createElement('p'); evidence.className = 'ingestion-run-evidence';
    evidence.append(evidenceBadge('contract-only', 'Contract only'), document.createTextNode(
      ' — adapter identity and accepted/rejected input counts are named in the API contract, not recorded by any adapter yet.'
    ));
    card.append(head, facts, textNode('p', `Recorded reason: ${reason}${failure}`, 'ingestion-run-reason'), evidence);
    return card;
  });
  list.replaceChildren(...cards);
}
function renderIngestionRunsUnavailable(selectedSource = 'all') {
  if (selectedSource === 'all') {
    state.ingestionRuns = [];
    state.ingestionRunsFetchedAt = null;
    if (state.traffic) updateTrafficFreshness();
  }
  byId('ingestion-runs-panel').setAttribute('aria-busy', 'false');
  byId('ingestion-runs-status').textContent = 'Unavailable';
  byId('ingestion-runs-list').replaceChildren(
    textNode('p', 'Ingestion receipts are unavailable or invalid. No partial receipt data is displayed.', 'ingestion-runs-empty')
  );
}
async function loadIngestionRuns() {
  if (ingestionRunsLoading) return;
  ingestionRunsLoading = true;
  const sourceSelect = byId('ingestion-source');
  const selectedSource = sourceSelect.value;
  const button = byId('ingestion-runs-retry'); button.disabled = true;
  sourceSelect.disabled = true;
  const panel = byId('ingestion-runs-panel'); panel.setAttribute('aria-busy', 'true');
  byId('ingestion-runs-status').textContent = 'Loading receipts…';
  if (selectedSource === 'all') {
    state.ingestionRuns = [];
    state.ingestionRunsFetchedAt = null;
    if (state.traffic) updateTrafficFreshness();
  }
  byId('ingestion-runs-list').replaceChildren(
    textNode('p', 'Loading selected source receipts…', 'ingestion-runs-empty')
  );
  try {
    if (selectedSource !== 'all' && !ingestionRunSources.has(selectedSource)) throw new Error('invalid source');
    renderIngestionRuns(validatedIngestionRuns(
      await requestBoundedJSON(`/api/ingestion-runs-v2?limit=8&source=${selectedSource}`, maxIngestionRunsResponseBytes),
      selectedSource
    ), selectedSource);
  } catch (_) { renderIngestionRunsUnavailable(selectedSource); }
  finally {
    ingestionRunsLoading = false;
    button.disabled = false;
    sourceSelect.disabled = false;
  }
}
function suricataInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function suricataIdentifier(value) {
  return typeof value === 'string' && value.length <= 64 && /^[A-Za-z][A-Za-z0-9_-]*$(?![\s\S])/u.test(value);
}
function validatedSuricataEnvelope(value) {
  const top = ['schema_version', 'status', 'failure_code', 'provenance', 'action_status', 'limits', 'summary', 'recent_runs', 'recent_alerts'];
  if (!referenceExactKeys(value, top)
      || value.schema_version !== 'suricata-evidence-projection-v1'
      || value.provenance !== 'external_suricata_signature_alerts'
      || value.action_status !== 'not_attempted'
      || !referenceExactKeys(value.limits, ['max_recent_runs', 'max_recent_alerts', 'max_query_ms', 'max_response_bytes'])
      || value.limits.max_recent_runs !== 5 || value.limits.max_recent_alerts !== 50
      || value.limits.max_query_ms !== 5000 || value.limits.max_response_bytes !== maxSuricataResponseBytes
      || !Array.isArray(value.recent_runs) || value.recent_runs.length > 5
      || !Array.isArray(value.recent_alerts) || value.recent_alerts.length > 50) {
    throw new Error('invalid Suricata response');
  }
  if (value.status !== 'available') {
    const validFailure = value.status === 'not_configured' ? value.failure_code === null
      : value.status === 'unavailable' && ['UNSUPPORTED_RUNTIME', 'STORE_UNAVAILABLE', 'INVALID_EVIDENCE', 'QUERY_TIMEOUT', 'RESPONSE_LIMIT'].includes(value.failure_code);
    if (!validFailure || value.summary !== null || value.recent_runs.length || value.recent_alerts.length) throw new Error('invalid Suricata refusal');
    return Object.freeze({...value, limits: Object.freeze({...value.limits}), recent_runs: Object.freeze([]), recent_alerts: Object.freeze([])});
  }
  const summaryFields = ['stored_runs', 'stored_alerts', 'validated_recent_runs', 'validated_recent_alerts', 'shown_alerts'];
  if (value.failure_code !== null || !referenceExactKeys(value.summary, summaryFields)
      || !summaryFields.every(key => suricataInteger(value.summary[key]))) throw new Error('invalid Suricata counts');
  const runs = value.recent_runs.map(run => {
    if (!referenceExactKeys(run, ['run_row_id', 'run_id', 'sensor_id', 'ruleset_id', 'declared_version', 'version_basis', 'ruleset_basis', 'consumer_attempt_id', 'alert_count', 'producer_reported_blocked_count'])
        || !suricataInteger(run.run_row_id, 1)
        || !['run_id', 'sensor_id', 'ruleset_id', 'consumer_attempt_id'].every(key => suricataIdentifier(run[key]))
        || typeof run.declared_version !== 'string' || run.declared_version.length > 11 || !/^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$(?![\s\S])/u.test(run.declared_version)
        || run.version_basis !== 'operator_declared' || run.ruleset_basis !== 'operator_declared'
        || !suricataInteger(run.alert_count, 1, 10000) || !suricataInteger(run.producer_reported_blocked_count, 0, run.alert_count)) {
      throw new Error('invalid Suricata publication');
    }
    return Object.freeze({...run});
  });
  if (new Set(runs.map(run => run.run_row_id)).size !== runs.length
      || runs.some((run, index) => index && run.run_row_id >= runs[index - 1].run_row_id)) throw new Error('invalid Suricata publication order');
  const runMap = new Map(runs.map(run => [run.run_row_id, run]));
  const addresses = value => typeof value === 'string' && value.length >= 2 && value.length <= 39 && /^[0-9a-f:.]+$(?![\s\S])/u.test(value);
  const alerts = value.recent_alerts.map(alert => {
    const run = alert && runMap.get(alert.run_row_id);
    if (!referenceExactKeys(alert, ['run_row_id', 'run_id', 'sensor_id', 'source_record_index', 'observed_at', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'rule', 'producer_reported_action', 'action_status', 'evidence_kind'])
        || !run || run.run_id !== alert.run_id || run.sensor_id !== alert.sensor_id
        || !suricataInteger(alert.source_record_index, 1, run.alert_count)
        || typeof alert.observed_at !== 'string' || alert.observed_at.length !== 27 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$(?![\s\S])/u.test(alert.observed_at) || !validRecordedTime(alert.observed_at)
        || !addresses(alert.src_ip) || !addresses(alert.dst_ip)
        || !suricataInteger(alert.src_port, 0, 65535) || !suricataInteger(alert.dst_port, 0, 65535)
        || !['TCP', 'UDP'].includes(alert.protocol)
        || !referenceExactKeys(alert.rule, ['gid', 'signature_id', 'rev', 'severity'])
        || !['gid', 'signature_id', 'rev'].every(key => suricataInteger(alert.rule[key], 1, 4294967295))
        || !suricataInteger(alert.rule.severity, 1, 255)
        || !['allowed', 'blocked'].includes(alert.producer_reported_action)
        || alert.action_status !== 'not_attempted' || alert.evidence_kind !== 'signature_match') throw new Error('invalid Suricata alert');
    return Object.freeze({...alert, rule: Object.freeze({...alert.rule})});
  });
  if (new Set(alerts.map(alert => `${alert.run_row_id}:${alert.source_record_index}`)).size !== alerts.length
      || alerts.some((alert, index) => index && (alert.run_row_id > alerts[index - 1].run_row_id
        || (alert.run_row_id === alerts[index - 1].run_row_id && alert.source_record_index >= alerts[index - 1].source_record_index)))
      || value.summary.validated_recent_runs !== runs.length || Math.min(5, value.summary.stored_runs) !== runs.length
      || value.summary.validated_recent_alerts !== runs.reduce((sum, run) => sum + run.alert_count, 0)
      || value.summary.stored_alerts < value.summary.validated_recent_alerts
      || value.summary.shown_alerts !== alerts.length || alerts.length !== Math.min(50, value.summary.validated_recent_alerts)
      || runs.some(run => alerts.filter(alert => alert.run_row_id === run.run_row_id).length > run.alert_count
        || alerts.filter(alert => alert.run_row_id === run.run_row_id && alert.producer_reported_action === 'blocked').length > run.producer_reported_blocked_count)) throw new Error('inconsistent Suricata counts');
  return Object.freeze({...value, limits: Object.freeze({...value.limits}), summary: Object.freeze({...value.summary}), recent_runs: Object.freeze(runs), recent_alerts: Object.freeze(alerts)});
}
function renderSuricataUnavailable(notConfigured = false) {
  byId('suricata-panel').setAttribute('aria-busy', 'false');
  byId('suricata-status').textContent = notConfigured ? 'Not configured' : 'Unavailable';
  byId('suricata-content').hidden = true;
  byId('suricata-summary').replaceChildren(); byId('suricata-runs').replaceChildren(); byId('suricata-alerts').replaceChildren();
  byId('suricata-message').textContent = notConfigured
    ? 'No Suricata store was selected at startup. Use dashboard --suricata-db with an existing private store to inspect its evidence.'
    : 'The selected Suricata snapshot is unavailable or invalid. No partial alert evidence is displayed. Core telemetry remains separate.';
}
function renderSuricataEvidence(value) {
  if (value.status !== 'available') { renderSuricataUnavailable(value.status === 'not_configured'); return; }
  byId('suricata-panel').setAttribute('aria-busy', 'false');
  byId('suricata-status').textContent = 'Startup snapshot · read only';
  byId('suricata-message').textContent = value.summary.stored_runs === 0
    ? 'The selected store contains no committed publications. This does not establish sensor health or an absence of threats.'
    : 'Validated recent publications from the separate Suricata store. Older publications contribute stored counts only; they were not fully revalidated.';
  byId('suricata-summary').replaceChildren(
    ingestionFact('Stored publications', formatNumber(value.summary.stored_runs)),
    ingestionFact('Stored external alerts', formatNumber(value.summary.stored_alerts)),
    ingestionFact('Validated recent alerts', formatNumber(value.summary.validated_recent_alerts)),
    ingestionFact('Shown alerts', formatNumber(value.summary.shown_alerts))
  );
  byId('suricata-runs').replaceChildren(...value.recent_runs.map(run => {
    const card = document.createElement('article'); card.className = 'ingestion-run'; card.setAttribute('role', 'listitem');
    const facts = document.createElement('dl'); facts.className = 'ingestion-run-facts';
    facts.append(ingestionFact('Sensor', run.sensor_id), ingestionFact('Ruleset', run.ruleset_id),
      ingestionFact('Declared version', run.declared_version), ingestionFact('Consumer attempt', run.consumer_attempt_id),
      ingestionFact('Committed alerts', formatNumber(run.alert_count)), ingestionFact('Producer-reported blocked', formatNumber(run.producer_reported_blocked_count)));
    card.append(textNode('h3', `Publication ${run.run_row_id} · ${run.run_id}`), facts);
    return card;
  }));
  const rows = value.recent_alerts.map(alert => {
    const row = document.createElement('tr');
    const endpoint = (address, port) => `${address.includes(':') ? `[${address}]` : address}:${port}`;
    const endpoints = `${endpoint(alert.src_ip, alert.src_port)} → ${endpoint(alert.dst_ip, alert.dst_port)} · ${alert.protocol}`;
    row.append(textNode('td', alert.observed_at), textNode('td', endpoints),
      textNode('td', `${alert.rule.gid}:${alert.rule.signature_id}:${alert.rule.rev} · producer severity ${alert.rule.severity}`),
      textNode('td', `${alert.producer_reported_action} · MEGALODON not attempted`));
    const source = document.createElement('td'); const link = textNode('a', `${alert.sensor_id} / ${alert.run_id} / record ${alert.source_record_index}`);
    link.setAttribute('href', '#suricata-provenance'); source.append(link); row.append(source); return row;
  });
  if (!rows.length) { const row = document.createElement('tr'); const cell = textNode('td', 'No committed signature alerts in the selected recent publications.', 'empty'); cell.setAttribute('colspan', '5'); row.append(cell); rows.push(row); }
  byId('suricata-alerts').replaceChildren(...rows); byId('suricata-content').hidden = false;
}
async function loadSuricataEvidence() {
  try { renderSuricataEvidence(validatedSuricataEnvelope(await requestBoundedJSON('/api/suricata', maxSuricataResponseBytes))); }
  catch (_) { renderSuricataUnavailable(); }
}
async function loadAdvisoryReceipt() {
  try {
    const receipt = validatedAdvisoryEnvelope(
      await requestBoundedJSON('/api/advisory-receipt', maxAdvisoryResponseBytes)
    );
    if (receipt === null) {
      renderAdvisoryUnavailable('No startup-supplied legacy advisory receipt is available. Explicit local requests use the separate control above.');
    } else {
      renderAdvisoryReceipt(receipt);
    }
  } catch (_) {
    renderAdvisoryUnavailable('The advisory receipt was unavailable or invalid. No partial model output is displayed, and no model request was made.');
  }
}
async function requestBoundedJSON(path, maxBytes) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  let reader = null;
  try {
    const response = await fetch(path, {headers: {'Accept': 'application/json'}, cache: 'no-store', mode: 'same-origin', credentials: 'omit', redirect: 'error', signal: controller.signal});
    if (!response.ok) throw new Error('bounded request failed');
    if (!response.headers || typeof response.headers.get !== 'function') throw new Error('bounded response headers unavailable');
    const declared = response.headers.get('Content-Length');
    if (declared !== null
        && (!/^[0-9]+$/.test(declared) || declared !== String(Number(declared))
            || !Number.isSafeInteger(Number(declared)) || Number(declared) > maxBytes)) {
      throw new Error('bounded response length invalid');
    }
    if (!response.body || typeof response.body.getReader !== 'function') throw new Error('bounded response body unavailable');
    reader = response.body.getReader();
    const chunks = []; let received = 0;
    while (true) {
      const part = await reader.read();
      if (!part || typeof part.done !== 'boolean'
          || (!part.done && !(part.value instanceof Uint8Array))) {
        throw new Error('bounded response chunk invalid');
      }
      if (part.done) break;
      received += part.value.byteLength;
      if (received > maxBytes) throw new Error('bounded response exceeded limit');
      chunks.push(part.value);
    }
    if (declared !== null && received !== Number(declared)) throw new Error('bounded response was partial');
    const bytes = new Uint8Array(received); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
  } finally {
    if (reader !== null) {
      try { await reader.cancel(); } catch (_) {}
    }
    window.clearTimeout(timeout);
  }
}
async function requestJSON(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(path, {headers: {'Accept': 'application/json'}, cache: 'no-store', mode: 'same-origin', credentials: 'omit', redirect: 'error', signal: controller.signal});
    if (!response.ok) {
      let payload = null;
      try { payload = await response.json(); } catch (_) {}
      const error = new Error(`request failed (${response.status})`);
      error.payload = payload;
      error.status = response.status;
      throw error;
    }
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
function formatBytes(value) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB'];
  const bytes = typeof value === 'bigint' ? value : BigInt(value);
  let divisor = 1n, unit = 0;
  while (bytes >= divisor * 1024n && unit < units.length - 1) { divisor *= 1024n; unit += 1; }
  if (unit === 0 || bytes >= divisor * 10n) return `${(bytes + divisor / 2n) / divisor} ${units[unit]}`;
  const tenths = (bytes * 10n + divisor / 2n) / divisor;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}
function trafficBins(events, count = 24) {
  const bins = Array.from({length: count}, () => ({events: 0, bytes: 0n}));
  if (!events.length) return bins;
  const times = events.map(item => new Date(item.observed_at).valueOf());
  const oldest = Math.min(...times), newest = Math.max(...times), span = Math.max(1, newest - oldest + 1);
  events.forEach((item, index) => {
    const target = oldest === newest ? count - 1 : Math.min(count - 1, Math.floor(((times[index] - oldest) / span) * count));
    bins[target].events += 1; bins[target].bytes += BigInt(item.byte_count);
  });
  return bins;
}
function trafficWindowLabel(firstObserved, lastObserved) {
  if (firstObserved === null || lastObserved === null) return 'Unavailable';
  const first = new Date(firstObserved), last = new Date(lastObserved);
  const elapsed = last.valueOf() - first.valueOf();
  if (!Number.isFinite(elapsed) || elapsed < 0) return 'Unavailable';
  const day = first.toLocaleDateString([], {month: 'short', day: 'numeric', year: 'numeric'});
  const firstTime = first.toLocaleTimeString([], {hour: 'numeric', minute: '2-digit', second: '2-digit'});
  const lastTime = last.toLocaleTimeString([], {hour: 'numeric', minute: '2-digit', second: '2-digit'});
  const sameDay = first.toLocaleDateString() === last.toLocaleDateString();
  const exactRange = sameDay ? `${day}, ${firstTime}–${lastTime}` : `${displayTime(first)} to ${displayTime(last)}`;
  if (elapsed === 0) return `Single timestamp · ${day}, ${firstTime}`;
  const totalSeconds = Math.max(1, Math.ceil(elapsed / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const duration = [hours ? `${hours}h` : '', minutes ? `${minutes}m` : '', `${seconds}s`].filter(Boolean).join(' ');
  return `${duration} · ${exactRange}`;
}
function renderTraffic(traffic) {
  if (traffic.status === 'unavailable') {
    renderTrafficUnavailable(false);
    return;
  }
  state.traffic = traffic;
  const bins = trafficBins(traffic.events);
  const maximum = bins.reduce((largest, item) => item.bytes > largest ? item.bytes : largest, 1n);
  const bars = bins.map((item, index) => {
    const bar = document.createElement('span');
    const level = item.events ? Math.max(1, Number((item.bytes * 10n + maximum - 1n) / maximum)) : 0;
    bar.className = `traffic-bar level-${level}${item.events ? '' : ' traffic-empty'}`;
    bar.title = `Window ${index + 1}: ${item.events} event${item.events === 1 ? '' : 's'}, ${formatBytes(item.bytes)}`;
    return bar;
  });
  const chart = byId('traffic-chart'); chart.replaceChildren(...bars);
  chart.setAttribute('aria-label', traffic.sampled_events
    ? `${traffic.sampled_events} newest stored events across 24 chronological bins, totaling ${formatBytes(traffic.total_bytes)}.`
    : 'No stored traffic metadata is available in the bounded sample.');
  byId('traffic-events').textContent = formatNumber(traffic.sampled_events);
  byId('traffic-bytes').textContent = formatBytes(traffic.total_bytes);
  byId('traffic-window').textContent = trafficWindowLabel(traffic.first_observed_at, traffic.last_observed_at);
  if (traffic.last_observed_at === null) {
    byId('traffic-last').replaceChildren(textNode('span', 'No event recorded'));
  } else {
    const observed = document.createElement('time'); observed.dateTime = traffic.last_observed_at;
    observed.textContent = formatRefreshTime(new Date(traffic.last_observed_at));
    byId('traffic-last').replaceChildren(observed);
  }
  byId('protocol-mix').replaceChildren(...traffic.protocols.map(item => {
    const pill = document.createElement('span'); pill.className = 'protocol-pill';
    pill.append(textNode('span', item.protocol), textNode('b', `${formatNumber(item.events)} · ${formatBytes(item.bytes)}`)); return pill;
  }));
  byId('traffic-status').textContent = traffic.sampled_events
    ? `Showing the newest ${formatNumber(traffic.sampled_events)} stored metadata records in chronological bins.`
    : 'The audit store is connected, but no event metadata is recorded yet.';
  updateTrafficFreshness();
  byId('traffic-panel').setAttribute('aria-busy', 'false');
}
function updateTrafficFreshness() {
  // An ingestion receipt cannot turn an unavailable traffic projection into
  // a measured zero, or overwrite its explicit unavailable badge.
  if (!state.traffic || state.lastRefreshFailed) return;
  const latest = state.ingestionRuns[0];
  const badge = byId('traffic-freshness');
  if (latest && latest.source === 'sample') {
    badge.textContent = `Sample source · refreshes every ${state.config.refresh_seconds}s`;
    badge.className = 'traffic-freshness sample';
  } else {
    badge.textContent = latest ? `Latest run: ${latest.source} · every ${state.config.refresh_seconds}s` : `Refreshes every ${state.config.refresh_seconds}s`;
    badge.className = 'traffic-freshness';
  }
}
function renderTrafficUnavailable(preserve = false) {
  byId('traffic-panel').setAttribute('aria-busy', 'false');
  byId('traffic-status').textContent = preserve
    ? 'Traffic refresh failed. The prior bounded traffic snapshot remains visible.'
    : 'Stored traffic metadata is unavailable. No traffic volume or health claim is shown.';
  byId('traffic-freshness').textContent = preserve ? 'Stale snapshot' : 'Unavailable';
  byId('traffic-freshness').className = 'traffic-freshness sample';
  if (!preserve) {
    state.traffic = null;
    byId('traffic-chart').replaceChildren();
    byId('traffic-chart').setAttribute('aria-label', 'Stored traffic metadata is unavailable.');
    byId('traffic-events').textContent = '—'; byId('traffic-bytes').textContent = '—'; byId('traffic-window').textContent = '—'; byId('traffic-last').textContent = '—';
    byId('protocol-mix').replaceChildren();
  }
}
function reportSnapshot() {
  const scope = byId('report-scope').value;
  const ingestion = scope === 'ingestion';
  if (ingestion ? !state.ingestionRunsFetchedAt : !state.summary || !state.traffic || !state.lastSuccessfulRefresh) return null;
  const title = byId('report-title-input').value.trim() || 'MEGALODON local telemetry report';
  const generatedAt = new Date().toISOString();
  const refreshedAt = ingestion ? new Date(state.ingestionRunsFetchedAt) : state.lastSuccessfulRefresh;
  const refreshedLabel = formatRefreshTime(refreshedAt);
  const common = {
    schema: 'megalodon-browser-report-v1', title, scope, generated_at: generatedAt,
    last_dashboard_refresh: refreshedAt.toISOString(),
    bounds: ingestion ? 'Newest 8 stored core ingestion receipts maximum, across all recorded sources.'
      : `Newest ${state.config.event_limit} detections and ${state.traffic.sample_limit} traffic records maximum`,
    limitation: ingestion
      ? 'Stored run counts are events, findings, and plan-only action records; adapter identity and accepted/rejected counts are not recorded. No sensor liveness, coverage, or host action is established.'
      : 'Stored metadata only; not capture completeness, wire speed, service health, or incident state.'
  };
  if (scope === 'detections') return {...common,
    source_scope: `${state.events.length} stored alerts shown from a maximum of ${state.config.event_limit}. Updated ${refreshedLabel}.`,
    detections: state.events.map(item => ({...item}))};
  if (scope === 'ingestion') {
    return {...common,
      source_scope: `${state.ingestionRuns.length} all-source run receipts loaded ${formatRefreshTime(new Date(state.ingestionRunsFetchedAt))}. Panel source filters do not change this report.`,
      ingestion_runs: state.ingestionRuns.map(item => ({...item}))};
  }
  return {...common,
    source_scope: `The counts above plus ${state.traffic.sampled_events} traffic records from a maximum of ${state.traffic.sample_limit}. Updated ${refreshedLabel}.`,
    summary: {...state.summary}, traffic: {
    sampled_events: state.traffic.sampled_events, total_bytes: state.traffic.total_bytes,
    first_observed_at: state.traffic.first_observed_at, last_observed_at: state.traffic.last_observed_at,
    protocols: state.traffic.protocols.map(item => ({...item}))
  }};
}
function reportPlainText(report) {
  const lines = [report.title, `Generated: ${report.generated_at}`, `Scope: ${report.scope}`, `Source scope: ${report.source_scope}`, report.bounds];
  if (report.summary) lines.push(`Events: ${report.summary.events}`, `Findings: ${report.summary.detections}`, `High / critical: ${report.summary.high_or_critical}`, `Actions: ${report.summary.actions}`, `Traffic sample: ${report.traffic.sampled_events} events, ${formatBytes(report.traffic.total_bytes)}`);
  if (report.detections) lines.push(`Returned findings: ${report.detections.length}`);
  if (report.ingestion_runs) lines.push(`Returned ingestion receipts: ${report.ingestion_runs.length}`);
  lines.push(`Limitation: ${report.limitation}`); return lines.join('\n');
}
function renderReportPreview() {
  const report = reportSnapshot(), card = byId('report-preview-card');
  if (!report) {
    const reason = byId('report-scope').value === 'ingestion' && !state.ingestionRunsFetchedAt
      ? 'Load the all-source ingestion receipts before creating this report.'
      : 'Wait for one successful summary and traffic refresh.';
    card.replaceChildren(textNode('p', 'Preview', 'eyebrow'), textNode('h3', 'Report unavailable'), textNode('p', reason));
    byId('report-feedback').textContent = reason; return null;
  }
  const facts = document.createElement('dl');
  const entries = report.summary
    ? [['Stored events', report.summary.events], ['Findings', report.summary.detections], ['Traffic records', `${report.traffic.sampled_events} · ${formatBytes(report.traffic.total_bytes)}`]]
    : report.detections
      ? [['Returned rows', report.detections.length], ['Priority rows', report.detections.filter(item => prioritySeverities.has(item.severity)).length], ['Newest bound', state.config.event_limit]]
      : [['Run receipts', report.ingestion_runs.length], ['Running receipts', report.ingestion_runs.filter(item => item.status === 'running').length], ['Needs review', report.ingestion_runs.filter(item => !['running', 'completed'].includes(item.status)).length]];
  entries.forEach(([label, value]) => { const item = document.createElement('div'); const shown = typeof value === 'number' ? formatNumber(value) : String(value); item.append(textNode('dt', label), textNode('dd', shown)); facts.append(item); });
  card.replaceChildren(textNode('p', 'Preview', 'eyebrow'), textNode('h3', report.title), textNode('p', `Generated ${formatRefreshTime(new Date(report.generated_at))} from the last successful local dashboard refresh.`), facts, textNode('p', `Source scope: ${report.source_scope}`), textNode('p', report.limitation));
  byId('report-feedback').textContent = 'Preview updated. Choose copy, download, or print.'; return report;
}
function reportCsv(report) {
  const quote = value => {
    const text = String(value ?? '');
    // CSV quoting contains delimiters, but does not make formulas inert.
    // Protect every cell, including metadata; never change the source report.
    const formulaLike = /^[\x00-\x1f]|^[\s\x00-\x1f]*[=+@-]/u.test(text);
    const exported = formulaLike ? "'" + text : text;
    return `"${exported.replaceAll('"', '""')}"`;
  };
  let rows;
  if (report.detections) rows = [['detected_at', 'severity', 'rule_id', 'src_ip', 'message'], ...report.detections.map(item => [item.detected_at, item.severity, item.rule_id, item.src_ip, item.message])];
  else if (report.ingestion_runs) rows = [['run_id', 'source', 'status', 'started_at', 'finished_at', 'processed_count', 'detection_count', 'action_count', 'termination_reason', 'failure_code'], ...report.ingestion_runs.map(item => [item.run_id, item.source, item.status, item.started_at, item.finished_at, item.processed_count, item.detection_count, item.action_count, item.termination_reason, item.failure_code])];
  else rows = [['metric', 'value'], ['events', report.summary.events], ['detections', report.summary.detections], ['high_or_critical', report.summary.high_or_critical], ['actions', report.summary.actions], ['traffic_sampled_events', report.traffic.sampled_events], ['traffic_total_bytes', report.traffic.total_bytes]];
  rows = [['report_scope', report.scope], ['source_scope', report.source_scope], ['last_dashboard_refresh', report.last_dashboard_refresh],
    ['bounds', report.bounds], ['limitation', report.limitation],
    ['csv_text_policy', 'Formula-like cells are prefixed with an apostrophe for spreadsheet review. Use JSON for original text.'], [], ...rows];
  return rows.map(row => row.map(quote).join(',')).join('\n') + '\n';
}
function downloadReport(contents, extension, type) {
  const blob = new Blob([contents], {type}); const url = URL.createObjectURL(blob);
  const link = document.createElement('a'); link.href = url; link.download = `megalodon-report-${new Date().toISOString().slice(0, 10)}.${extension}`;
  link.click(); URL.revokeObjectURL(url);
}
function hasActiveFilters() {
  return Boolean(
    byId('filter-query').value.trim()
    || byId('filter-severity').value !== 'ALL'
    || byId('filter-rule').value !== ''
    || state.activeBin !== null
  );
}
function baseFilteredEvents() {
  const severity = byId('filter-severity').value;
  const rule = byId('filter-rule').value;
  const query = byId('filter-query').value.trim().toLowerCase();
  return state.events.filter(event => {
    if (severity === 'PRIORITY' && !prioritySeverities.has(event.severity)) return false;
    if (severity !== 'ALL' && severity !== 'PRIORITY' && event.severity !== severity) return false;
    if (rule && event.rule_id !== rule) return false;
    if (!query) return true;
    return [event.detected_at, event.severity, event.rule_id, event.src_ip, event.message]
      .some(value => String(value || '').toLowerCase().includes(query));
  });
}
function buildTimeline(events) {
  const points = [];
  let invalidCount = 0;
  events.forEach((event, index) => {
    const timestamp = new Date(event.detected_at).valueOf();
    if (Number.isNaN(timestamp)) invalidCount += 1;
    else points.push({index, timestamp});
  });
  if (!points.length) return {bins: [], invalidCount};
  const oldest = Math.min(...points.map(point => point.timestamp));
  const newest = Math.max(...points.map(point => point.timestamp));
  const inclusiveSpan = newest - oldest + 1;
  const binCount = oldest === newest ? 1 : Math.min(maxTimelineBins, points.length, inclusiveSpan);
  const bins = Array.from({length: binCount}, (_, index) => ({
    start: oldest + Math.floor(inclusiveSpan * index / binCount),
    end: index === binCount - 1 ? newest : oldest + Math.floor(inclusiveSpan * (index + 1) / binCount) - 1,
    members: []
  }));
  points.forEach(point => {
    const index = oldest === newest
      ? 0
      : Math.min(binCount - 1, Math.ceil((((point.timestamp - oldest) + 1) / inclusiveSpan) * binCount) - 1);
    bins[index].members.push(point.index);
  });
  return {bins, invalidCount};
}
function timelineRange(bin) {
  const start = displayTime(new Date(bin.start));
  const end = displayTime(new Date(bin.end));
  return bin.start === bin.end ? start : `${start} to ${end}`;
}
function renderTimeline(model) {
  if (state.activeBin !== null && state.activeBin >= model.bins.length) state.activeBin = null;
  state.timelineBins = model.bins;
  const timeline = byId('timeline');
  const priorButtons = Array.from(timeline.children || []);
  const focusedIndex = priorButtons.indexOf(document.activeElement);
  const maximum = Math.max(1, ...model.bins.map(bin => bin.members.length));
  const buttons = model.bins.map((bin, index) => {
    const selected = state.activeBin === index;
    const count = bin.members.length;
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'timeline-bin';
    button.setAttribute('aria-pressed', String(selected));
    button.setAttribute('aria-label', `${count} returned detections from ${timelineRange(bin)}${selected ? '; selected' : ''}`);
    const level = count === 0 ? 0 : Math.max(1, Math.ceil((count / maximum) * 10));
    button.append(textNode('span', '', `timeline-bar level-${level}`), textNode('span', formatNumber(count), 'timeline-count'));
    button.addEventListener('click', () => {
      state.activeBin = selected ? null : index; state.timelineNotice = ''; applyFilters();
    });
    return button;
  });
  timeline.replaceChildren(...buttons);
  if (focusedIndex >= 0 && buttons.length) {
    const replacement = buttons[Math.min(focusedIndex, buttons.length - 1)];
    if (typeof replacement.focus === 'function') replacement.focus();
  }
  byId('clear-time-filter').hidden = state.activeBin === null;
  let status;
  if (!model.bins.length) status = 'No valid returned timestamps are available for the timeline.';
  else if (state.activeBin !== null) status = `Time filter selected: ${timelineRange(model.bins[state.activeBin])}.`;
  else status = `${formatNumber(model.bins.length)} chronological ${model.bins.length === 1 ? 'bin' : 'bins'} from the returned, non-time-filtered view.`;
  if (model.invalidCount) {
    status += ` ${formatNumber(model.invalidCount)} ${model.invalidCount === 1 ? 'row has' : 'rows have'} an invalid timestamp and ${model.invalidCount === 1 ? 'is' : 'are'} excluded from the timeline only.`;
  }
  if (state.timelineNotice) status += ` ${state.timelineNotice}`;
  if (byId('timeline-status').textContent !== status) byId('timeline-status').textContent = status;
}
function renderRuleOptions() {
  const select = byId('filter-rule');
  const selected = select.value;
  const rules = [...new Set(state.events.map(event => event.rule_id))]
    .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  const all = textNode('option', 'All rules'); all.value = '';
  const options = [];
  if (selected && !rules.includes(selected)) {
    const missing = textNode('option', `${selected} (not returned)`);
    missing.value = selected; missing.disabled = true; options.push(missing);
  }
  options.push(...rules.map(rule => { const option = textNode('option', rule); option.value = rule; return option; }));
  select.replaceChildren(all, ...options);
  select.value = selected;
}
function sameEvents(left, right) {
  return left.length === right.length && left.every((event, index) =>
    eventFields.every(field => event[field] === right[index][field])
  );
}
function renderReturnedSummary() {
  const count = state.events.length;
  byId('returned-status').textContent = count === state.config.event_limit
    ? `${formatNumber(count)} returned · configured maximum; older rows may be omitted`
    : `${formatNumber(count)} returned · ${formatNumber(state.config.event_limit)} configured maximum`;
  const priority = state.events.filter(event => prioritySeverities.has(event.severity)).length;
  byId('priority-status').textContent = `${formatNumber(priority)} high / critical ${priority === 1 ? 'row' : 'rows'} in returned set`;
  const rules = new Set(state.events.map(event => event.rule_id)).size;
  byId('rule-status').textContent = `${formatNumber(rules)} distinct ${rules === 1 ? 'rule' : 'rules'} in returned set`;
}
function updatePriorityChange(summary) {
  const current = summary.high_or_critical;
  const previous = state.lastPriorityTotal;
  let visible;
  let announcement = '';
  if (previous === null) visible = `Priority baseline established: ${formatNumber(current)} stored.`;
  else if (current > previous) {
    visible = `Stored high/critical count increased by ${formatNumber(current - previous)} to ${formatNumber(current)}.`;
    announcement = visible;
  } else if (current < previous) {
    visible = `Stored high/critical count decreased by ${formatNumber(previous - current)} to ${formatNumber(current)}.`;
    announcement = visible;
  } else visible = `No stored high/critical count change · ${formatNumber(current)} stored.`;
  if (byId('priority-change').textContent !== visible) byId('priority-change').textContent = visible;
  if (byId('priority-announcement').textContent !== announcement) {
    byId('priority-announcement').textContent = announcement;
  }
  state.lastPriorityTotal = current;
}
function renderEvents(events) {
  const body = byId('events');
  if (!events.length) {
    const filtered = state.events.length && hasActiveFilters();
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
function renderInitialUnavailable() {
  const row = document.createElement('tr');
  const cell = textNode('td', state.telemetryNotConfigured
    ? 'No audit store was available at launch. Import real data, then restart this HUD to review detections.'
    : 'Recent detections are unavailable until a complete dashboard refresh succeeds.', 'empty');
  cell.colSpan = 5; row.append(cell); byId('events').replaceChildren(row);
  const filterStatus = state.telemetryNotConfigured
    ? 'Detection filters are ready for a configured audit store.'
    : 'No successful dashboard data refresh is available.';
  if (byId('filter-status').textContent !== filterStatus) byId('filter-status').textContent = filterStatus;
  byId('returned-status').textContent = 'Returned rows unavailable';
  byId('priority-status').textContent = 'Priority rows unavailable';
  byId('rule-status').textContent = 'Rule count unavailable';
  byId('timeline').replaceChildren();
  const timelineStatus = 'No successful returned-timestamp set is available.';
  if (byId('timeline-status').textContent !== timelineStatus) byId('timeline-status').textContent = timelineStatus;
  byId('priority-change').textContent = state.telemetryNotConfigured
    ? 'Stored priority count unavailable until an audit store is available at startup.'
    : 'Stored priority baseline unavailable; retry refresh.';
}
function applyFilters() {
  if (!state.lastSuccessfulRefresh) { renderInitialUnavailable(); return; }
  const base = baseFilteredEvents();
  const model = buildTimeline(base);
  renderTimeline(model);
  const visible = state.activeBin === null
    ? base
    : base.filter((_, index) => model.bins[state.activeBin].members.includes(index));
  renderEvents(visible);
  const noun = state.events.length === 1 ? 'finding' : 'findings';
  const status = `${formatNumber(visible.length)} of ${formatNumber(state.events.length)} returned ${noun} shown${hasActiveFilters() ? ' with active filters' : ''}.`;
  if (byId('filter-status').textContent !== status) byId('filter-status').textContent = status;
}
function clearFilters() {
  byId('filter-query').value = '';
  byId('filter-severity').value = 'ALL';
  byId('filter-rule').value = '';
  state.activeBin = null;
  state.timelineNotice = '';
  applyFilters();
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
  empty.hidden = true; content.hidden = false; status.textContent = 'Schema-checked startup snapshot';
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
  empty.textContent = 'The configured offline summary could not be loaded. Recent SQLite telemetry is checked separately.';
  byId('offline-status').textContent = 'Unavailable';
}
function setConnection(label, className) {
  const connection = byId('connection');
  const nextClass = className ? `connection ${className}` : 'connection';
  if (connection.textContent !== label) connection.textContent = label;
  if (connection.className !== nextClass) connection.className = nextClass;
}
function formatRefreshTime(value) { return value.toLocaleString(); }
function setUpdatedTime(label, value = null) {
  const updated = byId('updated'); updated.textContent = label;
  if (value) updated.dateTime = value.toISOString();
  else updated.removeAttribute('datetime');
}
function renderScope() {
  byId('scope-status').textContent = `Newest ${formatNumber(state.config.event_limit)} detections maximum${state.configDegraded ? ' · safe defaults' : ''}`;
}
function referenceExactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}
function validatedReferenceSources(value) {
  if (!Array.isArray(value) || value.length > 2) throw new Error('invalid reference sources');
  value.forEach(source => {
    if (!source || typeof source !== 'object' || Array.isArray(source) || !referenceExactKeys(source, referenceSourceFields)) {
      throw new Error('invalid reference source');
    }
    referenceSourceFields.forEach(field => {
      if (typeof source[field] !== 'string' || source[field].length < 1 || source[field].length > 256) throw new Error('invalid reference source');
    });
  });
  return value;
}
function validatedReferenceStatus(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.schema !== 'string') throw new Error('invalid reference status');
  if (value.schema !== 'reference-library-status-v1' || typeof value.available !== 'boolean' || typeof value.status !== 'string') throw new Error('invalid reference status');
  referenceBoundary(value);
  if (!value.available) {
    if (!referenceExactKeys(value, ['schema', 'available', 'status', 'error', 'network_access_performed', 'persistence_status', 'action_status'])) throw new Error('invalid reference status');
    if (!['unavailable', 'integrity_failure'].includes(value.status) || typeof value.error !== 'string') throw new Error('invalid reference status');
    const expectedError = value.status === 'integrity_failure' ? 'reference bundle integrity failure' : 'reference bundle unavailable';
    if (value.error !== expectedError) referenceReject();
    return value;
  }
  if (!referenceExactKeys(value, ['schema', 'available', 'status', 'bundle_id', 'bundle_version', 'manifest_sha256', 'service_records', 'protocol_records', 'cache_entries', 'cache_limit', 'sources', 'warning', 'network_access_performed', 'persistence_status', 'action_status'])) throw new Error('invalid reference status');
  if (value.status !== 'ready' || ![value.service_records, value.protocol_records, value.cache_entries, value.cache_limit].every(item => Number.isSafeInteger(item) && item >= 0) || value.cache_entries > value.cache_limit) throw new Error('invalid reference status');
  if (![value.bundle_id, value.bundle_version, value.manifest_sha256, value.warning].every(item => typeof item === 'string' && item.length > 0 && item.length <= 512)) throw new Error('invalid reference status');
  if (value.network_access_performed !== false || value.persistence_status !== 'not_attempted' || value.action_status !== 'not_attempted') throw new Error('invalid reference status');
  validatedReferenceSources(value.sources);
  referenceReadyContract(value);
  return value;
}
function validatedReferenceResult(value, expectedKind = null, expectedQuery = null, expectedBundle = null) {
  const expected = ['schema', 'status', 'available', 'kind', 'bundle_id', 'bundle_version', 'manifest_sha256', 'query', 'match_count', 'matches', 'truncated', 'sources', 'warning', 'network_access_performed', 'persistence_status', 'action_status'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || !referenceExactKeys(value, expected)) throw new Error('invalid reference result');
  if (value.schema !== 'reference-library-lookup-v1' || value.available !== true || !['no_match', 'one_match', 'multiple_matches'].includes(value.status) || !['port', 'protocol'].includes(value.kind)) throw new Error('invalid reference result');
  if (![value.bundle_id, value.bundle_version, value.manifest_sha256, value.warning].every(item => typeof item === 'string' && item.length > 0 && item.length <= 512)) throw new Error('invalid reference result');
  if (!Number.isSafeInteger(value.match_count) || value.match_count < 0 || value.match_count > 20000 || !Array.isArray(value.matches) || value.matches.length > 8 || value.matches.length > value.match_count || typeof value.truncated !== 'boolean') throw new Error('invalid reference result');
  const queryKeys = value.kind === 'port' ? ['port', 'transport'] : ['number'];
  if (!value.query || typeof value.query !== 'object' || Array.isArray(value.query) || !referenceExactKeys(value.query, queryKeys)) throw new Error('invalid reference result');
  if (value.kind === 'port' && (typeof value.query.transport !== 'string' || !Number.isSafeInteger(value.query.port))) throw new Error('invalid reference result');
  if (value.kind === 'protocol' && !Number.isSafeInteger(value.query.number)) throw new Error('invalid reference result');
  const fields = value.kind === 'port' ? referencePortFields : referenceProtocolFields;
  value.matches.forEach(match => {
    if (!match || typeof match !== 'object' || Array.isArray(match) || !referenceExactKeys(match, fields)) throw new Error('invalid reference result');
    fields.forEach(field => {
      const item = match[field];
      if (item !== null && typeof item !== 'string' && !Number.isSafeInteger(item)) throw new Error('invalid reference result');
      if (typeof item === 'string' && item.length > 512) throw new Error('invalid reference result');
    });
  });
  validatedReferenceSources(value.sources);
  if (value.network_access_performed !== false || value.persistence_status !== 'not_attempted' || value.action_status !== 'not_attempted') throw new Error('invalid reference result');
  referenceLookupContract(value, expectedKind, expectedQuery, expectedBundle);
  return value;
}
function setReferenceStatus(message, mode) {
  const node = byId('reference-status');
  const nextClass = `reference-status ${mode || 'empty'}`;
  if (node.textContent !== message) node.textContent = message;
  if (node.className !== nextClass) node.className = nextClass;
}
function setReferenceFormsEnabled(enabled) {
  ['reference-transport', 'reference-port', 'reference-protocol'].forEach(id => { byId(id).disabled = !enabled; });
  ['reference-port-form', 'reference-protocol-form'].forEach(id => {
    const form = byId(id);
    Array.from(form.children || []).forEach(child => { if ('disabled' in child) child.disabled = !enabled; });
  });
}
function referenceChip(label) {
  return textNode('span', label, 'summary-chip');
}
function renderReferenceMeta(result) {
  const meta = byId('reference-meta');
  const query = result.kind === 'port' ? `${result.query.transport}/${result.query.port}` : `IP protocol ${result.query.number}`;
  const sourceText = result.sources.map(source => `${source.id} · updated ${source.registry_last_updated}`).join(' · ');
  meta.replaceChildren(
    referenceChip(`${result.status.replaceAll('_', ' ')} · ${formatNumber(result.match_count)} registered`),
    referenceChip(`Bundle ${result.bundle_id} · ${result.bundle_version}`),
    referenceChip(query),
    referenceChip(sourceText || 'Pinned source provenance available in manifest')
  );
  meta.hidden = false;
}
function renderReferenceResult(result) {
  const empty = byId('reference-empty');
  const results = byId('reference-results');
  renderReferenceMeta(result);
  if (!result.matches.length) {
    empty.textContent = 'No registration matches this exact lookup. This does not show that the observed endpoint is unknown or unsafe.';
    empty.hidden = false; results.hidden = true; results.replaceChildren(); return;
  }
  empty.hidden = true; results.hidden = false;
  const fields = result.kind === 'port' ? referencePortFields : referenceProtocolFields;
  const labels = {
    service_name: 'Service', transport: 'Transport', port_start: 'Port start', port_end: 'Port end', record_kind: 'Record kind', description: 'Description', registration_date: 'Registered', modification_date: 'Modified', source_row: 'Source row',
    keyword: 'Keyword', protocol_name: 'Protocol', decimal_start: 'Number start', decimal_end: 'Number end', ipv6_extension_header: 'IPv6 extension header'
  };
  const rows = result.matches.map(match => {
    const item = document.createElement('li'); item.className = 'reference-record';
    const definition = document.createElement('dl');
    fields.forEach(field => {
      if (match[field] === null || match[field] === '') return;
      definition.append(textNode('dt', labels[field] || field), textNode('dd', match[field]));
    });
    item.append(definition); return item;
  });
  const list = document.createElement('ul'); list.className = 'reference-records'; list.replaceChildren(...rows);
  results.replaceChildren(list);
}
function renderReferenceUnavailable(payload, fallbackMode = 'unavailable') {
  const mode = payload && payload.status === 'integrity_failure' ? 'integrity_failure'
    : fallbackMode === 'invalid_response' ? 'invalid_response' : 'unavailable';
  const message = mode === 'integrity_failure'
    ? 'Reference Library integrity failure. Lookup is disabled; no partial records are shown. Recheck after the local service has been repaired and restarted.'
    : mode === 'invalid_response'
      ? 'Reference response rejected. No new context was accepted; lookup is disabled. Recheck the local snapshot.'
      : 'Reference Library is unavailable. Recheck the local snapshot to retry. A server-side bundle failure requires local repair and service restart.';
  referenceState.available = false; referenceState.status = mode; referenceState.snapshot = null;
  clearReferenceResult(message); renderReferenceProvenance(null);
  setReferenceStatus(message, mode);
  byId('reference-bundle-label').textContent = mode === 'integrity_failure' ? 'Integrity failure'
    : mode === 'invalid_response' ? 'Invalid response' : 'Unavailable';
  syncReferenceControls();
}
async function loadReferenceStatus() {
  if (referenceState.statusLoading || referenceState.loading) return;
  referenceState.statusLoading = true;
  setReferenceStatus('Checking the existing local snapshot. This does not download or reload a registry.', 'empty');
  syncReferenceControls();
  try {
    const response = await requestJSON('/api/reference/status');
    let payload;
    try { payload = validatedReferenceStatus(response); } catch (_) { referenceReject(); }
    if (!payload.available) { renderReferenceUnavailable(payload, payload.status); return; }
    // A recheck starts a fresh display context, even when bundle identity is unchanged.
    clearReferenceResult();
    referenceState.snapshot = payload; referenceState.available = true; referenceState.status = 'ready';
    byId('reference-bundle-label').textContent = `IANA ${payload.bundle_version} · ${payload.bundle_id}`;
    renderReferenceProvenance(payload);
    setReferenceStatus('Pinned IANA snapshot ready. Enter one value for a read-only context lookup.', 'ready');
  } catch (error) {
    const failure = referenceFailureEnvelope(error);
    renderReferenceUnavailable(failure, (error && error.referenceInvalid) ? 'invalid_response' : 'unavailable');
  } finally {
    referenceState.statusLoading = false; syncReferenceControls();
  }
}
function decimalReferenceInput(value, maximum) {
  const text = String(value);
  if (!/^[0-9]+$/.test(text) || text.length > String(maximum).length || String(Number(text)) !== text || Number(text) > maximum) throw new Error('invalid reference input');
  return Number(text);
}
async function lookupReference(kind) {
  if (!referenceState.available || !referenceState.snapshot || referenceState.loading || referenceState.statusLoading) return;
  let query;
  try {
    if (kind === 'port') query = {transport: byId('reference-transport').value, port: decimalReferenceInput(byId('reference-port').value, 65535)};
    else if (kind === 'protocol') query = {number: decimalReferenceInput(byId('reference-protocol').value, 255)};
    else throw new Error('invalid lookup kind');
    referenceQueryContract(kind, query);
  } catch (_) {
    const prior = referenceState.lastResult;
    const retained = prior ? ` Displayed context is still for ${referenceQueryLabel(prior.kind, prior.query)}.` : '';
    setReferenceStatus((kind === 'port' ? 'Enter a normalized transport and a decimal port from 0 through 65535.' : 'Enter a decimal IP protocol number from 0 through 255.') + retained, prior ? 'stale' : 'empty');
    return;
  }
  referenceState.loading = true; syncReferenceControls();
  const label = referenceQueryLabel(kind, query);
  setReferenceStatus(`Loading bounded context for ${label}. Any displayed context remains from the previous lookup.`, 'empty');
  const params = kind === 'port' ? `transport=${encodeURIComponent(query.transport)}&port=${query.port}` : `number=${query.number}`;
  try {
    const response = await requestJSON(`/api/reference/${kind}?${params}`);
    let result;
    try { result = validatedReferenceResult(response, kind, query, referenceState.snapshot); }
    catch (_) { referenceReject(); }
    referenceState.lastResult = result; referenceState.lastQuery = query; renderReferenceResult(result);
    const suffix = result.truncated ? ' The returned rows are capped at 8.' : '';
    setReferenceStatus(result.status === 'no_match' ? `No registration found for ${label}.${suffix}` : `Reference context loaded for ${label}: ${formatNumber(result.match_count)} ${result.match_count === 1 ? 'registration' : 'registrations'}.${suffix}`, result.status === 'no_match' ? 'empty' : 'ready');
  } catch (error) {
    const failure = referenceFailureEnvelope(error);
    if (failure || (error && error.referenceInvalid)) {
      renderReferenceUnavailable(failure, (error && error.referenceInvalid) ? 'invalid_response' : 'unavailable'); return;
    }
    if (referenceState.lastResult) {
      const prior = referenceState.lastResult;
      setReferenceStatus(`Lookup for ${label} failed. Showing the last successful reference result as stale context for ${referenceQueryLabel(prior.kind, prior.query)}; no new data was applied.`, 'stale');
    } else {
      setReferenceStatus(`Lookup for ${label} failed. No reference result is available. Submit again or recheck the local snapshot.`, 'unavailable');
    }
  } finally { referenceState.loading = false; syncReferenceControls(); }
}
function setSnapshotStatus(mode) {
  const strip = byId('trust-strip');
  const status = byId('snapshot-status');
  const nextClass = `trust-strip ${mode}`;
  if (strip.className !== nextClass) strip.className = nextClass;
  const healthLimit = 'Dashboard API reachability does not measure capture or ingestion health.';
  let message;
  if (mode === 'unconfigured') {
    message = `No audit store was available at launch. Import real data, then restart the HUD.${state.paused ? ' Automatic refresh is paused.' : ''} ${healthLimit}`;
    setUpdatedTime('No audit store available at launch');
  } else if (mode === 'current') {
    message = `Dashboard data fetched successfully. ${healthLimit}`;
    setUpdatedTime(`Data fetched ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
  } else if (mode === 'paused') {
    if (state.lastSuccessfulRefresh) {
      message = `Automatic refresh paused. The last successful dashboard snapshot remains visible. ${healthLimit}`;
      setUpdatedTime(`Paused · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Automatic refresh paused. No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('Paused · no dashboard data available');
    }
  } else if (mode === 'checking') {
    if (state.lastSuccessfulRefresh) {
      const priorState = state.lastRefreshFailed
        ? 'Preserved dashboard data remains stale until a refresh succeeds.'
        : 'Preserved dashboard data is not treated as current until a refresh succeeds.';
      message = `Checking the dashboard API. ${priorState} ${healthLimit}`;
      setUpdatedTime(`Checking · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Checking the dashboard API. No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('Checking · no successful dashboard data yet');
    }
  } else if (mode === 'stale') {
    const pauseContext = state.paused ? ' Automatic refresh remains paused.' : '';
    if (state.lastSuccessfulRefresh) {
      message = `Refresh failed.${pauseContext} The last successful snapshot is stale. ${healthLimit}`;
      setUpdatedTime(`Stale · last success ${formatRefreshTime(state.lastSuccessfulRefresh)}`, state.lastSuccessfulRefresh);
    } else {
      message = `Refresh failed.${pauseContext} No successful dashboard data fetch is available. ${healthLimit}`;
      setUpdatedTime('No successful dashboard data available');
    }
  } else {
    message = `No successful dashboard data fetch yet. ${healthLimit}`;
    setUpdatedTime('No successful dashboard data yet');
  }
  if (status.textContent !== message) status.textContent = message;
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
  byId('triage-panel').setAttribute('aria-busy', 'true');
  if (!state.lastSuccessfulRefresh) byId('triage-controls').disabled = true;
  const button = byId('refresh-button'); button.disabled = true; button.textContent = 'Refreshing…';
  try {
    const [summaryResult, eventsResult, trafficResult] = await Promise.allSettled([
      requestJSON('/api/summary'), requestJSON(`/api/events?limit=${state.config.event_limit}`), requestRoomSnapshot()
    ]);
    acceptRoomResult(trafficResult);
    const expectedMissingStore = setupState.sourceStatus === 'not_configured' && !state.lastSuccessfulRefresh
      && [summaryResult, eventsResult].every(result => result.status === 'rejected'
        && result.reason && result.reason.status === 503
        && result.reason.payload && typeof result.reason.payload === 'object' && !Array.isArray(result.reason.payload)
        && referenceExactKeys(result.reason.payload, ['error']) && result.reason.payload.error === 'telemetry unavailable')
      && trafficResult.status === 'rejected' && trafficResult.reason && trafficResult.reason.status === 503
      && unavailableTrafficResponse(trafficResult.reason.payload);
    if (expectedMissingStore) {
      state.telemetryNotConfigured = true;
      state.lastRefreshFailed = false;
      renderInitialUnavailable();
      renderTrafficUnavailable(false);
      setSnapshotStatus('unconfigured');
      setConnection(state.paused ? 'Dashboard API · reachable, no audit store, refresh paused' : 'Dashboard API · reachable, no audit store', '');
      if (announce) byId('refresh-announcement').textContent = 'No audit store was available at launch. Import real data, then restart this HUD.';
      return;
    }
    state.telemetryNotConfigured = false;
    if (summaryResult.status !== 'fulfilled' || eventsResult.status !== 'fulfilled' || trafficResult.status !== 'fulfilled') {
      throw new Error('dashboard refresh failed');
    }
    const summary = validatedSummary(summaryResult.value);
    const events = validatedEvents(eventsResult.value);
    const traffic = validatedTraffic(trafficResult.value);
    if (state.activeBin !== null && !sameEvents(state.events, events)) {
      state.activeBin = null;
      state.timelineNotice = 'Returned rows changed; the prior time filter was cleared.';
    }
    state.events = events;
    state.summary = summary;
    state.lastSuccessfulRefresh = new Date();
    state.lastRefreshFailed = false;
    renderMetrics(summary); renderTraffic(traffic); renderRuleOptions(); renderReturnedSummary(); applyFilters(); renderScope(); renderReportPreview();
    updatePriorityChange(summary);
    setSnapshotStatus(state.paused ? 'paused' : 'current');
    setConnection(state.paused ? 'Dashboard API · reachable, refresh paused' : 'Dashboard API · reachable', 'ok');
    if (announce) byId('refresh-announcement').textContent = 'Dashboard data refreshed.';
  } catch (_) {
    state.telemetryNotConfigured = false;
    state.lastRefreshFailed = true;
    renderTrafficUnavailable(Boolean(state.traffic));
    if (!state.lastSuccessfulRefresh) renderInitialUnavailable();
    setConnection(state.paused ? 'Dashboard API · unavailable, refresh paused' : 'Dashboard API · unavailable', 'error');
    setSnapshotStatus('stale');
    if (announce) {
      byId('refresh-announcement').textContent = state.lastSuccessfulRefresh
        ? 'Dashboard refresh failed. Existing rows were preserved.'
        : 'Dashboard refresh failed. No prior dashboard data is available.';
    }
  } finally {
    state.refreshing = false; button.disabled = false; button.textContent = 'Refresh now';
    byId('triage-controls').disabled = false;
    byId('triage-panel').setAttribute('aria-busy', 'false');
  }
}
function togglePause() {
  state.paused = !state.paused;
  const button = byId('pause-button'); button.setAttribute('aria-pressed', String(state.paused));
  button.textContent = state.paused ? 'Resume refresh' : 'Pause refresh';
  if (state.paused) {
    if (state.telemetryNotConfigured) {
      setConnection('Dashboard API · reachable, no audit store, refresh paused', '');
      setSnapshotStatus('unconfigured');
    } else if (state.lastRefreshFailed) {
      setConnection('Dashboard API · unavailable, refresh paused', 'error');
      setSnapshotStatus('stale');
    } else {
      const pausedLabel = state.lastSuccessfulRefresh
        ? 'Dashboard API · reachable, refresh paused'
        : 'Dashboard API · refresh paused before first snapshot';
      setConnection(pausedLabel, state.lastSuccessfulRefresh ? 'ok' : '');
      setSnapshotStatus('paused');
    }
  } else {
    setConnection('Dashboard API · checking', '');
    setSnapshotStatus('checking');
  }
  if (state.paused) scheduleNext();
  else { refresh(false); scheduleNext(); }
  renderRoomControls();
}
function applyConfig(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || payload.schema !== 'dashboard-config-v1' || payload.read_only !== true) throw new Error('invalid dashboard config');
  const eventLimit = payload.event_limit, refreshSeconds = payload.refresh_seconds;
  if (!Number.isInteger(eventLimit) || eventLimit < 1 || eventLimit > 200) throw new Error('invalid event limit');
  if (!Number.isInteger(refreshSeconds) || refreshSeconds < 2 || refreshSeconds > 300) throw new Error('invalid refresh interval');
  state.config = {event_limit: eventLimit, refresh_seconds: refreshSeconds};
  renderScope();
}
async function bootstrap() {
  renderRoom();
  renderSoftwareShelf();
  pollHeartbeat();
  restoreWorkspaceFromHash();
  try { applyConfig(await requestJSON('/api/config')); }
  catch (_) {
    state.configDegraded = true; renderScope();
    setConnection('Dashboard API · using safe defaults', 'error');
  }
  try { renderOffline(await requestJSON('/api/offline-summary')); }
  catch (_) { renderOfflineError(); }
  loadAdvisoryReceipt();
  loadSuricataEvidence();
  loadIngestionRuns();
  loadReferenceStatus();
  await loadSetup();
  await refresh(false); scheduleNext();
}

function applyBaseFilters() { state.activeBin = null; state.timelineNotice = ''; applyFilters(); }
byId('filter-query').addEventListener('input', applyBaseFilters);
byId('filter-severity').addEventListener('change', applyBaseFilters);
byId('filter-rule').addEventListener('change', applyBaseFilters);
byId('clear-filters').addEventListener('click', clearFilters);
byId('clear-time-filter').addEventListener('click', () => { state.activeBin = null; state.timelineNotice = ''; applyFilters(); });
byId('refresh-button').addEventListener('click', () => refresh(true));
byId('pause-button').addEventListener('click', togglePause);
byId('ingestion-runs-retry').addEventListener('click', loadIngestionRuns);
byId('ingestion-source').addEventListener('change', loadIngestionRuns);
byId('reference-port-form').addEventListener('submit', event => { event.preventDefault(); lookupReference('port'); });
byId('reference-protocol-form').addEventListener('submit', event => { event.preventDefault(); lookupReference('protocol'); });
byId('reference-retry').addEventListener('click', loadReferenceStatus);
byId('reference-clear').addEventListener('click', () => {
  if (referenceState.loading || referenceState.statusLoading) return;
  clearReferenceResult(); syncReferenceControls();
  setReferenceStatus('Displayed context cleared. Stored records and the server cache were not changed.', referenceState.available ? 'ready' : 'unavailable');
});
byId('open-report-studio').addEventListener('click', () => {
  const studio = byId('report-studio');
  studio.open = true;
  byId('report-studio-action').textContent = 'Close report builder';
  renderReportPreview();
  if (typeof studio.scrollIntoView === 'function') studio.scrollIntoView({block: 'start'});
});
byId('report-studio').addEventListener('toggle', event => {
  byId('report-studio-action').textContent = event.currentTarget.open ? 'Close report builder' : 'Open report builder';
});
byId('triage-tools').addEventListener('toggle', event => {
  byId('triage-tools-action').textContent = event.currentTarget.open ? 'Hide controls' : 'Show controls';
});
byId('report-preview').addEventListener('click', renderReportPreview);
byId('report-scope').addEventListener('change', renderReportPreview);
byId('report-copy').addEventListener('click', async () => {
  const report = renderReportPreview(); if (!report) return;
  try { await navigator.clipboard.writeText(reportPlainText(report)); byId('report-feedback').textContent = 'Plain-language report summary copied.'; }
  catch (_) { byId('report-feedback').textContent = 'Clipboard unavailable. Select the preview text to copy it.'; }
});
byId('report-json').addEventListener('click', () => {
  const report = renderReportPreview(); if (!report) return;
  downloadReport(JSON.stringify(report, null, 2) + '\n', 'json', 'application/json');
  byId('report-feedback').textContent = 'Bounded JSON report downloaded.';
});
byId('report-csv').addEventListener('click', () => {
  const report = renderReportPreview(); if (!report) return;
  downloadReport(reportCsv(report), 'csv', 'text/csv');
  byId('report-feedback').textContent = 'Bounded CSV report downloaded.';
});
byId('report-print').addEventListener('click', () => {
  const report = renderReportPreview(); if (!report) return;
  window.print();
});
['reference-transport', 'reference-port', 'reference-protocol'].forEach(id => {
  byId(id).addEventListener(id === 'reference-transport' ? 'change' : 'input', referenceInputChanged);
});
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && !state.paused) { refresh(false); scheduleNext(); }
});
"""

from .control_room_assets import compose_control_room, ROOM_CSS, ROOM_JS
from .dashboard_app_viewer import APP_VIEWER_HTML, APP_VIEWER_CSS, APP_VIEWER_JS
from .dashboard_ai_assets import AI_PANEL, AI_CSS, AI_JS
from .dashboard_heartbeat import HEARTBEAT_CSS

DASHBOARD_CSS += REFERENCE_CONTRACT_CSS + ROOM_CSS + APP_VIEWER_CSS + AI_CSS + HEARTBEAT_CSS
INDEX_HTML = INDEX_HTML.replace("<!-- HUD_SETUP -->", SETUP_HTML)
INDEX_HTML = compose_control_room(INDEX_HTML)
INDEX_HTML = INDEX_HTML.replace('<!-- APP_VIEWER -->', APP_VIEWER_HTML)
INDEX_HTML = INDEX_HTML.replace('  <section class="analysis-window"', AI_PANEL + '  <section class="analysis-window"', 1)
DASHBOARD_JS += REFERENCE_CONTRACT_JS + LIFECYCLE_JS + READINESS_JS + CONTROLS_JS + SETUP_JS + INTEGRATIONS_JS + ROOM_JS + APP_VIEWER_JS + AI_JS + "\nbootstrap();\n"
