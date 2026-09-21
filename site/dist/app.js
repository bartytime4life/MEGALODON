const integrations = [
  {
    id: "core", name: "Python + SQLite", monogram: "PY", category: "core", status: "implemented", statusLabel: "Implemented",
    summary: "Validates bounded metadata and records events, detections, action decisions, and terminal receipts.",
    dataKind: "audit metadata", contract: "PacketEvent → local SQLite audit", owner: "megalodon.service",
    boundary: "No payload model, public listener, automatic action, or cloud dependency.",
    nextGate: "Representative replay and operator-owned retention policy.", ui: ["Event feed", "Detection linkage", "Run receipts"],
  },
  {
    id: "tshark", name: "Wireshark / TShark", monogram: "TS", category: "network", status: "implemented", statusLabel: "Implemented",
    summary: "Transforms an authorized saved PCAP or PCAPNG into bounded packet metadata and private reports.",
    dataKind: "packet metadata", contract: "Private PCAP/PCAPNG → offline-run-v1", owner: "megalodon.offline.tshark",
    boundary: "Linux-only, fixed /usr/bin/tshark, non-root, no live capture, payload, protocol tree, or name lookup.",
    nextGate: "Revalidate installed-tool compatibility and external-process containment.", ui: ["Traffic chart", "Protocol mix", "Packet rows"],
  },
  {
    id: "zeek", name: "Zeek", monogram: "ZK", category: "network", status: "implemented", statusLabel: "Implemented",
    summary: "Imports separately produced conn.log JSON or TSV as source-qualified flow metadata.",
    dataKind: "flow metadata", contract: "Declared conn.log profile → offline-run-v1", owner: "megalodon.offline.zeek",
    boundary: "MEGALODON never starts Zeek; flow counts never become packet counts; no response or egress.",
    nextGate: "Producer-profile compatibility and representative flow fixtures.", ui: ["Flow counter", "Conversation rows", "Protocol context"],
  },
  {
    id: "suricata", name: "Suricata", monogram: "SU", category: "network", status: "implemented", statusLabel: "Local read view",
    summary: "Capacity-gates atomic publication, reconciles unknown commits, and optionally shows bounded Suricata evidence in a read-only local dashboard startup snapshot.",
    dataKind: "alert metadata", contract: "suricata-eve-alert-input-v1", owner: "megalodon.offline.suricata",
    boundary: "Linux, non-root, and capability-free; existing owner-private store only. Reconciliation and the separate dashboard projection use locked read-only snapshots. No repair, retry, migration, retention deletion, sensor start, blocking, attribution, or response. This hosted Site has no runtime data connection.",
    nextGate: "Installed-producer and operator acceptance; verify snapshot age and source provenance before interpreting local results.", ui: ["Alert lane", "Severity", "Terminal receipt"],
    evidence: { label: "PR #239 · optional local read-only projection", url: "https://github.com/bartytime4life/MEGALODON/pull/239" },
  },
  {
    id: "scapy", name: "Scapy", monogram: "SC", category: "network", status: "bounded", statusLabel: "Optional",
    summary: "Provides explicitly enabled, interface-specific live packet metadata through the capture extra.",
    dataKind: "packet metadata", contract: "Selected interface → PacketEvent", owner: "megalodon.capture",
    boundary: "Capture authority and privilege remain external; no packet crafting or replay injection exists.",
    nextGate: "Least-privilege live-capture and backpressure validation.", ui: ["Interface rate", "Queue state", "Metadata rows"],
  },
  {
    id: "nftables", name: "nftables", monogram: "NF", category: "response", status: "plan", statusLabel: "Plan only",
    summary: "Renders inert, time-limited response proposals for review against validated global targets.",
    dataKind: "action plan", contract: "Validated target → planned ActionRecord", owner: "megalodon.firewall",
    boundary: "Live application is unsupported and refused before configuration, privilege, or subprocess work.",
    nextGate: "Durable intent, terminal outcome, reconciliation, recovery, and disposable-namespace tests.", ui: ["Planned actions", "Expiry", "Refusal receipts"],
  },
  {
    id: "clamav", name: "ClamAV", monogram: "CA", category: "endpoint", status: "manual", statusLabel: "Manual",
    summary: "Remains a separately operated file scanner with a reserved result surface in the control room.",
    dataKind: "file scan result", contract: "No MEGALODON intake contract", owner: "external operator",
    boundary: "No file-content intake, hash intake, signature update, daemon, quarantine, deletion, or result importer.",
    nextGate: "Versioned result contract, retention decision, and false-positive review.", ui: ["Reserved scan result", "Verdict", "Provenance"],
  },
  {
    id: "osquery", name: "osquery", monogram: "OQ", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future endpoint-inventory view built from a closed, privacy-reviewed query profile.",
    dataKind: "endpoint metadata", contract: "Not implemented", owner: "not implemented",
    boundary: "No arbitrary SQL, process environment, command-line dump, daemon, scheduler, or remote enrollment.",
    nextGate: "Closed table and field allowlist, query-pack contract, and local privacy review.", ui: ["Host posture", "Package inventory", "Query receipt"],
  },
  {
    id: "qwen", name: "Qwen + Ollama", monogram: "QW", category: "advisory", status: "manual", statusLabel: "Manual",
    summary: "Can explain one bounded completed metadata dossier through an explicit literal-loopback request.",
    dataKind: "advisory receipt", contract: "local-model-advisory-v1", owner: "megalodon.qwen_advisory",
    boundary: "The MEGALODON client uses literal loopback with no tools, retry, detector or response authority. It does not confine the separate Ollama process or prove that provider has no egress.",
    nextGate: "Independent review before invocation-to-dashboard orchestration.", ui: ["Advisory receipt", "Model provenance", "Fixed limitations"],
  },
  {
    id: "nmap", name: "Nmap", monogram: "NM", category: "network", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves an import-only interface for a completed, operator-supplied bounded inventory report.",
    dataKind: "network inventory", contract: "Future completed Nmap XML import", owner: "not implemented",
    boundary: "No scan launch, target selection, script engine, service-banner intake, or network activity.",
    nextGate: "Versioned XML contract, adversarial parser fixtures, privacy review, and size limits.", ui: ["Host inventory", "Port summary", "Import receipt"],
  },
  {
    id: "ossec", name: "OSSEC", monogram: "OS", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a source-qualified host-integrity alert lane from completed operator-supplied records.",
    dataKind: "host integrity alerts", contract: "Future bounded OSSEC JSON import", owner: "not implemented",
    boundary: "No agent enrollment, daemon control, unrestricted logs, configuration change, or active response.",
    nextGate: "Versioned alert contract, representative fixtures, redaction review, and limits.", ui: ["Integrity findings", "Host lane", "Import receipt"],
  },
  {
    id: "greenbone", name: "Greenbone CE", monogram: "GB", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a bounded review surface for a completed vulnerability report supplied by an operator.",
    dataKind: "vulnerability report", contract: "Future completed GMP XML import", owner: "not implemented",
    boundary: "No scanner launch, feed update, credential intake, target creation, scheduling, or remediation.",
    nextGate: "Versioned report contract, entity-expansion defenses, privacy review, and limits.", ui: ["Finding severity", "Affected asset", "Report receipt"],
  },
  {
    id: "zabbix", name: "Zabbix", monogram: "ZA", category: "availability", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future read-only availability summary with explicit endpoint and credential policy.",
    dataKind: "availability summary", contract: "Not implemented", owner: "not implemented",
    boundary: "No endpoint, credential, event history, background poller, acknowledgement, script, or remote command.",
    nextGate: "Read-only API allowlist, credential handling, request budgets, fixtures, and failure review.", ui: ["Service health", "Availability", "Read receipt"],
  },
  {
    id: "nagios", name: "Nagios Core", monogram: "NG", category: "availability", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future read-only availability surface without access to a command pipe or remote control.",
    dataKind: "availability summary", contract: "Not implemented", owner: "not implemented",
    boundary: "No CGI endpoint, credential, status archive, poller, acknowledgement, configuration, or command pipe.",
    nextGate: "Read-only field allowlist, credential handling, request budgets, fixtures, and failure review.", ui: ["Host status", "Service status", "Read receipt"],
  }
];

const workflows = {
  dashboard: {
    status: "Implemented", statusClass: "implemented", platform: "Local Linux reference", title: "Open your local evidence dashboard",
    summary: "Install the reviewed checkout for your user, then open MEGALODON from the application menu. The HUD opens with or without an audit store and provides explicit local checks. No cloud account or readiness-file export is needed locally.",
    command: "./scripts/install-local.sh",
    produces: ["Read-only view of your stored events", "Source-qualified detection links", "Available run receipts"],
    refuses: ["Remote exposure", "Host control", "Automatic sensor startup"],
    boundary: "Stored evidence is not proof of a currently running sensor. Check run timestamps and terminal outcomes."
  },
  replay: {
    status: "Implemented", statusClass: "implemented", platform: "Linux reference", title: "Bounded JSONL replay",
    summary: "Replay authorized metadata through finite line, byte, event, skipped-line, and optional elapsed-time limits while preserving terminal error evidence.",
    command: "python -m megalodon run --source jsonl --input ./events.jsonl --max-events 10000",
    produces: ["Accepted event ledger", "Detection and decision links", "Terminal run counters"],
    refuses: ["Unbounded aggregate reads", "Arbitrary event extensions", "Shell interpolation"],
    boundary: "The fixed aggregate UTF-8 input ceiling is 256 MiB; excess input fails closed."
  },
  offline: {
    status: "Bounded adapter", statusClass: "bounded", platform: "Linux only", title: "Isolated saved-capture analysis",
    summary: "Run a fixed-system TShark adapter against an explicitly selected PCAP or PCAPNG in a non-root analyst environment. Reports are private and redacted.",
    command: "python -m megalodon.offline --source tshark --input-root /absolute/private/input --input capture.pcapng --output /absolute/private/new-report --case case001 --max-records 10000 --timeout 30",
    produces: ["Typed metadata summary", "Redacted JSONL and CSV reports", "Run manifest and receipt"],
    refuses: ["Live capture", "Payload publication", "Root execution"],
    boundary: "Replace both absolute example paths with your private input and a new report directory. Fixed /usr/bin/tshark, bounded output and time; Windows desktop Wireshark is separate."
  },
  suricata: {
    status: "Implemented · optional local view", statusClass: "implemented", platform: "Linux · non-root · capability-free", title: "Review a bounded Suricata startup snapshot",
    summary: "Point the local dashboard at an existing private Suricata store. It validates a bounded read-only snapshot at startup and serves immutable review data; the hosted Site is not connected.",
    command: "python -m megalodon dashboard --suricata-db /absolute/private/suricata.sqlite",
    produces: ["Up to five validated recent publications", "At most 50 external alert metadata rows", "Explicit unconfigured, unavailable, and snapshot provenance states"],
    refuses: ["Database, schema, permission, or evidence writes", "Per-request database queries or live sensor access", "Retry, repair, retention, producer, or response authority"],
    boundary: "The optional projection validates a locked read-only startup snapshot within a cooperative five-second deadline and 64 KiB output bound. Snapshot freshness is explicit; external alert evidence does not become MEGALODON detection or action authority."
  },
  plans: {
    status: "Implemented / non-executing", statusClass: "implemented", platform: "Static catalog", title: "Capability and integration plans",
    summary: "Inspect a closed vocabulary of platform capabilities and integration steps without probing the host, locating executables, installing packages, or starting services.",
    command: "python -m megalodon hub-plan --platform linux",
    produces: ["Machine-readable workflow plan", "Explicit availability state", "Documented prerequisites"],
    refuses: ["Host probing", "Package installation", "Firewall or service changes"],
    boundary: "A plan is not an applied action, compatibility result, or production approval."
  }
};

const categories = [
  ["all", "All tools"], ["network", "Network"], ["endpoint", "Endpoint / file"], ["availability", "Availability"], ["advisory", "Advisory"], ["response", "Response"], ["core", "Core"]
];

const sourceToolIds = new Set(["core", "tshark", "zeek", "suricata", "scapy"]);
const toolPresenceKey = "megalodon-tool-presence-v2";
const toolPresenceValues = new Set(["unchecked", "installed", "missing"]);
const toolPresenceLabels = { unchecked: "Not checked", installed: "Installed · self-reported", missing: "Not installed · self-reported", stale: "Recheck required" };
const presenceMaxAge = 7 * 24 * 60 * 60 * 1000;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
function loadToolPresence() {
  try {
    const saved = JSON.parse(localStorage.getItem(toolPresenceKey) || "{}");
    if (!saved || typeof saved !== "object" || Array.isArray(saved)) return {};
    return Object.fromEntries(Object.entries(saved).filter(([id, value]) => integrations.some((item) => item.id === id) && value && typeof value === "object" && ["installed", "missing"].includes(value.status) && Number.isFinite(value.checkedAt) && value.checkedAt > 0 && value.checkedAt <= Date.now()));
  } catch {
    return {};
  }
}

const state = {
  activeView: "hud",
  readiness: null,
  toolQuery: "",
  toolFilter: "all",
  categoryFilter: "all",
  selectedTool: "core",
  toolPresence: loadToolPresence()
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value) => String(value).replace(/[&<>\"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[character]));

function presenceFor(id) {
  const note = state.toolPresence[id];
  if (!note) return "unchecked";
  if (Date.now() - note.checkedAt > presenceMaxAge) return "stale";
  return note.status;
}

function setToolPresence(id, value) {
  if (!integrations.some((item) => item.id === id) || !toolPresenceValues.has(value)) return;
  if (value === "unchecked") delete state.toolPresence[id];
  else state.toolPresence[id] = { status: value, checkedAt: Date.now() };
  try {
    localStorage.setItem(toolPresenceKey, JSON.stringify(state.toolPresence));
  } catch {
    // Status remains available for this page even if device-local storage is blocked.
  }
  renderIntegrationGrid();
  renderToolInspector();
}

function renderVerificationSummary() {
  const installed = integrations.filter((item) => presenceFor(item.id) === "installed").length;
  const missing = integrations.filter((item) => presenceFor(item.id) === "missing").length;
  const unchecked = integrations.length - installed - missing;
  const summary = $("#verification-summary");
  const stale = integrations.filter((item) => presenceFor(item.id) === "stale").length;
  if (summary) summary.textContent = `Manual notes: ${installed} reported installed · ${missing} reported not installed · ${stale} need recheck · ${unchecked - stale} not checked`;
}

function readinessLabel(id) {
  if (!state.readiness) return "Report: not loaded";
  const mapped = { core: "python-sqlite", tshark: "wireshark-tshark", qwen: "qwen-ollama", nagios: "nagios-core" }[id] || id;
  const report = state.readiness.tools.find((tool) => tool.id === mapped);
  const labels = { executable_found: "Executable found", not_found: "Not found on checked PATH", not_checked: "Not checked" };
  const stale = Date.now() - Date.parse(state.readiness.checked_at) > 24 * 60 * 60 * 1000;
  return `${stale ? "Stale report · " : "Report · "}${labels[report.status]}`;
}

let readinessImportSequence = 0;
async function importReadinessFile(file) {
  const sequence = ++readinessImportSequence;
  state.readiness = null;
  $("#clear-readiness").disabled = true;
  $("#readiness-feedback").textContent = file ? "Reading a bounded report… Previous report cleared." : "No readiness report loaded.";
  renderIntegrationGrid(); renderToolInspector();
  if (!file) return;
  try {
    if (!Number.isFinite(file.size) || file.size > 8192 || file.size < 2) throw new Error("Choose a JSON report no larger than 8 KiB.");
    const bytes = await file.arrayBuffer();
    if (sequence !== readinessImportSequence) return;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const report = validateReadinessReport(text);
    state.readiness = report;
    const age = Date.now() - Date.parse(report.checked_at);
    $("#readiness-feedback").textContent = `${age > 86400000 ? "STALE — more than 24 hours old. " : ""}14 tool results loaded · claimed check ${report.checked_at} · ${report.platform}. Schema accepted; report authenticity is not verified. Memory only.`;
    $("#clear-readiness").disabled = false;
  } catch (error) {
    if (sequence !== readinessImportSequence) return;
    $("#readiness-feedback").textContent = `Report rejected. ${error instanceof TypeError ? "The file must be valid UTF-8 JSON." : error.message} No results retained.`;
  }
  renderIntegrationGrid(); renderToolInspector();
}

function switchView(name, updateHistory = true) {
  if (!['hud', 'evidence', 'integrations', 'missions', 'boundaries'].includes(name)) return;
  if (!$( `[data-view-panel="${name}"]`)) return;
  if (!state.viewScroll) state.viewScroll = Object.create(null);
  state.viewScroll[state.activeView] = window.scrollY || 0;
  state.activeView = name;
  $$("[data-view-panel]").forEach((panel) => {
    const active = panel.dataset.viewPanel === name;
    panel.hidden = !active;
    panel.classList.toggle("active", active);
  });
  $$("[data-view]").forEach((button) => {
    const active = button.dataset.view === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  const heading = $(`[data-view-panel="${name}"] h1`);
  heading.setAttribute('tabindex', '-1');
  heading.focus({preventScroll: true});
  window.scrollTo({ top: state.viewScroll[name] || 0, behavior: "instant" });
  const hash = `#view=${name}`;
  if (updateHistory && window.location && window.location.hash !== hash && window.history) {
    try { window.history.pushState(null, '', hash); } catch { /* Keep navigation usable when history is unavailable. */ }
  }
}

function renderTelemetryUnavailable() {
  $("#feed-count").textContent = "No network records received by this Site.";
  const row = document.createElement("tr");
  const cell = document.createElement("td"); cell.colSpan = 6; cell.className = "empty-feed";
  cell.textContent = "Not connected. Review actual records in your local MEGALODON dashboard. Missing input is not zero traffic or zero threats.";
  row.append(cell); $("#event-feed").replaceChildren(row);
  $("#detection-lanes").textContent = "Unavailable — no detection evidence received.";
  $("#source-bars").textContent = "Unavailable — no source measurements received.";
  $("#run-list").textContent = "No runtime receipts loaded.";
  $("#run-inspector").innerHTML = '<h2>Review your local evidence</h2><p>The local dashboard reads your configured audit store. Its optional Suricata view is an immutable startup snapshot with explicit provenance and age.</p><p>Use Workflows for the local command. This Site cannot fetch your database or turn a readiness report into network evidence.</p><button class="control-button" id="local-workflow" type="button">View local dashboard command →</button>';
  $("#local-workflow").addEventListener("click", () => { renderWorkflow("dashboard"); switchView("missions"); });
}

function renderCategoryFilters() {
  $("#category-filter").replaceChildren(...categories.map(([id, label]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.className = state.categoryFilter === id ? "active" : "";
    button.setAttribute("aria-pressed", String(state.categoryFilter === id));
    button.addEventListener("click", () => {
      state.categoryFilter = id;
      const visible = integrations.filter((item) => id === "all" || item.category === id);
      if (!visible.some((item) => item.id === state.selectedTool)) state.selectedTool = visible[0]?.id ?? "core";
      renderCategoryFilters();
      renderIntegrationGrid();
      renderToolInspector();
    });
    return button;
  }));
}

function renderIntegrationGrid() {
  const visible = integrations.filter(item =>
    (state.categoryFilter === 'all' || item.category === state.categoryFilter)
    && (!state.toolQuery || `${item.name} ${item.summary} ${item.dataKind}`.toLowerCase().includes(state.toolQuery))
    && (state.toolFilter === 'all' || (state.toolFilter === 'data' ? sourceToolIds.has(item.id) : !!MegalodonControls.links()[item.id])));
  $('#tool-result-count').textContent = `${visible.length} of ${integrations.length} tools shown`;
  $('#tool-inspector').hidden = visible.length === 0;
  if (visible.length && !visible.some(item => item.id === state.selectedTool)) state.selectedTool = visible[0].id;
  $("#integration-grid").replaceChildren(...visible.map((item) => {
    const presence = presenceFor(item.id);
    const button = document.createElement("button");
    button.type = "button";
    button.className = `tool-card${state.selectedTool === item.id ? " active" : ""}`;
    button.setAttribute("aria-pressed", String(state.selectedTool === item.id));
    button.innerHTML = `<div class="tool-card-top"><span class="tool-monogram">${item.monogram}</span><div class="tool-state-stack"><span class="status-pill ${item.status}">${item.statusLabel}</span><span class="presence-pill ${presence}" aria-label="Installation status: ${toolPresenceLabels[presence]}"><i aria-hidden="true"></i>${toolPresenceLabels[presence]}</span></div></div><h2>${item.name}</h2><p>${item.summary}</p><span class="readiness-card-status">${readinessLabel(item.id)}</span><footer><span>${item.dataKind}</span><span>Open controls →</span></footer>`;
    button.addEventListener("click", () => {
      state.selectedTool = item.id;
      renderIntegrationGrid();
      renderToolInspector();
    });
    return button;
  }));
  renderVerificationSummary();
}

function renderToolInspector() {
  const item = integrations.find((candidate) => candidate.id === state.selectedTool) ?? integrations[0];
  const acquire = toolAcquisition[item.id];
  const lifecycle = resolveLifecycle(item.id);
  const presence = presenceFor(item.id);
  const hasHudLane = sourceToolIds.has(item.id);
  $("#tool-inspector").innerHTML = `
    <div class="inspector-head">
      <div><span class="tool-monogram">${item.monogram}</span><div><h2>${item.name}</h2><small>${item.dataKind}</small></div></div>
      <div class="inspector-statuses"><span class="status-pill ${item.status}">${item.statusLabel}</span><span class="presence-pill ${presence}"><i aria-hidden="true"></i>${toolPresenceLabels[presence]}</span></div>
    </div>
    <div id="shared-tool-controls"></div>
    <details class="tool-technical"><summary>Data connection &amp; technical details</summary>
    <div class="inspector-section"><span>MEGALODON contract</span><p>${item.contract}</p></div>
    <div class="inspector-section"><span>Imported presence report · self-reported</span><p>${readinessLabel(item.id)}</p><small class="panel-footnote">${state.readiness ? `Claimed check: ${state.readiness.checked_at} · ${state.readiness.platform} · path_presence_only` : "No report loaded. The browser has not inspected this device."}</small>${item.id === "qwen" ? "<p class=\"panel-footnote\">The report checks the Ollama executable only. It does not check a Qwen model or its digest.</p>" : ""}</div>
    <div class="inspector-section"><span>Integration owner</span><p>${item.owner}</p></div>
    <div class="inspector-section"><span>Local or planned review surfaces</span><div class="hud-slots">${item.ui.map((slot) => `<span>${slot}</span>`).join("")}</div></div>
    ${item.evidence ? `<div class="inspector-section"><span>Implementation reference</span><p><a class="evidence-link" href="${item.evidence.url}" target="_blank" rel="noopener noreferrer">${item.evidence.label} <span aria-hidden="true">↗</span></a></p></div>` : ""}
    </details>
    <div class="inspector-section acquire-section">
      <div class="acquire-heading"><span>Setup source</span><em>Operator managed</em></div>
      <p class="acquire-source">Official source · <strong>${acquire.source}</strong></p>
      <div class="platform-tags" aria-label="Companion vendor platforms; not MEGALODON acceptance">${acquire.platforms.map((platform) => `<span>${platform}</span>`).join("")}</div>
      ${acquire.command ? `<div class="install-command"><span>${acquire.commandLabel}</span><code>${acquire.command}</code><button type="button" data-copy-install>Copy command</button></div>` : `<div class="guided-install"><strong>Installation guidance</strong><span>Use the linked project or vendor instructions and keep installation under operator control.</span></div>`}
      <div class="acquire-actions"><a href="${acquire.url}" target="_blank" rel="noopener noreferrer">${acquire.linkLabel} <span aria-hidden="true">↗</span></a></div>
      <p class="acquire-note">${acquire.note}</p>
      <div class="verification-panel">
        <div class="verification-heading"><strong>Manual presence note</strong><span>${acquire.verificationLabel}</span></div>
        <p>Review this diagnostic before running it. It may execute the tool or contact its local service; it is separate from the metadata-only readiness probe. A result does not establish compatibility or service health.</p>
      <div class="verify-command"><code>${escapeHtml(lifecycle.verify)}</code><button type="button" data-copy-verify>Copy verify</button></div>
        <div class="presence-controls" role="group" aria-label="Record ${item.name} manual presence note">
          <button type="button" class="installed${presence === "installed" ? " active" : ""}" data-set-presence="installed" aria-pressed="${presence === "installed"}">I found it</button>
          <button type="button" class="missing${presence === "missing" ? " active" : ""}" data-set-presence="missing" aria-pressed="${presence === "missing"}">Not found by me</button>
          <button type="button" class="unchecked${presence === "unchecked" ? " active" : ""}" data-set-presence="unchecked" aria-pressed="${presence === "unchecked"}">Clear</button>
        </div>
        <small>${state.toolPresence[item.id] ? `Self-reported ${new Date(state.toolPresence[item.id].checkedAt).toISOString()}. ` : ""}Saved only in this browser; recheck after 7 days. Manual notes are not verified installation evidence.</small>
      </div>
      <p class="acquire-boundary"><strong>Operator action:</strong> this HUD opens setup guidance and copies lifecycle text. It never probes the host or executes an installer, uninstaller, service command, or package manager.</p>
    </div>
    <div class="inspector-section"><span>Authority boundary</span><p>${item.boundary}</p></div>
    <div class="inspector-section"><span>Next evidence gate</span><p>${item.nextGate}</p></div>
    <div class="inspector-warning">${hasHudLane ? "A local MEGALODON evidence path exists for this tool. This hosted Site has no connection to it." : "This interface is reserved only. MEGALODON does not currently ingest this tool's output."}</div>
    ${hasHudLane ? `<button class="control-button inspector-jump" type="button" data-source-jump="${item.id}">Review evidence locally</button>` : ""}
  `;
  const copyInstall = $("[data-copy-install]");
  if (copyInstall) copyInstall.addEventListener("click", async () => {
    await copyText(acquire.command, copyInstall, "Copied");
  });
  const copyVerify = $("[data-copy-verify]");
  if (copyVerify) copyVerify.addEventListener("click", async () => {
    await copyText(lifecycle.verify, copyVerify, "Copied");
  });
  $$('[data-set-presence]').forEach((button) => button.addEventListener('click', () => {
    setToolPresence(item.id, button.dataset.setPresence);
  }));
  MegalodonControls.mount($('#shared-tool-controls'), item.id, item.name, {
    changed() {
      renderIntegrationGrid();
      if ($('#tool-inspector').hidden) {
        $('#tool-quick-filter').focus();
      } else if (state.selectedTool !== item.id) {
        renderToolInspector();
        $('#tool-inspector h2').setAttribute('tabindex', '-1');
        $('#tool-inspector h2').focus();
      }
    }
  });
  const jump = $("[data-source-jump]");
  if (jump) jump.addEventListener("click", () => {
    renderWorkflow(item.id === "suricata" ? "suricata" : "dashboard");
    switchView("missions");
  });
}

async function copyText(value, button, successLabel = "Copied") {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = successLabel;
  } catch {
    const temporary = document.createElement("textarea");
    temporary.value = value;
    temporary.setAttribute("readonly", "");
    temporary.className = "clipboard-fallback";
    document.body.append(temporary);
    temporary.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { /* Ask the operator to select the visible text. */ }
    temporary.remove();
    button.textContent = copied ? successLabel : "Copy unavailable — select text";
  }
  window.setTimeout(() => { button.textContent = original; }, 1600);
}

function renderWorkflow(key) {
  const item = workflows[key];
  if (!item) return;
  $$(".mission").forEach((button) => {
    const active = button.dataset.workflow === key;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const badge = $("#workflow-status");
  badge.textContent = item.status;
  badge.className = `status-pill ${item.statusClass}`;
  $("#workflow-platform").textContent = item.platform;
  $("#workflow-title").textContent = item.title;
  $("#workflow-summary").textContent = item.summary;
  $("#workflow-command").textContent = item.command;
  $("#workflow-boundary").textContent = item.boundary;
  $("#workflow-produces").replaceChildren(...item.produces.map(listItem));
  $("#workflow-refuses").replaceChildren(...item.refuses.map(listItem));
}

function listItem(text) {
  const li = document.createElement("li");
  li.textContent = text;
  return li;
}

$$('[data-view]').forEach((button) => { button.setAttribute("aria-label", button.querySelector("span:last-child").textContent); button.addEventListener('click', () => switchView(button.dataset.view)); });
$('.brand').addEventListener('click', (event) => { event.preventDefault(); switchView('hud'); });
$$('[data-jump]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.jump)));
$$('.mission').forEach((button) => button.addEventListener('click', () => renderWorkflow(button.dataset.workflow)));

$("#readiness-file").addEventListener("change", (event) => importReadinessFile(event.target.files[0]));
$("#clear-readiness").addEventListener("click", () => { readinessImportSequence += 1; state.readiness = null; $("#readiness-file").value = ""; $("#readiness-feedback").textContent = "Report forgotten. No readiness results retained."; $("#clear-readiness").disabled = true; renderIntegrationGrid(); renderToolInspector(); });
$("#clear-tool-notes").addEventListener("click", () => { state.toolPresence = {}; try { localStorage.removeItem(toolPresenceKey); localStorage.removeItem("megalodon-tool-presence-v1"); } catch { /* Current page still clears. */ } renderIntegrationGrid(); renderToolInspector(); });

$("#copy-command").addEventListener("click", async () => {
  const command = $("#workflow-command").textContent;
  const button = $("#copy-command");
  await copyText(command, button);
});

renderTelemetryUnavailable();
renderCategoryFilters();
renderIntegrationGrid();
renderToolInspector();
renderWorkflow("dashboard");

$('#copy-local-install').addEventListener('click', () => copyText('./scripts/install-local.sh', $('#copy-local-install')));
$('#copy-hud-start').addEventListener('click', () => copyText('./scripts/start-local.sh', $('#copy-hud-start')));
$('#tool-search').addEventListener('input', () => { state.toolQuery = $('#tool-search').value.slice(0, 120).trim().toLowerCase(); renderIntegrationGrid(); renderToolInspector(); });
$('#tool-quick-filter').addEventListener('change', () => { state.toolFilter = $('#tool-quick-filter').value; renderIntegrationGrid(); renderToolInspector(); });

function restoreViewFromHash() {
  const hash = window.location.hash;
  if (hash === '') switchView('hud', false);
  else if (/^#view=(hud|evidence|integrations|missions|boundaries)$/.test(hash)) switchView(hash.slice(6), false);
}
window.addEventListener('popstate', restoreViewFromHash);
window.addEventListener('hashchange', restoreViewFromHash);
restoreViewFromHash();
