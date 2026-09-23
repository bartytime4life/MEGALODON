"""First-launch presentation and bounded startup receipt rendering."""

from .dashboard_heartbeat import HEARTBEAT_JS

SETUP_HTML = """
  <section class="hud-start" aria-labelledby="setup-title">
    <header class="setup-heading">
      <div><p class="eyebrow">Set up with confidence</p><h2 id="setup-title" tabindex="-1">Data and tools</h2>
      <p>Check this computer, then add only the software your workflow needs.</p></div>
      <a class="setup-help-link" href="#room-help-title">How this works <span aria-hidden="true">↗</span></a>
    </header>
    <div class="setup-main">
      <section class="setup-health" aria-labelledby="setup-check-title">
        <p class="setup-step">01 / CHECK YOUR COMPUTER</p>
        <h3 id="setup-check-title">Know what is ready</h3>
        <p>Read the local service, Python and SQLite versions, selected data store, and tool presence.</p>
        <div class="setup-check-actions"><button id="setup-check" class="setup-primary" type="button">Check this computer <span aria-hidden="true">→</span></button>
          <button id="setup-download-report" class="setup-report-button" type="button" disabled>Save check report</button></div>
        <p id="setup-check-status" class="setup-check-status" role="status" aria-live="polite">Ready when you are. Checks run only when you click.</p>
        <div id="setup-check-results" class="setup-check-results" aria-busy="false">
          <p class="setup-check-empty">Your checklist will appear here, with a next step for anything that needs attention.</p>
        </div>
        <p id="setup-source" role="status">Reading the selected data source…</p>
        <div id="hb-summary" class="hb-summary" role="status" aria-live="polite">Reading tool heartbeat…</div>
        <div class="setup-status-grid" aria-label="Tool observations">
          <div><span>Executables</span><b id="setup-installed-count">Not checked</b></div>
          <div><span>Process names</span><b id="setup-running-count">Not checked</b></div>
        </div>
        <p id="setup-readiness" role="status">Reading startup information…</p>
        <details class="tool-status-details"><summary>See every tool observation</summary>
          <p class="setup-boundary">Found means an executable is on the checked PATH. A process name is only a point-in-time observation. Neither proves health, installation quality, or a data connection.</p>
          <div id="setup-tool-status" class="tool-status-list"></div>
        </details>
        <p class="setup-check-boundary">Status lights show recent presence observations: green found, amber setup incomplete, red not found, grey unknown or stale. A matching process or model file does not prove health, a data connection, or AI readiness. Checks never scan, capture, or change configuration; installs run only when you press Install.</p>
      </section>
      <section class="setup-software" aria-labelledby="setup-software-title">
        <p class="setup-step">02 / CHOOSE YOUR WORKFLOW</p>
        <h3 id="setup-software-title" tabindex="-1">Software, without the guesswork</h3>
        <p>Python runs the HUD. Everything else supports a specific workflow; you do not need to download every tool.</p>
        <div class="setup-software-filters">
          <label for="setup-software-workflow">I want to…<select id="setup-software-workflow"><option value="start">Prepare the basics</option><option value="network">Review network evidence</option><option value="host">Explore host and security tools</option><option value="monitor">Explore monitoring tools</option><option value="ai">Explore local AI</option><option value="all">See all software</option></select></label>
          <label for="setup-software-search">Find software<input id="setup-software-search" type="search" placeholder="Search all software…" maxlength="80" autocomplete="off"></label>
        </div>
        <p id="setup-software-count" class="setup-software-count" role="status"></p>
        <div id="setup-software-list" class="setup-software-list"></div>
        <p class="setup-download-note">Install runs the Ubuntu package (your computer asks for your password) or the Python package for this HUD. Tools without a safe one-click package link to their official guide. <a href="#integrations-title">Review MEGALODON support in Apps →</a></p>
      </section>
    </div>
    <div class="setup-bottom">
      <details class="setup-launch-help">
        <summary>Reopen or stop MEGALODON</summary>
        <p id="setup-launch-intro">Reading the launch method for this HUD…</p>
        <code id="setup-reopen-command">Launch command unavailable</code>
        <button id="setup-reopen-copy" type="button" disabled>Copy reopen command</button>
        <p id="setup-launch-context">The terminal window owns this running session. Keep it open; press Ctrl+C there to stop the HUD.</p>
        <p id="setup-reopen-feedback" role="status"></p>
        <div id="setup-source-launch" hidden><p>From the reviewed repository folder, you can also check and launch the checkout:</p><code>./scripts/start-local.sh --check</code><code>./scripts/start-local.sh</code><p>The source launcher selects a compatible Python environment; it does not install packages or create sample data.</p></div>
        <p><a href="https://github.com/bartytime4life/MEGALODON/blob/main/docs/local-pc-setup.md" target="_blank" rel="noopener noreferrer">Open the local PC setup guide ↗</a> · <a href="#room-help-title">Get help in the HUD</a></p>
      </details>
      <details class="setup-actions-card">
        <summary>Change data for the next launch</summary>
        <div class="setup-form">
          <p>Prepare and copy a relaunch command for an existing data source. Empty fields keep this launcher's defaults. This form does not open or change files.</p>
          <label class="field">Settings file override<input id="setup-config" placeholder="/absolute/private/settings.toml" maxlength="512" aria-describedby="setup-config-note"></label>
          <p id="setup-config-note">An explicit settings file overrides the launcher's default settings for this launch only.</p>
          <label class="field">Completed offline run<input id="setup-offline" placeholder="/absolute/private/completed-run" maxlength="512"></label>
          <label class="field">Suricata store<input id="setup-suricata" placeholder="/absolute/private/suricata.db" maxlength="512"></label>
          <button id="setup-build" type="button">Prepare launch command</button>
          <code id="setup-command">Launch command unavailable</code><button id="setup-copy" type="button" disabled>Copy launch command</button>
          <p id="setup-feedback" role="status">Run the prepared command in your MEGALODON terminal.</p>
        </div>
      </details>
    </div>
  </section>
"""

SETUP_JS = r"""
const setupState = {readiness: null, runtime: null, sourceStatus: null};
const workflowToolIds = ['core', 'tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen', 'nmap', 'ossec', 'greenbone', 'zabbix', 'nagios'];
const startupToolIds = ['python-sqlite', 'wireshark-tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen-ollama', 'nmap', 'ossec', 'greenbone', 'zabbix', 'nagios-core'];
function toolPresenceText(index) {
  const report = setupState.readiness;
  if (!report) return 'Tool presence not checked';
  const labels = {executable_found: 'Executable found at launch', not_found: 'Not found on checked PATH', not_checked: 'Not checked by executable discovery'};
  return labels[report.tools[index].status];
}
const runtimeStatuses = new Set(['running', 'not_running', 'not_applicable', 'not_checked']);
function validatedRuntimeReport(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !referenceExactKeys(value, ['schema', 'checked_at', 'platform', 'probe_mode', 'boundaries', 'tools'])
      || value.schema !== 'megalodon-tool-runtime-v1'
      || value.probe_mode !== 'process_name_presence_only'
      || typeof value.checked_at !== 'string' || typeof value.platform !== 'string'
      || !Array.isArray(value.boundaries) || value.boundaries.length !== 4
      || !value.boundaries.every(item => typeof item === 'string' && item.length > 0 && item.length <= 240)
      || !Array.isArray(value.tools) || value.tools.length !== startupToolIds.length) throw new Error('Invalid runtime receipt');
  value.tools.forEach((tool, index) => {
    if (!tool || typeof tool !== 'object' || Array.isArray(tool)
        || !referenceExactKeys(tool, ['id', 'status']) || tool.id !== startupToolIds[index]
        || !runtimeStatuses.has(tool.status)) throw new Error('Invalid runtime receipt');
  });
  return value;
}
function renderToolStatus() {
  const evidence = latestToolEvidence();
  const readiness = evidence.readiness;
  const runtime = evidence.runtime;
  const names = {
    'python-sqlite': 'MEGALODON core', 'wireshark-tshark': 'Wireshark / TShark', zeek: 'Zeek', suricata: 'Suricata',
    scapy: 'Scapy', nftables: 'nftables', clamav: 'ClamAV', osquery: 'osquery', 'qwen-ollama': 'Qwen / Ollama',
    nmap: 'Nmap', ossec: 'OSSEC', greenbone: 'Greenbone', zabbix: 'Zabbix', 'nagios-core': 'Nagios Core'
  };
  const installedCount = readiness ? readiness.tools.filter(tool => tool.status === 'executable_found').length : null;
  const runningCount = runtime ? runtime.tools.filter(tool => tool.status === 'running').length : null;
  byId('setup-installed-count').textContent = installedCount === null ? 'Not checked'
    : readiness.tools.every(tool => tool.status === 'not_checked') ? 'Unable to check' : `${installedCount} found`;
  byId('setup-running-count').textContent = runningCount === null || !runtime.tools.some(tool => ['running', 'not_running'].includes(tool.status))
    ? 'Not checked' : `${runningCount} observed`;
  const presenceLabels = {executable_found: 'Executable found', not_found: 'Not found', not_checked: 'Not checked'};
  const runtimeLabels = {running: 'Process observed', not_running: 'Process not observed', not_applicable: 'Runtime not applicable', not_checked: 'Runtime not checked'};
  byId('setup-tool-status').replaceChildren(...startupToolIds.map((id, index) => {
    const row = document.createElement('div'); row.className = 'tool-status-row';
    const name = document.createElement('strong'); name.textContent = names[id] || id;
    const badges = document.createElement('div'); badges.className = 'tool-status-badges';
    const presenceStatus = readiness ? readiness.tools[index].status : 'not_checked';
    const runtimeStatus = runtime ? runtime.tools[index].status : 'not_checked';
    const presence = document.createElement('span'); presence.className = `status-badge ${presenceStatus}`; presence.textContent = presenceLabels[presenceStatus];
    const process = document.createElement('span'); process.className = `status-badge ${runtimeStatus}`; process.textContent = runtimeLabels[runtimeStatus];
    badges.append(presence, process); row.append(name, badges); return row;
  }));
}
async function loadSetup() {
  setupState.sourceStatus = null;
  try {
    const value = await requestJSON('/api/setup');
    if (!referenceExactKeys(value, ['schema', 'source_status', 'readiness', 'runtime']) || value.schema !== 'dashboard-setup-v2'
        || !['connected', 'not_configured'].includes(value.source_status)) throw new Error('Invalid setup receipt');
    const report = value.readiness === null ? null : validateReadinessReport(JSON.stringify(value.readiness));
    const runtime = value.runtime === null ? null : validatedRuntimeReport(value.runtime);
    setupState.readiness = report;
    setupState.runtime = runtime;
    setupState.sourceStatus = value.source_status;
    byId('setup-source').textContent = value.source_status === 'connected'
      ? 'The local data file is open. Traffic and alert counts come from this file.'
      : 'No local data file is available yet. Tool checks still work. After the first successful import, reopen the HUD before the new store appears.';
    byId('setup-readiness').textContent = report
      ? `Startup observations from ${formatRefreshTime(new Date(report.checked_at))}. Use Check this computer to update them.`
      : 'Choose Check this computer to read current local observations.';
    renderToolStatus();
    if (typeof integrationState !== 'undefined' && integrationState.snapshot) renderIntegrationMap();
  } catch (_) {
    setupState.sourceStatus = null;
    setupState.readiness = null;
    setupState.runtime = null;
    byId('setup-source').textContent = 'Setup information unavailable. Existing telemetry controls remain independent.';
    byId('setup-readiness').textContent = 'Startup observations are unavailable. Choose Check this computer to try a fresh read.';
    renderToolStatus();
  }
  renderSoftwareShelf();
}
const localCheckState = {snapshot: null, busy: false, failed: false, focusTool: null, retryAt: 0};
const softwareCatalog = [
  {id: 'python', name: 'Python', mark: 'Py', group: 'start', requirement: 'Required · 3.11+', purpose: 'The runtime that powers MEGALODON.', note: 'This HUD already runs in Python. Check its version here before installing another copy.', url: 'https://www.python.org/downloads/', link: 'Python downloads'},
  {id: 'git', name: 'Git', mark: 'Git', group: 'start', requirement: 'Optional · source checkout', purpose: 'Download and update a copy of the repository.', note: 'Needed for the clone workflow. A packaged installation or downloaded source archive does not require Git. Git presence is not included in these checks.', url: 'https://git-scm.com/downloads/', link: 'Git downloads'},
  {id: 'tshark', name: 'Wireshark / TShark', mark: 'Ws', group: 'network', requirement: 'Optional · saved packets', purpose: 'Inspect packet captures and extract metadata.', note: 'Use the guarded setup guide for the Linux TShark adapter. The HUD does not open packet captures or start capture.', url: 'https://www.wireshark.org/download.html', link: 'Wireshark downloads'},
  {id: 'zeek', name: 'Zeek', mark: 'Z', group: 'network', requirement: 'Optional · saved flow metadata', purpose: 'Turn network activity into structured connection logs.', note: 'The reviewed workflow uses a private, pinned producer. MEGALODON does not start Zeek.', url: 'https://zeek.org/get-zeek/', link: 'Zeek downloads'},
  {id: 'suricata', name: 'Suricata', mark: 'Su', group: 'network', requirement: 'Optional · imported alerts', purpose: 'Produce security alerts for later review.', note: 'Operate the sensor separately. An executable found here does not prove that alert data is connected.'},
  {id: 'scapy', name: 'Scapy', mark: 'Sc', group: 'network', requirement: 'Optional · capture extra', purpose: 'Provide Python packet handling for approved capture workflows.', note: 'Install in the MEGALODON Python environment. These checks do not inspect Python packages or grant capture permissions.', link: 'Scapy install guide'},
  {id: 'nftables', name: 'nftables', mark: 'nf', group: 'host', requirement: 'Optional · Linux only', purpose: 'Linux firewall tooling for reviewing response plans.', note: 'MEGALODON produces inert plans and refuses live rule application. Installing firewall tools is a separate administrator task.', url: 'https://netfilter.org/projects/nftables/index.html', link: 'nftables install guide'},
  {id: 'clamav', name: 'ClamAV', mark: 'Cl', group: 'host', requirement: 'Optional · manual companion', purpose: 'Scan files with a separately operated antivirus tool.', note: 'The HUD does not scan files or update signatures. Installation can add a signature-update service.'},
  {id: 'osquery', name: 'osquery', mark: 'oq', group: 'host', requirement: 'Optional · no importer', purpose: 'Explore endpoint inventory with SQL-style queries.', note: 'MEGALODON does not run queries, schedule inventory, or import osquery results.'},
  {id: 'qwen', name: 'Ollama + Qwen', mark: 'AI', group: 'ai', requirement: 'Optional · local advisory', purpose: 'Host an optional local language model for bounded explanations.', note: 'Ollama is the runtime; Qwen is a separate model download. The advisory workflow needs a validated local model registry. Checking observes only the Ollama executable and process.', link: 'Ollama downloads'},
  {id: 'nmap', name: 'Nmap', mark: 'Nm', group: 'network', requirement: 'Optional · no importer', purpose: 'Explore network inventory in a separate authorized workflow.', note: 'The HUD does not scan a network. A completed XML importer is a future integration.'},
  {id: 'ossec', name: 'OSSEC', mark: 'OS', group: 'host', requirement: 'Optional · no importer', purpose: 'Monitor host integrity using a separately managed agent.', note: 'Choose your server or agent role in the vendor guide. Enrollment and active response stay outside MEGALODON.'},
  {id: 'greenbone', name: 'Greenbone', mark: 'Gb', group: 'host', requirement: 'Optional · no importer', purpose: 'Manage vulnerability assessments in a separate console.', note: 'A multi-service container deployment. MEGALODON neither launches scans nor imports its reports.', link: 'Greenbone install guide'},
  {id: 'zabbix', name: 'Zabbix', mark: 'Za', group: 'monitor', requirement: 'Optional · no connection', purpose: 'Monitor infrastructure in a separately managed service.', note: 'Select the server or agent package for your system. The HUD can save a console link, but has no data connection.', link: 'Zabbix download selector'},
  {id: 'nagios', name: 'Nagios Core', mark: 'Na', group: 'monitor', requirement: 'Optional · no connection', purpose: 'Review service availability in its own monitoring console.', note: 'Configure hosts and plugins in Nagios. The HUD does not access its command pipe or credentials.'}
];
// Keep reading context across check updates and filter changes; keys are the fixed catalog.
const softwareGuidanceOpen = new Map(softwareCatalog.map(item => [item.id, false]));
let softwareShelfGeneration = 0;
function checkTimestamp(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && Date.parse(value) <= Date.now() + 300000
    && new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
}
function validateLocalCheckReport(value) {
  const version = value => typeof value === 'string' && /^\d{1,3}(?:\.\d{1,3}){1,3}(?:[a-z0-9.+-]{0,24})?$/.test(value);
  if (!referenceExactKeys(value, ['schema', 'checked_at', 'environment', 'source', 'readiness', 'runtime'])
      || value.schema !== 'dashboard-local-checks-v1' || !checkTimestamp(value.checked_at)
      || !referenceExactKeys(value.environment, ['python_version', 'sqlite_version', 'platform'])
      || !version(value.environment.python_version) || !version(value.environment.sqlite_version)
      || !['linux', 'windows', 'other'].includes(value.environment.platform)
      || !referenceExactKeys(value.source, ['status'])
      || !['available', 'not_configured', 'unavailable'].includes(value.source.status)) throw new Error('Invalid local check report');
  const readiness = validateReadinessReport(JSON.stringify(value.readiness));
  const runtime = validatedRuntimeReport(value.runtime);
  if (!checkTimestamp(runtime.checked_at) || !['linux', 'windows', 'other'].includes(runtime.platform)
      || runtime.platform !== value.environment.platform || readiness.platform !== value.environment.platform) throw new Error('Invalid local check platform');
  return {...value, readiness, runtime};
}
async function requestLocalCheck() {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  let reader = null;
  try {
    const response = await fetch('/api/local-checks', {headers: {'Accept': 'application/json', 'X-Megalodon-Check': '1'}, cache: 'no-store', mode: 'same-origin', credentials: 'omit', redirect: 'error', signal: controller.signal});
    if (!response.ok) { const error = new Error('Check unavailable'); error.status = response.status; throw error; }
    const declared = response.headers.get('Content-Length');
    if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || !Number.isSafeInteger(Number(declared)) || Number(declared) > 20480)) throw new Error('Invalid check length');
    reader = response.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw new Error('Invalid check body');
      size += part.value.byteLength;
      if (size > 20480) throw new Error('Check too large');
      chunks.push(part.value);
    }
    if (declared !== null && Number(declared) !== size) throw new Error('Incomplete check');
    const bytes = new Uint8Array(size); let offset = 0;
    chunks.forEach(chunk => { bytes.set(chunk, offset); offset += chunk.byteLength; });
    return validateLocalCheckReport(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)));
  } finally {
    if (reader) { try { await reader.cancel(); } catch (_) {} }
    window.clearTimeout(timeout);
  }
}
function latestToolEvidence() { return localCheckState.snapshot || setupState; }
function optionalToolSummary(readiness) {
  const tools = readiness.tools.filter(tool => tool.id !== 'python-sqlite');
  const eligible = tools.filter(tool => tool.id !== 'scapy');
  const found = tools.filter(tool => tool.status === 'executable_found').length;
  const missing = tools.filter(tool => tool.status === 'not_found').length;
  const unchecked = tools.filter(tool => tool.status === 'not_checked').length;
  const eligibleUnchecked = eligible.filter(tool => tool.status === 'not_checked').length;
  const counts = `${found} found · ${missing} not found · ${unchecked} not checked`;
  if (eligibleUnchecked === eligible.length) return {
    result: 'Unable to check', state: 'neutral',
    detail: `${counts}. Executable discovery could not check any eligible tools. This check inspects Linux PATH only; Scapy needs a separate Python-package check.`
  };
  return {result: counts, state: eligibleUnchecked ? 'neutral' : 'ready', detail: eligibleUnchecked
    ? 'Partial observation: some eligible tools could not be checked. Missing optional software does not block the HUD.'
    : 'Missing optional software does not block the HUD. Scapy is not included in executable discovery. Choose a workflow to see what you need.'};
}
function softwarePresence(item) {
  const receipt = localCheckState.snapshot;
  const stale = localCheckState.failed ? 'Previous observation · ' : '';
  if (item.id === 'python') return receipt ? `${stale}Python ${receipt.environment.python_version} in this service` : 'Check to see the active runtime';
  if (item.id === 'git') return 'Git is not included in local checks';
  const index = workflowToolIds.indexOf(item.id);
  const evidence = latestToolEvidence();
  if (!evidence.readiness || index < 0) return 'Availability not checked';
  const labels = {executable_found: 'Executable found', not_found: 'Not found on checked PATH', not_checked: 'Not checked by executable discovery'};
  const stamp = receipt ? 'at last check' : 'at HUD launch';
  return `${stale}${labels[evidence.readiness.tools[index].status]} · ${stamp}`;
}
function renderSoftwareShelf() {
  const generation = ++softwareShelfGeneration;
  const query = String(byId('setup-software-search').value || '').trim().toLowerCase();
  const workflow = byId('setup-software-workflow').value || 'start';
  const items = softwareCatalog.filter(item => query
    ? `${item.name} ${item.purpose} ${item.requirement}`.toLowerCase().includes(query)
    : workflow === 'all' || item.group === workflow);
  byId('setup-software-count').textContent = query ? `${items.length} matching ${items.length === 1 ? 'tool' : 'tools'} across all workflows` : `${items.length} ${items.length === 1 ? 'tool' : 'tools'} in this workflow`;
  const rows = items.map(item => {
    const row = textNode('article', '', 'software-row'); row.id = `software-${item.id}`;
    if (localCheckState.focusTool === item.id && localCheckState.snapshot && !localCheckState.failed) row.className += ' software-checked';
    const heading = textNode('div', '', 'software-heading');
    const mark = textNode('span', item.mark, 'software-mark'); mark.setAttribute('aria-hidden', 'true');
    const title = textNode('h4', ''); if (item.id !== 'git') title.append(heartbeatLight(item.id)); title.append(textNode('span', item.name));
    const identity = textNode('div', '', 'software-identity'); identity.append(title, textNode('span', item.requirement, 'software-requirement'));
    if (item.id !== 'git') identity.append(heartbeatDetail(item.id));
    heading.append(mark, identity); row.append(heading, textNode('p', item.purpose, 'software-purpose'));
    const presence = textNode('p', softwarePresence(item), 'software-presence'); presence.id = `software-status-${item.id}`;
    presence.hidden = heartbeatState.byId.size > 0;
    const actions = textNode('div', '', 'software-actions');
    if (item.id !== 'git' && item.id !== 'python') actions.append(installControl(item.id, item.name));
    const link = textNode('a', `${item.link || item.name + ' downloads'} ↗`, 'software-download');
    link.href = item.url || toolAcquisition[item.id].url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.setAttribute('aria-label', `${item.link || item.name + ' downloads'} — official publisher, opens a new tab`); actions.append(link);
    if (item.id !== 'git' && item.id !== 'scapy') {
      const check = textNode('button', localCheckState.busy ? 'Checking…' : item.id === 'python' ? 'Check runtime' : 'Check availability', 'software-check');
      check.type = 'button'; check.id = `software-check-${item.id}`; check.disabled = localCheckState.busy; check.setAttribute('aria-label', `Check ${item.name} availability`); check.setAttribute('aria-describedby', presence.id);
      check.hidden = heartbeatState.byId.size > 0 && item.id !== 'python';
      check.addEventListener('click', () => runLocalChecks(item.id)); actions.append(check);
    }
    const more = textNode('details', '', 'software-details'); more.id = `software-guidance-${item.id}`;
    more.open = softwareGuidanceOpen.get(item.id);
    more.addEventListener('toggle', () => {
      // Ignore queued events from nodes removed by a newer search or check render.
      if (generation === softwareShelfGeneration) softwareGuidanceOpen.set(item.id, more.open);
    });
    more.append(textNode('summary', 'What to know before installing'), textNode('p', item.note));
    if (item.id === 'qwen') { const model = textNode('a', 'Browse Qwen models separately ↗'); model.href = 'https://ollama.com/library/qwen2.5'; model.target = '_blank'; model.rel = 'noopener noreferrer'; more.append(model); }
    if (['tshark', 'zeek', 'nftables'].includes(item.id)) { const guide = textNode('a', 'MEGALODON setup guidance ↗'); guide.href = toolAcquisition[item.id].url; guide.target = '_blank'; guide.rel = 'noopener noreferrer'; more.append(guide); }
    row.append(presence, actions, more); return row;
  });
  byId('setup-software-list').replaceChildren(...(rows.length ? rows : [textNode('p', 'No software matches. Try a product name such as Python, Zeek, or Ollama.', 'setup-check-empty')]));
}
function renderLocalCheckResults() {
  const report = localCheckState.snapshot;
  byId('setup-download-report').disabled = !report || localCheckState.busy || localCheckState.failed;
  if (!report) {
    if (localCheckState.failed) byId('setup-readiness').textContent = 'Current checks are unavailable. Any startup observations shown below are stale.';
    return;
  }
  const source = {
    available: ['Readable', 'The selected store passed a bounded read. Review Traffic for qualified evidence.'],
    not_configured: ['No data file yet', 'You can use setup without data. After the first successful import, reopen the HUD before the new store appears. Open Help for import guidance.'],
    unavailable: ['Needs attention', 'The selected store could not be read. Review your launch settings and the local PC setup guide.']
  }[report.source.status];
  const optional = optionalToolSummary(report.readiness);
  const checks = [
    ['Local service', 'Responded', 'The HUD answered this check on this computer.', 'ready'],
    ['Active runtime', `Python ${report.environment.python_version} · SQLite ${report.environment.sqlite_version}`, `Reported by the running service · ${report.environment.platform}.`, 'ready'],
    ['Selected data store', source[0], source[1], report.source.status === 'available' ? 'ready' : 'attention'],
    ['Optional tools', optional.result, optional.detail, optional.state]
  ];
  byId('setup-check-results').replaceChildren(...checks.map(([title, result, detail, observation]) => {
    const state = localCheckState.failed ? 'neutral' : observation;
    const row = textNode('div', '', `setup-check-row check-${state}`);
    const indicator = textNode('span', state === 'ready' ? '✓' : state === 'attention' ? '!' : '—', `setup-check-indicator is-${state}`); indicator.setAttribute('aria-hidden', 'true');
    const body = textNode('div'); body.append(textNode('strong', title), textNode('b', `${localCheckState.failed ? 'Previous: ' : ''}${result}`), textNode('p', detail)); row.append(indicator, body); return row;
  }));
  byId('setup-source').hidden = true;
  byId('setup-readiness').textContent = `${localCheckState.failed ? 'Previous observations — stale' : 'Observed'} ${formatRefreshTime(new Date(report.checked_at))}. Check again after changing tools. Results may be reused for five seconds.`;
  renderToolStatus();
}
async function runLocalChecks(focusTool = null) {
  if (localCheckState.busy) return;
  if (Date.now() < localCheckState.retryAt) { byId('setup-check-status').textContent = 'A check is already running. Wait five seconds, then choose Check this computer.'; return; }
  const initiatingControl = document.activeElement && document.activeElement.id;
  localCheckState.busy = true; localCheckState.focusTool = focusTool;
  byId('setup-check').disabled = true; byId('setup-check').textContent = 'Checking this computer…';
  byId('setup-check-results').setAttribute('aria-busy', 'true'); byId('setup-download-report').disabled = true;
  byId('setup-check-status').textContent = 'Reading local versions, the selected store, and tool observations…';
  renderSoftwareShelf();
  try {
    const report = await requestLocalCheck();
    localCheckState.snapshot = report; localCheckState.failed = false; localCheckState.retryAt = 0;
    const item = softwareCatalog.find(entry => entry.id === focusTool);
    byId('setup-check-status').textContent = item ? `${item.name}: ${softwarePresence(item)}. All local checks updated.` : `Check complete at ${formatRefreshTime(new Date(report.checked_at))}. Review your checklist below.`;
  } catch (error) {
    localCheckState.failed = true;
    const message = error.status === 429 ? 'A local check is already running. Wait five seconds, then try again.'
      : error.status === 403 ? 'Local checks are available in HUD mode. Open Help for the launch command.'
      : error.name === 'AbortError' ? 'The check timed out. Confirm the HUD terminal is still open, then try again.'
      : 'The check could not be completed. Confirm the HUD terminal is still open, then try again.';
    if (error.status === 429) localCheckState.retryAt = Date.now() + 5000;
    byId('setup-check-status').textContent = message + (localCheckState.snapshot ? ' Previous results are stale.' : ' No current result is available.');
  } finally {
    localCheckState.busy = false;
    byId('setup-check').disabled = false; byId('setup-check').textContent = localCheckState.failed ? 'Try checking again' : 'Check this computer →';
    byId('setup-check-results').setAttribute('aria-busy', 'false');
    renderLocalCheckResults(); renderSoftwareShelf();
    if (initiatingControl && (initiatingControl === 'setup-check' || initiatingControl.startsWith('software-check-'))) {
      const control = byId(initiatingControl) || byId('setup-check');
      if (control && typeof control.focus === 'function') control.focus({preventScroll: true});
    }
  }
}
byId('setup-check').addEventListener('click', () => runLocalChecks());
byId('setup-software-search').addEventListener('input', renderSoftwareShelf);
byId('setup-software-workflow').addEventListener('change', () => { byId('setup-software-search').value = ''; renderSoftwareShelf(); });
byId('setup-download-report').addEventListener('click', () => {
  if (!localCheckState.snapshot || localCheckState.busy || localCheckState.failed) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(localCheckState.snapshot, null, 2) + '\n'], {type: 'application/json'}));
  const link = document.createElement('a'); link.href = url; link.download = 'megalodon-local-checks.json'; link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  byId('setup-check-status').textContent = 'Check report download prepared. It contains the displayed observations, without local file paths.';
});

function hudLaunchCommand(values) {
  let command = validatedHudLaunch(typeof localHudLaunch === 'undefined' ? null : localHudLaunch).command;
  [['config', '--config'], ['offline', '--offline-run'], ['suricata', '--suricata-db']].forEach(([key, flag]) => {
    const value = values[key];
    if (!value) return;
    if (typeof value !== 'string' || value.length > 512 || !value.startsWith('/') || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Use absolute Linux paths without control characters.');
    command += ` ${flag} '${value.replace(/'/g, "'\"'\"'")}'`;
  });
  return command;
}
function validatedHudLaunch(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== 2 || !Object.hasOwn(value, 'mode') || !Object.hasOwn(value, 'command')
      || !['desktop', 'source'].includes(value.mode) || typeof value.command !== 'string'
      || !value.command.trim() || value.command.length > 4096 || /[\x00-\x1f\x7f]/.test(value.command)) {
    throw new Error('Launch guidance is unavailable. Reopen MEGALODON using your original launcher.');
  }
  return value;
}
function renderLaunchHelp() {
  try {
    const launch = validatedHudLaunch(typeof localHudLaunch === 'undefined' ? null : localHudLaunch);
    const desktop = launch.mode === 'desktop';
    const intro = desktop
      ? 'Reopen MEGALODON from your application menu, or use this stable launcher in a terminal.'
      : 'This HUD is running from a source environment. Use this command to reopen the same environment, or use the source launcher from your reviewed checkout.';
    ['setup-launch-intro', 'help-launch-intro'].forEach(id => { byId(id).textContent = intro; });
    ['setup-reopen-command', 'help-reopen-command', 'setup-command'].forEach(id => { byId(id).textContent = launch.command; });
    ['setup-source-launch', 'help-source-launch'].forEach(id => { byId(id).hidden = desktop; });
    byId('setup-config-note').textContent = desktop
      ? 'Leave empty to keep the installed settings. A settings file entered here overrides that default for this launch only.'
      : 'An explicit settings file overrides the launcher defaults for this launch only.';
    byId('setup-reopen-copy').disabled = false;
    byId('setup-copy').disabled = false;
    byId('setup-build').disabled = false;
  } catch (error) {
    ['setup-launch-intro', 'help-launch-intro'].forEach(id => { byId(id).textContent = error.message; });
    ['setup-reopen-command', 'help-reopen-command', 'setup-command'].forEach(id => { byId(id).textContent = 'Launch command unavailable'; });
    ['setup-source-launch', 'help-source-launch'].forEach(id => { byId(id).hidden = true; });
    ['setup-reopen-copy', 'setup-copy', 'setup-build'].forEach(id => { byId(id).disabled = true; });
  }
}
byId('setup-build').addEventListener('click', () => {
  try {
    byId('setup-command').textContent = hudLaunchCommand({config: byId('setup-config').value, offline: byId('setup-offline').value, suricata: byId('setup-suricata').value});
    byId('setup-copy').disabled = false;
    byId('setup-feedback').textContent = 'Command prepared for this launcher. Stop the current HUD with Ctrl+C in its terminal, then run the command in a terminal.';
  } catch (error) { byId('setup-copy').disabled = true; byId('setup-feedback').textContent = error.message; }
});
['setup-config', 'setup-offline', 'setup-suricata'].forEach(id => byId(id).addEventListener('input', () => {
  byId('setup-copy').disabled = true; byId('setup-feedback').textContent = 'Choose Prepare launch command to apply these changes.';
}));
byId('setup-copy').addEventListener('click', async () => {
  if (byId('setup-copy').disabled) return;
  try { await navigator.clipboard.writeText(byId('setup-command').textContent); byId('setup-feedback').textContent = 'Launch command copied.'; }
  catch (_) { byId('setup-feedback').textContent = 'Select and copy the displayed command; clipboard unavailable.'; }
});
byId('setup-reopen-copy').addEventListener('click', async () => {
  if (byId('setup-reopen-copy').disabled) return;
  try { await navigator.clipboard.writeText(validatedHudLaunch(localHudLaunch).command); byId('setup-reopen-feedback').textContent = 'Reopen command copied.'; }
  catch (_) { byId('setup-reopen-feedback').textContent = 'Select and copy the displayed command; clipboard unavailable.'; }
});
renderLaunchHelp();
"""
SETUP_JS += HEARTBEAT_JS
