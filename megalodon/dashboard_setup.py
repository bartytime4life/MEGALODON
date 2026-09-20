"""First-launch presentation and bounded startup receipt rendering."""

SETUP_HTML = """
  <section class="hud-start" aria-labelledby="setup-title">
    <div class="setup-overview">
      <p class="eyebrow">On this computer</p>
      <h2 id="setup-title" tabindex="-1">Data and tools</h2>
      <ol class="setup-journey" aria-label="Local PC setup path">
        <li><strong>1. Prepare</strong><span>Use Python 3.11 or newer. Linux is the reference platform; companion tools are optional.</span></li>
        <li><strong>2. Launch</strong><span>Open the HUD manually. Keep its terminal open; stop it with Ctrl+C when finished.</span></li>
        <li><strong>3. Review</strong><span>Check the source and tools below. Traffic and Findings need qualified saved metadata.</span></li>
      </ol>
      <p id="setup-source" role="status">Checking the selected data source…</p>
      <div class="setup-status-grid" aria-label="Startup status summary">
        <div><span>Tools available</span><b id="setup-installed-count">Checking</b></div>
        <div><span>Processes at launch</span><b id="setup-running-count">Checking</b></div>
      </div>
      <p id="setup-readiness" role="status">Checking for startup tool information…</p>
      <details class="tool-status-details"><summary>Which tools were found?</summary>
        <p class="setup-boundary">Available means an executable was found. Processes at launch means a matching process name was seen when the HUD started. Neither result proves that a tool is healthy or connected.</p>
        <div id="setup-tool-status" class="tool-status-list"></div>
      </details>
    </div>
    <details class="setup-launch-help">
      <summary>Manual launch and environment checks</summary>
      <p>From the repository root, check this checkout, then launch:</p>
      <code>./scripts/start-local.sh --check</code>
      <code>./scripts/start-local.sh</code>
      <p>The launcher uses an available compatible Python environment. It does not install packages, start sensors, or create sample data. For an installed package, activate its environment and run <code>python -m megalodon hud</code></p>
      <p>See the <a href="https://github.com/bartytime4life/MEGALODON/blob/main/docs/platform-baseline.md" target="_blank" rel="noopener noreferrer">platform setup guide</a> for environment preparation. This checkout also includes <code>docs/local-pc-setup.md</code> for manual launch and troubleshooting.</p>
    </details>
    <details class="setup-actions-card">
      <summary>Change data for the next launch</summary>
      <div class="setup-form">
        <p>Optional. Leave every field empty to use the default audit store. This creates a command; it does not open or change any file.</p>
        <label class="field">Settings file<input id="setup-config" placeholder="/absolute/private/settings.toml" maxlength="512"></label>
        <label class="field">Completed offline run<input id="setup-offline" placeholder="/absolute/private/completed-run" maxlength="512"></label>
        <label class="field">Suricata store<input id="setup-suricata" placeholder="/absolute/private/suricata.db" maxlength="512"></label>
        <button id="setup-build" type="button">Prepare launch command</button>
        <code id="setup-command">python -m megalodon hud</code>
        <button id="setup-copy" type="button">Copy launch command</button>
        <p id="setup-feedback" role="status">No files are selected or opened by this form.</p>
      </div>
    </details>
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
  const readiness = setupState.readiness;
  const runtime = setupState.runtime;
  const names = {
    'python-sqlite': 'MEGALODON core', 'wireshark-tshark': 'Wireshark / TShark', zeek: 'Zeek', suricata: 'Suricata',
    scapy: 'Scapy', nftables: 'nftables', clamav: 'ClamAV', osquery: 'osquery', 'qwen-ollama': 'Qwen / Ollama',
    nmap: 'Nmap', ossec: 'OSSEC', greenbone: 'Greenbone', zabbix: 'Zabbix', 'nagios-core': 'Nagios Core'
  };
  const installedCount = readiness ? readiness.tools.filter(tool => tool.status === 'executable_found').length : null;
  const runningCount = runtime ? runtime.tools.filter(tool => tool.status === 'running').length : null;
  byId('setup-installed-count').textContent = installedCount === null ? 'Not checked' : `${installedCount} found`;
  byId('setup-running-count').textContent = runningCount === null ? 'Not checked' : `${runningCount} observed`;
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
      : 'No local data file is available yet. Tool checks still work, but traffic and alert counts do not.';
    byId('setup-readiness').textContent = report
      ? `Tool checks ran ${formatRefreshTime(new Date(report.checked_at))}. Restart the HUD to check again.`
      : 'Run the HUD command to check which tools are available and running.';
    renderToolStatus();
    if (typeof integrationState !== 'undefined' && integrationState.snapshot) renderIntegrationMap();
  } catch (_) {
    setupState.sourceStatus = null;
    setupState.readiness = null;
    setupState.runtime = null;
    byId('setup-source').textContent = 'Setup information unavailable. Existing telemetry controls remain independent.';
    byId('setup-readiness').textContent = 'No tool-presence claim is available. Restart with python -m megalodon hud to check at launch.';
    renderToolStatus();
  }
}
function hudLaunchCommand(values) {
  let command = 'python -m megalodon hud';
  [['config', '--config'], ['offline', '--offline-run'], ['suricata', '--suricata-db']].forEach(([key, flag]) => {
    const value = values[key];
    if (!value) return;
    if (typeof value !== 'string' || value.length > 512 || !value.startsWith('/') || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Use absolute Linux paths without control characters.');
    command += ` ${flag} '${value.replace(/'/g, "'\"'\"'")}'`;
  });
  return command;
}
byId('setup-build').addEventListener('click', () => {
  try {
    byId('setup-command').textContent = hudLaunchCommand({config: byId('setup-config').value, offline: byId('setup-offline').value, suricata: byId('setup-suricata').value});
    byId('setup-copy').disabled = false;
    byId('setup-feedback').textContent = 'Command prepared. Stop this HUD with Ctrl+C, then run the command from your MEGALODON environment.';
  } catch (error) { byId('setup-copy').disabled = true; byId('setup-feedback').textContent = error.message; }
});
['setup-config', 'setup-offline', 'setup-suricata'].forEach(id => byId(id).addEventListener('input', () => {
  byId('setup-copy').disabled = true; byId('setup-feedback').textContent = 'Choose Prepare launch command to apply these changes.';
}));
byId('setup-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(byId('setup-command').textContent); byId('setup-feedback').textContent = 'Launch command copied.'; }
  catch (_) { byId('setup-feedback').textContent = 'Select and copy the displayed command; clipboard unavailable.'; }
});
"""
