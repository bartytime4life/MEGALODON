"""First-launch presentation and bounded startup receipt rendering."""

SETUP_HTML = """
  <section class="hud-start" aria-labelledby="setup-title">
    <div>
      <h2 id="setup-title">Your local control desk</h2>
      <p id="setup-source" role="status">Checking the selected data source…</p>
      <div class="start-actions">
        <a href="#integrations-title" class="start-link">Tools &amp; consoles</a>
        <a href="#offline-title">Review a saved capture</a>
        <a href="#suricata-title">Suricata alerts</a>
      </div>
    </div>
    <div>
      <p id="setup-readiness" role="status">Checking for startup tool information…</p>
      <details><summary>Choose existing data for the next launch</summary>
        <p>Optional. Leave fields empty to use the default audit store. Paths stay in this page; the command reads selected files at startup.</p>
        <label class="field">Settings file<input id="setup-config" placeholder="/absolute/private/settings.toml" maxlength="512"></label>
        <label class="field">Completed offline run<input id="setup-offline" placeholder="/absolute/private/completed-run" maxlength="512"></label>
        <label class="field">Suricata store<input id="setup-suricata" placeholder="/absolute/private/suricata.db" maxlength="512"></label>
        <button id="setup-build" type="button">Prepare launch command</button>
        <code id="setup-command">python -m megalodon hud</code>
        <button id="setup-copy" type="button">Copy launch command</button>
        <p id="setup-feedback" role="status">No files are selected or opened by this form.</p>
      </details>
    </div>
  </section>
"""

SETUP_JS = r"""
const setupState = {readiness: null};
const workflowToolIds = ['core', 'tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen', 'nmap', 'ossec', 'greenbone', 'zabbix', 'nagios'];
function toolPresenceText(index) {
  const report = setupState.readiness;
  if (!report) return 'Tool presence not checked';
  const labels = {executable_found: 'Executable found at launch', not_found: 'Not found on checked PATH', not_checked: 'Not checked by executable discovery'};
  return labels[report.tools[index].status];
}
async function loadSetup() {
  try {
    const value = await requestJSON('/api/setup');
    if (!referenceExactKeys(value, ['schema', 'source_status', 'readiness']) || value.schema !== 'dashboard-setup-v1'
        || !['connected', 'not_configured'].includes(value.source_status)) throw new Error('Invalid setup receipt');
    const report = value.readiness === null ? null : validateReadinessReport(JSON.stringify(value.readiness));
    setupState.readiness = report;
    byId('setup-source').textContent = value.source_status === 'connected'
      ? 'Your selected audit store is open. Stored events refresh here automatically; capture and companion services run separately.'
      : 'HUD ready. No audit store exists at the selected path yet. Tools and reference lookup work now; network measurements remain unavailable. After importing real data, restart this HUD.';
    byId('setup-readiness').textContent = report
      ? `${report.tools.filter(tool => tool.status === 'executable_found').length} of 12 executable checks found a tool at launch. Python/SQLite and Scapy are not checked. Snapshot: ${report.checked_at}. Presence is not running state; restart the HUD to recheck.`
      : 'For tool presence without importing a report, start with: python -m megalodon hud. The dashboard command keeps host checks off.';
    if (typeof integrationState !== 'undefined' && integrationState.snapshot) renderIntegrationMap();
  } catch (_) {
    byId('setup-source').textContent = 'Setup information unavailable. Existing telemetry controls remain independent.';
    byId('setup-readiness').textContent = 'No tool-presence claim is available. Restart with python -m megalodon hud to check at launch.';
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
