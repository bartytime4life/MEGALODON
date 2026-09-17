"""Presentation for the static integration map; no tool or telemetry access."""

INTEGRATIONS_HTML = """
  <section class="panel integrations-panel" aria-labelledby="integrations-title">
    <div class="panel-head">
      <div><h2 id="integrations-title" tabindex="-1">Apps &amp; integrations</h2><p>See what was found, what MEGALODON supports, what you control, and what remains unknown. Open a saved local console in a new tab or review its evidence here.</p></div>
      <span class="timestamp" id="integrations-profile">No profile loaded</span>
    </div>
    <p class="reference-warning" id="integrations-boundary">Green means a candidate executable was found during the bounded startup PATH check. Red means it was not found on that checked PATH. Neither proves installation method, compatibility, running health, sensor coverage, or trust.</p>
    <div class="app-state-legend" aria-label="App status legend">
      <span class="state-found"><i class="app-dot" aria-hidden="true"></i>Found candidate</span>
      <span class="state-missing"><i class="app-dot" aria-hidden="true"></i>Not found</span>
      <span class="state-unknown"><i class="app-dot" aria-hidden="true"></i>Not checked or unknown</span>
    </div>
    <div class="integration-controls">
      <label class="field" for="integrations-platform"><span>Documentation profile</span>
        <select id="integrations-platform"><option value="linux">Linux</option><option value="windows">Windows evaluation</option><option value="other">Other platforms</option></select>
      </label>
      <button id="integrations-load" type="button">Load integration map</button>
      <label class="field" for="integrations-query"><span>Filter this map</span>
        <input id="integrations-query" type="search" maxlength="160" autocomplete="off" placeholder="Tool, input, output, or gate">
      </label>
      <label class="field" for="integrations-status-filter"><span>Documented availability</span>
        <select id="integrations-status-filter">
          <option value="ALL">All statuses</option><option value="implemented">Implemented</option><option value="optional">Optional</option>
          <option value="evaluation_only">Evaluation only</option><option value="contract_only">Contract only</option><option value="manual_only">Manual only</option>
          <option value="guest_only">Guest only</option><option value="proposed">Proposed</option><option value="unsupported">Unsupported</option>
        </select>
      </label>
      <label class="field" for="integrations-presence-filter"><span>Startup presence</span>
        <select id="integrations-presence-filter">
          <option value="ALL">All presence states</option><option value="found">Found candidate</option>
          <option value="missing">Not found</option><option value="unknown">Not checked or unknown</option>
        </select>
      </label>
      <button id="integrations-clear" type="button" class="button-secondary">Clear map filters</button>
    </div>
    <p class="reference-status" id="integrations-status" role="status" aria-live="polite" aria-atomic="true">Choose a documentation profile, then load the static map. No host has been inspected.</p>
    <div class="integration-cards" id="integrations-cards" aria-busy="false"></div>
    <p class="integration-footnote">Commands in details are inert reference templates, never HUD execution controls. Presence, repository support, operator administration and runtime health are separate facts. Console links open in a new tab so this local HUD remains the fixed return point. Windows evaluation and guest-only workflows are not native Windows support.</p>
  </section>
"""

INTEGRATIONS_CSS = """
h1[id], h2[id] { scroll-margin-top: 18px; }
.integration-controls { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; padding: 18px 22px 0; }
.integration-controls .field { flex: 1 1 180px; min-width: 0; }
.integration-controls button { min-height: 44px; }
.integration-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 18px 22px; }
.integration-card { min-width: 0; padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .34); overflow-wrap: anywhere; }
.integration-card h3 { margin: 0 0 9px; font-size: .95rem; }
.integration-zone { margin: 0 0 6px; color: var(--aqua); font-size: .65rem; font-weight: 850; letter-spacing: .1em; text-transform: uppercase; }
.integration-card .summary-chip { display: inline-block; border-radius: 9px; }
.app-state-legend { display:flex; flex-wrap:wrap; gap:12px; padding:14px 22px 0; color:var(--muted); font-size:.76rem; }
.app-state-legend span { display:inline-flex; align-items:center; gap:7px; }
.app-status-grid { display:grid; gap:7px; margin:13px 0; }
.app-status-row { display:grid; grid-template-columns:auto minmax(0,1fr); gap:2px 8px; align-items:start; padding:9px 10px; border:1px solid var(--line); border-radius:10px; background:rgba(110,216,255,.035); }
.app-status-row .app-dot { grid-row:1 / span 2; margin-top:.24rem; }
.app-status-row strong { font-size:.76rem; color:var(--text); }
.app-status-row small { color:var(--muted); font-size:.7rem; line-height:1.4; }
.app-dot { display:inline-block; width:10px; height:10px; flex:0 0 10px; border:2px solid currentColor; border-radius:50%; }
.state-found { color:#51e6cf; } .state-found .app-dot { background:#51e6cf; }
.state-missing { color:#ff758f; } .state-missing .app-dot { background:#ff758f; }
.state-unknown { color:#99b2ba; } .state-unknown .app-dot { background:transparent; }
.state-supported { color:#6ed8ff; } .state-supported .app-dot { background:#6ed8ff; }
.app-return-note { color:var(--muted); font-size:.72rem; line-height:1.45; }
.integration-flow { display: grid; gap: 6px; margin: 14px 0; }
.integration-card dt { color: var(--muted); font-size: .7rem; font-weight: 800; letter-spacing: .04em; }
.integration-card dd { margin: 0 0 8px; font-size: .8rem; line-height: 1.5; }
.integration-gate { padding: 10px; border-left: 3px solid var(--amber); background: rgba(255, 209, 102, .045); font-size: .78rem; line-height: 1.5; }
.integration-card summary { min-height: 44px; padding: 12px 0; color: var(--cyan); cursor: pointer; font-size: .8rem; font-weight: 750; }
.integration-card details dl { margin: 8px 0 0; }
.integration-footnote { margin: 0; padding: 0 22px 22px; color: var(--muted); font-size: .76rem; line-height: 1.6; }
.integration-empty { grid-column: 1 / -1; margin: 0; padding: 18px; color: var(--muted); font-size: .85rem; }
@media (max-width: 720px) { .integration-cards { grid-template-columns: 1fr; } }
@media (max-width: 560px) {
  .integration-controls, .integration-cards { padding-right: 14px; padding-left: 14px; }
  .integration-footnote { padding-right: 14px; padding-left: 14px; }
  .integration-controls .field, .integration-controls button { flex-basis: 100%; }
}
"""

INTEGRATIONS_JS = r"""

// Static plans are a separate read model. They do not participate in telemetry
// polling, reference lookup, persistence, execution, or connection health.
const integrationState = {snapshot: null, loading: false, pendingPlatform: null, failed: false};
const integrationPlatforms = ['linux', 'windows', 'other'];
const integrationStatuses = {
  implemented: 'Implemented', optional: 'Optional', evaluation_only: 'Evaluation only — unverified',
  contract_only: 'Contract only — no importer', manual_only: 'Separate manual tool',
  guest_only: 'Guest only — not native', proposed: 'Proposed — not implemented', unsupported: 'Unsupported'
};
const integrationIds = [
  'core-metadata', 'offline-packet-metadata', 'offline-flow-metadata', 'alert-metadata',
  'live-metadata-capture', 'time-limited-response', 'manual-file-scan', 'endpoint-inventory',
  'local-ai-advisory', 'network-inventory-import', 'host-integrity-import',
  'vulnerability-report-import', 'zabbix-availability-read', 'nagios-availability-read'
];
const integrationPresenceStates = {
  executable_found: {filter: 'found', className: 'state-found', label: 'Installed candidate found', detail: 'Executable found on the bounded startup PATH; installation method and compatibility remain unverified.'},
  not_found: {filter: 'missing', className: 'state-missing', label: 'Not found on checked PATH', detail: 'The executable was absent from the checked Linux PATH; it may exist elsewhere.'},
  not_checked: {filter: 'unknown', className: 'state-unknown', label: 'Presence not checked', detail: 'This app was not eligible for the executable-only startup check.'}
};
const integrationQualificationStates = {
  implemented: {className: 'state-supported', label: 'Implemented integration path'},
  optional: {className: 'state-unknown', label: 'Optional integration path'},
  evaluation_only: {className: 'state-unknown', label: 'Evaluation-only path'},
  contract_only: {className: 'state-missing', label: 'Contract only; importer absent'},
  manual_only: {className: 'state-unknown', label: 'Manual companion only'},
  guest_only: {className: 'state-unknown', label: 'Guest-only path'},
  proposed: {className: 'state-missing', label: 'Proposed; not implemented'},
  unsupported: {className: 'state-missing', label: 'Unsupported'}
};
const integrationZones = {
  'core-metadata': 'Core telemetry', 'offline-packet-metadata': 'Packet data',
  'offline-flow-metadata': 'Flow data', 'alert-metadata': 'Detection data',
  'live-metadata-capture': 'Capture source', 'time-limited-response': 'Response review',
  'manual-file-scan': 'Endpoint data', 'endpoint-inventory': 'Endpoint data',
  'local-ai-advisory': 'Advisory context', 'network-inventory-import': 'Discovery data',
  'host-integrity-import': 'Endpoint data', 'vulnerability-report-import': 'Vulnerability data',
  'zabbix-availability-read': 'Availability data', 'nagios-availability-read': 'Availability data'
};
const integrationFields = [
  'id', 'component', 'software', 'selected_status', 'source_kind', 'integration_owner',
  'input_contract', 'output_contract', 'entry_point', 'launch_policy', 'data_boundary',
  'action_boundary', 'next_gate'
];
const integrationEnvelopeFields = [
  'schema', 'capability_schema', 'selected_platform', 'hub_mode', 'default_posture',
  'execution_performed', 'network_access_performed', 'host_change_performed', 'action_status', 'workflows'
];
function integrationExactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every(key => Object.prototype.hasOwnProperty.call(value, key));
}
function validatedIntegrationMap(value, expectedPlatform) {
  if (!integrationPlatforms.includes(expectedPlatform)
      || !integrationExactKeys(value, integrationEnvelopeFields)
      || value.schema !== 'megalodon-integration-hub-v1'
      || value.capability_schema !== 'megalodon-capability-catalog-v1'
      || value.selected_platform !== expectedPlatform || value.hub_mode !== 'static_plan_only'
      || value.default_posture !== 'observe_only' || value.action_status !== 'not_attempted'
      || value.execution_performed !== false || value.network_access_performed !== false
      || value.host_change_performed !== false || !Array.isArray(value.workflows)
      || value.workflows.length !== integrationIds.length) throw new Error('invalid integration map');
  const seen = new Set();
  value.workflows.forEach(item => {
    if (!integrationExactKeys(item, integrationFields) || !integrationIds.includes(item.id)
        || !Object.prototype.hasOwnProperty.call(integrationZones, item.id)
        || seen.has(item.id) || !Object.prototype.hasOwnProperty.call(integrationStatuses, item.selected_status)) {
      throw new Error('invalid integration workflow');
    }
    integrationFields.forEach(field => {
      if (field === 'entry_point' && item[field] === null) return;
      if (typeof item[field] !== 'string' || item[field].length < 1 || item[field].length > 512) {
        throw new Error('invalid integration field');
      }
    });
    seen.add(item.id);
  });
  return value;
}
function integrationDefinition(label, value, parent) {
  parent.append(textNode('dt', label), textNode('dd', value));
}
function integrationCapabilityState(toolIndex, item) {
  const tool = setupState.readiness && setupState.readiness.tools[toolIndex];
  const presence = integrationPresenceStates[tool ? tool.status : 'not_checked'];
  return {
    presence,
    qualification: {...integrationQualificationStates[item.selected_status],
      detail: integrationStatuses[item.selected_status] + '; producer qualification and native acceptance remain separate.'},
    administration: {className: 'state-unknown', label: 'Operator managed',
      detail: 'The HUD cannot install, start, stop, remove, configure, or update this app.'},
    health: {className: 'state-unknown', label: 'Runtime health unknown',
      detail: 'No service, endpoint, sensor-liveness, data-freshness, or coverage probe was performed.'}
  };
}
function integrationStatusRow(name, state) {
  const row = document.createElement('div'); row.className = 'app-status-row ' + state.className;
  const dot = document.createElement('i'); dot.className = 'app-dot'; dot.setAttribute('aria-hidden', 'true');
  row.append(dot, textNode('strong', name + ': ' + state.label), textNode('small', state.detail));
  return row;
}
function integrationCard(item) {
  const card = document.createElement('article'); card.className = 'integration-card';
  card.append(
    textNode('p', integrationZones[item.id], 'integration-zone'),
    textNode('h3', item.software),
    textNode('span', integrationStatuses[item.selected_status], 'summary-chip')
  );
  const toolIndex = integrationIds.indexOf(item.id);
  const toolId = workflowToolIds[toolIndex];
  const capability = integrationCapabilityState(toolIndex, item);
  const matrix = document.createElement('section'); matrix.className = 'app-status-grid'; matrix.setAttribute('aria-label', item.software + ' capability state');
  matrix.append(integrationStatusRow('Presence', capability.presence),
                integrationStatusRow('MEGALODON support', capability.qualification),
                integrationStatusRow('Administration', capability.administration),
                integrationStatusRow('Health', capability.health));
  card.append(matrix);
  const reviewTargets = {core: '#detections-title', tshark: '#offline-title', zeek: '#offline-title', suricata: '#suricata-title', qwen: '#analysis-window-title'};
  if (reviewTargets[toolId]) {
    const review = textNode('a', 'Review evidence →', 'companion-button'); review.href = reviewTargets[toolId]; card.append(review);
  }
  MegalodonControls.mount(card, toolId, item.software);
  card.append(textNode('p', 'Open companion consoles in a new tab; return to this HUD tab for MEGALODON navigation.', 'app-return-note'));
  const flow = document.createElement('dl'); flow.className = 'integration-flow';
  integrationDefinition('Input', item.input_contract, flow);
  integrationDefinition('Output', item.output_contract, flow);
  const details = document.createElement('details');
  details.append(textNode('summary', 'Data connection details'), flow, textNode('p', `Next gate: ${item.next_gate}`, 'integration-gate'));
  const facts = document.createElement('dl');
  [
    ['Workflow', item.id], ['Source kind', item.source_kind], ['Integration owner', item.integration_owner],
    ['Launch policy', item.launch_policy], ['Data boundary', item.data_boundary], ['Action boundary', item.action_boundary],
    ['Inert command template (not a launch control)', item.entry_point === null ? 'No MEGALODON runtime entry point' : item.entry_point]
  ].forEach(([label, value]) => integrationDefinition(label, value, facts));
  details.append(facts); card.append(details);
  return card;
}
function integrationViewStatus(visibleCount) {
  const snapshot = integrationState.snapshot;
  let message;
  if (!snapshot) {
    message = integrationState.failed
      ? 'Integration map unavailable. No partial map was applied. Retry loading the selected profile.'
      : 'No successful integration map is available. Choose a profile and load the static map.';
  } else {
    const chosen = byId('integrations-platform').value;
    message = `${visibleCount} of ${snapshot.workflows.length} workflows shown for the loaded ${snapshot.selected_platform} documentation profile. This map request does not inspect the host.`;
    if (chosen !== snapshot.selected_platform) message += ` Selected profile ${integrationPlatforms.includes(chosen) ? chosen : 'invalid'} is not loaded; the previous profile remains visible.`;
    if (integrationState.failed) message = 'Load failed. Preserved map is stale. ' + message;
  }
  // Local filters must not erase request state or relabel the dispatched profile.
  if (integrationState.loading) message = `Loading the static ${integrationState.pendingPlatform} documentation profile. No tool is being connected. ` + message;
  return message;
}
function renderIntegrationMap() {
  const snapshot = integrationState.snapshot;
  const query = byId('integrations-query').value.slice(0, 160).trim().toLowerCase();
  const status = byId('integrations-status-filter').value;
  const presence = byId('integrations-presence-filter').value || 'ALL';
  const rows = snapshot ? snapshot.workflows.filter(item => {
    if (status !== 'ALL' && item.selected_status !== status) return false;
    const toolIndex = integrationIds.indexOf(item.id);
    if (presence !== 'ALL' && integrationCapabilityState(toolIndex, item).presence.filter !== presence) return false;
    return !query || integrationFields.some(field => typeof item[field] === 'string' && item[field].toLowerCase().includes(query));
  }) : [];
  const cards = rows.map(integrationCard);
  if (!cards.length) cards.push(textNode('p', snapshot ? 'No documented workflows match these map filters.' : 'No integration map has been loaded.', 'integration-empty'));
  byId('integrations-cards').replaceChildren(...cards);
  byId('integrations-profile').textContent = snapshot ? `Loaded profile: ${snapshot.selected_platform} · static only` : 'No profile loaded';
  byId('integrations-status').textContent = integrationViewStatus(rows.length);
}
async function loadIntegrationMap() {
  if (integrationState.loading) return;
  const platform = byId('integrations-platform').value;
  if (!integrationPlatforms.includes(platform)) {
    byId('integrations-status').textContent = 'Choose one supported documentation profile. No request was made.'; return;
  }
  integrationState.loading = true;
  integrationState.pendingPlatform = platform;
  byId('integrations-load').disabled = true;
  byId('integrations-platform').disabled = true;
  byId('integrations-cards').setAttribute('aria-busy', 'true');
  byId('integrations-status').textContent = `Loading the static ${platform} documentation profile. No tool is being connected.`;
  try {
    const snapshot = validatedIntegrationMap(await requestJSON(`/api/integrations?platform=${platform}`), platform);
    integrationState.snapshot = snapshot;
    integrationState.failed = false;
  } catch (_) {
    integrationState.failed = true;
  } finally {
    integrationState.loading = false;
    integrationState.pendingPlatform = null;
    byId('integrations-load').disabled = false;
    byId('integrations-platform').disabled = false;
    byId('integrations-cards').setAttribute('aria-busy', 'false');
    renderIntegrationMap();
  }
}
// First entry may fetch the same-origin static read model; page bootstrap and
// telemetry polling never wait for this panel, and failures require manual retry.
function maybeLoadIntegrationMap() {
  if (!integrationState.snapshot && !integrationState.loading && !integrationState.failed) loadIntegrationMap();
}
byId('integrations-load').addEventListener('click', loadIntegrationMap);
byId('integrations-query').addEventListener('input', renderIntegrationMap);
byId('integrations-status-filter').addEventListener('change', renderIntegrationMap);
byId('integrations-presence-filter').addEventListener('change', renderIntegrationMap);
byId('integrations-platform').addEventListener('change', renderIntegrationMap);
byId('integrations-clear').addEventListener('click', () => {
  byId('integrations-query').value = ''; byId('integrations-status-filter').value = 'ALL';
  byId('integrations-presence-filter').value = 'ALL'; renderIntegrationMap();
});
"""
