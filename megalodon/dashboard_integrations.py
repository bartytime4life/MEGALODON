"""Presentation for the static integration map; no tool or telemetry access."""

from .status_glossary import GLOSSARY_ANCHOR_ID
from .dashboard_action_plane import ACTION_HTML

INTEGRATIONS_HTML = """
  <section class="panel integrations-panel" aria-labelledby="integrations-title">
    <div class="panel-head">
      <div><h2 id="integrations-title" tabindex="-1">Actions &amp; apps</h2><p>Run a bounded local check, preview a routine, or review supported companion apps. Service starts require <a href="#tool-management-controls">authorization for this local HUD launch</a>.</p></div>
      <span class="timestamp" id="integrations-profile">No profile loaded</span>
    </div>
    __ACTION_PLANE__
    <p class="reference-warning" id="integrations-boundary">Green means a candidate executable was found during the bounded startup PATH check. Red means it was not found on that checked PATH. Neither proves installation method, compatibility, running health, sensor coverage, or trust.</p>
    <p class="reference-status" id="integrations-freshness">Presence: not checked yet.</p>
    <div class="app-state-legend" aria-label="App status legend">
      <span class="state-found"><i class="app-dot" aria-hidden="true"></i>Found candidate</span>
      <span class="state-missing"><i class="app-dot" aria-hidden="true"></i>Not found</span>
      <span class="state-unknown"><i class="app-dot" aria-hidden="true"></i>Not checked or unknown</span>
      <a href="#__GLOSSARY_ANCHOR__">What do all these statuses mean? →</a>
    </div>
    <div class="integration-controls">
      <label class="field" for="integrations-platform"><span>Platform guide</span>
        <select id="integrations-platform"><option value="linux">Linux</option><option value="windows">Windows evaluation</option><option value="other">Other platforms</option></select>
      </label>
      <button id="integrations-load" type="button">Load integration map</button>
      <label class="field" for="integrations-query"><span>Search tools</span>
        <input id="integrations-query" type="search" maxlength="160" autocomplete="off" placeholder="Name, data type, or capability">
      </label>
      <label class="field" for="integrations-status-filter"><span>Availability</span>
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
    <section class="app-service-start" aria-labelledby="app-service-start-title">
      <h3 id="app-service-start-title">Start installed services</h3>
      <p>These controls start only a fixed service already installed on this computer. A process observation does not prove that the app is healthy or connected to MEGALODON.</p>
      <div id="app-service-start-list" class="app-service-start-list">Reading local service observations…</div>
      <p id="app-service-start-feedback" role="status" aria-live="polite"></p>
    </section>
    <!-- APP_VIEWER -->
    <div class="integration-cards" id="integrations-cards" aria-busy="false"></div>
    <p class="integration-footnote">Commands in details are reference templates. An app's own console uses that app's permissions and may include administration controls. Viewing a console does not connect its data to MEGALODON. Desktop apps need a separately configured web viewer.</p>
  </section>
"""
if "__GLOSSARY_ANCHOR__" not in INTEGRATIONS_HTML:
    raise AssertionError("glossary anchor placeholder missing from INTEGRATIONS_HTML")
INTEGRATIONS_HTML = INTEGRATIONS_HTML.replace("__GLOSSARY_ANCHOR__", GLOSSARY_ANCHOR_ID)
INTEGRATIONS_HTML = INTEGRATIONS_HTML.replace("__ACTION_PLANE__", ACTION_HTML)

INTEGRATIONS_CSS = """
h1[id], h2[id] { scroll-margin-top: 18px; }
.integration-controls { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; padding: 18px 22px 0; }
.integration-controls .field { flex: 1 1 180px; min-width: 0; }
.integration-controls button { min-height: 44px; }
.integration-cards { display: grid; grid-template-columns: 1fr; gap: 8px; padding: 14px 22px 18px; }
.integration-card { min-width: 0; border: 1px solid var(--line); border-radius: 12px; background: rgba(3, 13, 19, .34); overflow-wrap: anywhere; }
.integration-card > summary { display: grid; grid-template-columns: minmax(170px, 1fr) minmax(0, 1.4fr); gap: 12px; align-items: center; min-height: 64px; padding: 11px 13px; cursor: pointer; list-style: none; }
.integration-card > summary::-webkit-details-marker { display: none; }
.integration-card[open] > summary { border-bottom: 1px solid var(--line); background: rgba(81, 230, 207, .04); }
.integration-identity { display: grid; gap: 3px; }
.integration-title { color: var(--text); font-size: .86rem; font-weight: 800; }
.integration-zone { margin: 0; color: var(--aqua); font-size: .62rem; font-weight: 850; letter-spacing: .09em; text-transform: uppercase; }
.integration-summary-status { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.integration-card .summary-chip { display: inline-block; border-radius: 9px; }
.integration-card-body { padding: 14px; }
.app-state-legend { display:flex; flex-wrap:wrap; gap:12px; padding:14px 22px 0; color:var(--muted); font-size:.76rem; }
.app-state-legend span { display:inline-flex; align-items:center; gap:7px; }
.app-state-legend a { color: var(--cyan); text-underline-offset: 3px; margin-left: auto; }
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
.integration-card-body details > summary { min-height: 44px; padding: 12px 0; color: var(--cyan); cursor: pointer; font-size: .8rem; font-weight: 750; }
.integration-card details dl { margin: 8px 0 0; }
.integration-footnote { margin: 0; padding: 0 22px 22px; color: var(--muted); font-size: .76rem; line-height: 1.6; }
.integration-empty { grid-column: 1 / -1; margin: 0; padding: 18px; color: var(--muted); font-size: .85rem; }
.app-service-start { margin:14px 22px 0; padding:14px; border:1px solid var(--line); border-radius:12px; background:rgba(3,13,19,.34); }
.app-service-start h3 { margin:0 0 .4rem; font-size:.95rem; }
.app-service-start > p { margin:.25rem 0 .8rem; color:var(--muted); font-size:.76rem; line-height:1.5; }
.app-service-start-list { display:grid; gap:.55rem; font-size:.8rem; }
.app-service-start-row { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:.5rem; padding:.7rem; border:1px solid var(--line); border-radius:9px; }
.app-service-start-row > div { min-width:0; overflow-wrap:anywhere; }
.app-service-start-row .hb-detail { margin-left:1.1rem; }
@media (max-width: 720px) { .integration-card > summary { grid-template-columns: 1fr; } .integration-summary-status { justify-content: flex-start; } }
@media (max-width: 560px) {
  .integration-controls, .integration-cards { padding-right: 14px; padding-left: 14px; }
  .app-service-start { margin-right:14px; margin-left:14px; }
  .integration-footnote { padding-right: 14px; padding-left: 14px; }
  .integration-controls .field, .integration-controls button { flex-basis: 100%; }
}
"""

INTEGRATIONS_JS = r"""

// The integration map is a static read model. The service controls below use
// the separate heartbeat and fixed, operator-authorized start route.
const integrationState = {snapshot: null, loading: false, pendingPlatform: null, failed: false};
const integrationPlatforms = ['linux', 'windows', 'other'];
const startableServiceIds = ['suricata', 'qwen', 'ossec', 'zabbix', 'nagios'];
const startableServiceNames = {suricata:'Suricata', qwen:'Ollama', ossec:'OSSEC', zabbix:'Zabbix', nagios:'Nagios Core'};
function appServiceStartControl(id, name, tool) {
  const action = document.createElement('div');
  const entry = heartbeatState.catalog.find(item => item.id === id);
  const job = heartbeatState.job && heartbeatState.job.tool === id && heartbeatState.job.action === 'start' ? heartbeatState.job : null;
  if (tool.service === 'running') {
    action.append(textNode('span', 'Expected process observed; no start needed.', 'hb-detail'));
  } else if (tool.service !== 'stopped') {
    action.append(textNode('span', 'Service state is unknown; start unavailable.', 'hb-detail'));
  } else if (!entry || !entry.startable) {
    action.append(textNode('span', entry && entry.start_terminal
      ? `Start separately in a terminal: ${entry.start_terminal}`
      : 'No supported service-start action was found on this computer.', 'hb-detail'));
  } else {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'hb-install';
    const mine = Boolean(job && job.state === 'running');
    const busyElsewhere = !mine && heartbeatState.job && heartbeatState.job.state === 'running';
    button.textContent = mine ? 'Starting…' : `Start ${name}`;
    button.disabled = Boolean(!heartbeatState.managementEnabled || !toolManagementToken()
      || heartbeatStale() || busyElsewhere || mine);
    button.addEventListener('click', () => startInstall(id, name, entry, 'start'));
    action.append(button);
    if (!heartbeatState.managementEnabled || !toolManagementToken()) {
      const authorize = textNode('a', heartbeatState.managementEnabled ? 'Enter launch token' : 'Enable Start in this HUD', 'hb-detail');
      authorize.href = '#tool-management-controls'; action.append(authorize);
    }
    if (busyElsewhere) action.append(textNode('span', 'Another install or service start is already running; wait for it to finish.', 'hb-detail'));
    if (job && job.state === 'failed') action.append(textNode('span', 'Service-start command failed. See the app card for details.', 'hb-detail'));
    if (job && job.state === 'succeeded') action.append(textNode('span', 'Service-start command finished. Status is checked separately.', 'hb-detail'));
  }
  return action;
}
function renderAppServiceStarts() {
  const list = byId('app-service-start-list');
  if (!list) return;
  if (heartbeatStale() || !heartbeatState.catalog) {
    list.textContent = heartbeatState.failed ? 'Local service observations are unavailable. Retry when this HUD reconnects.'
      : heartbeatStale() ? 'Local service observations are stale. Refresh before starting a service.'
      : 'Reading local service observations…';
    return;
  }
  const rows = startableServiceIds.flatMap(id => {
    const tool = heartbeatState.byId.get(id);
    if (!tool || tool.installed !== 'yes') return [];
    const row = document.createElement('div'); row.className = 'app-service-start-row';
    const identity = document.createElement('div');
    const title = textNode('strong', ''); title.append(heartbeatLight(id), textNode('span', startableServiceNames[id]));
    identity.append(title, heartbeatDetail(id));
    row.append(identity, appServiceStartControl(id, startableServiceNames[id], tool));
    return [row];
  });
  list.replaceChildren(...(rows.length ? rows : [textNode('p', 'No supported installed service was observed. Check the app cards for setup guidance.') ]));
}
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
  const basePresence = integrationPresenceStates[tool ? tool.status : 'not_checked'];
  const presence = {...basePresence, detail: `${basePresence.detail} ${appsPresenceFreshnessNote()}`};
  return {
    presence,
    qualification: {...integrationQualificationStates[item.selected_status],
      detail: integrationStatuses[item.selected_status] + '; producer qualification and native acceptance remain separate.'},
    administration: {className: 'state-unknown', label: 'Operator managed',
      detail: 'Observation is the default. An explicitly enabled Linux HUD and its operator token allow fixed Install/Start actions after confirmation. The HUD has no stop, removal, or configuration action.'},
    health: {className: 'state-unknown', label: 'See the status light',
      detail: 'The heartbeat observes installation, process uptime and service state. It does not probe endpoints, sensor liveness, data freshness, or coverage.'}
  };
}
function integrationStatusRow(name, state) {
  const row = document.createElement('div'); row.className = 'app-status-row ' + state.className;
  const dot = document.createElement('i'); dot.className = 'app-dot'; dot.setAttribute('aria-hidden', 'true');
  row.append(dot, textNode('strong', name + ': ' + state.label), textNode('small', state.detail));
  return row;
}
function integrationCard(item) {
  const card = document.createElement('details'); card.className = 'integration-card';
  const summary = document.createElement('summary');
  const identity = document.createElement('span'); identity.className = 'integration-identity';
  const title = textNode('span', '', 'integration-title'); title.append(heartbeatLight(workflowToolIds[integrationIds.indexOf(item.id)]), textNode('span', item.software));
  identity.append(textNode('span', integrationZones[item.id], 'integration-zone'), title);
  const statuses = document.createElement('span'); statuses.className = 'integration-summary-status';
  statuses.append(textNode('span', integrationStatuses[item.selected_status], 'summary-chip'));
  const toolIndex = integrationIds.indexOf(item.id);
  const toolId = workflowToolIds[toolIndex];
  statuses.append(textNode('span', toolPresenceText(toolIndex), 'summary-chip'));
  summary.append(identity, statuses); card.append(summary);
  const body = document.createElement('div'); body.className = 'integration-card-body';
  const capability = integrationCapabilityState(toolIndex, item);
  const matrix = document.createElement('section'); matrix.className = 'app-status-grid'; matrix.setAttribute('aria-label', item.software + ' capability state');
  matrix.append(integrationStatusRow('Presence', capability.presence),
                integrationStatusRow('MEGALODON support', capability.qualification),
                integrationStatusRow('Administration', capability.administration),
                integrationStatusRow('Health', capability.health));
  body.append(matrix, heartbeatDetail(toolId), installControl(toolId, item.software));
  const reviewTargets = {core: '#detections-title', tshark: '#offline-title', zeek: '#offline-title', suricata: '#suricata-title', qwen: '#analysis-window-title'};
  if (reviewTargets[toolId]) {
    const review = textNode('a', 'Review evidence →', 'companion-button'); review.href = reviewTargets[toolId]; body.append(review);
  }
  MegalodonControls.mount(body, toolId, item.software, typeof appConsole === 'undefined' ? {} : appConsole);
  body.append(textNode('p', 'View in HUD provides a place for this app. If its console blocks embedding or requires a separate sign-in window, use Open companion console.', 'app-return-note'));
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
  details.append(facts); body.append(details); card.append(body);
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
  // One shared freshness line for every Presence row below, instead of an
  // operator having to expand each card to see when it was last checked.
  byId('integrations-freshness').textContent = `Presence: ${appsPresenceFreshnessNote()}`;
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
