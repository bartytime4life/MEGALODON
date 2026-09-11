"""Presentation for the static integration map; no tool or telemetry access."""

INTEGRATIONS_HTML = """
  <section class="panel integrations-panel" aria-labelledby="integrations-title">
    <div class="panel-head">
      <div><h2 id="integrations-title" tabindex="-1">Integration Map</h2><p>Follow each documented input to its output, ownership boundary, and next acceptance gate.</p></div>
      <span class="timestamp" id="integrations-profile">No profile loaded</span>
    </div>
    <p class="reference-warning" id="integrations-boundary">Static capability map — not installed-tool detection, live connectivity, or health monitoring. Loading this map does not install, start, connect, or configure anything.</p>
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
      <button id="integrations-clear" type="button" class="button-secondary">Clear map filters</button>
    </div>
    <p class="reference-status" id="integrations-status" role="status" aria-live="polite" aria-atomic="true">Choose a documentation profile, then load the static map. No host has been inspected.</p>
    <div class="integration-cards" id="integrations-cards" aria-busy="false"></div>
    <p class="integration-footnote">Commands in details are inert reference templates, not launch controls or platform-specific installation instructions. Windows evaluation and guest-only workflows are not native Windows support. Installed-tool, resource, privacy, and independent-review gates remain separate.</p>
  </section>
"""

INTEGRATIONS_CSS = """
.section-nav { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 24px; }
.section-nav a { display: inline-flex; align-items: center; min-height: 44px; padding: 9px 14px; color: var(--text); text-decoration: none; border: 1px solid var(--line); border-radius: 11px; background: rgba(110, 216, 255, .05); }
.section-nav a:hover { text-decoration: underline; }
h1[id], h2[id] { scroll-margin-top: 18px; }
.integration-controls { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; padding: 18px 22px 0; }
.integration-controls .field { flex: 1 1 180px; min-width: 0; }
.integration-controls button { min-height: 44px; }
.integration-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; padding: 18px 22px; }
.integration-card { min-width: 0; padding: 16px; border: 1px solid var(--line); border-radius: 14px; background: rgba(3, 13, 19, .34); overflow-wrap: anywhere; }
.integration-card h3 { margin: 0 0 9px; font-size: .95rem; }
.integration-card .summary-chip { display: inline-block; border-radius: 9px; }
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
  .section-nav a { flex: 1 1 130px; }
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
  'live-metadata-capture', 'time-limited-response', 'manual-file-scan', 'endpoint-inventory'
];
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
function integrationCard(item) {
  const card = document.createElement('article'); card.className = 'integration-card';
  card.append(textNode('h3', item.software), textNode('span', integrationStatuses[item.selected_status], 'summary-chip'));
  const flow = document.createElement('dl'); flow.className = 'integration-flow';
  integrationDefinition('Input', item.input_contract, flow);
  integrationDefinition('Output', item.output_contract, flow);
  card.append(flow, textNode('p', `Next gate: ${item.next_gate}`, 'integration-gate'));
  const details = document.createElement('details');
  details.append(textNode('summary', 'Inspect contract and boundaries'));
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
    message = `${visibleCount} of ${snapshot.workflows.length} workflows shown for the loaded ${snapshot.selected_platform} documentation profile. No host has been inspected.`;
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
  const rows = snapshot ? snapshot.workflows.filter(item => {
    if (status !== 'ALL' && item.selected_status !== status) return false;
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
// No automatic fetch: this panel cannot delay the telemetry bootstrap path.
byId('integrations-load').addEventListener('click', loadIntegrationMap);
byId('integrations-query').addEventListener('input', renderIntegrationMap);
byId('integrations-status-filter').addEventListener('change', renderIntegrationMap);
byId('integrations-platform').addEventListener('change', renderIntegrationMap);
byId('integrations-clear').addEventListener('click', () => {
  byId('integrations-query').value = ''; byId('integrations-status-filter').value = 'ALL'; renderIntegrationMap();
});
"""
