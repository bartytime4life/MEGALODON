"""Presentation-only Reference Library validation and provenance helpers.

No files, sensors, services, storage, or network are touched by importing this
module. Its JavaScript is included in the existing same-origin dashboard asset.
Browser checks bind API claims; they do not independently verify bundle bytes.
"""

REFERENCE_CONTRACT_JS = r"""
const referenceExpectedSources = {
  port: 'iana-service-names-port-numbers',
  protocol: 'iana-protocol-numbers'
};
function referenceReject() {
  const error = new Error('invalid reference response');
  error.referenceInvalid = true;
  throw error;
}
function referenceBoundary(value) {
  if (!value || value.network_access_performed !== false
      || value.persistence_status !== 'not_attempted'
      || value.action_status !== 'not_attempted') referenceReject();
}
function referenceBundleContract(value) {
  referenceBoundary(value);
  if (typeof value.manifest_sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(value.manifest_sha256)
      || value.bundle_version !== 'v1') referenceReject();
}
function referenceSourceContract(sources, expectedIds) {
  validatedReferenceSources(sources);
  if (sources.length !== expectedIds.length) referenceReject();
  const ids = sources.map(source => source.id);
  if (new Set(ids).size !== ids.length
      || !expectedIds.every(id => ids.includes(id))) referenceReject();
}
function referenceReadyContract(value) {
  referenceBundleContract(value);
  referenceSourceContract(value.sources, Object.values(referenceExpectedSources));
  if (value.service_records > 20000 || value.protocol_records > 512
      || value.cache_limit !== 16) referenceReject();
}
function referenceQueryContract(kind, query) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) referenceReject();
  if (kind === 'port') {
    if (!referenceExactKeys(query, ['transport', 'port'])
        || !['tcp', 'udp', 'sctp', 'dccp'].includes(query.transport)
        || !Number.isSafeInteger(query.port) || query.port < 0 || query.port > 65535) referenceReject();
  } else if (kind === 'protocol') {
    if (!referenceExactKeys(query, ['number']) || !Number.isSafeInteger(query.number)
        || query.number < 0 || query.number > 255) referenceReject();
  } else referenceReject();
}
function referenceSameBundle(left, right) {
  return Boolean(left && right && ['bundle_id', 'bundle_version', 'manifest_sha256']
    .every(key => left[key] === right[key]));
}
function referenceLookupContract(value, expectedKind = null, expectedQuery = null, expectedBundle = null) {
  referenceBundleContract(value);
  referenceQueryContract(value.kind, value.query);
  referenceSourceContract(value.sources, [referenceExpectedSources[value.kind]]);
  const expectedStatus = value.match_count === 0 ? 'no_match'
    : value.match_count === 1 ? 'one_match' : 'multiple_matches';
  if (value.status !== expectedStatus
      || value.matches.length !== Math.min(value.match_count, 8)
      || value.truncated !== (value.match_count > 8)) referenceReject();
  if (expectedKind !== null) {
    referenceQueryContract(expectedKind, expectedQuery);
    if (value.kind !== expectedKind
        || !Object.keys(expectedQuery).every(key => value.query[key] === expectedQuery[key])) referenceReject();
  }
  if (expectedBundle !== null) {
    if (!referenceSameBundle(value, expectedBundle) || value.warning !== expectedBundle.warning) referenceReject();
    const source = value.sources[0];
    const expectedSource = expectedBundle.sources.find(item => item.id === source.id);
    if (!expectedSource || !referenceSourceFields.every(key => source[key] === expectedSource[key])) referenceReject();
  }
  const fields = value.kind === 'port' ? referencePortFields : referenceProtocolFields;
  const numericFields = value.kind === 'port' ? ['port_start', 'port_end', 'source_row']
    : ['decimal_start', 'decimal_end', 'source_row'];
  value.matches.forEach(match => {
    fields.forEach(field => {
      if (numericFields.includes(field)) {
        if (!Number.isSafeInteger(match[field]) || match[field] < (field === 'source_row' ? 1 : 0)) referenceReject();
      } else if (match[field] !== null && typeof match[field] !== 'string') referenceReject();
    });
    const start = value.kind === 'port' ? match.port_start : match.decimal_start;
    const end = value.kind === 'port' ? match.port_end : match.decimal_end;
    const query = value.kind === 'port' ? value.query.port : value.query.number;
    if (start > end || end > (value.kind === 'port' ? 65535 : 255)
        || query < start || query > end
        || (value.kind === 'port' && match.transport !== value.query.transport)) referenceReject();
  });
}
function referenceFailureEnvelope(error) {
  if (!error || error.status !== 503 || !error.payload) return null;
  try {
    const payload = validatedReferenceStatus(error.payload);
    return payload.available === false ? payload : null;
  } catch (_) { return null; }
}
function referenceQueryLabel(kind, query) {
  return kind === 'port' ? `${query.transport}/${query.port}` : `IP protocol ${query.number}`;
}
function clearReferenceResult(message = 'Enter a value to inspect registration context.') {
  referenceState.lastResult = null;
  referenceState.lastQuery = null;
  byId('reference-meta').replaceChildren();
  byId('reference-meta').hidden = true;
  byId('reference-results').replaceChildren();
  byId('reference-results').hidden = true;
  byId('reference-empty').textContent = message;
  byId('reference-empty').hidden = false;
}
function syncReferenceControls() {
  const busy = referenceState.loading || referenceState.statusLoading;
  setReferenceFormsEnabled(referenceState.available === true && !busy);
  byId('reference-retry').disabled = busy;
  byId('reference-retry').textContent = referenceState.statusLoading ? 'Checking snapshot…' : 'Recheck local snapshot';
  byId('reference-clear').disabled = busy || !referenceState.lastResult;
  byId('reference-panel').setAttribute('aria-busy', String(busy));
}
function renderReferenceProvenance(payload) {
  const target = byId('reference-provenance');
  target.replaceChildren();
  if (!payload) { target.hidden = true; return; }
  const definition = document.createElement('dl');
  definition.className = 'reference-provenance-facts';
  const add = (name, value) => definition.append(textNode('dt', name), textNode('dd', value));
  add('Bundle', `${payload.bundle_id} · ${payload.bundle_version}`);
  add('Manifest SHA-256 (reported by local API)', payload.manifest_sha256);
  add('Verification scope', 'Browser validates response consistency. The server validates bundled bytes. No live IANA check is performed.');
  payload.sources.forEach(source => {
    add('Registry', source.id);
    add('Registry URL (text only; not contacted)', source.registry_url);
    add('Registry last updated', source.registry_last_updated);
    add('Retrieval time recorded in manifest', source.retrieved_at);
    add('Retrieval time basis', source.retrieved_at_basis);
  });
  add('Interpretation', payload.warning);
  target.append(definition);
  target.hidden = false;
}
function referenceInputChanged() {
  if (!referenceState.lastResult || referenceState.loading || referenceState.statusLoading) return;
  const result = referenceState.lastResult;
  setReferenceStatus(`Inputs edited. Displayed context is still for ${referenceQueryLabel(result.kind, result.query)}; submit a lookup to change it.`, 'stale');
}
"""

REFERENCE_CONTRACT_CSS = """
.reference-actions { display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 22px 0; }
.reference-provenance { margin: 16px 22px 22px; border-top: 1px solid var(--line); padding-top: 14px; }
.reference-provenance summary { cursor: pointer; color: var(--text); font-size: .82rem; font-weight: 750; }
.reference-provenance-facts { display: grid; grid-template-columns: minmax(140px, .35fr) minmax(0, 1fr); gap: 10px 16px; }
.reference-provenance-facts dt { color: var(--muted); font-size: .73rem; }
.reference-provenance-facts dd { margin: 0; overflow-wrap: anywhere; font-size: .76rem; line-height: 1.55; }
.reference-status.invalid_response { color: var(--amber); }
@media (max-width: 560px) {
  .reference-actions, .reference-provenance { margin-right: 14px; margin-left: 14px; }
  .reference-provenance-facts { grid-template-columns: 1fr; gap: 5px; }
  .reference-provenance-facts dd { margin-bottom: 10px; }
}
"""
