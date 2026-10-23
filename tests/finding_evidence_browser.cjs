/* Run shipped room code against inert DOM/HTTP doubles; never invoke a tool. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {code, payload, empty} = JSON.parse(fs.readFileSync(0, 'utf8'));
const nodes = new Map(), calls = [];
let document;
class Element {
  constructor(tag = 'div') {
    this.tag = tag; this.children = []; this.attrs = {}; this.dataset = {};
    this.listeners = {}; this.hidden = false; this.scrollTop = 0; this.scrollLeft = 0;
    this.value = ''; this._text = '';
  }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  append(...children) { for (const child of children) {child.parent = this; this.children.push(child);} }
  replaceChildren(...children) { this.children = []; this._text = ''; this.append(...children); }
  setAttribute(name, value) {
    this.attrs[name] = String(value);
    if (name === 'data-evidence-key') this.dataset.evidenceKey = String(value);
  }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  contains(node) { return node === this || this.children.some(child => child.contains(node)); }
  focus(options) { document.activeElement = this; this.focusOptions = options; }
  set innerHTML(_) { throw Error('unsafe HTML sink'); }
}
const byId = id => {
  if (!nodes.has(id)) nodes.set(id, Object.assign(new Element(), {id}));
  return nodes.get(id);
};
const textNode = (tag, text = '', className = '') => Object.assign(new Element(tag), {textContent: text, className});
document = {activeElement: null, createElement: tag => new Element(tag),
  createElementNS: (_, tag) => new Element(tag)};
byId('room-evidence-content').append(byId('room-evidence-details'));
byId('room-evidence-details').append(byId('evidence-summary'));
byId('room-evidence-content').hidden = true;
byId('room-evidence-close').hidden = true;
function response(value, status = 200, oversized = false) {
  const bytes = oversized ? new Uint8Array(262145) : new TextEncoder().encode(JSON.stringify(value));
  let sent = false;
  return {ok: status >= 200 && status < 300, status, body: {getReader: () => ({
    read: async () => sent ? {done: true} : {done: false, value: (sent = true, bytes)}, cancel: async () => {}})}};
}
const context = {document, byId, textNode, Date, BigInt, AbortSignal, TextDecoder, TextEncoder, Uint8Array,
  payload, empty, referenceExactKeys: (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
    && Object.keys(v).length === keys.length && keys.every(key => Object.hasOwn(v, key)),
  knownSeverities: new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  fetch: async (path, options) => {calls.push({path, options}); return response(payload);}};
vm.createContext(context);
vm.runInContext(code, context, {timeout: 1000});
const run = source => vm.runInContext(source, context, {timeout: 1000});
const firstButton = () => run('[...roomEvidenceState.buttons.values()][0]');
const openFirst = () => firstButton().listeners.click();
const accept = value => {context.next = value; run('acceptRoomResult({status:"fulfilled",value:next})');};
const copy = () => JSON.parse(JSON.stringify(payload));

(async () => {
  run('renderRoom()');
  assert.equal(byId('room-evidence-content').hidden, true);
  assert.match(byId('room-findings-table').textContent, /No qualified data/);
  accept(payload); openFirst();
  assert.match(byId('room-case-summary').textContent,/3 linked metadata events and 2 findings/);
  assert.match(byId('room-case-coverage').textContent,/Completeness beyond/);
  assert.equal(run('roomCaseState.address'),'192.0.2.1');
  const linkedCaseButtons=byId('room-case-timeline').children[0].children[2].children[0].children[3].children;
  linkedCaseButtons[0].listeners.click();
  assert.equal(byId('room-evidence-finding').textContent,'1');
  run('roomState.failed=true;renderRoom()');
  assert.match(byId('room-case-status').textContent,/Stale retained snapshot/);
  run('roomState.failed=false;renderRoom()');
  byId('room-case-address').value='203.0.113.99';
  byId('room-case-address').listeners.change();
  assert.match(byId('room-case-status').textContent,/selected address is absent/);
  assert.match(byId('room-case-summary').textContent,/0 linked metadata events/);
  accept(payload);
  assert.equal(run('roomCaseState.address'),'203.0.113.99','refresh must not silently switch address');
  byId('room-case-address').value='192.0.2.1';
  byId('room-case-address').listeners.change();
  assert.equal(calls.length,0,'automatic case uses admitted records without new requests');
  const finding = payload.findings[0], event = payload.events.find(row => row.id === finding.event_id);
  for (const [id, expected] of Object.entries({finding: finding.id, event: event.id, run: event.run_id,
    observed: event.observed_at, detected: finding.detected_at, generated: payload.generated_at}))
    assert.equal(byId('room-evidence-' + id).textContent, expected);
  assert.notEqual(byId('room-evidence-observed').textContent, byId('room-evidence-detected').textContent);
  assert.equal(byId('room-evidence-bytes').textContent, '9223372036854775807 reported bytes');
  assert.match(byId('room-evidence-version').textContent, /unknown; not stored/);
  assert.match(byId('room-evidence-explanation').textContent, /authorized testing/);
  assert.match(byId('room-evidence-explanation').textContent, /not proof/);
  assert.match(byId('room-evidence-age').textContent, /refreshed projection does not make/);
  assert.equal(document.activeElement, byId('room-evidence-title'));
  assert.equal(firstButton().attrs['aria-expanded'], 'true');
  assert.equal(calls.length, 0, 'selection reads already admitted data without requests');

  const originalButton = firstButton(), originalTable = byId('room-findings-table').children[0];
  const detail = byId('room-evidence-details'); detail.open = true;
  byId('evidence-summary').focus();
  byId('room-findings-table').scrollTop = 71; byId('room-findings-table').scrollLeft = 13;
  const refreshed = copy(); refreshed.generated_at = new Date(Date.now() - 1000).toISOString();
  accept(refreshed);
  assert.equal(firstButton(), originalButton);
  assert.equal(byId('room-findings-table').children[0], originalTable);
  assert.equal(document.activeElement, byId('evidence-summary'));
  assert.equal(detail.open, true);
  assert.equal(byId('room-findings-table').scrollTop, 71);
  assert.equal(byId('room-findings-table').scrollLeft, 13);
  assert.equal(byId('room-evidence-generated').textContent, refreshed.generated_at);
  assert.equal(byId('room-evidence-observed').textContent, event.observed_at);

  context.fetch = async (path, options) => {calls.push({path, options}); return response({}, 503);};
  await run('refreshRoom()');
  assert.match(byId('room-evidence-status').textContent, /Stale evidence/);
  assert.equal(byId('room-evidence-content').hidden, false);
  assert.equal(byId('room-evidence-bytes').textContent, '9223372036854775807 reported bytes');
  context.fetch = async (path, options) => {calls.push({path, options}); return response({}, 200, true);};
  await run('refreshRoom()');
  assert.match(byId('room-evidence-status').textContent, /Stale evidence/);
  const malformed = copy(); malformed.findings[0].rule_id = '<img src=x onerror=alert(1)>';
  accept(malformed);
  assert.match(byId('room-evidence-status').textContent, /Stale evidence/);
  assert.doesNotMatch(byId('room-evidence-title').textContent, /<img/);
  accept(payload);
  assert.match(byId('room-evidence-status').textContent, /^Stored evidence/);
  const expired = copy(); expired.generated_at = new Date(Date.now() - 301000).toISOString();
  accept(expired);
  assert.match(byId('room-evidence-status').textContent, /Stale evidence/);
  accept(payload);

  // Reused numeric IDs must not silently replace a reviewed source or finding.
  for (const mutate of [p => {p.events[0].run_id = '2';}, p => {p.events[0].source = 'scapy';},
    p => {p.findings[0].rule_id = 'DNS_TUNNELING';}, p => {p.events[0].src_ip = '192.0.2.9';}]) {
    accept(payload); openFirst(); const changed = copy(); mutate(changed); accept(changed);
    assert.equal(byId('room-evidence-content').hidden, true, 'changed source identity clears inspection');
    assert.equal(run('roomEvidenceState.key'), null);
  }
  accept(payload); openFirst();
  const gone = copy(); gone.findings = gone.findings.slice(1); accept(gone);
  assert.equal(byId('room-evidence-content').hidden, true);
  assert.match(byId('room-evidence-status').textContent, /absence does not establish resolution/);
  accept(payload); openFirst();
  run('roomState.range="hour";renderRoom()');
  assert.equal(byId('room-evidence-content').hidden, true);
  assert.match(byId('room-evidence-status').textContent, /time range changed/);
  run('roomState.range="recorded";renderRoom()'); openFirst();
  byId('room-evidence-close').listeners.click();
  assert.equal(document.activeElement, firstButton());
  assert.equal(byId('room-evidence-content').hidden, true);
  openFirst();
  const start = Date.parse('2026-09-17T12:00:00Z'), end = start + 60000;
  context.managed = {schema: 'megalodon-traffic-history-v2', records: [], gaps: ['Synthetic retained range.'],
    source_segments: [], candidate_count: 0, range: {start: new Date(start).toISOString(), end: new Date(end).toISOString()},
    next_cursor: null, truncated: false};
  context.fetch = async (path, options) => {calls.push({path, options}); return response(context.managed);};
  await run(`refreshRoom({history:{start:${start},end:${end},before:null,next:null,candidates:0,previous:[]},range:"custom"})`);
  assert.equal(byId('room-evidence-content').hidden, true);
  assert.match(byId('room-evidence-status').textContent, /Retained history/);
  assert.equal(run('roomEvidenceState.buttons.size'), 0);
  assert.match(byId('room-case-status').textContent,/Managed history/);
  assert.equal(byId('room-case-timeline').children.length,0);
  context.fetch = async (path, options) => {calls.push({path, options}); return response(payload);};
  await run('refreshRoom({history:null,range:"recorded"})');
  assert.equal(run('roomEvidenceState.buttons.size'), 2);
  assert.equal(byId('room-evidence-content').hidden, true, 'returning latest requires explicit reselection');
  openFirst(); accept(empty);
  assert.equal(byId('room-evidence-content').hidden, true);
  assert.match(byId('room-findings-table').textContent, /No qualified data/);
  for (const expression of ['p.events.push({...p.events[0]})', 'p.findings.push({...p.findings[0]})',
    'p.findings[0].event_id="999"', 'p.events[0].byte_count="9223372036854775808"'])
    assert.throws(() => run('{const p=JSON.parse(JSON.stringify(payload));' + expression + ';validateTraffic(p)}'));
  assert.equal(byId('room-case-timeline').children.length,0,'empty projection clears prior case');
  accept(payload);
  run(`{const selected={...roomState.selection,events:Array.from({length:101},(_,i)=>({...payload.events[0],id:String(i+1)})),findings:[]};renderRoomCase(selected,false);}`);
  assert.match(byId('room-case-coverage').textContent,/first 100 of 101/);
  assert.equal(byId('room-case-timeline').children[0].children[2].children.length,100);
  assert.ok(calls.every(call => call.options.method === 'GET' && call.path.startsWith('/api/traffic')
    && call.options.mode === 'same-origin' && call.options.redirect === 'error'));
  console.log('qualified finding lineage, identity, exact bytes, independent clocks, passive reads, stale/recovery and history transitions passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
