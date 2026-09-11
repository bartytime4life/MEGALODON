'use strict';
// Executes source-derived Reference Library functions against a synthetic DOM.
// No HTTP server, real telemetry, sensors, filesystem application state, or DNS.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {test} = require('node:test');
const asset = process.env.MEGALODON_TEST_ASSET;
if (!asset) throw new Error('MEGALODON_TEST_ASSET must identify the test asset');
const code = fs.readFileSync(asset, 'utf8');
const baseline = process.env.MEGALODON_TEST_BASELINE === '1';
const originalFunctions = ['byId', 'textNode', 'formatNumber', 'requestJSON',
  'referenceExactKeys', 'validatedReferenceSources', 'validatedReferenceStatus', 'validatedReferenceResult',
  'setReferenceStatus', 'setReferenceFormsEnabled', 'referenceChip', 'renderReferenceMeta',
  'renderReferenceResult', 'renderReferenceUnavailable', 'loadReferenceStatus',
  'decimalReferenceInput', 'lookupReference'];
const addedFunctions = ['referenceReject', 'referenceBoundary', 'referenceBundleContract',
  'referenceSourceContract', 'referenceReadyContract', 'referenceQueryContract',
  'referenceSameBundle', 'referenceLookupContract', 'referenceFailureEnvelope',
  'referenceQueryLabel', 'clearReferenceResult', 'syncReferenceControls',
  'renderReferenceProvenance', 'referenceInputChanged'];
function extractFunction(name) {
  const start = new RegExp(`^(?:async )?function ${name}\\(`, 'm').exec(code);
  if (!start) throw new Error(`Required source function is missing: ${name}`);
  const rest = code.slice(start.index);
  const lineEnd = rest.indexOf('\n');
  // Three existing one-line helpers have both braces on the same line.
  if (rest.slice(0, lineEnd).endsWith('}')) return rest.slice(0, lineEnd);
  const end = rest.indexOf('\n}');
  if (end < 0) throw new Error(`Function boundary missing: ${name}`);
  return rest.slice(0, end + 2);
}
function extractConst(name) {
  const match = code.match(new RegExp(`^const ${name} = [\\s\\S]*?;`, 'm'));
  if (!match) throw new Error(`Required source constant is missing: ${name}`);
  return match[0];
}
const names = originalFunctions.concat(baseline ? [] : addedFunctions);
const seam = ['referenceState', 'referenceSourceFields', 'referencePortFields', 'referenceProtocolFields']
  .concat(baseline ? [] : ['referenceExpectedSources']).map(extractConst).join('\n')
  + '\n' + names.map(extractFunction).join('\n');
class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {};
    this.listeners = {}; this.value = ''; this.disabled = false; this.hidden = false;
    this.className = ''; this._text = '';
  }
  set innerHTML(_) { throw new Error('HTML injection sink used'); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(' '); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this._text = ''; this.children = [...nodes]; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  getAttribute(key) { return this.attributes[key]; }
  addEventListener(event, callback) { (this.listeners[event] ||= []).push(callback); }
  fire(event) { for (const listener of this.listeners[event] || []) listener({preventDefault() {}}); }
}
function runtime() {
  const elements = new Map(), requests = [], queue = [], timers = new Map();
  let timerId = 0;
  const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  ['reference-port-form', 'reference-protocol-form'].forEach(id => get(id).append(new Element('button')));
  get('reference-port').value = '443'; get('reference-transport').value = 'tcp'; get('reference-protocol').value = '6';
  const context = vm.createContext({Intl, AbortController, console,
    document: {getElementById: get, createElement: tag => new Element(tag)},
    window: {setTimeout(fn, delay) { const id = ++timerId; timers.set(id, {fn, delay}); return id; },
      clearTimeout(id) { timers.delete(id); }},
    async fetch(path, options) {
      requests.push({path, options});
      if (!queue.length) throw new Error('Unplanned test request');
      const next = queue.shift();
      if (typeof next === 'function') return await next(path, options);
      if (next instanceof Error) throw next;
      return {ok: next.status >= 200 && next.status < 300, status: next.status, async json() {
        if (next.jsonError) throw next.jsonError;
        return structuredClone(next.payload);
      }};
    }
  });
  vm.runInContext(seam, context, {timeout: 1000});
  const call = (fn, ...args) => { context.testArgs = args; return vm.runInContext(`${fn}(...testArgs)`, context, {timeout: 1000}); };
  const state = () => vm.runInContext('referenceState', context);
  const enqueue = (payload, status = 200) => queue.push({payload, status});
  return {context, call, state, get, requests, queue, timers, enqueue,
    async ready() { enqueue(statusFixture()); await call('loadReferenceStatus'); },
    async lookup(payload = lookupFixture()) { enqueue(payload); await call('lookupReference', payload.kind); }};
}
const flags = {network_access_performed: false, persistence_status: 'not_attempted', action_status: 'not_attempted'};
const source = id => ({id, registry_url: 'https://www.iana.org/assignments/' + id,
  registry_last_updated: '2026-09-07', retrieved_at: '2026-09-10T00:00:00.000000Z',
  retrieved_at_basis: 'Synthetic test timestamp, not production provenance'});
function statusFixture() {
  return {schema: 'reference-library-status-v1', available: true, status: 'ready',
    bundle_id: 'synthetic-test-bundle', bundle_version: 'v1', manifest_sha256: 'a'.repeat(64),
    service_records: 10, protocol_records: 10, cache_entries: 0, cache_limit: 16,
    sources: [source('iana-service-names-port-numbers'), source('iana-protocol-numbers')],
    warning: 'Synthetic context is not observed traffic or a safety verdict.', ...flags};
}
function failureFixture(status = 'unavailable') {
  return {schema: 'reference-library-status-v1', available: false, status,
    error: status === 'integrity_failure' ? 'reference bundle integrity failure' : 'reference bundle unavailable', ...flags};
}
function lookupFixture(kind = 'port', count = 1, number = kind === 'port' ? 443 : 6) {
  const snapshot = statusFixture();
  const match = kind === 'port' ? {service_name: 'synthetic', transport: 'tcp', port_start: number,
    port_end: number, record_kind: 'single', description: 'Synthetic registration',
    registration_date: null, modification_date: null, source_row: 1}
    : {keyword: 'synthetic', protocol_name: 'Synthetic protocol', decimal_start: number,
      decimal_end: number, record_kind: 'single', ipv6_extension_header: null, source_row: 1};
  return {schema: 'reference-library-lookup-v1', available: true,
    status: count === 0 ? 'no_match' : count === 1 ? 'one_match' : 'multiple_matches', kind,
    bundle_id: snapshot.bundle_id, bundle_version: snapshot.bundle_version, manifest_sha256: snapshot.manifest_sha256,
    query: kind === 'port' ? {transport: 'tcp', port: number} : {number}, match_count: count,
    matches: Array.from({length: Math.min(count, 8)}, (_, i) => ({...match, source_row: i + 1})),
    truncated: count > 8, sources: [snapshot.sources[kind === 'port' ? 0 : 1]], warning: snapshot.warning, ...flags};
}
// These controls use existing public validators in BOTH baseline and candidate.
// A failure on baseline therefore reflects permissive behavior, not missing APIs.
const invalidResults = [
  ['different submitted port', () => lookupFixture('port', 1, 80)],
  ['different requested kind', () => lookupFixture('protocol')],
  ['different bundle hash', p => {p.manifest_sha256 = 'b'.repeat(64);}],
  ['different bundle id', p => {p.bundle_id = 'other';}],
  ['wrong bundle version', p => {p.bundle_version = 'v2';}],
  ['malformed hash', p => {p.manifest_sha256 = 'not-a-sha';}],
  ['missing source provenance', p => {p.sources = [];}],
  ['wrong source registry', p => {p.sources[0].id = 'iana-protocol-numbers';}],
  ['mismatched source retrieval', p => {p.sources[0].retrieved_at = 'changed';}],
  ['mismatched interpretation warning', p => {p.warning = 'safe';}],
  ['count and status contradiction', p => {p.status = 'no_match';}],
  ['missing returned matches', p => {p.matches = [];}],
  ['false truncation claim', p => {p.truncated = true;}],
  ['uncapped count with false truncation', () => {const p=lookupFixture('port',9);p.truncated=false;return p;}],
  ['unsupported transport', p => {p.query.transport = 'smb';}],
  ['negative port', p => {p.query.port = -1;}],
  ['out of range port', p => {p.query.port = 65536;}],
  ['record does not contain requested port', p => {p.matches[0].port_start = 80;p.matches[0].port_end=80;}],
  ['inverted record range', p => {p.matches[0].port_start = 500;}],
  ['out of range record', p => {p.matches[0].port_end = 65536;}],
  ['record transport mismatch', p => {p.matches[0].transport = 'udp';}],
  ['numeric range encoded as text', p => {p.matches[0].port_start = '443';}],
  ['source row zero', p => {p.matches[0].source_row = 0;}],
  ['description encoded as number', p => {p.matches[0].description = 9;}]
];
for (const [name, mutate] of invalidResults) {
  test('rejects ' + name, () => {
    const r = runtime(); let p = lookupFixture(); p = mutate(p) || p;
    assert.throws(() => r.call('validatedReferenceResult', p, 'port', {transport:'tcp',port:443}, statusFixture()));
  });
}
const invalidStatuses = [
  ['failure claims network access', p => {p.network_access_performed = true;}],
  ['failure claims persistence', p => {p.persistence_status = 'written';}],
  ['failure claims action execution', p => {p.action_status = 'performed';}],
  ['failure contains arbitrary diagnostic', p => {p.error = '/private/upstream-detail';}]
];
for (const [name, mutate] of invalidStatuses) {
  test('rejects ' + name, () => {
    const p = failureFixture(); mutate(p); assert.throws(() => runtime().call('validatedReferenceStatus', p));
  });
}
for (const [name, mutate] of [
  ['missing sources', p => {p.sources=[];}], ['duplicate sources', p => {p.sources[1]=p.sources[0];}],
  ['malformed manifest hash', p => {p.manifest_sha256='bad';}],
  ['oversized service count', p => {p.service_records=20001;}],
  ['oversized protocol count', p => {p.protocol_records=513;}],
  ['unsupported cache limit', p => {p.cache_limit=17;}]
]) test('status rejects ' + name, () => { const p=statusFixture();mutate(p);assert.throws(()=>runtime().call('validatedReferenceStatus',p)); });

if (!baseline) {
  for (const kind of ['port','protocol']) for (const count of [0,1,2,8,9]) {
    test(`accepts ${kind} count ${count}`, () => {
      const p=lookupFixture(kind,count);const r=runtime();
      assert.equal(r.call('validatedReferenceStatus',statusFixture()).status,'ready');
      assert.equal(r.call('validatedReferenceResult',p,kind,p.query,statusFixture()).match_count,count);
    });
  }
  for (const [kind,number] of [['port',0],['port',65535],['protocol',0],['protocol',255]]) {
    test(`accepts boundary ${kind}/${number}`,()=>{const p=lookupFixture(kind,1,number);assert.doesNotThrow(()=>runtime().call('validatedReferenceResult',p,kind,p.query,statusFixture()));});
  }
  test('rejects negative protocol and out of range protocol records',()=>{
    for(const num of [-1,256]) {const p=lookupFixture('protocol',1,num);assert.throws(()=>runtime().call('validatedReferenceResult',p));}
  });
  test('initial status failure can be explicitly rechecked',async()=>{
    const r=runtime();r.queue.push(new Error('network failed'));await r.call('loadReferenceStatus');
    assert.equal(r.state().available,false);assert.equal(r.get('reference-retry').disabled,false);
    assert.equal(r.get('reference-port').disabled,true);await r.ready();
    assert.equal(r.state().available,true);assert.equal(r.get('reference-port').disabled,false);
    assert.equal(r.requests.length,2);assert(r.requests.every(x=>x.path==='/api/reference/status'));
  });
  test('transient lookup failure preserves exact previous query as stale',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.get('reference-port').value='80';
    r.queue.push(new Error('private upstream text'));await r.call('lookupReference','port');
    assert.equal(r.state().lastResult.query.port,443);assert.match(r.get('reference-status').textContent,/tcp\/80 failed.*stale context for tcp\/443/);
    assert(!r.get('reference-status').textContent.includes('private upstream'));
    assert.equal(r.get('reference-port').disabled,false);assert.equal(r.timers.size,0);
  });
  test('valid integrity failure clears display and retained memory',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.enqueue(failureFixture('integrity_failure'),503);await r.call('lookupReference','port');
    assert.equal(r.state().available,false);assert.equal(r.state().lastResult,null);assert.equal(r.state().snapshot,null);
    assert.equal(r.get('reference-results').children.length,0);assert.equal(r.get('reference-meta').children.length,0);
    assert.equal(r.get('reference-provenance').children.length,0);assert.equal(r.get('reference-retry').disabled,false);
    assert.match(r.get('reference-status').textContent,/repair.*restart/);
  });
  test('invalid successful lookup disables until fresh status and clears prior',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.enqueue(lookupFixture('port',1,80));await r.call('lookupReference','port');
    assert.equal(r.state().status,'invalid_response');assert.equal(r.state().lastResult,null);
    assert.equal(r.get('reference-port').disabled,true);await r.ready();assert.equal(r.get('reference-port').disabled,false);
  });
  test('successful recheck clears previous context even for same bundle',async()=>{
    const r=runtime();await r.ready();await r.lookup();await r.ready();
    assert.equal(r.state().lastResult,null);assert.equal(r.get('reference-clear').disabled,true);assert.equal(r.requests.length,3);
  });
  test('recheck does not hide cached server failure as successful repair',async()=>{
    const r=runtime();r.enqueue(failureFixture(),503);await r.call('loadReferenceStatus');
    r.enqueue(failureFixture(),503);await r.call('loadReferenceStatus');assert.equal(r.state().available,false);
    assert.match(r.get('reference-status').textContent,/local repair and service restart/);
  });
  test('forged failure envelope is not treated as verified integrity failure',async()=>{
    const r=runtime();await r.ready();await r.lookup();const p=failureFixture('integrity_failure');p.action_status='performed';
    r.enqueue(p,503);await r.call('lookupReference','port');
    assert.equal(r.state().lastResult.query.port,443);assert.match(r.get('reference-status').textContent,/stale/);
    assert(!r.get('reference-status').textContent.includes('integrity failure'));
  });
  test('missing initial result stays honest on lookup transport failure',async()=>{
    const r=runtime();await r.ready();r.queue.push(new Error('offline'));await r.call('lookupReference','port');
    assert.equal(r.state().lastResult,null);assert.match(r.get('reference-status').textContent,/No reference result is available/);
    assert.equal(r.get('reference-port').disabled,false);
  });
  test('concurrent status and lookup submissions cannot duplicate requests',async()=>{
    const r=runtime();let finish;r.queue.push(()=>new Promise(resolve=>{finish=resolve;}));
    const pending=r.call('loadReferenceStatus');assert.equal(r.get('reference-retry').disabled,true);
    await r.call('loadReferenceStatus');await r.call('lookupReference','port');assert.equal(r.requests.length,1);
    finish({ok:true,status:200,json:async()=>statusFixture()});await pending;
    assert.equal(r.get('reference-panel').getAttribute('aria-busy'),'false');
  });
  test('lookup controls lock while request is pending and unlock afterwards',async()=>{
    const r=runtime();await r.ready();let finish;r.queue.push(()=>new Promise(resolve=>{finish=resolve;}));
    const pending=r.call('lookupReference','port');assert.equal(r.get('reference-port').disabled,true);
    assert.equal(r.get('reference-retry').disabled,true);await r.call('lookupReference','protocol');await r.call('loadReferenceStatus');
    assert.equal(r.requests.length,2);finish({ok:true,status:200,json:async()=>lookupFixture()});await pending;
    assert.equal(r.get('reference-port').disabled,false);assert.equal(r.get('reference-clear').disabled,false);
  });
  test('edited inputs do not relabel retained result',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.get('reference-port').value='80';r.call('referenceInputChanged');
    assert.match(r.get('reference-status').textContent,/still for tcp\/443/);assert.equal(r.requests.length,2);
  });
  test('clear removes local display only and performs no request',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.call('clearReferenceResult');r.call('syncReferenceControls');
    assert.equal(r.state().lastResult,null);assert.equal(r.requests.length,2);assert.equal(r.state().snapshot.bundle_id,'synthetic-test-bundle');
  });
  test('invalid local inputs do not fetch and preserve prior identity',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.get('reference-port').value='00443';await r.call('lookupReference','port');
    assert.equal(r.requests.length,2);assert.match(r.get('reference-status').textContent,/still for tcp\/443/);
  });
  test('untrusted provenance and record text never becomes HTML or navigation',async()=>{
    const r=runtime(),p=statusFixture();p.sources[0].registry_url='javascript:alert(1)';p.warning='<img src=x onerror=alert(1)>';
    r.enqueue(p);await r.call('loadReferenceStatus');const text=r.get('reference-provenance').textContent;
    assert(text.includes('javascript:alert(1)'));assert(text.includes('<img'));assert(text.includes('reported by local API'));
    const descendants=node=>[node,...node.children.flatMap(descendants)];
    assert(descendants(r.get('reference-provenance')).every(n=>!['A','IMG','SCRIPT','IFRAME'].includes(n.tagName)));
    const match=lookupFixture();match.warning=p.warning;match.sources[0]=p.sources[0];match.matches[0].description='<script>bad()</script>';
    await r.lookup(match);assert(r.get('reference-results').textContent.includes('<script>bad()</script>'));
  });
  test('request policy is same-origin credential-free no-redirect with five-second cleanup',async()=>{
    const r=runtime();await r.ready();const options=r.requests[0].options;
    assert.equal(options.mode,'same-origin');assert.equal(options.credentials,'omit');assert.equal(options.redirect,'error');
    assert.equal(options.cache,'no-store');assert.equal(options.headers.Accept,'application/json');assert.equal(r.timers.size,0);
  });
  test('timeout aborts and releases busy state without a real timer or socket',async()=>{
    const r=runtime();r.queue.push((_,opts)=>new Promise((resolve,reject)=>opts.signal.addEventListener('abort',()=>reject(new Error('aborted')))));
    const pending=r.call('loadReferenceStatus');assert.equal(r.timers.size,1);
    const timer=[...r.timers.values()][0];assert.equal(timer.delay,5000);timer.fn();await pending;
    assert.equal(r.timers.size,0);assert.equal(r.state().statusLoading,false);assert.equal(r.get('reference-retry').disabled,false);
  });
  test('malformed JSON releases request state without accepting new context',async()=>{
    const r=runtime();await r.ready();await r.lookup();r.queue.push({status:200,jsonError:new SyntaxError('bad JSON')});
    await r.call('lookupReference','port');assert.equal(r.state().lastResult.query.port,443);
    assert.match(r.get('reference-status').textContent,/stale/);assert.equal(r.state().loading,false);assert.equal(r.timers.size,0);
  });
  test('invalid status response is rejected with fixed user-facing text',async()=>{
    const r=runtime();const p=statusFixture();p.manifest_sha256='secret-file-path';r.enqueue(p);await r.call('loadReferenceStatus');
    assert.equal(r.state().status,'invalid_response');assert(!r.get('reference-status').textContent.includes('secret-file-path'));
  });
}
