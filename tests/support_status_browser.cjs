const assert = require('node:assert/strict'), vm = require('node:vm');
let input = '';
process.stdin.on('data', value => input += value);
process.stdin.on('end', async () => {
  const {code, settings_code, fixture} = JSON.parse(input), nodes = new Map(), listeners = new Map(), timers = new Map(), requests = [];
  let serial = 0, failure = false, hold = null;
  const model = {model: 'Synthetic saved model', message: 'Saved choice.', compute_mode: 'cpu', options: [],
    updated_at: null, last_response_at: null, last_attempt_at: null, response_ms: null,
    loaded: true, memory_bytes: 1024, vram_bytes: 0, selection_state: 'saved',
    response_test: {state: 'passed', model: 'Synthetic saved model', message: 'Synthetic completed reply.', selection_saved: true,
      compute_mode: 'cpu', started_at: '2026-11-11T12:00:00Z', finished_at: '2026-11-11T12:00:01Z',
      duration_ms: 1000, error_code: null, timeout_seconds: 30}};
  let payload = {...fixture, capture: {...fixture.capture, state: 'running'}, model};
  function element() { return {textContent: '', children: [], attributes: {}, dataset: {}, events: {}, value: '', hidden: false,
    setAttribute(key, value) { this.attributes[key] = value; },
    append(...values) { this.children.push(...values); }, replaceChildren(...values) { this.children = values; },
    addEventListener(key, value) { this.events[key] = value; }, querySelectorAll() { return []; },
    contains() { return false; }, focus() {}}; }
  const get = id => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  const document = {hidden: false, getElementById: get, createElement: element, addEventListener() {}};
  const window = {location: {hash: ''}, addEventListener(type, listener) {
    if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(listener);
  }, dispatchEvent(event) { for (const listener of listeners.get(event.type) || []) listener(event); }};
  const context = {document, window, localHudLaunch: {}, heartbeatState: {report: {tools: [{installed: 'yes'}]}}, heartbeatStale: () => false,
    CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init.detail; } },
    TextEncoder, TextDecoder, Uint8Array, AbortController,
    setTimeout(fn, delay) { const id = ++serial; timers.set(id, {fn, delay}); return id; }, clearTimeout(id) { timers.delete(id); },
    fetch: async (path, options) => { requests.push({path, options}); if (hold) await hold;
      if (failure) throw Error('Synthetic read failure');
      return {ok: true, status: 200, headers: {get: () => null}, text: async () => JSON.stringify(payload)}; }};
  vm.runInNewContext(code + settings_code, context);
  await window.megalodonSupportConfiguration.refresh(true);
  assert.equal(get('settings-traffic-summary').textContent, 'Capturing');
  assert.equal(get('settings-model-summary').textContent, 'Local test passed');
  assert.equal(get('settings-apps-summary').textContent, '1 installed');
  let release; hold = new Promise(resolve => release = resolve);
  const reading = window.megalodonSupportConfiguration.refresh(true);
  assert.equal(get('settings-traffic-summary').textContent, 'Capturing', 'pending is distinct from a failed observation');
  assert.equal(get('settings-model-summary').textContent, 'Local test passed');
  failure = true; release(); await reading; hold = null;
  assert.equal(get('settings-traffic-summary').textContent, 'Unavailable');
  assert.equal(get('settings-model-summary').textContent, 'Unavailable');
  assert.equal(get('settings-model-name').textContent, 'Synthetic saved model', 'a failed observation does not erase the saved preference');
  assert.equal(get('settings-apps-summary').textContent, '1 installed', 'installed-app heartbeat is a separate source');
  for (const id of ['support-config-capture-start', 'support-config-qwen', 'support-model-test']) {
    assert.equal(get(id).disabled, true, id + ' must refuse stale authority');
    await get(id).events.click?.();
  }
  assert.ok(requests.every(request => request.options.method === 'GET'));
  failure = false;
  payload = {...payload, capture: {...payload.capture, state: 'stopped'}, model: {...model, loaded: false,
    response_test: {...model.response_test, state: 'idle'}}};
  await window.megalodonSupportConfiguration.refresh(true);
  assert.equal(get('settings-traffic-summary').textContent, 'Stopped');
  assert.equal(get('settings-model-summary').textContent, 'Not loaded');
  console.log('Setup summaries preserve pending/read failure/recovery and independent source states');
});
process.on('unhandledRejection', error => { console.error(error); process.exitCode = 1; });
