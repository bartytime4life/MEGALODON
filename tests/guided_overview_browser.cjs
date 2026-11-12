const assert = require('node:assert/strict'), vm = require('node:vm');
let input = '';
process.stdin.on('data', value => input += value).on('end', async () => {
  const {code, fixture} = JSON.parse(input), nodes = new Map(), timers = new Map(), requests = [];
  let payload = structuredClone(fixture), failure = false, serial = 0, now = Date.parse(fixture.observed_at), release;
  let held = new Promise(resolve => release = resolve);
  function element(tag = '') {
    return {tag, textContent: '', children: [], attributes: {}, dataset: {}, style: {}, events: {}, hidden: false,
      disabled: false, value: '', setAttribute(key, value) {this.attributes[key] = String(value);},
      append(...values) {this.children.push(...values);}, replaceChildren(...values) {this.children = values;},
      addEventListener(key, callback) {this.events[key] = callback;}, focus() {document.activeElement = this;}};
  }
  function get(id) {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);}
  const document = {hidden: false, activeElement: null, getElementById: get, createElement: element,
    createElementNS: (_, tag) => element(tag), addEventListener() {}};
  class Clock extends Date {static now() {return now;}}
  const context = {localHudLaunch: {}, window: {}, document, Date: Clock, TextEncoder, TextDecoder, Uint8Array,
    AbortController, setTimeout(callback, ms) {const id = ++serial; timers.set(id, {callback, ms}); return id;},
    clearTimeout: id => timers.delete(id), fetch: async (path, options) => {
      requests.push({path, options}); if (held) await held;
      if (path !== '/api/operations' || failure) throw Error('Unavailable synthetic status');
      return {ok: true, headers: {get: () => null}, text: async () => JSON.stringify(payload)};
    }};
  const settle = async () => {await new Promise(resolve => setImmediate(resolve)); await new Promise(resolve => setImmediate(resolve));};
  const click = async id => {get(id).events.click(); await settle();};
  const poll = async () => {
    const item = [...timers].find(([, value]) => value.ms === 2000);
    assert.ok(item, 'existing operations refresh remains scheduled');
    timers.delete(item[0]); await item[1].callback(); await settle();
  };
  const expect = (state, title, target) => {
    assert.equal(get('ops-guide').dataset.state, state);
    assert.equal(get('ops-guide-title').textContent, title);
    assert.equal(get('ops-guide-next').attributes.href, target);
  };
  vm.runInNewContext(code, context);
  expect('unavailable', 'Reading local observations', '#room-findings-title');
  assert.equal(get('ops-guide-refresh').attributes['aria-disabled'], 'true');
  assert.equal(get('ops-guide-refresh').disabled, false, 'loading keeps the control focusable');
  release(); held = null; await settle();
  expect('observed', 'Explore observed connections', '#ops-lens-title');
  assert.match(get('ops-guide-message').textContent, /No sensor alert labels returned/);
  const next = get('ops-guide-next'); next.focus(); await poll();
  assert.equal(get('ops-guide-next'), next); assert.equal(document.activeElement, next, 'polling preserves the focused link');
  const refresh = get('ops-guide-refresh'); refresh.focus();
  held = new Promise(resolve => release = resolve);
  const background = poll(); await settle();
  assert.equal(refresh.textContent, 'Refresh observations', 'automatic reads never churn the label');
  assert.equal(refresh.attributes['aria-disabled'], 'true');
  assert.equal(refresh.disabled, false, 'native focus is preserved during a slow automatic read');
  assert.equal(document.activeElement, refresh);
  const waiting = requests.length; await click('ops-guide-refresh');
  assert.equal(requests.length, waiting, 'pending guard prevents a duplicate request');
  release(); held = null; await background;
  assert.equal(document.activeElement, refresh); assert.equal(refresh.attributes['aria-disabled'], 'false');
  const before = requests.length;
  await click('ops-guide-refresh');
  assert.equal(requests.length, before + 1, 'explicit refresh reuses only the existing operations read');
  assert.equal(requests.at(-1).path, '/api/operations');
  for (const state of ['stopped', 'idle', 'unconfigured', 'failed']) {
    payload = {...fixture, capture: {state}}; await poll();
    expect('capture', 'Choose what to observe', '#support-capture-title');
  }
  payload = {...fixture, capture: {state: 'failed', failure_reason: 'permission_required'}}; await poll();
  expect('capture', 'Review capture access', '#support-capture-title');
  payload = {...fixture, endpoints: [], timeline: [], protocols: [], summary: Object.fromEntries(Object.keys(fixture.summary).map(key => [key, 0]))};
  await poll(); expect('waiting', 'Waiting for observations', '#support-capture-title');
  assert.match(get('ops-guide-message').textContent, /no observed metadata/);
  payload = structuredClone(fixture); payload.endpoints[1].findings = [{source: 'Synthetic fixture', signature: 'Review this observation', severity: 'medium', observed_at: fixture.observed_at}];
  await poll(); expect('sensor', 'Review sensor observations', '#ops-lens-title');
  assert.match(get('ops-guide-message').textContent, /1 returned sensor observation/);
  assert.match(get('ops-guide-message').textContent, /separate from saved Findings/);
  const shared = {observed_at: fixture.observed_at, severity: 'medium'};
  payload.endpoints[1].findings = [{...shared, source: 'a|b', signature: 'c'}, {...shared, source: 'a', signature: 'b|c'}];
  payload.endpoints[0].findings = [{...shared, source: 'a|b', signature: 'c'}];
  await poll(); assert.match(get('ops-guide-message').textContent, /2 returned sensor observations/);
  assert.equal(get('ops-findings').textContent, '2', 'distinct tuples survive delimiters and duplicate endpoint labels count once');
  for (const state of ['idle', 'stopped', 'failed']) {
    payload = {...structuredClone(fixture), recording_mode: 'connection_summaries', capture: {state}};
    await poll(); expect('observed', 'Explore sensor summaries', '#ops-lens-title');
    assert.doesNotMatch(get('ops-guide-message').textContent, /capture settings/);
    payload.endpoints[1].findings = [{...shared, source: 'Synthetic sensor context', signature: 'Observe'}];
    await poll(); expect('sensor', 'Review sensor observations', '#ops-lens-title');
  }
  payload = {...payload, endpoints: [], timeline: [], protocols: [], summary: Object.fromEntries(Object.keys(fixture.summary).map(key => [key, 0]))};
  await poll(); expect('waiting', 'Waiting for sensor observations', '#integrations-title');
  payload = {...structuredClone(fixture), recording_mode: 'packet_metadata'}; await poll();
  await click('ops-pause'); expect('unavailable', 'Resume current observations', '#ops-lens-title');
  assert.equal(get('ops-guide-refresh').textContent, 'Resume view');
  const paused = requests.length; await click('ops-guide-refresh');
  assert.equal(requests.length, paused + 1, 'resume changes display refresh only');
  expect('observed', 'Explore observed connections', '#ops-lens-title');
  now += 11000; await poll(); expect('unavailable', 'Refresh current observations', '#room-findings-title');
  assert.match(get('ops-guide-message').textContent, /no longer current/);
  failure = true; await poll(); expect('unavailable', 'Refresh current observations', '#room-findings-title');
  assert.match(get('ops-guide-message').textContent, /could not be checked/);
  failure = false; now = Date.parse(fixture.observed_at); payload = structuredClone(fixture);
  await click('ops-guide-refresh'); expect('observed', 'Explore observed connections', '#ops-lens-title');
  assert.ok(requests.every(request => request.options.method === 'GET'), 'guidance never posts or starts a protected action');
  assert.ok(requests.every(request => ['/api/operations', '/api/defense'].includes(request.path)), 'no new endpoint or background read');
  assert.equal(next.events.click, undefined, 'next step remains a native read-only fragment link');
  console.log('guided overview states, retry, focus, and read-only boundaries passed');
}).on('error', error => {console.error(error); process.exitCode = 1;});
process.on('unhandledRejection', error => {console.error(error); process.exitCode = 1;});
