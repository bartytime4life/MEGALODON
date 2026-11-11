const assert = require('node:assert/strict'), vm = require('node:vm');
let input = '';
process.stdin.on('data', value => input += value);
process.stdin.on('end', async () => {
  const {code, scenario} = JSON.parse(input), nodes = new Map(), timers = new Map(), reads = [], listeners = new Map();
  let serial = 0, enabled = scenario !== 'paused', explaining = false;
  function node(tag = '') {
    return {tag, ownText: '', children: [], events: {}, attributes: {}, value: '', hidden: false,
      get textContent() { return this.ownText + this.children.map(child => child.textContent).join(' '); },
      set textContent(value) { this.ownText = String(value); this.children = []; },
      append(...values) { this.children.push(...values); },
      replaceChildren(...values) { this.ownText = ''; this.children = values; },
      setAttribute(key, value) { this.attributes[key] = value; },
      getAttribute(key) { return this.attributes[key] || null; },
      addEventListener(key, listener) { this.events[key] = listener; }, contains() { return false; }};
  }
  const get = id => { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); };
  get('knowledge-setup').attributes['aria-labelledby'] = 'knowledge-title';
  get('findings-workbench').attributes['data-findings-owned'] = 'true';
  const knowledge = {state: 'ready', entries: 0, used_bytes: 0, sources: {}, generation: 'synthetic',
    rollback_available: false, last_check: null, enabled: false, token: 'a'.repeat(32)};
  const patterns = () => ({enabled, automatic: false, baseline: {ready_groups: 2, largest_group_hours: 24},
    unresolved: 0, reviews: [], gaps: [], truncated: false, job: {state: explaining ? 'running' : 'idle', message: 'Synthetic only.'}});
  const result = title => ({results: [{title, identifier: 'reference', edition: 'synthetic', url: 'https://example.test/', excerpt: title} ]});
  const response = (value, ok = true) => ({ok, text: async () => JSON.stringify(value)});
  const context = {document: {hidden: false, activeElement: null, getElementById: get,
    createElement: node, addEventListener(type, listener) { listeners.set(type, listener); }}, URL, AbortController,
    setTimeout(fn, delay) { const id = ++serial; timers.set(id, {fn, delay}); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(path) {
      if (path.startsWith('/api/knowledge/search?') || path.startsWith('/api/intelligence?device=')) return new Promise((resolve, reject) => reads.push({path, resolve, reject}));
      return Promise.resolve(response(path === '/api/knowledge' ? knowledge : patterns()));
    }};
  vm.runInNewContext(code, context);
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const poll = async () => { const entry = [...timers].find(([,timer]) => timer.delay === 750 || timer.delay === 15000);
    assert.ok(entry); timers.delete(entry[0]); await entry[1].fn(); };
  const edit = value => { get('ki-search').value = value; get('ki-search').events.input?.(); };
  const submit = () => get('ki-search-form').events.submit({preventDefault() {}});
  await poll();
  if (scenario.startsWith('device-')) {
    const choose = address => listeners.get('megalodon:endpoint-selected')({detail: address});
    const review = label => ({reviews: [{id: label, device: '192.0.2.1', label, interface: 'synthetic', measurement: 'metadata',
      what_happened: label + ' source facts', why_it_matters: 'Synthetic comparison.', what_you_can_do: 'Read the saved evidence.',
      sensor: 'Synthetic source', start: '2026-11-11T12:00:00Z', end: '2026-11-11T13:00:00Z',
      required_measurements: 'Source-qualified metadata', facts: {label}, analysis: {state: 'not_requested'}}]});
    choose('192.0.2.1'); await settle(); assert.equal(reads.length, 1);
    if (scenario === 'device-deselected') {
      choose(null); reads[0].resolve(response(review('old A'))); await settle();
      assert.match(get('ki-device-review').textContent, /Select a device/);
      assert.doesNotMatch(get('ki-device-review').textContent, /old A/);
    } else {
      choose('192.0.2.2'); choose('192.0.2.1'); await settle(); assert.equal(reads.length, 3);
      reads[2].resolve(response(review('fresh A'))); await settle();
      assert.match(get('ki-device-review').textContent, /192\.0\.2\.1.*fresh A/);
      if (scenario === 'device-failure') reads[0].resolve(response({error: 'obsolete A failure'}, false));
      else reads[0].resolve(response(review('obsolete A')));
      reads[1].resolve(response({reviews: []})); await settle();
      assert.match(get('ki-device-review').textContent, /fresh A source facts/);
      assert.doesNotMatch(get('ki-device-review').textContent, /obsolete|could not be read/);
      choose('192.0.2.1'); assert.equal(reads.length, 3, 'unchanged selection does not issue a duplicate read');
    }
  } else if (scenario === 'paused') {
    assert.match(get('ki-hud-status').textContent, /learning paused/i);
    assert.doesNotMatch(get('ki-hud-status').textContent, /watching|learning usual/i);
    assert.match(get('ki-learning').textContent, /2 source\/device groups/);
    assert.match(get('ki-learning').textContent, /24 of 24/);
    assert.match(get('ki-learning').textContent, /paused/i);
    explaining = true; await poll();
    assert.match(get('ki-hud-status').textContent, /paused.*explaining/i, 'a saved explanation is distinct from ongoing learning');
    enabled = true; explaining = false; await poll();
    assert.match(get('ki-hud-status').textContent, /watching for changes/);
  } else {
    edit('first'); const first = submit();
    await settle(); assert.equal(reads.length, 1);
    if (scenario === 'edited') {
      edit('second'); reads[0].resolve(response(result('first result'))); await first;
      assert.doesNotMatch(get('ki-search-results').textContent, /first result/);
    } else {
      edit('second'); const second = submit(); await settle(); assert.equal(reads.length, 2);
      if (scenario === 'repeated') { edit('first'); const third = submit(); await settle();
        reads[2].resolve(response(result('current first result'))); await third;
        reads[1].resolve(response(result('second result'))); await second;
      } else { reads[1].resolve(response(result('second result'))); await second; }
      if (scenario === 'failure') reads[0].resolve(response({error: 'obsolete failure'}, false));
      else reads[0].resolve(response(result('obsolete first result')));
      await first;
      assert.match(get('ki-search-results').textContent, scenario === 'repeated' ? /current first result/ : /second result/);
      assert.doesNotMatch(get('ki-search-results').textContent, /obsolete/);
      assert.equal(get('ki-search-results').attributes['aria-busy'], 'false');
    }
  }
  console.log('intelligence status/search scenario passed: ' + scenario);
});
process.on('unhandledRejection', error => { console.error(error); process.exitCode = 1; });
