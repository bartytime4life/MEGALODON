const assert = require('node:assert/strict');
const vm = require('node:vm');
const {code, scenario} = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));

(async () => {
  class Element {
    constructor() { this.children = []; this.events = {}; this.hidden = false; this.value = ''; this.open = false; this.textContent = ''; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    removeAttribute(name) { delete this[name]; }
    addEventListener(name, listener) { this.events[name] = listener; }
  }
  const nodes = new Map();
  const get = id => { if (!nodes.has(id)) nodes.set(id, new Element()); return nodes.get(id); };
  const A = 'a'.repeat(32), B = 'b'.repeat(32), pending = [], timers = new Map();
  let timer = 0;
  const saved = id => ({id, state: 'ready', created_at: '2026-11-11T12:00:00Z', start: '2026-11-10T12:00:00Z', end: '2026-11-11T12:00:00Z', title: id, coverage: {gaps: []}, summary: {}});
  let payload = {schema: 'megalodon-reports-v1', available: true, local_only: true, operator_token: null,
    reports: [saved(A), saved(B)], job: {state: 'idle'}, schedule: {enabled: false, time: '09:00', frequency: 'daily'}};
  const document = {hidden: false, getElementById: get, createElement: () => new Element(), addEventListener() {}};
  get('reports-range').value = 'day';
  const context = {window: {addEventListener() {}}, document, Date, Number, Math, JSON, TextEncoder, TextDecoder, AbortController,
    setTimeout(fn, ms) { timers.set(++timer, {fn, ms}); return timer; }, clearTimeout(id) { timers.delete(id); },
    fetch(path) {
      if (path === '/api/reports') return Promise.resolve(response(payload));
      return new Promise((resolve, reject) => pending.push({path, resolve, reject}));
    }};
  function response(value) { return {ok: true, headers: {get: () => null}, text: async () => typeof value === 'string' ? value : JSON.stringify(value)}; }
  const settle = async () => { await new Promise(setImmediate); await new Promise(setImmediate); };
  function take(id, kind) {
    const index = pending.findIndex(request => request.path.includes('/' + id + '/' + kind));
    assert.ok(index >= 0, 'expected current ' + kind + ' request for ' + id[0]);
    return pending.splice(index, 1)[0];
  }
  async function html(id, request = take(id, 'html')) { request.resolve(response('<!doctype html><html><body>Report ' + id[0] + '</body></html>')); await settle(); }
  function details(label, offset = 0) { return {records: [{id: label, title: label, source: 'synthetic', severity: 'high', evidence_reference: 'fixture:' + label}], total: 151, offset}; }
  async function findings(id, label, request = take(id, 'findings')) { request.resolve(response(details(label))); await settle(); }
  async function select(id) { get('reports-saved').value = id; get('reports-saved').events.change(); await settle(); }
  async function poll() { const [id, value] = [...timers].find(([, value]) => value.ms === 30000); timers.delete(id); await value.fn(); await settle(); }
  const rows = () => get('reports-findings-rows').children;
  const rowTitle = () => rows()[0]?.children[1].children[0].textContent;
  vm.runInNewContext(code, context);
  await settle();
  const initialDocument = take(A, 'html');

  if (scenario === 'expired-document') {
    payload.reports = payload.reports.map(report => ({...report, state: 'expired'}));
    await poll(); await html(A, initialDocument);
    assert.equal(get('reports-document').hidden, true);
    assert.equal(get('reports-print').disabled, true);
  } else if (scenario === 'document-reselection') {
    await select(B); const otherDocument = take(B, 'html');
    await select(A); const currentDocument = take(A, 'html');
    initialDocument.reject(Error('obsolete document failure')); await settle();
    assert.match(get('reports-status').textContent, /Opening saved report/);
    await html(A, currentDocument);
    await html(B, otherDocument);
    assert.match(get('reports-document').srcdoc, /Report a/);
    assert.equal(get('reports-document').hidden, false);
  } else {
    await html(A, initialDocument);
    get('reports-findings-panel').open = true;
    get('reports-findings-panel').events.toggle(); await settle();
    const initialFindings = take(A, 'findings');
    if (scenario === 'obsolete-completion') {
      await select(B); await html(B); const currentFindings = take(B, 'findings');
      initialFindings.reject(Error('obsolete details failure')); await settle();
      assert.match(get('reports-findings-status').textContent, /Opening finding details/);
      assert.equal(get('reports-findings-next').disabled, true);
      get('reports-findings-panel').events.toggle(); await settle();
      assert.equal(pending.filter(request => request.path.includes('/findings?')).length, 0, 'obsolete completion cannot release the current request');
      await findings(B, 'Beta finding', currentFindings);
      assert.equal(rowTitle(), 'high · Beta finding');
    } else if (scenario === 'pending-success' || scenario === 'pending-failure') {
      await select(B); await html(B); const currentFindings = take(B, 'findings');
      await findings(B, 'Beta finding', currentFindings);
      const status = get('reports-findings-status').textContent;
      if (scenario === 'pending-failure') initialFindings.reject(Error('obsolete details failure'));
      else initialFindings.resolve(response(details('Obsolete Alpha finding')));
      await settle();
      assert.equal(rowTitle(), 'high · Beta finding');
      assert.equal(get('reports-findings-status').textContent, status);
      assert.equal(get('reports-findings-next').disabled, false);
    } else if (scenario === 'expired-pending') {
      payload.reports = payload.reports.map(report => ({...report, state: 'expired'}));
      await poll();
      initialFindings.resolve(response(details('Expired Alpha finding'))); await settle();
      assert.equal(rows().length, 0);
      assert.equal(get('reports-findings-next').disabled, true);
      assert.equal(get('reports-document').hidden, true);
    } else {
      await findings(A, 'Alpha finding', initialFindings);
      assert.equal(rowTitle(), 'high · Alpha finding');
      if (scenario === 'manual-expired') {
        payload.reports = [saved(A), {...saved(B), state: 'expired'}]; await poll();
        await select(B);
        assert.equal(rows().length, 0);
        assert.equal(get('reports-findings-next').disabled, true);
        assert.equal(get('reports-document').hidden, true);
      } else if (scenario === 'failed-page') {
        get('reports-findings-next').events.click(); await settle();
        const failed = take(A, 'findings'); assert.match(failed.path, /offset=50/);
        failed.reject(Error('page unavailable')); await settle();
        assert.equal(rowTitle(), 'high · Alpha finding');
        assert.equal(get('reports-findings-previous').disabled, true, 'the failed page was never committed');
        get('reports-findings-next').events.click(); await settle();
        const retry = take(A, 'findings'); assert.match(retry.path, /offset=50/, 'retry must not skip the failed page');
        retry.resolve(response(details('Second page', 50))); await settle();
        assert.match(get('reports-findings-status').textContent, /^51–51/);
      } else {
        if (scenario === 'automatic-selection') payload.job = {state: 'ready', report_id: B};
        else payload.reports = [saved(B)];
        await poll();
        assert.equal(get('reports-saved').value, B);
        assert.equal(rows().length, 0, 'a different report cannot inherit old findings');
        assert.equal(get('reports-findings-next').disabled, true);
        assert.doesNotMatch(get('reports-findings-status').textContent, /of 151/);
        await html(B);
        take(B, 'findings').reject(Error('new details unavailable')); await settle();
        assert.equal(rows().length, 0);
        assert.doesNotMatch(get('reports-findings-status').textContent, /remain visible/);
      }
    }
  }
  console.log('Reports selection regression passed: ' + scenario);
})().catch(error => { console.error(error); process.exitCode = 1; });
