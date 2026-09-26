const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  try {
    const {code} = JSON.parse(input), nodes = new Map(), timers = new Map(), listeners = {};
    let timerId = 0, calls = 0;
    function element(tag = '') {
      return {tag, children: [], textContent: '', attrs: {}, className: '',
        append(...items) {this.children.push(...items);},
        replaceChildren(...items) {this.children = items; this.textContent = '';},
        setAttribute(k, v) {this.attrs[k] = v;}, addEventListener() {}};
    }
    const byId = id => {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);};
    const allText = node => node.textContent + ' ' + node.children.map(allText).join(' ');
    const light = element('i'); light.heartbeatTool = 'qwen';
    const detail = element('span'); detail.heartbeatTool = 'qwen';
    const context = {Date, Map, AbortController, workflowToolIds: ['qwen'], byId,
      formatRefreshTime: date => date.toISOString(),
      textNode: (tag, text = '', className = '') => Object.assign(element(tag), {textContent: text, className}),
      document: {visibilityState: 'visible', createElement: element,
        addEventListener(name, fn) {listeners[name] = fn;},
        querySelectorAll(selector) {return selector === '[data-heartbeat-tool]' ? [light]
          : selector === '[data-heartbeat-detail]' ? [detail] : [];}},
      window: {setTimeout(fn, delay) {const id = ++timerId; timers.set(id, {fn, delay}); return id;},
        clearTimeout(id) {timers.delete(id);}},
    };
    const report = () => ({schema: 'megalodon-tool-heartbeat-v1', checked_at: new Date().toISOString(),
      tools: [{id: 'qwen', light: 'green', installed: 'yes', expects_service: true,
        service: 'running', model: 'present', installed_since: '2026-01-01T00:00:00Z'}]});
    const success = async path => {calls++; return {ok: true, status: 200,
      json: async () => path === '/api/heartbeat' ? report() : {tools: [], job: {state: 'idle'}}};};
    context.fetch = success;
    vm.createContext(context); vm.runInContext(code, context, {timeout: 1000});
    const run = value => vm.runInContext(value, context, {timeout: 1000});
    await run('pollHeartbeat()');
    assert.match(light.className, /hb-green/);
    assert.doesNotMatch(detail.textContent, /healthy|installed 1\//i);
    assert.match(detail.textContent, /example qwen2\.5:7b/i);
    assert.match(detail.textContent, /not.*AI readiness/i);
    assert.equal([...timers.values()][0].delay, 60000);
    context.greenbone = {id: 'greenbone', light: 'grey', installed: 'unknown',
      installed_since: null, expects_service: true, service: 'stopped', model: null};
    run("heartbeatState.byId.set('greenbone', greenbone)");
    light.heartbeatTool = detail.heartbeatTool = 'greenbone';
    run('repaintHeartbeat()');
    assert.match(light.className, /hb-grey/);
    assert.equal(detail.textContent, 'Status unknown');
    assert.doesNotMatch(light.attrs['aria-label'], /installed|healthy|file metadata/i);
    light.heartbeatTool = detail.heartbeatTool = 'qwen';
    context.fetch = async () => {throw Error('private failure detail');};
    await run('pollHeartbeat()');
    assert.match(light.className, /hb-grey/);
    assert.doesNotMatch(light.className, /hb-green|hb-pending/);
    assert.match(light.attrs['aria-label'], /stale/i);
    assert.match(detail.textContent, /stale/i);
    assert.doesNotMatch(detail.textContent, /private failure|healthy/);
    assert.match(allText(byId('hb-summary')), /stale/i);
    assert.doesNotMatch(allText(byId('hb-summary')), /1 .*observed/);
    assert.equal(timers.size, 1);
    const initialRetry = [...timers.values()][0];
    assert.equal(initialRetry.delay, 5000);
    for (let i = 0; i < 8; i++) await run('pollHeartbeat()');
    assert.equal([...timers.values()][0].delay, 60000);
    context.fetch = success;
    await run('pollHeartbeat()');
    assert.match(light.className, /hb-green/);
    assert.equal(run('heartbeatState.failed'), false);
    assert.equal([...timers.values()][0].delay, 60000);
    context.fetch = async path => {
      if(path === '/api/install') throw Error('installer unavailable');
      return success(path);
    };
    await run('pollHeartbeat()');
    assert.equal(run('heartbeatState.failed'), false, 'Installer failure must not discard successful tool observations');
    assert.equal(run('heartbeatState.catalogFailed'), true);
    assert.equal(run('heartbeatState.managementEnabled'), false);
    assert.match(light.className, /hb-green/);
    assert.match(byId('tool-management-status').textContent, /Install status unavailable/);
    context.fetch = async path => {
      if(path === '/api/heartbeat') throw Error('observation unavailable');
      return success(path);
    };
    await run('pollHeartbeat()');
    assert.equal(run('heartbeatState.failed'), true);
    assert.equal(run('heartbeatState.catalogFailed'), false);
    assert.match(light.className, /hb-grey/);
    context.fetch=success;await run('pollHeartbeat()');
    for (const checked_at of ['not-a-date', '2000-01-01T00:00:00Z', '2999-01-01T00:00:00Z']) {
      context.bad = {...report(), checked_at};
      assert.throws(() => run('validHeartbeat(bad)'), /Expired/);
    }
    context.document.visibilityState = 'hidden';
    const before = calls;
    await run('pollHeartbeat()');
    assert.equal(calls, before);
    assert.equal(timers.size, 0);
    context.document.visibilityState = 'visible';
    listeners.visibilitychange();
    assert.equal(timers.size, 1, 'A briefly hidden tab resumes its normal polling timer');
    run('heartbeatState.report.checked_at = "2000-01-01T00:00:00Z"; repaintHeartbeat();');
    assert.match(light.className, /hb-grey/);
    assert.match(detail.textContent, /stale/i);
    const releases = [];
    context.fetch = path => {calls++; return new Promise(resolve => {releases.push(() => resolve({
      ok: true, status: 200, json: async () => path === '/api/heartbeat' ? report() : {tools: [], job: {state: 'idle'}},
    }));});};
    const pending = run('pollHeartbeat()');
    const pendingCalls = calls;
    await run('pollHeartbeat()');
    assert.equal(calls, pendingCalls, 'Only one poll may be in flight');
    releases.forEach(release => release());
    await pending;
    assert.equal(run('heartbeatState.polling'), false);
    assert.equal(timers.size, 1);
    process.stdout.write('heartbeat observation checks passed\n');
  } catch (error) {process.stderr.write(error.stack + '\n'); process.exitCode = 1;}
});
