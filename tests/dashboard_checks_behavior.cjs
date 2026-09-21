const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  try {
    const {code, report} = JSON.parse(input), nodes = new Map(), calls = [], timers = new Map();
    const artifacts = [], downloads = [], revoked = [];
    let timerId = 0;
    function element(tag = '') {
      return {tag, children: [], textContent: '', value: '', attrs: {}, listeners: {}, disabled: false,
        append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
        setAttribute(k, v) { this.attrs[k] = v; }, addEventListener(k, v) { this.listeners[k] = v; },
        focus(options) { context.document.activeElement = this; this.focusOptions = options; },
        click() { this.clicked = true; if (this.download) downloads.push(this.download); }, set innerHTML(_) { throw Error('Unsafe HTML sink'); }};
    }
    const byId = id => { if (!nodes.has(id)) nodes.set(id, Object.assign(element(), {id})); return nodes.get(id); };
    const allText = node => node.textContent + ' ' + node.children.map(allText).join(' ');
    const context = {
      byId, document: {createElement: element}, Date, Uint8Array, TextDecoder, TextEncoder, AbortController, Blob,
      localHudLaunch: {mode: 'source', command: "'/tmp/reviewed checkout/.venv/bin/python' -m megalodon hud"},
      URL: {createObjectURL(blob) {artifacts.push(blob); return 'blob:local-check-test';}, revokeObjectURL(url) {revoked.push(url);}},
      textNode: (tag, text = '', className = '') => Object.assign(element(tag), {textContent: text, className}),
      referenceExactKeys: (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k)),
      formatRefreshTime: date => date.toISOString(),
      toolAcquisition: Object.fromEntries(['suricata','scapy','clamav','osquery','qwen','nmap','ossec','greenbone','zabbix','nagios','tshark','zeek','nftables'].map(id => [id, {url: 'https://publisher.example/' + id}])),
      window: {setTimeout(fn, delay) {const id = ++timerId; timers.set(id, {fn, delay}); return id;}, clearTimeout(id) {timers.delete(id);}},
      report,
      fetch: async () => {throw Error('PRIVATE_PATH');},
    };
    vm.createContext(context); vm.runInContext(code, context, {timeout: 1000});
    const run = value => vm.runInContext(value, context, {timeout: 1000});
    const response = (value, status = 200) => {
      const bytes = new TextEncoder().encode(JSON.stringify(value)); let sent = false;
      return {ok: status === 200, status, headers: {get: () => String(bytes.length)},
        body: {getReader: () => ({read: async () => sent ? {done:true} : {done:false, value:(sent=true, bytes)}, cancel: async () => {}})}};
    };
    assert.equal(calls.length, 0, 'Checks must not run automatically');
    assert.equal(run('hudLaunchCommand({})'), context.localHudLaunch.command);
    assert.match(byId('setup-launch-intro').textContent, /source environment/);
    assert.equal(byId('setup-source-launch').hidden, false);
    assert.equal(byId('help-source-launch').hidden, false);
    assert.equal(byId('setup-command').textContent, context.localHudLaunch.command);
    assert.equal(byId('setup-copy').disabled, false);
    context.localHudLaunch = {mode: 'desktop', command: "'/home/example/.local/bin/megalodon-hud' --config '/home/example/.config/MEGALODON/settings.toml'"};
    run('renderLaunchHelp()');
    assert.match(byId('setup-launch-intro').textContent, /application menu/);
    assert.match(byId('help-launch-intro').textContent, /stable launcher/);
    assert.equal(byId('setup-source-launch').hidden, true);
    assert.equal(byId('help-source-launch').hidden, true);
    assert.equal(run('hudLaunchCommand({})'), context.localHudLaunch.command);
    assert.equal(run('hudLaunchCommand({config: "/tmp/override.toml"})'), context.localHudLaunch.command + " --config '/tmp/override.toml'");
    assert.match(byId('setup-config-note').textContent, /overrides that default/);
    for (const invalid of [{mode: 'desktop', command: 'safe', extra: 'PRIVATE'}, {mode: 'bogus', command: 'safe'}, {mode: 'source', command: ''}, {mode: 'source', command: 'bad\ncommand'}, null]) {
      context.localHudLaunch = invalid;
      assert.throws(() => run('hudLaunchCommand({})'));
      run('renderLaunchHelp()');
      assert.equal(byId('setup-copy').disabled, true);
      assert.equal(byId('setup-reopen-copy').disabled, true);
      assert.doesNotMatch(byId('setup-launch-intro').textContent, /PRIVATE|bad\ncommand/);
    }
    context.localHudLaunch = {mode: 'source', command: "'/tmp/reviewed checkout/.venv/bin/python' -m megalodon hud"};
    run('renderLaunchHelp()');
    run('renderSoftwareShelf()');
    assert.equal(byId('setup-software-list').children.length, 2);
    byId('setup-software-search').value = 'Zeek';
    run('renderSoftwareShelf()');
    assert.equal(byId('setup-software-list').children[0].id, 'software-zeek');
    byId('setup-software-search').value = 'not-a-tool';
    run('renderSoftwareShelf()');
    assert.match(allText(byId('setup-software-list')), /No software matches/);
    byId('setup-software-search').value = '';
    byId('setup-software-workflow').value = 'all';
    run('renderSoftwareShelf()');
    assert.equal(byId('setup-software-list').children.length, 15);
    context.fetch = async (path, options) => {calls.push({path, options}); return response(report);};
    context.document.activeElement = byId('setup-check');
    await run('runLocalChecks()');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, '/api/local-checks');
    assert.equal(calls[0].options.headers['X-Megalodon-Check'], '1');
    assert.equal(calls[0].options.mode, 'same-origin');
    assert.equal(calls[0].options.redirect, 'error');
    assert.equal(calls[0].options.credentials, 'omit');
    assert.equal(byId('setup-check').disabled, false);
    assert.equal(context.document.activeElement, byId('setup-check'));
    assert.equal(byId('setup-check').focusOptions.preventScroll, true);
    assert.equal(byId('setup-download-report').disabled, false);
    assert.match(allText(byId('setup-check-results')), /Python.*SQLite/);
    assert.match(allText(byId('setup-check-results')), /first successful import, reopen the HUD/);
    assert.equal(timers.size, 0);
    byId('setup-download-report').listeners.click();
    assert.deepEqual(downloads, ['megalodon-local-checks.json']);
    assert.deepEqual(JSON.parse(await artifacts[0].text()), report);
    for (const timer of timers.values()) timer.fn();
    timers.clear();
    assert.deepEqual(revoked, ['blob:local-check-test']);
    const guidance = id => byId('setup-software-list').children.find(row => row.id === 'software-' + id).children.find(node => node.tag === 'details');
    const oldGuidance = guidance('python');
    oldGuidance.open = true; oldGuidance.listeners.toggle();
    await run('runLocalChecks("python")');
    assert.equal(guidance('python').open, true, 'Checks should preserve expanded instructions');
    oldGuidance.open = false; oldGuidance.listeners.toggle();
    run('renderSoftwareShelf()');
    assert.equal(guidance('python').open, true, 'Removed nodes must not overwrite current instructions');
    const unchecked = structuredClone(report);
    unchecked.readiness.tools.forEach(tool => {tool.status = 'not_checked';});
    context.fetch = async () => response(unchecked);
    await run('runLocalChecks()');
    const optionalRow = () => byId('setup-check-results').children.find(row => allText(row).includes('Optional tools'));
    assert.match(allText(optionalRow()), /Unable to check/);
    assert.match(allText(optionalRow()), /0 found · 0 not found · 13 not checked/);
    assert.equal(optionalRow().children[0].textContent, '—');
    assert.doesNotMatch(optionalRow().children[0].className, /is-ready/);
    assert.equal(byId('setup-installed-count').textContent, 'Unable to check');
    const partial = structuredClone(unchecked);
    partial.readiness.tools[1].status = 'executable_found';
    partial.readiness.tools[2].status = 'not_found';
    context.fetch = async () => response(partial);
    await run('runLocalChecks()');
    assert.match(allText(optionalRow()), /1 found · 1 not found · 11 not checked/);
    assert.match(allText(optionalRow()), /Partial observation/);
    assert.equal(optionalRow().children[0].textContent, '—');
    run('setupState.readiness = JSON.parse(JSON.stringify(report.readiness)); setupState.readiness.tools[1].status = "not_found";');
    assert.match(run('toolPresenceText(1)'), /Not found/, 'Apps keeps its startup observation after the Home check finds the executable');
    assert.match(run('softwarePresence(softwareCatalog.find(item => item.id === "tshark"))'), /Executable found.*last check/);
    context.fetch = async () => response(report);
    await run('runLocalChecks()');
    for (const change of ['p.extra="PRIVATE"', 'p.source.extra="PRIVATE"', 'p.environment.platform="bogus"', 'p.checked_at="2026-02-30T00:00:00Z"', 'p.runtime.extra="PRIVATE"', 'p.runtime.tools[0].status="healthy"']) {
      assert.throws(() => run('{const p=JSON.parse(JSON.stringify(report));'+change+';validateLocalCheckReport(p)}'), change);
    }
    context.fetch = async () => {throw Error('PRIVATE_PATH');};
    await run('runLocalChecks()');
    assert.match(byId('setup-check-status').textContent, /Previous results are stale/);
    assert.doesNotMatch(byId('setup-check-status').textContent, /PRIVATE_PATH/);
    assert.equal(byId('setup-download-report').disabled, true);
    byId('setup-download-report').listeners.click();
    assert.equal(downloads.length, 1, 'A failed check must not export old results as current');
    assert.match(allText(byId('setup-check-results')), /Previous:/);
    let resolveRequest;
    context.fetch = () => new Promise(resolve => {resolveRequest = resolve;});
    const pending = run('runLocalChecks("zeek")');
    assert.equal(byId('setup-check').disabled, true);
    await run('runLocalChecks()');
    resolveRequest(response(report)); await pending;
    assert.equal(run('localCheckState.failed'), false);
    assert.equal(byId('setup-download-report').disabled, false);
    context.fetch = async () => response({}, 429);
    await run('runLocalChecks()');
    assert.match(byId('setup-check-status').textContent, /Wait five seconds/);
    await run('runLocalChecks()');
    assert.match(byId('setup-check-status').textContent, /already running/);
    run('localCheckState.retryAt=0');
    context.fetch = async () => response({}, 403);
    await run('runLocalChecks()');
    assert.match(byId('setup-check-status').textContent, /HUD mode/);
    context.fetch = async () => response({oversized: 'x'.repeat(20481)});
    await run('runLocalChecks()');
    assert.equal(run('localCheckState.failed'), true);
    context.fetch = (_, {signal}) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(Error('timeout'), {name:'AbortError'}))));
    const timed = run('runLocalChecks()');
    const timer = [...timers.values()][0];
    assert.equal(timer.delay, 5000);
    timer.fn(); await timed;
    assert.match(byId('setup-check-status').textContent, /timed out/);
    assert.equal(byId('setup-check').disabled, false);
    assert.equal(timers.size, 0);
    console.log('Explicit checks, validation, overlap, stale recovery, limits, timeout, and software filtering passed');
  } catch (error) {console.error(error); process.exitCode = 1;}
});
