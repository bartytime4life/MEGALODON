const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  try {
    const {code, report} = JSON.parse(input), nodes = new Map(), calls = [], timers = new Map();
    const artifacts = [], downloads = [], revoked = [], copied = [];
    let clipboardFails = false;
    let timerId = 0;
    const contains = (node, target) => node === target || node.children.some(child => contains(child, target));
    function element(tag = '') {
      return {tag, tagName: tag.toUpperCase(), children: [], textContent: '', value: '', attrs: {}, listeners: {}, disabled: false,
        append(...items) { items.forEach(item => {item.parentElement = this;}); this.children.push(...items); },
        contains(target) { return contains(this, target); },
        replaceChildren(...items) {
          if (this.children.some(child => contains(child, context.document.activeElement))) context.document.activeElement = context.document.body;
          this.children.forEach(child => {child.parentElement = null;});
          this.children = []; this.append(...items);
        },
        closest(selector) {
          for (let node = this; node; node = node.parentElement) {
            if (selector === '.workspace-view' && String(node.className || '').split(/\s+/).includes('workspace-view')) return node;
          }
          return null;
        },
        setAttribute(k, v) { this.attrs[k] = v; }, addEventListener(k, v) { this.listeners[k] = v; },
        focus(options) { context.document.activeElement = this; this.focusOptions = options; },
        click() { this.clicked = true; if (this.download) downloads.push(this.download); }, set innerHTML(_) { throw Error('Unsafe HTML sink'); }};
    }
    const find = (node, id) => node.id === id ? node : node.children.map(child => find(child, id)).find(Boolean);
    const byId = id => {
      for (const node of nodes.values()) {const found = find(node, id); if (found) return found;}
      if (id.startsWith('software-')) return null;
      if (!nodes.has(id)) nodes.set(id, Object.assign(element(), {id}));
      return nodes.get(id);
    };
    const allText = node => node.textContent + ' ' + node.children.map(allText).join(' ');
    const context = {
      byId, document: {createElement: element, body: element('body'), hidden: false}, Date, Uint8Array, TextDecoder, TextEncoder, AbortController, Blob,
      localHudLaunch: {mode: 'source', command: "'/tmp/reviewed checkout/.venv/bin/python' -m megalodon hud"},
      localAccountCommands: null,
      URL: {createObjectURL(blob) {artifacts.push(blob); return 'blob:local-check-test';}, revokeObjectURL(url) {revoked.push(url);}},
      textNode: (tag, text = '', className = '') => Object.assign(element(tag), {textContent: text, className}),
      referenceExactKeys: (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k)),
      formatRefreshTime: date => date.toISOString(),
      toolAcquisition: Object.fromEntries(['suricata','scapy','clamav','osquery','qwen','nmap','tshark','zeek','nftables'].map(id => [id, {url: 'https://publisher.example/' + id}])),
      window: {setTimeout(fn, delay) {const id = ++timerId; timers.set(id, {fn, delay}); return id;}, clearTimeout(id) {timers.delete(id);}},
      navigator: {clipboard: {async writeText(value) {if (clipboardFails) throw Error('denied'); copied.push(value);}}},
      report,
      fetch: async () => {throw Error('PRIVATE_PATH');},
    };
    context.document.activeElement = context.document.body;
    const setupWorkspace = byId('workspace-setup'); setupWorkspace.className = 'workspace-view'; setupWorkspace.hidden = false;
    const softwareDisclosure = element('details'); softwareDisclosure.open = true;
    softwareDisclosure.append(element('summary'), byId('setup-software-search'), byId('setup-software-list'));
    setupWorkspace.append(byId('setup-check'), softwareDisclosure);
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
    assert.equal(byId('account-password-set-copy').disabled, true);
    assert.equal(byId('account-launch-build').disabled, false);
    byId('account-port').value = '8798';
    byId('account-launch-build').listeners.click();
    assert.equal(byId('account-launch-command').textContent, context.localHudLaunch.command + ' --port 8798 --require-sign-in');
    assert.match(byId('account-launch-feedback').textContent, /Stop the current HUD first/);
    await byId('account-launch-copy').listeners.click();
    assert.equal(copied.pop(), context.localHudLaunch.command + ' --port 8798 --require-sign-in');
    byId('account-port').value = '0';
    byId('account-port').listeners.input();
    assert.equal(byId('account-launch-copy').disabled, true);
    byId('account-launch-build').listeners.click();
    assert.match(byId('account-launch-feedback').textContent, /port from 1 to 65535/);
    byId('account-port').value = '';
    context.localAccountCommands = {set: 'unsafe\ncommand', status: 'status'};
    run('renderAccountHelp()');
    assert.equal(byId('account-password-set-copy').disabled, true);
    assert.doesNotMatch(byId('account-password-command').textContent, /unsafe/);
    context.localAccountCommands = {set: "'/tmp/reviewed checkout/.venv/bin/python' -m megalodon.local_install password set",
      status: "'/tmp/reviewed checkout/.venv/bin/python' -m megalodon.local_install password status"};
    run('renderAccountHelp()');
    assert.equal(byId('account-password-set-copy').disabled, false);
    await byId('account-password-set-copy').listeners.click();
    assert.equal(copied.pop(), context.localAccountCommands.set);
    await byId('account-password-status-copy').listeners.click();
    assert.equal(copied.pop(), context.localAccountCommands.status);
    assert.equal(byId('tool-management-command').textContent, context.localHudLaunch.command + ' --enable-tool-management');
    assert.equal(byId('tool-management-copy').disabled, false);
    assert.match(byId('tool-management-copy-status').textContent, /not been run/);
    await byId('tool-management-copy').listeners.click();
    assert.equal(copied.pop(), context.localHudLaunch.command + ' --enable-tool-management');
    assert.match(byId('tool-management-copy-status').textContent, /copied.*not run/i);
    clipboardFails = true;
    await byId('tool-management-copy').listeners.click();
    assert.match(byId('tool-management-copy-status').textContent, /Clipboard unavailable.*not run/);
    assert.match(byId('tool-management-command').textContent, /--enable-tool-management$/);
    clipboardFails = false;
    context.localHudLaunch = {mode: 'desktop', command: "'/home/example/.local/bin/megalodon-hud' --config '/home/example/.config/MEGALODON/settings.toml'"};
    run('renderLaunchHelp()');
    assert.match(byId('setup-launch-intro').textContent, /application menu/);
    assert.match(byId('help-launch-intro').textContent, /stable launcher/);
    assert.match(byId('setup-launch-intro').textContent, /background HUD keeps its existing settings/);
    assert.match(byId('help-launch-intro').textContent, /Explicit options start a separate foreground session.*Stop the current HUD first/);
    assert.equal(byId('setup-source-launch').hidden, true);
    assert.equal(byId('help-source-launch').hidden, true);
    assert.equal(run('hudLaunchCommand({})'), context.localHudLaunch.command);
    assert.equal(run('toolManagementLaunchCommand()'), context.localHudLaunch.command + ' --enable-tool-management');
    context.localHudLaunch = {mode: 'desktop', command: "'/home/example/.local/bin/megalodon-hud' --enable-tool-management --config '/home/example/.config/MEGALODON/settings.toml'"};
    assert.equal(run('toolManagementLaunchCommand()'), context.localHudLaunch.command, 'existing authorization flag must not be duplicated');
    context.localHudLaunch = {mode: 'desktop', command: "'/home/example/.local/bin/megalodon-hud' --enable-tool-management --enable-tool-management"};
    assert.throws(() => run('toolManagementLaunchCommand()'));
    context.localHudLaunch = {mode: 'desktop', command: "'/home/example/.local/bin/megalodon-hud' --config '/home/example/.config/MEGALODON/settings.toml'"};
    assert.equal(run('hudLaunchCommand({config: "/tmp/override.toml"})'), context.localHudLaunch.command + " --config '/tmp/override.toml'");
    assert.match(byId('setup-config-note').textContent, /overrides that default/);
    byId('setup-port').value = '8798';
    byId('setup-build').listeners.click();
    assert.equal(byId('setup-command').textContent, context.localHudLaunch.command + ' --port 8798');
    assert.match(byId('setup-feedback').textContent, /Command prepared, not run/);
    assert.match(byId('setup-feedback').textContent, /address printed by the new session/);
    await byId('setup-copy').listeners.click();
    assert.equal(copied.pop(), context.localHudLaunch.command + ' --port 8798');
    assert.equal(calls.length, 0, 'Preparing or copying a launch must not make a request');
    byId('setup-port').value = '0';
    byId('setup-port').listeners.input();
    assert.equal(byId('setup-copy').disabled, true);
    byId('setup-build').listeners.click();
    assert.equal(byId('setup-copy').disabled, true);
    assert.match(byId('setup-feedback').textContent, /port from 1 to 65535/);
    byId('setup-port').value = '';
    byId('setup-build').listeners.click();
    assert.equal(byId('setup-command').textContent, context.localHudLaunch.command);
    for (const invalid of [{mode: 'desktop', command: 'safe', extra: 'PRIVATE'}, {mode: 'bogus', command: 'safe'}, {mode: 'source', command: ''}, {mode: 'source', command: 'bad\ncommand'}, null]) {
      context.localHudLaunch = invalid;
      assert.throws(() => run('hudLaunchCommand({})'));
      run('renderLaunchHelp()');
      assert.equal(byId('setup-copy').disabled, true);
      assert.equal(byId('setup-reopen-copy').disabled, true);
      assert.equal(byId('tool-management-copy').disabled, true);
      assert.equal(byId('tool-management-command').textContent, 'Restart command for Install/Start/Open unavailable');
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
    assert.equal(byId('setup-software-list').children.length, 13);
    context.fetch = async (path, options) => {calls.push({path, options}); return response(report);};
    context.document.activeElement = byId('setup-check');
    const successfulCheck = await run('runLocalChecks()');
    assert.equal(successfulCheck.ok, true);
    assert.match(successfulCheck.message, /Check complete/);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, '/api/local-checks');
    assert.equal(calls[0].options.headers['X-Megalodon-Check'], '1');
    assert.equal(calls[0].options.mode, 'same-origin');
    assert.equal(calls[0].options.redirect, 'error');
    assert.equal(calls[0].options.credentials, 'same-origin');
    assert.equal(byId('setup-check').disabled, false);
    assert.equal(context.document.activeElement, byId('setup-check'));
    assert.equal(byId('setup-check').focusOptions.preventScroll, true);
    assert.equal(byId('setup-download-report').disabled, false);
    assert.match(allText(byId('setup-check-results')), /Python.*SQLite/);
    assert.match(allText(byId('setup-check-results')), /importing into the configured location, refresh the HUD/);
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
    assert.match(allText(optionalRow()), /0 found · 0 not found · 11 not checked/);
    assert.equal(optionalRow().children[0].textContent, '—');
    assert.doesNotMatch(optionalRow().children[0].className, /is-ready/);
    assert.equal(byId('setup-installed-count').textContent, 'Unable to check');
    const partial = structuredClone(unchecked);
    partial.readiness.tools[1].status = 'executable_found';
    partial.readiness.tools[2].status = 'not_found';
    context.fetch = async () => response(partial);
    await run('runLocalChecks()');
    assert.match(allText(optionalRow()), /1 found · 1 not found · 9 not checked/);
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
    const failedCheck = await run('runLocalChecks()');
    assert.equal(failedCheck.ok, false);
    assert.match(failedCheck.message, /could not be completed/);
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
    for (const outcome of ['success', 'failure']) {
      for (const destination of ['setup-software-search', 'workspace-tab-live']) {
        let finish;
        context.fetch = () => new Promise((resolve, reject) => {
          finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
        });
        byId('setup-check').focus();
        const checking = byId('setup-check').listeners.click();
        const nextControl = byId(destination); nextControl.focus();
        setupWorkspace.hidden = destination === 'workspace-tab-live';
        finish(); await checking;
        assert.equal(context.document.activeElement, nextControl,
          `${outcome}: a completed check must preserve the operator's focus on ${destination}`);
        setupWorkspace.hidden = false;
      }
      let finish;
      context.fetch = () => new Promise((resolve, reject) => {
        finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
      });
      byId('setup-check').focus();
      const hiddenCheck = byId('setup-check').listeners.click();
      setupWorkspace.hidden = true; context.document.activeElement = context.document.body;
      finish(); await hiddenCheck;
      assert.equal(context.document.activeElement, context.document.body,
        `${outcome}: focus must not return to a hidden Setup workspace`);
      setupWorkspace.hidden = false;

      context.fetch = async () => {
        if (outcome === 'failure') throw Error('PRIVATE_PATH');
        return response(report);
      };
      const priorRuntimeButton = byId('software-check-python'); priorRuntimeButton.focus();
      const runtimeCheck = priorRuntimeButton.listeners.click();
      assert.equal(context.document.activeElement, context.document.body,
        'The shelf render removes the initiating runtime-check button');
      await runtimeCheck;
      assert.notEqual(byId('software-check-python'), priorRuntimeButton);
      assert.equal(context.document.activeElement, byId('software-check-python'),
        `${outcome}: the replacement runtime-check button must recover otherwise lost focus`);
      assert.equal(context.document.activeElement.focusOptions.preventScroll, true);

      for (const destination of ['software-summary-python', 'software-primary-python', 'software-guide-zeek']) {
        context.fetch = () => new Promise((resolve, reject) => {
          finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
        });
        byId('setup-check').focus();
        const shelfCheck = byId('setup-check').listeners.click();
        const guidance = byId(destination === 'software-guide-zeek' ? 'software-guidance-zeek' : 'software-guidance-python');
        guidance.open = destination === 'software-guide-zeek'; guidance.listeners.toggle();
        const previousControl = byId(destination); previousControl.focus();
        finish(); await shelfCheck;
        const replacementControl = byId(destination);
        assert.notEqual(replacementControl, previousControl);
        assert.equal(context.document.activeElement, replacementControl,
          `${outcome}: a completed check must retain focus moved to ${destination}`);
        assert.equal(replacementControl.focusOptions.preventScroll, true);
      }

      context.fetch = () => new Promise((resolve, reject) => {
        finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
      });
      byId('setup-check').focus();
      const filteredCheck = byId('setup-check').listeners.click();
      byId('software-summary-python').focus();
      // A changed filter is applied by the completion render, so the former
      // shelf target has no equivalent. Do not return to the initiating button.
      byId('setup-software-search').value = 'Zeek';
      finish(); await filteredCheck;
      assert.equal(byId('software-summary-python'), null);
      assert.equal(context.document.activeElement, byId('setup-software-search'),
        `${outcome}: a filtered-away shelf target should recover focus at search`);
      byId('setup-software-search').value = ''; run('renderSoftwareShelf()');

      context.fetch = () => new Promise((resolve, reject) => {
        finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
      });
      byId('setup-check').focus();
      const collapsedGuidanceCheck = byId('setup-check').listeners.click();
      const zeekGuidance = byId('software-guidance-zeek');
      zeekGuidance.open = true; zeekGuidance.listeners.toggle();
      byId('software-guide-zeek').focus();
      zeekGuidance.open = false; zeekGuidance.listeners.toggle();
      finish(); await collapsedGuidanceCheck;
      assert.equal(context.document.activeElement, byId('setup-software-search'),
        `${outcome}: a link inside collapsed guidance must not receive focus`);
      assert.equal(byId('software-guide-zeek').focusOptions, undefined);

      context.fetch = () => new Promise((resolve, reject) => {
        finish = () => outcome === 'success' ? resolve(response(report)) : reject(Error('PRIVATE_PATH'));
      });
      byId('software-check-python').focus();
      const collapsedShelfCheck = byId('software-check-python').listeners.click();
      softwareDisclosure.open = false; context.document.activeElement = context.document.body;
      finish(); await collapsedShelfCheck;
      assert.equal(context.document.activeElement, context.document.body,
        `${outcome}: a collapsed software shelf must not recover focus inside it`);
      softwareDisclosure.open = true;
    }
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
    console.log('Explicit checks, validation, overlap, focus ownership, stale recovery, limits, timeout, and software filtering passed');
  } catch (error) {console.error(error); process.exitCode = 1;}
});
