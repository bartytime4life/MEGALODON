const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  try {
    const {code} = JSON.parse(input), nodes = new Map(), controls = [], requests = [];
    let enabled = false, confirmation = true, postStatus = 202, postState = 'running';
    let observedJob = {state: 'idle'};
    const token = 't'.repeat(32);
    function element(tag = '') {
      return {tag, children: [], textContent: '', value: '', events: {},
        append(...items) {this.children.push(...items);},
        replaceChildren(...items) {this.children = items;},
        setAttribute() {}, addEventListener(name, fn) {this.events[name] = fn;}};
    }
    const byId = id => {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);};
    const tools = [
      {id: 'scapy', installed: 'no', light: 'red', service: 'none'},
      {id: 'zabbix', installed: 'yes', light: 'amber', expects_service: true, service: 'stopped'},
      {id: 'qwen', installed: 'yes', light: 'amber', expects_service: true, service: 'running', model: 'missing'},
    ];
    const catalog = [
      {id: 'scapy', method: 'pip', one_click: true, terminal: 'python -m pip install scapy', summary: 'Synthetic Scapy package'},
      {id: 'zabbix', method: 'apt', one_click: true, startable: true, start_terminal: 'sudo systemctl start zabbix-agent.service'},
      {id: 'qwen', method: 'ollama', one_click: true, terminal: 'ollama pull qwen2.5:7b', summary: 'Synthetic example model'},
    ];
    const context = {Date, Map, AbortController, workflowToolIds: tools.map(tool => tool.id), byId,
      formatRefreshTime: date => date.toISOString(),
      textNode: (tag, text = '', className = '') => Object.assign(element(tag), {textContent: text, className}),
      document: {visibilityState: 'visible', createElement: element, addEventListener() {},
        querySelectorAll(selector) {return selector === '[data-heartbeat-install]' ? controls : [];}},
      window: {setTimeout() {return 1;}, clearTimeout() {}, confirm() {return confirmation;}},
      localStorage: new Proxy({}, {get() {throw Error('token must not use localStorage');}}),
      sessionStorage: new Proxy({}, {get() {throw Error('token must not use sessionStorage');}}),
      fetch: async (path, options) => {
        requests.push({path, options});
        if (options.method === 'POST') return {ok: postStatus === 202, status: postStatus,
          json: async () => postStatus === 202 ? {state: postState, ...JSON.parse(options.body), output: []}
            : {error: 'tool management operator authorization required'}};
        return {ok: true, status: 200, json: async () => path === '/api/heartbeat'
          ? {schema: 'megalodon-tool-heartbeat-v1', checked_at: new Date().toISOString(), tools}
          : {tools: catalog, management: {enabled}, job: observedJob}};
      },
    };
    vm.createContext(context);
    vm.runInContext(code, context, {timeout: 1000});
    const run = script => vm.runInContext(script, context, {timeout: 1000});
    const settled = () => new Promise(resolve => setImmediate(resolve));
    const posts = () => requests.filter(request => request.options.method === 'POST');
    await run('pollHeartbeat()');
    const serviceRows = () => byId('app-service-start-list').children;
    const zabbixRow = () => serviceRows().find(row => row.children[0].children[0].children[1].textContent === 'Zabbix');
    assert.equal(serviceRows().length, 2, 'only installed service tools appear in Apps');
    assert.equal(zabbixRow().children[1].children[0].disabled, true, 'Apps start needs opt-in');
    run("heartbeatState.report.checked_at = new Date(Date.now() - 120000).toISOString(); renderAppServiceStarts()");
    assert.match(byId('app-service-start-list').textContent, /observations are stale/);
    run('heartbeatState.report.checked_at = new Date().toISOString(); renderAppServiceStarts()');
    const wrap = run('installControl("scapy", "Scapy")'); controls.push(wrap);
    assert.equal(byId('tool-management-token').disabled, true);
    assert.equal(wrap.children.some(node => node.tag === 'button'), false);
    assert.match(wrap.children[0].textContent, /Observation mode.*terminal/);
    await run('startInstall("scapy", "Scapy", heartbeatState.catalog[0])');
    assert.equal(posts().length, 0);
    enabled = true;
    await run('pollHeartbeat()');
    assert.equal(byId('tool-management-token').disabled, false);
    assert.equal(wrap.children[0].disabled, true);
    byId('tool-management-token').value = token;
    byId('tool-management-token').events.input();
    assert.equal(wrap.children[0].disabled, false);
    confirmation = false;
    await wrap.children[0].events.click();
    assert.equal(posts().length, 0);
    confirmation = true;
    await wrap.children[0].events.click(); await settled();
    assert.equal(posts().length, 1);
    assert.deepEqual(JSON.parse(posts()[0].options.body), {tool: 'scapy', action: 'install'});
    assert.equal(posts()[0].options.headers['X-Megalodon-Install-Token'], token);
    for (const request of requests.filter(request => request.options.method !== 'POST')) {
      assert.equal(request.options.headers['X-Megalodon-Install-Token'], undefined);
      assert.equal(request.path.includes(token), false);
    }
    const service = run('installControl("zabbix", "Zabbix")'); controls.push(service);
    assert.equal(service.children[0].textContent, 'Start service');
    await service.children[0].events.click(); await settled();
    assert.equal(JSON.parse(posts()[1].options.body).action, 'start');
    observedJob = {state: 'idle'};
    await run('pollHeartbeat()');
    assert.equal(zabbixRow().children[1].children[0].disabled, false, 'Apps start is available with a launch token');
    await zabbixRow().children[1].children[0].events.click(); await settled();
    assert.deepEqual(JSON.parse(posts().at(-1).options.body), {tool: 'zabbix', action: 'start'});
    assert.match(byId('app-service-start-feedback').textContent, /Starting Zabbix/);
    const model = run('installControl("qwen", "Qwen")');
    assert.equal(model.children[0].textContent, 'Download Qwen model');
    postStatus = 403;
    await model.children[0].events.click(); await settled();
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children[0].disabled, true);
    assert.match(byId('setup-check-status').textContent, /could not be installed: tool management operator authorization required/);
    byId('tool-management-token').value = token;
    byId('tool-management-forget').events.click();
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children[0].disabled, true);
    const afterForget = posts().length;
    await run('startInstall("scapy", "Scapy", heartbeatState.catalog[0])');
    assert.equal(posts().length, afterForget, 'Forgetting authorization prevents further POSTs');

    postStatus = 202;
    byId('tool-management-token').value = token;
    for (const [tool, name, entryIndex, action, command, pending] of [
      ['scapy', 'Scapy', 0, 'install', 'Installation command', 'Installing Scapy'],
      ['zabbix', 'Zabbix', 1, 'start', 'Service-start command', 'Starting Zabbix'],
    ]) {
      for (const terminal of ['succeeded', 'failed']) {
        const expected = terminal === 'succeeded'
          ? `${command} finished. Status is checked separately.`
          : `${command} failed. See the tool for details.`;
        postState = terminal;
        observedJob = {tool, action, state: terminal, output: []};
        await run(`startInstall('${tool}', '${name}', heartbeatState.catalog[${entryIndex}], '${action}')`);
        await settled();
        assert.equal(byId('setup-check-status').textContent, expected, `${action}: immediate ${terminal}`);
        assert.equal(JSON.parse(posts().at(-1).options.body).action, action);

        postState = 'running';
        observedJob = {tool, action, state: 'running', output: []};
        await run(`startInstall('${tool}', '${name}', heartbeatState.catalog[${entryIndex}], '${action}')`);
        await settled();
        assert.match(byId('setup-check-status').textContent, new RegExp(pending));
        observedJob = {...observedJob, state: terminal};
        await run('pollHeartbeat()');
        assert.equal(byId('setup-check-status').textContent, expected, `${action}: polled ${terminal}`);
        assert.doesNotMatch(byId('setup-check-status').textContent, /Installing|Starting|healthy|integrated|lights refreshed/);
      }
    }
    // A running job for one tool silently disabled every other tool's
    // Install/Start button with no indication why; both surfaces must now
    // say so instead of leaving an unexplained disabled control.
    observedJob = {tool: 'scapy', action: 'install', state: 'running', output: []};
    await run('pollHeartbeat()');
    const zabbixAction = zabbixRow().children[1];
    assert.equal(zabbixAction.children[0].disabled, true, 'a different tool\'s running job disables this Start button');
    assert.match(zabbixAction.children[1].textContent, /Another install or service start is already running/);
    const zabbixCard = run('installControl("zabbix", "Zabbix")');
    assert.equal(zabbixCard.children[0].disabled, true);
    assert.match(zabbixCard.children[0].title, /Another install or service start is already running/);
    const scapyCard = run('installControl("scapy", "Scapy")');
    assert.equal(scapyCard.children[0].textContent, 'Installing…', 'the running job\'s own button shows progress, not the elsewhere hint');
    assert.doesNotMatch(scapyCard.children[0].title, /Another install or service start/);
    observedJob = {state: 'idle'};
    await run('pollHeartbeat()');
    byId('tool-management-token').value = token;
    enabled = false;
    await run('pollHeartbeat()');
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children.some(node => node.tag === 'button'), false);
    process.stdout.write('tool management browser checks passed\n');
  } catch (error) {process.stderr.write(error.stack + '\n'); process.exitCode = 1;}
});
