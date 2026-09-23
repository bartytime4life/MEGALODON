const vm = require('node:vm');
const assert = require('node:assert/strict');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  try {
    const {code} = JSON.parse(input), nodes = new Map(), controls = [], requests = [];
    let enabled = false, confirmation = true, postStatus = 202;
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
          json: async () => postStatus === 202 ? {state: 'running', ...JSON.parse(options.body), output: []}
            : {error: 'tool management operator authorization required'}};
        return {ok: true, status: 200, json: async () => path === '/api/heartbeat'
          ? {schema: 'megalodon-tool-heartbeat-v1', checked_at: new Date().toISOString(), tools}
          : {tools: catalog, management: {enabled}, job: {state: 'idle'}}};
      },
    };
    vm.createContext(context);
    vm.runInContext(code, context, {timeout: 1000});
    const run = script => vm.runInContext(script, context, {timeout: 1000});
    const settled = () => new Promise(resolve => setImmediate(resolve));
    const posts = () => requests.filter(request => request.options.method === 'POST');
    await run('pollHeartbeat()');
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
    const model = run('installControl("qwen", "Qwen")');
    assert.equal(model.children[0].textContent, 'Download Qwen model');
    postStatus = 403;
    await model.children[0].events.click(); await settled();
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children[0].disabled, true);
    byId('tool-management-token').value = token;
    byId('tool-management-forget').events.click();
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children[0].disabled, true);
    byId('tool-management-token').value = token;
    enabled = false;
    await run('pollHeartbeat()');
    assert.equal(byId('tool-management-token').value, '');
    assert.equal(wrap.children.some(node => node.tag === 'button'), false);
    process.stdout.write('tool management browser checks passed\n');
  } catch (error) {process.stderr.write(error.stack + '\n'); process.exitCode = 1;}
});
