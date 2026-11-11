const assert = require('node:assert/strict');
const vm = require('node:vm');
const {code, scenario} = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));

function harness() {
  const nodes = new Map(), controls = [], requests = [], copied = [], confirmations = [];
  let context;
  function element(tag = 'div') {
    return {tagName: tag.toUpperCase(), children: [], attributes: {}, events: {}, value: '', textContent: '', hidden: false, disabled: false, open: false,
      append(...items) {for (const child of items) {child.parentElement = this; this.children.push(child);}},
      contains(target) {return this === target || this.children.some(child => child.contains(target));},
      replaceChildren(...items) {
        if (this.children.some(child => child.contains(context.document.activeElement))) context.document.activeElement = context.document.body;
        for (const child of this.children) child.parentElement = null;
        this.children = []; this.append(...items);
      },
      querySelectorAll(selector) {
        const tags = selector.split(',').map(tag => tag.toUpperCase()), matches = [];
        for (const child of this.children) {
          if (tags.includes(child.tagName)) matches.push(child);
          matches.push(...child.querySelectorAll(selector));
        }
        return matches;
      },
      querySelector(selector) {return this.querySelectorAll(selector)[0] || null;},
      setAttribute(key, value) {this.attributes[key] = value;},
      addEventListener(key, callback) {this.events[key] = callback;},
      focus(options) {context.document.activeElement = this; this.focusOptions = options;},
      click() {if (!this.disabled) return this.events.click?.();},
    };
  }
  const byId = id => {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id);};
  const tools = [
    {id: 'suricata', installed: 'yes', light: 'amber', expects_service: true, service: 'stopped'},
    {id: 'scapy', installed: 'no', light: 'red', expects_service: false, service: 'none'},
    {id: 'qwen', installed: 'yes', light: 'green', expects_service: true, service: 'running', model: 'present'},
  ];
  const catalog = [
    {id: 'suricata', method: 'apt', one_click: true, startable: true, terminal: 'sudo apt-get install suricata',
      start_terminal: 'sudo systemctl start suricata.service', uninstall_terminal: 'sudo apt-get remove --no-install-recommends suricata'},
    {id: 'scapy', method: 'pip', one_click: true, terminal: 'python -m pip install scapy', uninstall_terminal: 'python -m pip uninstall scapy'},
    {id: 'qwen', method: 'ollama', one_click: true, terminal: 'ollama pull qwen2.5:7b', uninstall_terminal: 'ollama rm qwen2.5:7b'},
  ];
  context = {Date, Map, AbortController, tools, catalog, byId, workflowToolIds: tools.map(tool => tool.id),
    textNode: (tag, text = '', className = '') => Object.assign(element(tag), {textContent: text, className}),
    formatRefreshTime: date => date.toISOString(),
    document: {body: element('body'), hidden: false, visibilityState: 'visible', createElement: element, addEventListener() {},
      querySelectorAll: selector => selector === '[data-heartbeat-install]' ? controls : []},
    window: {setTimeout() {return 1;}, clearTimeout() {}, confirm(message) {confirmations.push(message); return false;}},
    navigator: {clipboard: {async writeText(value) {copied.push(value);}}},
    fetch: async (path, options) => {requests.push({path, options}); throw Error('Repaint must not make requests');},
  };
  context.document.activeElement = context.document.body;
  vm.createContext(context); vm.runInContext(code, context, {timeout: 1000});
  const run = script => vm.runInContext(script, context, {timeout: 1000});
  run("heartbeatState.catalog = catalog; heartbeatState.byId = new Map(tools.map(tool => [tool.id, tool])); heartbeatState.report = {checked_at: new Date().toISOString(), tools}; heartbeatState.managementEnabled = true; heartbeatState.sessionToken = 't'.repeat(32)");
  const wrap = id => {
    const result = run(`installControl(${JSON.stringify(id)}, ${JSON.stringify(id)})`);
    controls.push(result); context.document.body.append(result); return result;
  };
  const repaint = () => run('repaintHeartbeat()');
  const meaningfulChange = () => run("heartbeatState.job = {tool: 'scapy', action: 'install', state: 'failed', output: ['A synthetic job update']}");
  function readOnly() {
    assert.equal(requests.length, 0, 'Repaint and command copying must not submit or execute work');
    assert.equal(confirmations.length, 0, 'Repaint must not request installation confirmation');
  }
  return {context, tools, catalog, wrap, repaint, meaningfulChange, readOnly, copied, element};
}

const plan = wrap => wrap.querySelector('details');
const review = wrap => plan(wrap)?.querySelector('summary');
const copy = wrap => plan(wrap)?.querySelector('button');

function interruptRender(h, wrap, stage) {
  const method = stage === 'partial-append' ? 'append' : 'replaceChildren';
  const original = wrap[method];
  let interrupted = false;
  wrap[method] = function (...items) {
    if (interrupted) return original.apply(this, items);
    interrupted = true;
    if (stage !== 'before-replace') original.apply(this, items);
    throw Error('Synthetic repaint interruption');
  };
  try { assert.throws(() => h.repaint(), /Synthetic repaint interruption/); }
  finally { wrap[method] = original; }
  assert.equal(interrupted, true, 'The changed observation reaches the injected fault');
  assert.equal(wrap.hidden, true, 'An interrupted rendering must not expose old or partial controls');
  assert.equal(wrap.heartbeatControls.size, 0, 'Failed controls cannot supply focus identity');
  assert.equal(wrap.heartbeatRemoval, null, 'An interrupted review requires fresh review');
  for (const button of wrap.querySelectorAll('button')) {
    assert.equal(button.disabled, true, 'Surviving action controls are disabled');
    button.click();
  }
  assert.deepEqual(h.copied, [], 'Failure handling never copies'); h.readOnly();
}

async function exercise() {
  const h = harness(), wrap = h.wrap(scenario === 'model-focus' ? 'qwen' : 'suricata');
  if (scenario === 'removal-summary') {
    const oldPlan = plan(wrap); oldPlan.open = true; review(wrap).focus();
    h.meaningfulChange(); h.repaint();
    assert.notEqual(plan(wrap), oldPlan, 'A changed job actually repaints the control');
    assert.equal(plan(wrap).open, true, 'The same reviewed removal command stays expanded');
    assert.equal(h.context.document.activeElement, review(wrap));
    assert.equal(review(wrap).focusOptions.preventScroll, true);
    plan(wrap).open = false; review(wrap).focus();
    h.tools[0].service = 'running'; h.repaint();
    assert.equal(plan(wrap).open, false, 'A closed review stays closed');
    assert.equal(h.context.document.activeElement, review(wrap), 'Removing an earlier Start button must not change summary focus');
    assert.deepEqual(h.copied, []);
  } else if (scenario === 'removal-copy') {
    const oldPlan = plan(wrap); oldPlan.open = true; copy(wrap).focus();
    h.tools[0].service = 'running'; h.repaint();
    assert.notEqual(plan(wrap), oldPlan);
    assert.equal(plan(wrap).open, true);
    assert.equal(h.context.document.activeElement, copy(wrap), 'Copy focus follows the reviewed command when the Start control disappears');
    assert.equal(copy(wrap).focusOptions.preventScroll, true);
    assert.deepEqual(h.copied, [], 'Repainting never copies a command');
    await copy(wrap).click();
    assert.deepEqual(h.copied, [h.catalog[0].uninstall_terminal], 'Only an explicit Copy click writes the exact reviewed command');
    h.meaningfulChange(); h.repaint();
    assert.equal(plan(wrap).open, true);
    assert.equal(h.context.document.activeElement, copy(wrap));
    assert.equal(h.copied.length, 1);
  } else if (scenario === 'changed-command') {
    plan(wrap).open = true; copy(wrap).focus();
    h.catalog[0].uninstall_terminal = 'sudo apt-get purge --no-install-recommends suricata'; h.repaint();
    assert.equal(plan(wrap).open, false, 'A changed command needs a new review');
    assert.equal(plan(wrap).querySelector('code').textContent, h.catalog[0].uninstall_terminal);
    assert.equal(h.context.document.activeElement, h.context.document.body, 'Focus must not transfer to a different command');
    assert.deepEqual(h.copied, []);
    plan(wrap).open = true; copy(wrap).focus();
    h.tools[1].installed = 'yes'; h.catalog[1].uninstall_terminal = h.catalog[0].uninstall_terminal;
    wrap.heartbeatTool = 'scapy'; h.repaint();
    assert.equal(plan(wrap).open, false, 'An identical command belonging to a different tool needs a new review');
    assert.equal(h.context.document.activeElement, h.context.document.body);
  } else if (scenario === 'availability') {
    for (const reason of ['stale', 'failed', 'catalog', 'catalog-failed', 'uninstalled', 'unknown-install', 'missing-tool']) {
      const current = harness(), target = current.wrap('suricata');
      plan(target).open = true; copy(target).focus();
      const change = {stale: "heartbeatState.report.checked_at = '2000-01-01T00:00:00Z'", failed: 'heartbeatState.failed = true',
        catalog: 'heartbeatState.catalog = null', 'catalog-failed': 'heartbeatState.catalogFailed = true',
        uninstalled: "tools[0].installed = 'no'", 'unknown-install': "tools[0].installed = 'unknown'", 'missing-tool': "heartbeatState.byId.delete('suricata')"}[reason];
      vm.runInContext(change, current.context); current.repaint();
      assert.equal(plan(target), null, reason + ': unavailable evidence removes the removal plan');
      assert.equal(current.context.document.activeElement, current.context.document.body, reason + ': the old copy target is gone');
      vm.runInContext("heartbeatState.failed = false; heartbeatState.catalogFailed = false; heartbeatState.catalog = catalog; tools[0].installed = 'yes'; heartbeatState.byId.set('suricata', tools[0]); heartbeatState.report.checked_at = new Date().toISOString()", current.context);
      current.repaint();
      assert.equal(plan(target).open, false, reason + ': recovered evidence requires a fresh review');
      assert.deepEqual(current.copied, []); current.readOnly();
    }
  } else if (scenario === 'model-focus') {
    h.tools[2].selected_model = {model: 'local-test-model'}; h.repaint();
    const oldLink = wrap.querySelector('a'); oldLink.focus();
    h.meaningfulChange(); h.repaint();
    const link = wrap.querySelector('a');
    assert.notEqual(link, oldLink, 'The selected-model branch actually repaints');
    assert.equal(link.href, '#support-model-title');
    assert.equal(h.context.document.activeElement, link, 'The selected-model early branch restores its navigation link');
    assert.equal(link.focusOptions.preventScroll, true);
    const outside = h.element('button'); h.context.document.body.append(outside); outside.focus();
    h.tools[2].selected_model.model = 'another-local-test-model'; h.repaint();
    assert.equal(h.context.document.activeElement, outside, 'An update must not reclaim focus moved elsewhere');
  } else if (scenario === 'action-identity') {
    h.tools[0].installed = 'no'; h.repaint();
    const install = wrap.querySelector('button'); assert.match(install.textContent, /Install/); install.focus();
    h.tools[0].installed = 'yes'; h.repaint();
    const start = wrap.querySelector('button'); assert.equal(start.textContent, 'Start service');
    assert.equal(h.context.document.activeElement, h.context.document.body, 'An Install button must not transfer focus to Start at the same index');
    start.focus(); h.catalog[0].start_terminal = 'sudo systemctl start another-test.service'; h.repaint();
    assert.equal(h.context.document.activeElement, h.context.document.body, 'A different start command must not inherit focus');
  } else if (scenario === 'visibility') {
    for (const reason of ['hidden-wrap', 'collapsed-parent', 'closed-plan', 'hidden-page']) {
      const current = harness(), target = current.wrap('suricata');
      plan(target).open = true; copy(target).focus();
      if (reason === 'hidden-wrap') target.hidden = true;
      if (reason === 'collapsed-parent') {
        const parent = current.element('details'); parent.append(target); current.context.document.body.append(parent);
      }
      if (reason === 'closed-plan') plan(target).open = false;
      if (reason === 'hidden-page') current.context.document.hidden = true;
      current.meaningfulChange(); current.repaint();
      assert.equal(current.context.document.activeElement, current.context.document.body, reason + ': hidden controls must not recover focus');
      assert.deepEqual(current.copied, []); current.readOnly();
    }
  } else if (scenario === 'interrupted-render') {
    for (const stage of ['before-replace', 'after-replace', 'partial-append']) {
      const current = harness(), target = current.wrap('suricata');
      plan(target).open = true; copy(target).focus();
      current.tools[0].service = 'running';
      interruptRender(current, target, stage);
      current.repaint();
      assert.equal(target.hidden, false, 'Successful retry restores prior visibility');
      assert.equal(target.querySelectorAll('button').some(node => node.textContent === 'Start service'), false,
        'The identical heartbeat retries and removes the obsolete Start control');
      assert.equal(plan(target).open, false, 'Retry does not restore interrupted review');
      assert.equal(current.context.document.activeElement, current.context.document.body, 'Retry does not inherit failed focus');
      const recovered = plan(target); current.repaint();
      assert.equal(plan(target), recovered, 'Only the completed retry is cached');
      assert.deepEqual(current.copied, []); current.readOnly();
    }
  } else if (scenario === 'interrupted-invalidation') {
    for (const reason of ['changed-command', 'stale', 'catalog-failed', 'missing-tool']) {
      const current = harness(), target = current.wrap('suricata');
      plan(target).open = true; copy(target).focus();
      if (reason === 'changed-command') current.catalog[0].uninstall_terminal += ' --purge';
      if (reason === 'stale') vm.runInContext('heartbeatState.failed = true', current.context);
      if (reason === 'catalog-failed') vm.runInContext('heartbeatState.catalogFailed = true', current.context);
      if (reason === 'missing-tool') vm.runInContext("heartbeatState.byId.delete('suricata')", current.context);
      interruptRender(current, target, 'before-replace');
      current.repaint();
      assert.equal(target.hidden, false);
      if (reason === 'changed-command') {
        assert.equal(plan(target).open, false);
        assert.equal(plan(target).querySelector('code').textContent, current.catalog[0].uninstall_terminal);
      } else {
        assert.equal(plan(target), null, reason + ': the identical retry removes stale review');
        vm.runInContext("heartbeatState.failed = false; heartbeatState.catalogFailed = false; heartbeatState.byId.set('suricata', tools[0])", current.context);
        current.repaint();
        assert.equal(plan(target).open, false, reason + ': evidence recovery still needs fresh review');
      }
      assert.equal(current.context.document.activeElement, current.context.document.body);
      assert.deepEqual(current.copied, []); current.readOnly();
    }
  } else if (scenario === 'interrupted-branches') {
    for (const branch of ['selected-model', 'missing-entry', 'hidden-wrap']) {
      const current = harness(), target = current.wrap(branch === 'selected-model' ? 'qwen' : 'suricata');
      if (branch === 'selected-model') current.tools[2].selected_model = {model: 'local-test-model'};
      if (branch === 'missing-entry') vm.runInContext('heartbeatState.catalog = []', current.context);
      if (branch === 'hidden-wrap') { target.hidden = true; current.meaningfulChange(); }
      interruptRender(current, target, branch === 'selected-model' ? 'partial-append' : 'before-replace');
      current.repaint();
      assert.equal(target.hidden, branch === 'hidden-wrap', 'Retry preserves the original visibility');
      const children = [...target.children]; current.repaint();
      assert.deepEqual(target.children, children, 'Successful early branches are cached too');
      if (branch === 'selected-model') assert.equal(target.querySelector('a').href, '#support-model-title');
      if (branch === 'missing-entry') assert.equal(target.children.length, 0);
      assert.deepEqual(current.copied, []); current.readOnly();
    }
  } else if (scenario === 'unchanged') {
    const oldPlan = plan(wrap); oldPlan.open = true; copy(wrap).focus();
    h.repaint();
    assert.equal(plan(wrap), oldPlan, 'An unchanged heartbeat keeps the existing control nodes');
    assert.equal(h.context.document.activeElement, copy(wrap));
  } else throw Error('Unknown scenario');
  h.readOnly();
  console.log(scenario + ' passed');
}

exercise().catch(error => {console.error(error); process.exitCode = 1;});
