const test = require('node:test');
const assert = require('node:assert/strict');
const { validateReadinessReport, readinessToolIds, readinessBoundaries } = require('../dist/readiness.js');

const now = Date.parse('2026-09-16T19:00:00Z');
function report() {
  return { schema: 'megalodon-tool-readiness-v1', checked_at: '2026-09-16T18:59:00Z', platform: 'linux', probe_mode: 'path_presence_only', tools: readinessToolIds.map(id => ({ id, status: ['python-sqlite', 'scapy'].includes(id) ? 'not_checked' : 'executable_found' })), boundaries: [...readinessBoundaries] };
}
const parse = value => validateReadinessReport(JSON.stringify(value), now);

test('accepts a complete presence-only report without promoting claims', () => {
  const result = parse(report());
  assert.equal(result.tools.length, 14);
  assert.equal(result.tools.find(tool => tool.id === 'qwen-ollama').status, 'executable_found');
  assert.equal(result.probe_mode, 'path_presence_only');
});

for (const [name, mutate] of [
  ['unknown root field', r => { r.host = '<script>alert(1)</script>'; }],
  ['unknown tool field', r => { r.tools[2].path = '/private/path'; }],
  ['missing tool', r => r.tools.pop()],
  ['duplicate tool identity', r => { r.tools[2].id = r.tools[1].id; }],
  ['reordered tools', r => r.tools.reverse()],
  ['unknown status', r => { r.tools[2].status = 'installed'; }],
  ['forged Scapy probe', r => { r.tools[4].status = 'executable_found'; }],
  ['forged Python SQLite probe', r => { r.tools[0].status = 'executable_found'; }],
  ['non-Linux presence claim', r => { r.platform = 'windows'; }],
  ['missing boundary', r => r.boundaries.pop()],
  ['changed boundary', r => { r.boundaries[0] = 'Installed and safe to run'; }],
  ['wrong probe mode', r => { r.probe_mode = 'execute'; }],
  ['timezone ambiguity', r => { r.checked_at = '2026-09-16T18:59:00'; }],
  ['invalid date normalized by Date', r => { r.checked_at = '2026-02-30T18:59:00Z'; }],
  ['future time', r => { r.checked_at = '2026-09-16T19:05:01Z'; }],
  ['non-string timestamp', r => { r.checked_at = now; }]
]) test(`rejects ${name}`, () => { const data = report(); mutate(data); assert.throws(() => parse(data)); });

test('non-Linux reports may only say not checked', () => {
  const data = report(); data.platform = 'windows'; data.tools.forEach(tool => { tool.status = 'not_checked'; });
  assert.equal(parse(data).platform, 'windows');
});

test('older reports stay dated so the UI can label them stale', () => {
  const data = report(); data.checked_at = '2026-09-01T00:00:00Z';
  assert.equal(parse(data).checked_at, data.checked_at);
});

test('duplicate JSON keys and escaped duplicate keys cannot hide a second claim', () => {
  const raw = JSON.stringify(report());
  assert.throws(() => validateReadinessReport(raw.replace('"platform":"linux"', '"platform":"windows","platform":"linux"'), now));
  assert.throws(() => validateReadinessReport(raw.replace('"platform":"linux"', '"plat\\u0066orm":"windows","platform":"linux"'), now));
  assert.throws(() => validateReadinessReport(raw.replace('"status":"not_checked"', '"status":"installed","status":"not_checked"'), now));
});

test('bounded input rejects oversized, deeply nested and malformed JSON', () => {
  assert.throws(() => validateReadinessReport(' '.repeat(8193), now));
  assert.throws(() => validateReadinessReport('['.repeat(1000) + ']'.repeat(1000), now));
  assert.throws(() => validateReadinessReport('{"schema":', now));
  assert.throws(() => validateReadinessReport(null, now));
});

test('readiness validator and app contain no network or program execution path', () => {
  const fs = require('node:fs');
  const source = ['../dist/readiness.js', '../dist/app.js'].map(path => fs.readFileSync(require.resolve(path), 'utf8')).join('\n');
  assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|eval)\s*\(/);
});

test('an older rejected read cannot replace a newer accepted import', async () => {
  const fs = require('node:fs'), vm = require('node:vm');
  const code = fs.readFileSync(require.resolve('../dist/app.js'), 'utf8');
  const importer = code.slice(code.indexOf('let readinessImportSequence'), code.indexOf('\nfunction switchView'));
  const bytes = new TextEncoder().encode(JSON.stringify(report()));
  const nodes = new Map();
  const context = { state: { readiness: null }, $: id => { if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id); }, renderIntegrationGrid() {}, renderToolInspector() {}, TextDecoder, Date, Number, Error, TypeError, validateReadinessReport: text => validateReadinessReport(text, now) };
  vm.createContext(context); vm.runInContext(importer, context);
  let rejectOld;
  context.oldFile = { size: bytes.length, arrayBuffer: () => new Promise((resolve, reject) => { rejectOld = reject; }) };
  context.newFile = { size: bytes.length, arrayBuffer: async () => bytes.buffer };
  const old = vm.runInContext('importReadinessFile(oldFile)', context);
  await vm.runInContext('importReadinessFile(newFile)', context);
  const loaded = nodes.get('#readiness-feedback').textContent;
  assert.match(loaded, /14 tool results loaded/);
  rejectOld(new Error('synthetic delayed read error')); await old;
  assert.ok(context.state.readiness);
  assert.equal(nodes.get('#readiness-feedback').textContent, loaded);
  assert.equal(nodes.get('#clear-readiness').disabled, false);
});

test('older successful reads cannot restore a report after a newer rejection', async () => {
  const fs = require('node:fs'), vm = require('node:vm');
  const code = fs.readFileSync(require.resolve('../dist/app.js'), 'utf8');
  const importer = code.slice(code.indexOf('let readinessImportSequence'), code.indexOf('\nfunction switchView'));
  const bytes = new TextEncoder().encode(JSON.stringify(report()));
  const nodes = new Map();
  const context = { state: { readiness: null }, $: id => { if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id); }, renderIntegrationGrid() {}, renderToolInspector() {}, TextDecoder, Date, Number, Error, TypeError, validateReadinessReport: text => validateReadinessReport(text, now) };
  vm.createContext(context); vm.runInContext(importer, context);
  let resolveOld;
  context.oldFile = { size: bytes.length, arrayBuffer: () => new Promise(resolve => { resolveOld = resolve; }) };
  context.invalidFile = { size: 9999, arrayBuffer: async () => { throw new Error('must not read oversized file'); } };
  const old = vm.runInContext('importReadinessFile(oldFile)', context);
  await vm.runInContext('importReadinessFile(invalidFile)', context);
  const rejected = nodes.get('#readiness-feedback').textContent;
  assert.match(rejected, /Report rejected/);
  resolveOld(bytes.buffer); await old;
  assert.equal(context.state.readiness, null);
  assert.equal(nodes.get('#readiness-feedback').textContent, rejected);
  assert.equal(nodes.get('#clear-readiness').disabled, true);
});

test('the HTML declares unique evidence controls and loads its local validator first', () => {
  const fs = require('node:fs'), path = require('node:path');
  const html = fs.readFileSync(require.resolve('../dist/index.html'), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ['event-search', 'event-disposition', 'event-feed', 'event-inspector', 'run-list', 'run-inspector', 'readiness-file', 'clear-readiness', 'readiness-feedback']) assert.ok(ids.includes(id));
  assert.ok(html.indexOf('src="./readiness.js"') < html.indexOf('src="./app.js"'));
  for (const match of html.matchAll(/(?:src|href)="\.\/([^"]+)"/g)) assert.ok(fs.existsSync(path.join(path.dirname(require.resolve('../dist/index.html')), match[1])));
  assert.match(html, /Delivered in/);
  assert.match(html, /MEGALODON\/pull\/241/);
  assert.match(html, /main@5583ac1/);
  assert.doesNotMatch(html, /pending merge/);
});

const {lifecycleCommands, resolveLifecycle} = require('../dist/lifecycle.js');

test('lifecycle choices cover the exact fourteen tools without inventing unknown installations', () => {
  assert.deepEqual(Object.keys(lifecycleCommands).sort(), ['core','tshark','zeek','suricata','scapy','nftables','clamav','osquery','qwen','nmap','ossec','greenbone','zabbix','nagios'].sort());
  for (const id of ['zeek','ossec','nagios','zabbix']) {
    assert.equal(resolveLifecycle(id).uninstall, null);
    assert.equal(resolveLifecycle(id).reinstall, null);
  }
});

test('Qwen inspect, removal and download use the same example model and literal local provider', () => {
  const qwen = resolveLifecycle('qwen');
  for (const action of ['verify','uninstall','reinstall']) {
    assert.match(qwen[action], /OLLAMA_HOST=127\.0\.0\.1:11434/);
    assert.match(qwen[action], /qwen2\.5:7b/);
  }
  assert.match(qwen.note, /mutable tag.*not the approved registry/);
});

test('Zabbix selection scopes package operations to exactly one role', () => {
  for (const [role, pkg] of [['agent2','zabbix-agent2'], ['agent','zabbix-agent'], ['mysql','zabbix-server-mysql']]) {
    const choice = resolveLifecycle('zabbix', role);
    assert.equal(choice.uninstall, `sudo apt-get remove ${pkg}`);
    assert.equal(choice.reinstall, `sudo apt-get install --reinstall ${pkg}`);
  }
  for (const invalid of [undefined, '', 'all', '__proto__']) {
    assert.equal(resolveLifecycle('zabbix', invalid).reinstall, null);
  }
});

test('Greenbone labels report container and image effects, not a complete uninstall or running scanner', () => {
  const greenbone = resolveLifecycle('greenbone');
  assert.equal(greenbone.verify, 'docker compose images');
  assert.equal(greenbone.uninstall, 'docker compose down');
  assert.match(greenbone.labels.uninstall, /retain data\/images/);
  assert.match(greenbone.labels.reinstall, /do not start/);
  assert.match(greenbone.note, /Neither is a complete uninstall\/reinstall/);
});

test('scanner reference does not silently add daemon/update roles or purge configuration', () => {
  assert.equal(resolveLifecycle('clamav').reinstall, 'sudo apt-get install --reinstall clamav');
  assert.equal(resolveLifecycle('suricata').reinstall, 'sudo apt-get install --reinstall suricata');
  assert.doesNotMatch(JSON.stringify(lifecycleCommands), /--purge|\s-y\b|remove-orphans/);
});

test('disconnected HUD has no generated observations, fixtures or refresh timer', () => {
  const fs = require('node:fs');
  const app = fs.readFileSync(require.resolve('../dist/app.js'), 'utf8');
  const html = fs.readFileSync(require.resolve('../dist/index.html'), 'utf8');
  assert.doesNotMatch(app, /eventTemplates|runExamples|addSyntheticEvent|chartSeries|setInterval|Math\.sin|demo-event/);
  assert.doesNotMatch(html, /SYNTHETIC PREVIEW|12,480|7 synthetic|41%|INTACT/);
  for (const id of ['metric-events','metric-flows','metric-detections']) assert.ok(html.includes(`id="${id}">—</strong>`));
  assert.match(html, /NOT CONNECTED/);
  assert.ok(html.indexOf('src="./lifecycle.js"') < html.indexOf('src="./app.js"'));
});

test('exchange map separates the implemented offline STIX reader from inert SIEM/SOAR contracts', () => {
  const fs = require('node:fs');
  const html = fs.readFileSync(require.resolve('../dist/index.html'), 'utf8');
  assert.match(html, /id="external-exchange"/);
  for (const value of ['STIX 2.1', 'ECS 9.5.0', 'OCSF 1.9.0', 'Reader implemented', 'Contract only', 'Zero attempts; status not attempted']) assert.ok(html.includes(value));
  assert.match(html, /No TAXII, persistence, model, attribution, or action/);
  assert.match(html, /No collector, credential, or network delivery/);
  assert.match(html, /No endpoint, webhook, playbook, or host action/);
  assert.doesNotMatch(html, /Connect TAXII|Send to SIEM|Run playbook|Choose STIX bundle/);
});

test('whole application initializes and navigates without a feed or browser network API', () => {
  const fs = require('node:fs'), vm = require('node:vm');
  class Element {
    constructor() { this.children=[]; this.dataset={}; this.textContent=''; this.value=''; this.classList={toggle(){}}; }
    setAttribute() {} removeAttribute() {} addEventListener() {} focus() {}
    replaceChildren(...children) { this.children=children; } append(...children) { this.children.push(...children); }
    querySelector() { return new Element(); }
  }
  const nodes=new Map();
  const document={querySelector(s){ if(!nodes.has(s)) nodes.set(s,new Element()); return nodes.get(s); }, querySelectorAll(){ return []; }, createElement(){ return new Element(); }};
  const context={document, window:{matchMedia(){return {matches:true};},scrollTo(){}}, localStorage:{getItem(){return null;}}, Date, console};
  vm.createContext(context);
  for(const path of ['../dist/lifecycle.js','../dist/controls.js','../dist/app.js']) vm.runInContext(fs.readFileSync(require.resolve(path),'utf8'),context);
  for(const view of ['hud','evidence','integrations','missions','boundaries']) vm.runInContext(`switchView('${view}')`,context);
  for(const id of Object.keys(lifecycleCommands)) vm.runInContext(`state.selectedTool='${id}'; renderToolInspector()`,context);
  assert.match(nodes.get('#feed-count').textContent, /No network records/);
  assert.match(nodes.get('#tool-inspector').innerHTML, /Manual presence note/);
});
