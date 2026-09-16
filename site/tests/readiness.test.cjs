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
  assert.match(html, /Candidate feature · pending merge/);
  assert.match(html, /not part of the displayed baseline/);
});
