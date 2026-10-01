const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const context = {module:{exports:{}}};
vm.runInNewContext(require('node:fs').readFileSync(0,'utf8'),context);
const {validateReadinessReport, readinessToolIds, readinessBoundaries} = context.module.exports;

const now = Date.parse('2026-09-16T19:00:00Z');
function report() {
  return { schema: 'megalodon-tool-readiness-v2', checked_at: '2026-09-16T18:59:00Z', platform: 'linux', probe_mode: 'path_presence_only', tools: readinessToolIds.map(id => ({ id, status: ['python-sqlite', 'scapy'].includes(id) ? 'not_checked' : 'executable_found' })), boundaries: [...readinessBoundaries] };
}
const parse = value => validateReadinessReport(JSON.stringify(value), now);

test('accepts a complete presence-only report without promoting claims', () => {
  const result = parse(report());
  assert.equal(result.tools.length, 10);
  assert.equal(result.tools.find(tool => tool.id === 'qwen-ollama').status, 'executable_found');
  assert.equal(result.probe_mode, 'path_presence_only');
});

test('v1 reports require regeneration and retired tool IDs fail closed', () => {
  const old = report(); old.schema = 'megalodon-tool-readiness-v1';
  assert.throws(() => parse(old), /Run python -m megalodon readiness again/);
  for (const id of ['ossec', 'zabbix']) {
    const retired = report(); retired.tools[9].id = id;
    assert.throws(() => parse(retired), /exact 10-tool/);
  }
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

