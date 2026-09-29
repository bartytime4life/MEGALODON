const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('hosted companion section has one local entry and no manual upload controls', () => {
  const page = fs.readFileSync(path.join(__dirname, '../dist/index.html'), 'utf8');
  const section = page.split('<section class="companion-section"', 2)[1]
    .split('<!-- TELEMETRY_COVERAGE_START -->', 1)[0];
  assert.equal((section.match(/class="companion-panel /g) || []).length, 3);
  assert.equal((section.match(/href="http:\/\/127\.0\.0\.1:8787\/#[^"]+"/g) || []).length, 1);
  assert.doesNotMatch(section, /type="file"|Choose File|Load (inventory|scan|package)/i);
  assert.match(section, /cannot read this PC/);
});
