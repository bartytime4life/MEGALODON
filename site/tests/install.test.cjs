const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const html = fs.readFileSync(require.resolve('../dist/index.html'), 'utf8');
const app = fs.readFileSync(require.resolve('../dist/app.js'), 'utf8');

test('the hosted quick start presents the user install before the source launcher', () => {
  const install = html.indexOf('./scripts/install-local.sh');
  const source = html.indexOf('./scripts/start-local.sh');
  assert.ok(install > -1);
  assert.ok(source > install);
  assert.match(html, /Install once\. Open like an app\./);
  assert.match(html, /No sudo\./);
  assert.match(html, /application menu/);
  assert.match(html, /This Site cannot tell whether your HUD is running\./);
  assert.match(html, /data-jump="missions">Setup &amp; runbooks<\/button>/);
  assert.match(html, /An empty local HUD means evidence is unavailable, not zero traffic\./);
});

test('quick-start copy buttons copy only the documented local commands', () => {
  for (const id of ['copy-local-install', 'copy-hud-start']) {
    assert.match(html, new RegExp(`<button id="${id}" type="button">`));
  }
  assert.match(app, /copyText\('\.\/scripts\/install-local\.sh', \$\('#copy-local-install'\)\)/);
  assert.match(app, /copyText\('\.\/scripts\/start-local\.sh', \$\('#copy-hud-start'\)\)/);
  assert.doesNotMatch(app, /copyText\([^\n]*(?:sudo|curl|wget)/);
});

test('install links identify the merged source and protect new tabs', () => {
  const links = [...html.matchAll(/<a\s+href="([^"]+)"[^>]*>/g)]
    .filter(([, href]) => href.includes('/16742fed020283aafad35e30238986c851d7542a'));
  assert.equal(links.length, 2);
  for (const match of links) {
    assert.match(match[0], /target="_blank"/);
    assert.match(match[0], /rel="noopener noreferrer"/);
  }
});
