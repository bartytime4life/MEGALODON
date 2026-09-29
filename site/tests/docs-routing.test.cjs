const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const siteRoot = path.join(__dirname, '..');
const repositoryRoot = path.join(siteRoot, '..');
const html = fs.readFileSync(path.join(siteRoot, 'dist/index.html'), 'utf8');
const app = fs.readFileSync(path.join(siteRoot, 'dist/app.js'), 'utf8');
const css = fs.readFileSync(path.join(siteRoot, 'dist/styles.css'), 'utf8');
const guide = fs.readFileSync(path.join(repositoryRoot, 'docs/operator-workflows.md'), 'utf8');

test('the hosted console exposes exactly four application views', () => {
  assert.deepEqual(
    [...html.matchAll(/data-view="([^"]+)"/g)].map(([, view]) => view),
    ['hud', 'evidence', 'integrations', 'boundaries']
  );
  assert.deepEqual(
    [...html.matchAll(/data-view-panel="([^"]+)"/g)].map(([, view]) => view),
    ['hud', 'evidence', 'integrations', 'boundaries']
  );
  assert.match(app, /\['hud', 'evidence', 'integrations', 'boundaries'\]\.includes\(name\)/);
});

test('the hosted surface is named as a console rather than the local HUD', () => {
  assert.match(html, /<title>MEGALODON — Hosted reference console<\/title>/);
  assert.match(html, /data-view="hud"[^>]*>[\s\S]*?<span>Overview<\/span><\/button>/);
  assert.match(html, /aria-label="MEGALODON hosted reference console"/);
  assert.doesNotMatch(html, />Activity HUD<|MEGALODON activity HUD|Defensive operations HUD/);
  assert.match(app, /this hosted console opens setup guidance/);
  assert.doesNotMatch(app, /this HUD opens setup guidance/);
});

test('the retired Runbooks surface and its behavior are absent', () => {
  for (const source of [html, app, css]) {
    assert.doesNotMatch(source, /data-view(?:-panel)?="missions"|\bmission-(?:deck|list|panel|columns|topline)\b|\bworkflow-(?:status|platform|title|summary|command|boundary|produces|refuses)\b/);
  }
  assert.doesNotMatch(html, /Setup &amp; runbooks|>Runbooks<|copy-local-install|copy-hud-start|copy-command/);
  assert.doesNotMatch(app, /const workflows|renderWorkflow|copy-local-install|copy-hud-start|copy-command/);
});

test('setup and workflow actions use protected repository documentation links', () => {
  const setup = 'https://github.com/bartytime4life/MEGALODON/blob/29cd2b29e45460d79df4a24132e3563362b0ea3c/docs/local-pc-setup.md';
  const workflows = 'https://github.com/bartytime4life/MEGALODON/blob/main/docs/operator-workflows.md';
  const links = [...`${html}\n${app}`.matchAll(/<a\s+[^>]*href="([^"]+)"[^>]*>/g)]
    .filter(([, href]) => href === setup || href.startsWith(workflows));
  assert.equal(links.length, 4);
  for (const match of links) {
    assert.match(match[0], /target="_blank"/);
    assert.match(match[0], /rel="noopener noreferrer"/);
  }
  for (const label of ['Setup guide ↗', 'Dashboard workflow guide ↗', 'Local setup guide ↗', 'Local dashboard workflow ↗']) {
    assert.ok(`${html}\n${app}`.includes(label));
  }
  assert.match(app, /operator-workflows\.md#local-dashboard/);
  for (const link of html.matchAll(/<a\s+[^>]*href="http:\/\/127\.0\.0\.1:8787\/#[^"]+"[^>]*>/g)) {
    assert.match(link[0], /target="_blank"/);
    assert.match(link[0], /rel="noopener noreferrer"/);
  }
  assert.match(html, /Open local app controls ↗/);
  assert.doesNotMatch(`${html}\n${app}`, /Open local Apps|Open local evidence view/);
});

test('the operator workflow index states status and authority boundaries', () => {
  assert.match(guide, /^Status: \*\*IMPLEMENTED DOCUMENTATION INDEX; NO NEW RUNTIME OR OPERATIONAL\nAUTHORITY\.\*\*/m);
  for (const heading of ['Local dashboard', 'Bounded JSONL replay', 'Saved capture', 'Suricata review', 'Integration plans']) {
    assert.match(guide, new RegExp(`^## ${heading}$`, 'm'));
  }
  for (const boundary of [
    'does not start a sensor',
    'does not capture live traffic',
    'does not perform live capture',
    'does not poll or start a sensor',
    'does not probe the host'
  ]) assert.ok(guide.includes(boundary));
  assert.match(guide, /adds no[\s\S]*operational authority/);
});
