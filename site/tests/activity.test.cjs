const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const htmlPath = require.resolve('../dist/index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const activity = html.split('<section class="view active" data-view-panel="hud"')[1].split('<section class="view" data-view-panel="evidence"')[0];

test('Activity presents one truthful live-feed boundary alongside saved charts', () => {
  assert.equal((activity.match(/class="activity-evidence-boundary"/g) || []).length, 1);
  const boundary = activity.match(/<section class="activity-evidence-boundary"[\s\S]*?<\/section>/)?.[0];
  assert.ok(boundary);
  for (const statement of [
    'Live feed unavailable here',
    'This hosted page has no live local telemetry connection.',
    'Loaded summaries are saved, unverified snapshots.',
    'Unavailable does not mean zero traffic, healthy sensors, or a safe system.',
    'Local runtime evidence remains separate.'
  ]) assert.ok(boundary.includes(statement));
  assert.doesNotMatch(boundary, /<(?:a|button|input|details)\b|localhost|127\.0\.0\.1/);
});

test('Activity restores saved summary charts without claiming a live connection', () => {
  for (const id of ['snapshot-file','snapshot-clear','snapshot-status','snapshot-events','snapshot-findings',
    'snapshot-bytes','snapshot-sources','snapshot-range','snapshot-timeline','snapshot-lanes-chart',
    'snapshot-protocols-chart','snapshot-severities-chart','snapshot-sources-chart','snapshot-detectors-chart']) {
    assert.match(activity, new RegExp('id="' + id + '"'));
  }
  assert.match(activity, /The file stays in this browser tab; these charts are a saved view, not a live feed/);
  assert.match(activity, /Open local app controls/);
  assert.match(html, /Starting a service does not connect its data/);
  assert.match(activity, /href="https:\/\/github\.com\/bartytime4life\/MEGALODON\/blob\/29cd2b29e45460d79df4a24132e3563362b0ea3c\/docs\/local-pc-setup\.md"[^>]*target="_blank"[^>]*rel="noopener noreferrer">Setup guide ↗<\/a>/);
  assert.match(activity, /operator-workflows\.md"[^>]*target="_blank"[^>]*rel="noopener noreferrer">Dashboard workflow guide ↗<\/a>/);
  assert.match(activity, /id="reference-globe"/);
});

test('the bounded hosted summary script is shipped and loaded', () => {
  assert.match(html, /src="\.\/snapshot\.js"/);
  assert.equal(fs.existsSync(path.join(path.dirname(htmlPath), 'snapshot.js')), true);
});
