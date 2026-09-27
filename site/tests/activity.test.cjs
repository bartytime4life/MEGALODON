const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const htmlPath = require.resolve('../dist/index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const activity = html.split('<section class="view active" data-view-panel="hud"')[1].split('<section class="view" data-view-panel="evidence"')[0];

test('Activity presents one passive and truthful evidence boundary', () => {
  assert.equal((activity.match(/class="activity-evidence-boundary"/g) || []).length, 1);
  const boundary = activity.match(/<section class="activity-evidence-boundary"[\s\S]*?<\/section>/)?.[0];
  assert.ok(boundary);
  for (const statement of [
    'Unavailable here',
    'This hosted page has not read local telemetry.',
    'Activity evidence is unavailable here.',
    'Unavailable does not mean zero traffic, healthy sensors, or a safe system.',
    'Local runtime evidence remains separate.'
  ]) assert.ok(boundary.includes(statement));
  assert.doesNotMatch(boundary, /<(?:a|button|input|details)\b|localhost|127\.0\.0\.1/);
});

test('Activity has no telemetry loader, localhost jump, or import-only summary charts', () => {
  assert.doesNotMatch(activity, /snapshot-(?:file|clear|status|metrics|range|grid|timeline|lanes|protocols|severities|sources|detectors)|Visual evidence summary|Load summary JSON|Traffic history/);
  assert.doesNotMatch(activity, /http:\/\/127\.0\.0\.1:8787|Open local (?:visual )?HUD/);
  assert.match(activity, /Manual imports for separate evidence workflows remain separate from traffic activity evidence\./);
  assert.match(activity, /href="https:\/\/github\.com\/bartytime4life\/MEGALODON\/blob\/main\/docs\/local-pc-setup\.md"[^>]*target="_blank"[^>]*rel="noopener noreferrer">Setup guide ↗<\/a>/);
  assert.match(activity, /operator-workflows\.md"[^>]*target="_blank"[^>]*rel="noopener noreferrer">Dashboard workflow guide ↗<\/a>/);
  assert.match(activity, /id="reference-globe"/);
});

test('the retired hosted summary script is neither shipped nor loaded', () => {
  assert.doesNotMatch(html, /src="\.\/snapshot\.js"/);
  assert.equal(fs.existsSync(path.join(path.dirname(htmlPath), 'snapshot.js')), false);
});
