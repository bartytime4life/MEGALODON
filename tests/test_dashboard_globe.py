"""Browser-only source context must never create a location from invalid input."""

import shutil
import subprocess

import pytest

from megalodon.dashboard_globe import GLOBE_HTML, GLOBE_CSS, GLOBE_JS
from megalodon.dashboard import INDEX_HTML, DASHBOARD_JS


def test_globe_is_in_visible_traffic_workspace_and_uses_validated_projection():
    assert GLOBE_HTML in INDEX_HTML
    assert 'id="room-globe-entry-title">Activity globe' in INDEX_HTML
    assert INDEX_HTML.index('id="room-globe-entry-title"') < INDEX_HTML.index('id="workspace-analysis"')
    assert '<a href="#room-traffic-title">Open activity globe' in INDEX_HTML
    assert INDEX_HTML.index(GLOBE_HTML) > INDEX_HTML.index('id="workspace-traffic"')
    assert INDEX_HTML.index(GLOBE_HTML) < INDEX_HTML.index('id="room-traffic-grid"')
    projection = DASHBOARD_JS.split('function validatedTraffic(value)', 1)[1].split('function unavailableTrafficResponse', 1)[0]
    assert 'const source = validateTraffic(value)' in projection
    assert 'src_ip: event.src_ip' in projection
    assert 'id: event.id' in projection
    assert 'renderGlobe(traffic)' in DASHBOARD_JS
    assert 'renderGlobeUnavailable(preserve)' in DASHBOARD_JS
    assert 'Schematic land · 30° grid' in GLOBE_HTML
    assert 'Previous snapshot · source IPs and map labels' in DASHBOARD_JS
    assert '.activity-globe.stale .activity-globe-list .matched span' in GLOBE_CSS
    assert '.activity-globe-note { font-size: .875rem; }' in GLOBE_CSS


def test_offline_map_validation_matching_and_stale_state():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for dashboard JavaScript behavior')
    harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => code += chunk);
process.stdin.on('end', async () => {
  const context = {TextEncoder, TextDecoder};
  vm.createContext(context);
  vm.runInContext(code, context);
  const evaluate = source => vm.runInContext(source, context);
  assert.equal(evaluate("normalizeGlobeIp('2001:DB8::1')"),
    '2001:0db8:0000:0000:0000:0000:0000:0001');
  for (const address of ['256.1.1.1', '01.2.3.4', '2001:::1', '2001:db8::1::2', 'fe80::1%eth0']) {
    assert.equal(evaluate(`normalizeGlobeIp(${JSON.stringify(address)})`), null);
  }
  for (const bad of [
    '', 'ip,latitude,longitude,label\n',
    'ip,latitude,longitude,label\n192.0.2.1,91,0,Impossible',
    'ip,latitude,longitude,label\n192.0.2.1,1,Infinity,Impossible',
    'ip,latitude,longitude,label\n192.0.2.1,1,1,<script>,extra',
    'ip,latitude,longitude,label\n192.0.2.1,1,1,first\n192.0.2.1,2,2,duplicate',
    'ip,latitude,longitude,label\n192.0.2.1,1,1,first\ninvalid,2,2,partial'
  ]) assert.throws(() => evaluate(`parseGlobeMapping(${JSON.stringify(bad)})`));
  const map = evaluate("parseGlobeMapping('ip,latitude,longitude,label\\n192.0.2.1,41,-73,Reviewed east\\n2001:db8::1,-12,100,Reviewed south')");
  assert.equal(map.size, 2);
  assert.equal(map.get('192.0.2.1').latitude, 40);
  assert.equal(map.get('192.0.2.1').longitude, -75);
  context.mapping = map;
  context.traffic = {status:'available', events:[
    {id:'1', observed_at:'2026-09-26T01:00:00Z', src_ip:'192.0.2.1'},
    {id:'2', observed_at:'2026-09-26T02:00:00Z', src_ip:'198.51.100.2'},
    {id:'3', observed_at:'2026-09-26T03:00:00Z', src_ip:'2001:DB8::1'}]};
  let view = evaluate('globeViewModel(traffic,mapping)');
  assert.equal(view.kind, 'mapped');
  assert.equal(view.active.ip, '2001:DB8::1');
  assert.equal(view.entries[1].location, null);
  const noMap = evaluate('globeViewModel(traffic,null)');
  assert.equal(noMap.kind, 'no-map');
  assert.equal(noMap.entries.length, 3);
  assert.equal(noMap.entries[0].ip, '2001:DB8::1');
  assert.equal(noMap.entries[0].location, null);
  assert.equal(evaluate('globeViewModel({status:"unavailable",events:[]},mapping)').kind, 'unavailable');
  assert.equal(evaluate('globeViewModel({status:"available",events:[]},mapping)').kind, 'empty');
  view = evaluate('globeViewModel(traffic,mapping,true)');
  assert.equal(view.kind, 'stale');
  assert.equal(view.active, null);
  assert.equal(view.entries.length, 3);
  const nodes = new Map();
  function fakeNode() {
    return {textContent:'', className:'', hidden:false, style:{}, children:[], attrs:{},
      replaceChildren(...children) {this.children = children;},
      setAttribute(name,value) {this.attrs[name] = value;}, append(...children) {this.children.push(...children);}};
  }
  context.document = {hidden:false, createElement: () => fakeNode()};
  context.window = {matchMedia: () => ({matches:true})};
  context.byId = id => {if (!nodes.has(id)) nodes.set(id, fakeNode()); return nodes.get(id);};
  context.textNode = (tag,content) => ({tag,textContent:content});
  evaluate('globeState.mapping = mapping; renderGlobe(traffic)');
  assert.equal(nodes.get('room-globe-entry-status').textContent, 'Mapped source context available');
  assert.equal(nodes.get('activity-globe-list').children.length, 3);
  evaluate('renderGlobeUnavailable(true)');
  assert.equal(nodes.get('activity-globe-list-heading').textContent, 'Previous snapshot · source IPs and map labels');
  assert.equal(nodes.get('activity-globe-list').attrs['aria-label'], 'Previous snapshot source IP mapping status');
  assert.match(nodes.get('activity-globe').className, /stale/);
  assert.equal(nodes.get('room-globe-entry-status').textContent, 'Previous traffic snapshot · no current marker');
  const input = {value:'selected.csv', files:[]};
  context.fileEvent = {currentTarget:input};
  input.files = [{size:74, arrayBuffer:async () => {
    context.fileEvent.currentTarget = null;
    return new TextEncoder().encode('ip,latitude,longitude,label\n192.0.2.1,40,-75,Reviewed region').buffer;
  }}];
  await evaluate('loadGlobeFile(fileEvent)');
  assert.equal(input.value, '');
  assert.match(nodes.get('activity-globe-file-status').textContent, /1 offline address loaded/);
  process.stdout.write('globe-guarded\n');
});
"""
    result = subprocess.run([node, '-e', harness], input=GLOBE_JS, text=True,
                            capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'globe-guarded\n'
