"""Browser-only source context must never create a location from invalid input."""

import base64
import shutil
import subprocess

import pytest

from megalodon.dashboard_globe import GLOBE_HTML, GLOBE_CSS, GLOBE_JS
from megalodon.dashboard_globe_land import LAND_MASK_BASE64, LAND_MASK_WIDTH, LAND_MASK_HEIGHT
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
    assert 'renderGlobe(traffic);' not in DASHBOARD_JS
    assert 'renderGlobeUnavailable(preserve);' not in DASHBOARD_JS
    assert 'startGlobeHour();' in DASHBOARD_JS
    assert "validateHistory(await requestRoomSnapshot(path), {start, end, before: null})" in DASHBOARD_JS
    assert 'Natural Earth land · 30° grid' in GLOBE_HTML
    assert 'width="420" height="420"' in GLOBE_HTML
    assert "fetch('/api/offline-locations'" in GLOBE_JS
    assert "method: 'POST'" in GLOBE_JS
    assert "'X-Megalodon-Location': '1'" in GLOBE_JS
    assert "credentials: 'omit', mode: 'same-origin', redirect: 'error'" in GLOBE_JS
    assert 'if (!state.paused && !document.hidden) await refreshGlobeHour()' in GLOBE_JS
    assert 'refreshGlobeHour(true)' in DASHBOARD_JS
    assert 'refreshGlobeHour(); scheduleNext();' in DASHBOARD_JS
    assert 'localStorage' not in GLOBE_JS
    assert 'Previous snapshot · source IPs and map labels' in DASHBOARD_JS
    assert '.activity-globe.stale .activity-globe-list .matched span' in GLOBE_CSS
    assert '.activity-globe-note { font-size: .875rem; }' in GLOBE_CSS
    assert '.activity-globe-bin.high::before' in GLOBE_CSS
    assert '.activity-globe-bin.selected .activity-globe-bar' in GLOBE_CSS
    assert 'grid-template-areas: ". histogram ." "label slider live" ". axis ."' in GLOBE_CSS
    assert 'grid-template-areas: "histogram" "label" "slider" "axis" "live"' in GLOBE_CSS
    assert GLOBE_HTML.index('class="activity-globe-rail"') < GLOBE_HTML.index('id="activity-globe-histogram"') < GLOBE_HTML.index('id="activity-globe-minute"')
    assert 'input { height: 44px; }' in GLOBE_CSS
    assert 'at most 20 distinct public IPs per view, signal IPs first' in GLOBE_HTML


def test_embedded_natural_earth_mask_has_expected_land_and_water():
    assert (LAND_MASK_WIDTH, LAND_MASK_HEIGHT) == (720, 360)
    mask = base64.b64decode(LAND_MASK_BASE64, validate=True)
    assert len(mask) == LAND_MASK_WIDTH * LAND_MASK_HEIGHT // 8

    def land(latitude, longitude):
        x = int((longitude + 180) * 2) % LAND_MASK_WIDTH
        y = min(LAND_MASK_HEIGHT - 1, max(0, int((90 - latitude) * 2)))
        bit = y * LAND_MASK_WIDTH + x
        return bool(mask[bit >> 3] & (1 << (bit & 7)))

    assert land(40, -100)  # North America
    assert land(0, 25)  # Africa
    assert land(-20, 135)  # Australia
    assert not land(0, 0)  # Gulf of Guinea
    assert not land(0, -140)  # Pacific


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
    {id:'3', observed_at:'2026-09-26T03:00:00Z', src_ip:'2001:DB8::1'}],
    signalByEvent:new Map([['3','high']])};
  let view = evaluate('globeViewModel(traffic,mapping)');
  assert.equal(view.kind, 'mapped');
  assert.equal(view.active.ip, '2001:DB8::1');
  assert.equal(evaluate('globeViewModel(traffic,mapping,false,null)').kind, 'signal-waiting');
  assert.equal(evaluate('globeViewModel(traffic,mapping,false,null).active'), null);
  assert.equal(view.entries[1].location, null);
  const noMap = evaluate('globeViewModel(traffic,null)');
  assert.equal(noMap.kind, 'signal-unmapped');
  assert.equal(noMap.entries.length, 3);
  assert.equal(noMap.entries[0].ip, '2001:DB8::1');
  assert.equal(noMap.entries[0].location, null);
  assert.equal(evaluate('globeViewModel({...traffic,signalByEvent:new Map()},null)').kind, 'no-map');
  assert.equal(evaluate('globeViewModel({...traffic,signalByEvent:new Map()},mapping)').kind, 'monitoring');
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
  context.state = {paused:true};
  context.byId = id => {if (!nodes.has(id)) nodes.set(id, fakeNode()); return nodes.get(id);};
  context.textNode = (tag,content) => ({tag,textContent:content});
  evaluate('globeState.mapping = mapping; renderGlobe(traffic)');
  assert.equal(nodes.get('room-globe-entry-status').textContent, 'Mapped signal source context available');
  assert.equal(nodes.get('activity-globe-list').children.length, 3);
  assert.equal(nodes.get('activity-globe-focus-time').textContent, 'Observed 2026-09-26 · 03:00:00 UTC');
  assert.equal(nodes.get('activity-globe-lead').textContent.includes('2026-09-26T'), false);
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


def test_hour_model_selection_signals_location_validation_and_pause_labels():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for dashboard JavaScript behavior')
    harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => code += chunk);
process.stdin.on('end', () => {
  const context = {TextEncoder, TextDecoder};
  vm.createContext(context);
  vm.runInContext(code, context);
  const evaluate = source => vm.runInContext(source, context);
  const start = Date.parse('2026-09-26T00:00:00Z'), end = start + 3600000;
  context.page = {traffic: {events: [
    {id:'1', observed_at:'2026-09-26T00:10:15Z', src_ip:'8.8.8.8'},
    {id:'2', observed_at:'2026-09-26T00:10:55Z', src_ip:'9.9.9.9'},
    {id:'3', observed_at:'2026-09-26T00:40:01Z', src_ip:'1.1.1.1'}],
    findings: [
      {event_id:'1', severity:'MEDIUM'}, {event_id:'2', severity:'HIGH'},
      {event_id:'2', severity:'LOW'}]}};
  context.start = start; context.end = end;
  let model = evaluate('globeHourModel(page,start,end,null,true)');
  assert.equal(model.index, 40);
  assert.equal(model.peak, 2);
  assert.equal(model.bins.length, 60);
  assert.equal(model.bins[10].signal, 'high');
  assert.equal(model.bins[40].signal, 'quiet');
  assert.equal(model.traffic.events[0].id, '3');
  assert.equal(model.traffic.signalByEvent.get('2'), 'high');
  model = evaluate('globeHourModel(page,start,end,start+10*60000,false)');
  assert.equal(model.index, 10);
  assert.equal(model.traffic.events.length, 2);
  context.recentPage = {traffic:{events:[
    {id:'4',observed_at:'2026-09-26T00:58:10Z',src_ip:'8.8.8.8'},
    {id:'5',observed_at:'2026-09-26T00:59:10Z',src_ip:'1.1.1.1'}],
    findings:[{event_id:'4',severity:'MEDIUM'}]}};
  const recent = evaluate('globeHourModel(recentPage,start,end,null,true)');
  assert.equal(recent.index, 59);
  assert.equal(recent.bins[59].count, 1);
  assert.equal(recent.traffic.events.length, 2); // The prior-minute signal stays visible in Live.
  assert.equal(recent.traffic.signalByEvent.get('4'), 'review');
  assert.equal(evaluate("globeSignalLabel('quiet')"), 'No linked finding (safety unknown)');
  assert.equal(evaluate("globePublicIp('192.0.2.1')"), null);
  assert.equal(evaluate("globePublicIp('2001:db8::1')"), null);
  assert.equal(evaluate("globePublicIp('8.8.8.8')"), '8.8.8.8');
  assert.equal(evaluate("globePublicIp('2001:4860:4860::8888')"), '2001:4860:4860::8888');
  context.manyTraffic = {events:Array.from({length:21},(_,i)=>({id:String(i),
    observed_at:'2026-09-26T00:59:00Z',src_ip:`8.8.8.${i+1}`})),
    signalByEvent:new Map([['20','high']])};
  assert.equal(evaluate('globeLocationIps(manyTraffic).length'), 20);
  assert.equal(evaluate('globeLocationIps(manyTraffic)[0]'), '8.8.8.21');
  assert.equal(evaluate("globeMotionMode({kind:'monitoring',active:null},false,false,false,true)"), 'spin');
  assert.equal(evaluate("globeMotionMode({kind:'signal-unmapped',active:null},false,false,false,true)"), 'spin');
  assert.equal(evaluate("globeMotionMode({kind:'mapped',active:{ip:'8.8.8.8'}},false,false,false,true)"), 'hold');
  assert.equal(evaluate("globeMotionMode({kind:'monitoring',active:null},false,true,false,true)"), 'still');
  assert.equal(evaluate("globeMotionMode({kind:'monitoring',active:null},true,false,false,true)"), 'still');
  assert.equal(evaluate("globeMotionMode({kind:'monitoring',active:null},false,false,true,true)"), 'still');
  assert.equal(evaluate('globeFocusDwell(1)'), 8000);
  assert.equal(evaluate('globeFocusDwell(2)'), 4000);
  assert.equal(evaluate('globeFocusDwell(10)'), 2500);
  context.locations = {schema:'dashboard-offline-locations-v1', status:'available', source:'offline database',
    locations:{'8.8.8.8':{latitude:41, longitude:-73, label:'Approximate region'}}};
  assert.equal(evaluate("validateGlobeLocations(locations,['8.8.8.8']).mapping.get('8.8.8.8').longitude"), -75);
  context.locations6 = {schema:'dashboard-offline-locations-v1', status:'available', source:'offline database',
    locations:{'2001:4860:4860::8888':{latitude:41, longitude:-73, label:'Approximate region'}}};
  assert.equal(evaluate("validateGlobeLocations(locations6,['2001:4860:4860::8888']).mapping.get(normalizeGlobeIp('2001:4860:4860::8888')).longitude"), -75);
  assert.throws(() => evaluate("validateGlobeLocations(locations,['9.9.9.9'])"));
  const nodes = new Map();
  function fakeNode() {return {textContent:'', style:{}, attrs:{}, children:[],
    replaceChildren(...children){this.children=children;},
    setAttribute(name,value){this.attrs[name]=value;}};}
  context.document = {createElement: () => fakeNode(), hidden:false};
  context.byId = id => {if(!nodes.has(id)) nodes.set(id,fakeNode());return nodes.get(id);};
  context.state = {paused:false};
  evaluate('renderGlobeView = () => {}');
  evaluate('globeState.hour.page=page; globeState.hour.start=start; globeState.hour.end=end; globeState.hour.fetchedAt=end; globeState.hour.live=true;');
  evaluate('renderGlobeHour()');
  assert.match(nodes.get('activity-globe-selected-time').textContent, /Live · latest stored · 00:40 UTC.*1 returned record.*safety unknown/);
  assert.match(nodes.get('activity-globe-minute').attrs['aria-valuetext'], /00:40 UTC.*1 returned record.*safety unknown/);
  assert.equal(nodes.get('activity-globe-selected-count').textContent, '1');
  assert.equal(nodes.get('activity-globe-peak-count').textContent, '2');
  assert.match(nodes.get('activity-globe-histogram').children[10].className, /high/);
  assert.match(nodes.get('activity-globe-histogram').children[40].className, /selected/);
  nodes.get('activity-globe-histogram').children[10].onpointerenter();
  assert.match(nodes.get('activity-globe-hover-detail').textContent, /Hovered · 00:10 UTC.*2 returned records.*High priority signal/);
  nodes.get('activity-globe-histogram').children[10].onpointerleave();
  assert.match(nodes.get('activity-globe-hover-detail').textContent, /use the slider/);
  assert.match(nodes.get('activity-globe-histogram').attrs['aria-label'], /empty bins do not prove no traffic/i);
  evaluate('globeState.hour.live=false; globeState.hour.selectedAt=start+10*60000; globeState.hour.partial=true; state.paused=true; renderGlobeHour()');
  assert.match(nodes.get('activity-globe-selected-time').textContent, /Selected · 00:10 UTC.*2 returned records.*High priority signal/);
  assert.match(nodes.get('activity-globe-minute').attrs['aria-valuetext'], /00:10 UTC.*High priority signal/);
  assert.equal(nodes.get('activity-globe-selected-count').textContent, '2');
  assert.match(nodes.get('activity-globe-hour-status').textContent, /Partial hour.*refresh paused/);
  assert.match(nodes.get('activity-globe-coverage').textContent, /Partial view/);
  evaluate('globeState.hour.selectedAt=start+11*60000; globeState.hour.failed=true; renderGlobeHour()');
  assert.match(nodes.get('activity-globe-selected-time').textContent, /Previous page.*0 returned records.*safety unknown/);
  assert.match(nodes.get('activity-globe-minute').attrs['aria-valuetext'], /Previous page.*0 returned records.*safety unknown/);
  let timerId = 0;
  context.window = {setTimeout: () => ++timerId, clearTimeout: () => {}};
  context.focusMap = evaluate("parseGlobeMapping('ip,latitude,longitude,label\\n8.8.8.8,40,-75,East\\n9.9.9.9,20,20,Other')");
  evaluate('state.paused=false; syncGlobeFocus(focusMap)');
  assert.equal(evaluate('globeState.focus.id'), null); // A stale empty minute has no current signal.
  // Restore the signal-bearing minute through the renderer before testing focus order.
  evaluate('globeState.hour.selectedAt=start+10*60000; globeState.hour.failed=false; renderGlobeHour(); syncGlobeFocus(focusMap)');
  assert.equal(evaluate('globeState.focus.id'), '2'); // High before review.
  assert.ok(evaluate('globeState.focus.until-Date.now()') <= 4000);
  evaluate('globeState.focus.until=Date.now()-1; syncGlobeFocus(focusMap)');
  assert.equal(evaluate('globeState.focus.id'), '1'); // Review is not starved.
  evaluate('globeState.focus.until=Date.now()-1; syncGlobeFocus(focusMap); syncGlobeFocus(focusMap)');
  assert.equal(evaluate('globeState.focus.id'), null); // An unchanged finding does not relock.
  evaluate("globeState.traffic.events.push({id:'6',observed_at:'2026-09-26T00:10:56Z',src_ip:'8.8.8.8'}); globeState.traffic.signalByEvent.set('6','high'); syncGlobeFocus(focusMap)");
  assert.equal(evaluate('globeState.focus.id'), '6'); // A new finding joins promptly.
  evaluate('document.hidden=true; syncGlobeFocus(focusMap)');
  assert.equal(evaluate('globeState.focus.id'), null);
  process.stdout.write('hour-model-guarded\n');
});
"""
    result = subprocess.run([node, '-e', harness], input=GLOBE_JS, text=True,
                            capture_output=True, timeout=5, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'hour-model-guarded\n'
