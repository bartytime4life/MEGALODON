"""Behavioral browser-logic checks with synthetic, explicitly non-live fixtures."""
from html.parser import HTMLParser
import json
import shutil
import subprocess

import pytest

from megalodon.control_room_assets import ROOM_JS
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_traffic import TrafficDashboardStore, unavailable
from megalodon.storage import Store
from test_dashboard_traffic import add_run


def test_seven_workspaces_and_persistent_return():
    for name in ('live', 'traffic', 'findings', 'interfaces', 'reports', 'analysis', 'help'):
        assert f'id="workspace-tab-{name}"' in INDEX_HTML
        assert f'id="workspace-{name}"' in INDEX_HTML
    assert INDEX_HTML.count('class="room-back"') == 1
    assert 'Audit history — may include sample and unlinked rows' in INDEX_HTML
    assert 'id="room-report-create"' in INDEX_HTML
    assert 'id="room-report-download" disabled' in INDEX_HTML
    assert 'id="room-report-preview"' in INDEX_HTML
    assert 'Local report preview is unavailable' not in INDEX_HTML


def test_startup_controls_belong_to_home_outside_audit_history():
    detail_ids = {'room-feed-status', 'room-history-status', 'room-range-description'}
    control_ids = {'room-range', 'room-apply', 'room-refresh', 'room-pause'}

    class OwnershipParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.parents = []
            self.owners = {}

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            element_id = attrs.get('id', '')
            if element_id.startswith('setup-') or element_id in detail_ids | control_ids:
                assert element_id not in self.owners, f'Duplicate control: {element_id}'
                self.owners[element_id] = list(self.parents)
            if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
                self.parents.append((tag, attrs))

        def handle_endtag(self, tag):
            for index in range(len(self.parents) - 1, -1, -1):
                if self.parents[index][0] == tag:
                    del self.parents[index:]
                    break

    parser = OwnershipParser()
    parser.feed(INDEX_HTML)
    assert {'setup-title', 'setup-source', 'setup-tool-status', 'setup-config',
            'setup-offline', 'setup-suricata', 'setup-build', 'setup-copy'} <= parser.owners.keys()
    for element_id, parents in parser.owners.items():
        if not element_id.startswith('setup-'):
            continue
        workspaces = [attrs['id'] for _, attrs in parents if attrs.get('role') == 'tabpanel']
        assert workspaces == ['workspace-live']
        assert not any('room-audit-history' in attrs.get('class', '').split() for _, attrs in parents)
    assert not any(tag == 'details' for tag, _ in parser.owners['setup-title'])
    assert 'id="setup-title" tabindex="-1"' in INDEX_HTML
    assert 'href="#setup-title"' in INDEX_HTML
    for element_id in detail_ids:
        disclosures = [attrs for tag, attrs in parser.owners[element_id] if tag == 'details']
        assert len(disclosures) == 1
        assert disclosures[0].get('class') == 'room-feed-details'
        assert 'open' not in disclosures[0]
    for element_id in control_ids:
        assert not any(tag == 'details' for tag, _ in parser.owners[element_id])


def test_projection_browser_filters_truth_and_failure(tmp_path):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node required for browser logic')
    path = tmp_path / 'private' / 'audit.db'
    with Store(path) as writer:
        add_run(writer, finding=True)
        with TrafficDashboardStore(path) as reader:
            payload = reader.traffic()
    script = r'''
const vm=require('vm'),assert=require('node:assert/strict');let input='';
process.stdin.setEncoding('utf8');process.stdin.on('data',c=>input+=c);
process.stdin.on('end',async()=>{try{
const {code,payload,unavailable}=JSON.parse(input),nodes=new Map(),calls=[];
function element(tag='') {return {tag,children:[],textContent:'',attrs:{},listeners:{},
append(...items){this.children.push(...items)},replaceChildren(...items){this.children=items},
setAttribute(k,v){this.attrs[k]=v},addEventListener(k,v){this.listeners[k]=v},
set innerHTML(v){throw Error('unsafe sink')}};}
const document={createElement:element,createElementNS:(ns,tag)=>element(tag)};
const byId=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id)};
const textNode=(tag,text='',cls='')=>Object.assign(element(tag),{textContent:text,className:cls});
const textOf=n=>n.textContent+' '+n.children.map(textOf).join(' ');
function response(value,status) {const bytes=new TextEncoder().encode(JSON.stringify(value));let sent=false;return {ok:status>=200&&status<300,status,body:{getReader:()=>({read:async()=>sent?{done:true}:{done:false,value:(sent=true,bytes)},cancel:async()=>{}})}};}
const context={document,byId,textNode,Date,BigInt,AbortSignal,TextDecoder,TextEncoder,Uint8Array,payload,
referenceExactKeys:(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)),
knownSeverities:new Set(['LOW','MEDIUM','HIGH','CRITICAL']),
fetch:async(path,options)=>{calls.push({path,options});throw Error('PRIVATE_FAILURE')}};
vm.createContext(context);vm.runInContext(code,context,{timeout:1000});
const run=code=>vm.runInContext(code,context,{timeout:1000});run('renderRoom()');
assert.equal(run('roomEndpoint("192.0.2.1",0)'),'192.0.2.1:0');
assert.equal(run('roomEndpoint("2001:db8::1",443)'),'[2001:db8::1]:443');
assert.equal(run('roomEndpoint("2001:db8::1",null)'),'2001:db8::1');
assert.match(byId('room-home-summary').textContent,/No qualified data available/);
assert.equal(byId('room-count').textContent,'Unavailable');assert.equal(calls.length,0);
assert.equal(byId('room-connection').textContent,'Not checked');
assert.equal(run('downloadRoomReport()'),false);
assert.equal(run('previewRoomReport()'),false);assert.equal(byId('room-report-download').disabled,true);
assert.match(byId('room-report-status').textContent,/No qualified data/);
context.fetch=async(path,options)=>{calls.push({path,options});return response(unavailable,503)};
await run('refreshRoom()');assert.equal(calls.length,1);assert.equal(run('roomState.snapshot.status'),'unavailable');
assert.equal(run('roomState.failed'),false);assert.equal(run('roomState.connected'),true);
assert.equal(byId('room-connection').textContent,'Connected · read-only');assert.equal(byId('room-overall').textContent,'No qualified data');
run('roomState.snapshot=validateTraffic(payload);renderRoom()');
assert.match(byId('room-home-summary').textContent,/1 stored metadata events and 1 linked findings/);
assert.match(textOf(byId('room-traffic-grid')),/9223372036854775807 reported bytes/);
assert.equal(byId('room-traffic-grid').children.length,8);
assert.match(textOf(byId('room-traffic-grid')),/local-subnet or sensor-vantage/);
assert.match(textOf(byId('room-traffic-grid')),/12345/);
assert.match(textOf(byId('room-traffic-grid')),/192\.0\.2\.1:12345/);
assert.equal(run('previewRoomReport()'),true);assert.equal(byId('room-report-download').disabled,false);
const reportJson=run('roomState.report.json'),report=JSON.parse(reportJson);
assert.deepEqual(Object.keys(report),['schema','generated_at','title','range','sources','vantage','quality','freshness','unit','counts','findings','limitations','build']);
assert.equal(report.schema,'megalodon-local-report-v1');
assert.deepEqual(report.counts,{events:1,findings:1,reported_bytes:'9223372036854775807'});
assert.deepEqual(report.sources,['jsonl']);assert.equal(report.vantage,'unknown');
assert.deepEqual(report.findings,[{rule_id:payload.findings[0].rule_id,severity:payload.findings[0].severity,count:1}]);
assert.equal(report.limitations.length,7);assert.ok(Buffer.byteLength(reportJson,'utf8')<=65536);
assert.doesNotMatch(reportJson,/192\.0\.2\.|198\.51\.100\.|PRIVATE_|event_id|src_ip|dst_ip/);
assert.match(textOf(byId('room-report-preview')),/megalodon-local-report-v1/);
assert.equal(calls.length,1);
// A background repaint or later snapshot must not destroy the reviewed bytes.
run('renderRoom()');assert.equal(run('roomState.report.json'),reportJson);
assert.equal(byId('room-report-download').disabled,false);
assert.match(byId('room-report-context').textContent,/Held preview created/);
assert.match(byId('room-report-context').textContent,/range changes do not update/);
run('roomState.snapshot=validateTraffic({...payload,generated_at:new Date().toISOString()});renderRoom()');
assert.equal(run('roomState.report.json'),reportJson);
const revoked=[],downloaded=[];let captured;
context.Blob=class {constructor(parts){captured=parts.join('');}};
context.setTimeout=callback=>callback();
context.URL={createObjectURL:()=>{throw Error('PRIVATE_DOWNLOAD_FAILURE');},revokeObjectURL:url=>revoked.push(url)};
assert.equal(run('downloadRoomReport()'),false);
assert.match(byId('room-report-status').textContent,/preview is preserved/);
assert.doesNotMatch(byId('room-report-status').textContent,/PRIVATE_/);
assert.equal(run('roomState.report.json'),reportJson);
context.URL.createObjectURL=()=> 'blob:local-test';
// A failed click also releases its object URL without discarding the preview.
assert.equal(run('downloadRoomReport()'),false);
assert.deepEqual(revoked,['blob:local-test']);
context.document.createElement=tag=>Object.assign(element(tag),{click(){downloaded.push(this.download);}});
assert.equal(run('downloadRoomReport()'),true);
assert.equal(captured,reportJson);assert.equal(downloaded.length,1);
assert.deepEqual(revoked,['blob:local-test','blob:local-test']);
assert.equal(calls.length,1);
assert.equal(run('roomReportDocument(Date.parse(roomState.snapshot.generated_at)-60001).document.freshness'),'stale');
assert.equal(run('roomReportDocument(Date.parse(roomState.snapshot.generated_at)).document.freshness'),'current_by_five_minute_ui_threshold');
assert.equal(run('roomReportDocument(Date.parse(roomState.snapshot.generated_at)+300001).document.freshness'),'stale');
run('roomState.range="custom";roomState.custom={start:Date.parse("2026-09-16T00:00:00Z"),end:Date.parse("2026-09-16T01:00:00Z")};renderRoom()');
assert.equal(run('roomState.selection.events.length'),0);
assert.equal(run('roomState.report.json'),reportJson);
assert.equal(run('downloadRoomReport()'),true);assert.equal(captured,reportJson);
assert.equal(run('previewRoomReport()'),false);
assert.equal(run('roomState.report'),null);assert.equal(byId('room-report-download').disabled,true);
run('roomState.range="recorded";roomState.custom=null;renderRoom()');
assert.equal(run('previewRoomReport()'),true);
byId('room-report-discard').listeners.click();
assert.equal(run('roomState.report'),null);assert.equal(byId('room-report-download').disabled,true);
assert.equal(byId('room-report-discard').disabled,true);assert.equal(byId('room-report-preview').hidden,true);
assert.equal(byId('room-report-preview').children.length,0);
assert.equal(run('roomSelection(payload,"hour",null,Date.parse("2026-09-18T00:00:00Z")).events.length'),0);
assert.throws(()=>run('roomSelection(payload,"custom",{start:0,end:Date.now()})'));
assert.throws(()=>run('roomSelection(payload,"custom",{start:2,end:1})'));
assert.equal(run('roomSelection(payload,"recorded",null,Date.parse("2026-01-01T00:00:00Z")).events.length'),1);
assert.equal(run('roomStamp("2024-02-29T23:59:59.123456Z")'),true);
assert.equal(run('roomStamp("2026-02-29T12:00:00Z")'),false);
assert.equal(run('roomStamp("2026-04-31T12:00:00Z")'),false);
for(const expression of [
'p.events.push({...p.events[0]})','p.events[0].protocol="<img src=x>"',
'p.events[0].tcp_flags.push("<script>")','p.events[0].src_port=65536',
'p.events[0].byte_count="9223372036854775808"','p.findings[0].event_id="123456"',
'p.window.end=null','p.events[0].raw="PRIVATE_BODY"','p.build.extra="secret"',
'p.events[0].id="9007199254740992"','p.findings[0].detector_version="made-up"',
'p.generated_at="2026-02-30T12:00:00Z"']) {
assert.throws(()=>run('{const p=JSON.parse(JSON.stringify(payload));'+expression+';validateTraffic(p)}'));
}
context.fetch=async(path,options)=>{calls.push({path,options});throw Error('PRIVATE_FAILURE')};
await run('refreshRoom()');assert.equal(calls.length,2);assert.equal(calls[1].path,'/api/traffic');
assert.equal(calls[1].options.method,'GET');assert.equal(calls[1].options.credentials,'omit');
assert.equal(byId('room-connection').textContent,'Unavailable · preserved view');
assert.equal(byId('room-coverage').textContent,'Stale');assert.match(byId('room-home-summary').textContent,/1 stored metadata events/);
assert.doesNotMatch(textOf(byId('room-traffic-grid')),/PRIVATE_FAILURE/);
context.fetch=async()=>({ok:true,body:{getReader:()=>({read:async()=>({done:false,value:new Uint8Array(262145)}),cancel:async()=>{}})}});
await run('refreshRoom()');assert.equal(run('roomState.failed'),true);assert.equal(run('roomState.snapshot.events.length'),1);
console.log('bounded projection, exact integer totals, filters, bad inputs and stale preservation passed');
}catch(error){console.error(error);process.exitCode=1}});
'''
    result = subprocess.run([node, '-e', script], input=json.dumps({'code': ROOM_JS, 'payload': payload,
                                                                    'unavailable': unavailable()}),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_workspace_navigation_preserves_context_and_uses_closed_fragments():
    """Run the shipped navigation with a synthetic DOM, not a copied algorithm."""
    from megalodon.dashboard_assets import DASHBOARD_JS
    if not shutil.which('node'):
        pytest.skip('Node required for navigation behavior')
    constants = DASHBOARD_JS[DASHBOARD_JS.index('const workspaceIds ='):DASHBOARD_JS.index('const state =')]
    navigation = DASHBOARD_JS[DASHBOARD_JS.index('function byId('):DASHBOARD_JS.index('function textNode(')]
    harness = r'''
const assert = require('node:assert/strict');
const nodes = new Map(), listeners = {}, history = [];
let viewportWidth = 1440, viewportHeight = 1000;
const document = {scrollingElement:{scrollTop:0}, getElementById(id) {
  if (!nodes.has(id)) nodes.set(id, {scrollTop:0, hidden:false, attrs:{}, listeners:{},
    setAttribute(k,v){this.attrs[k]=v;}, addEventListener(k,v){this.listeners[k]=v;},
    focus(options){this.focusOptions=options; document.activeElement=this;},
    scrollIntoView(){this.scrolled=true;}});
  return nodes.get(id);
}, addEventListener(){}};
const window = {location:{hash:''}, addEventListener(k,v){listeners[k]=v;},
  matchMedia(query){assert.equal(query, '(max-width: 560px), (max-height: 500px)');
    return {matches:viewportWidth <= 560 || viewportHeight <= 500};},
  history:{pushState(a,b,hash){history.push(hash);window.location.hash=hash;}}};
'''
    checks = r'''
const scroll = byId('workspace-content');
scroll.scrollTop = 210;
navigateWorkspace('traffic');
assert.equal(scroll.scrollTop, 0);
assert.equal(window.location.hash, '#workspace-traffic');
scroll.scrollTop = 95;
navigateWorkspace('live');
assert.equal(scroll.scrollTop, 210);
navigateWorkspace('live');
assert.equal(scroll.scrollTop, 210);
assert.equal(history.length, 2);
window.location.hash = '#workspace-traffic'; listeners.popstate();
assert.equal(scroll.scrollTop, 95);
assert.equal(byId('workspace-tab-traffic').attrs['aria-selected'], 'true');
assert.equal(byId('workspace-live').hidden, true);
assert.equal(byId('workspace-traffic').scrolled, undefined);
for (const id of workspaceIds) assert.equal(workspaceFromHash('#workspace-' + id), id);
for (const hash of ['#constructor', '#__proto__', '#workspace-unknown', '#'.repeat(129)]) {
  assert.equal(workspaceFromHash(hash), null);
}
window.location.hash = '#reference-title'; listeners.hashchange();
assert.equal(byId('reference-title').scrolled, true);
window.history.pushState = () => {throw Error('disabled');};
navigateWorkspace('help');
assert.equal(byId('workspace-help').hidden, false);
// Narrow and short layouts scroll the page; workspace offsets from desktop
// must neither replace page offsets nor be overwritten by them.
for (const [width, height] of [[375,812], [720,500]]) {
  viewportWidth = width; viewportHeight = height;
  navigateWorkspace('live');
  document.scrollingElement.scrollTop = 840;
  navigateWorkspace('traffic');
  document.scrollingElement.scrollTop = 630;
  navigateWorkspace('live');
  assert.equal(document.scrollingElement.scrollTop, 840);
  window.location.hash = '#workspace-traffic'; listeners.popstate();
  assert.equal(document.scrollingElement.scrollTop, 630);
  assert.equal(byId('workspace-traffic').hidden, false);
  const trafficTab = byId('workspace-tab-traffic');
  trafficTab.listeners.keydown({key:'ArrowRight', preventDefault(){}});
  const focusedTab = byId('workspace-tab-findings');
  assert.equal(document.activeElement, focusedTab);
  assert.equal(focusedTab.attrs['aria-selected'], 'true');
  assert.equal(focusedTab.focusOptions, undefined,
    'Keyboard navigation must let native focus reveal its tab rather than prevent scrolling');
  window.location.hash = '#reference-title'; listeners.hashchange();
  assert.equal(byId('reference-title').scrolled, true);
  assert.equal(byId('workspace-analysis').hidden, false);
}
viewportWidth = 1440; viewportHeight = 1000;
navigateWorkspace('live');
assert.equal(scroll.scrollTop, 210, 'Desktop keeps its own saved workspace position');
navigateWorkspace('traffic');
assert.equal(scroll.scrollTop, 95);
'''
    result = subprocess.run([shutil.which('node'), '-e', harness + constants + navigation + checks],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
