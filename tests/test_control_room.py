"""Behavioral browser-logic checks with synthetic, explicitly non-live fixtures."""
import json
import shutil
import subprocess

import pytest

from megalodon.control_room_assets import ROOM_JS
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_traffic import TrafficDashboardStore
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
const {code,payload}=JSON.parse(input),nodes=new Map(),calls=[];
function element(tag='') {return {tag,children:[],textContent:'',attrs:{},listeners:{},
append(...items){this.children.push(...items)},replaceChildren(...items){this.children=items},
setAttribute(k,v){this.attrs[k]=v},addEventListener(k,v){this.listeners[k]=v},
set innerHTML(v){throw Error('unsafe sink')}};}
const document={createElement:element,createElementNS:(ns,tag)=>element(tag)};
const byId=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id)};
const textNode=(tag,text='',cls='')=>Object.assign(element(tag),{textContent:text,className:cls});
const textOf=n=>n.textContent+' '+n.children.map(textOf).join(' ');
const context={document,byId,textNode,Date,BigInt,AbortSignal,TextDecoder,TextEncoder,Uint8Array,payload,
referenceExactKeys:(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k)),
knownSeverities:new Set(['LOW','MEDIUM','HIGH','CRITICAL']),
fetch:async(path,options)=>{calls.push({path,options});throw Error('PRIVATE_FAILURE')}};
vm.createContext(context);vm.runInContext(code,context,{timeout:1000});
const run=code=>vm.runInContext(code,context,{timeout:1000});run('renderRoom()');
assert.match(byId('room-home-summary').textContent,/No qualified data available/);
assert.equal(byId('room-count').textContent,'Unavailable');assert.equal(calls.length,0);
assert.equal(run('downloadRoomReport()'),false);
assert.equal(run('previewRoomReport()'),false);assert.equal(byId('room-report-download').disabled,true);
assert.match(byId('room-report-status').textContent,/No qualified data/);
run('roomState.snapshot=validateTraffic(payload);renderRoom()');
assert.match(byId('room-home-summary').textContent,/1 stored metadata events and 1 linked findings/);
assert.match(textOf(byId('room-traffic-grid')),/9223372036854775807 reported bytes/);
assert.equal(byId('room-traffic-grid').children.length,8);
assert.match(textOf(byId('room-traffic-grid')),/local-subnet or sensor-vantage/);
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
assert.equal(calls.length,0);
run('renderRoom()');assert.equal(run('roomState.report'),null);assert.equal(byId('room-report-download').disabled,true);
assert.equal(run('roomSelection(payload,"hour",null,Date.parse("2026-09-18T00:00:00Z")).events.length'),0);
assert.throws(()=>run('roomSelection(payload,"custom",{start:0,end:Date.now()})'));
assert.throws(()=>run('roomSelection(payload,"custom",{start:2,end:1})'));
assert.equal(run('roomSelection(payload,"recorded",null,Date.parse("2026-01-01T00:00:00Z")).events.length'),1);
for(const expression of [
'p.events.push({...p.events[0]})','p.events[0].protocol="<img src=x>"',
'p.events[0].tcp_flags.push("<script>")','p.events[0].src_port=65536',
'p.events[0].byte_count="9223372036854775808"','p.findings[0].event_id="123456"',
'p.window.end=null','p.events[0].raw="PRIVATE_BODY"','p.build.extra="secret"',
'p.events[0].id="9007199254740992"','p.findings[0].detector_version="made-up"']) {
assert.throws(()=>run('{const p=JSON.parse(JSON.stringify(payload));'+expression+';validateTraffic(p)}'));
}
await run('refreshRoom()');assert.equal(calls.length,1);assert.equal(calls[0].path,'/api/traffic');
assert.equal(calls[0].options.method,'GET');assert.equal(calls[0].options.credentials,'omit');
assert.equal(byId('room-coverage').textContent,'Stale');assert.match(byId('room-home-summary').textContent,/1 stored metadata events/);
assert.doesNotMatch(textOf(byId('room-traffic-grid')),/PRIVATE_FAILURE/);
context.fetch=async()=>({ok:true,body:{getReader:()=>({read:async()=>({done:false,value:new Uint8Array(262145)}),cancel:async()=>{}})}});
await run('refreshRoom()');assert.equal(run('roomState.failed'),true);assert.equal(run('roomState.snapshot.events.length'),1);
console.log('bounded projection, exact integer totals, filters, bad inputs and stale preservation passed');
}catch(error){console.error(error);process.exitCode=1}});
'''
    result = subprocess.run([node, '-e', script], input=json.dumps({'code': ROOM_JS, 'payload': payload}),
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
