"""Exercise the real read-only export and browser import contract together."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from megalodon.hud_snapshot import main, snapshot_from_projection
from megalodon.dashboard_traffic import TrafficDashboardStore, unavailable
from megalodon.dashboard_snapshot import SNAPSHOT_VALIDATOR_JS
from megalodon.models import PacketEvent, DetectionResult, ActionRecord
from megalodon.storage import Store


def test_export_projection_roundtrip_and_privacy(tmp_path, capsys):
    path = tmp_path / 'private' / 'audit.db'
    now = datetime.now(timezone.utc)
    with Store(path) as writer:
        run = writer.start_ingestion_run('jsonl', started_at=now)
        for severity in ('LOW', 'HIGH'):
            event = PacketEvent(now, '192.0.2.1', '198.51.100.1', 'TCP', byte_count=2**63-1)
            findings = [DetectionResult(now, 'PORT_SCAN', severity, '192.0.2.1', '198.51.100.1', 'PRIVATE_TEXT', {}, 'PRIVATE_RECOMMENDATION')]
            writer.record_event_bundle(event, findings, [ActionRecord(now, 'block', '192.0.2.1', 'not_attempted', 'PRIVATE_REASON')], run_id=run)
        writer.finish_ingestion_run(run, 'source_exhausted', finished_at=now)
        before = writer.summary()
        assert main(['--database',str(path)]) == 0
        text = capsys.readouterr().out
        value = json.loads(text)
        assert value['lanes'] == [0,1,1]
        assert value['reported_bytes'] == str(2*(2**63-1))
        assert value['events'] == sum(value['timeline']) == 2
        assert all(secret not in text for secret in ('192.0.2','198.51.100','PRIVATE_',str(path)))
        assert writer.summary() == before
        node = shutil.which('node')
        if node:
            script = SNAPSHOT_VALIDATOR_JS + "\nlet s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{const x=validateHudSnapshot(s);if(x.events!==2)process.exit(1);});"
            subprocess.run([node,'-e',script], input=text,text=True,check=True,cwd=tmp_path,timeout=10)


def test_no_export_for_unqualified_or_missing_database(tmp_path, capsys):
    with pytest.raises(ValueError):
        snapshot_from_projection(unavailable())
    assert main(['--database',str(tmp_path/'missing.db')]) == 1
    assert not (tmp_path/'missing.db').exists()
    assert capsys.readouterr().out == ''


def test_highest_severity_counts_each_event_once():
    projection={'status':'available','generated_at':'2026-01-01T00:00:00Z','window':{'start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:00:00Z'},'truncated':False,'quality':'unknown',
      'events':[{'id':'1','observed_at':'2026-01-01T00:00:00Z','byte_count':'0','protocol':'TCP','source':'jsonl'}],
      'findings':[{'event_id':'1','severity':s,'rule_id':'PORT_SCAN'} for s in ('LOW','HIGH','CRITICAL')]}
    assert snapshot_from_projection(projection)['lanes']==[0,0,1]


def test_snapshot_http_route_preserves_readonly_scope_and_refuses_queries(tmp_path):
    from http.client import HTTPConnection
    from http.server import ThreadingHTTPServer
    from threading import Thread
    from megalodon.dashboard import DashboardHandler
    path = tmp_path / 'private' / 'audit.db'
    now = datetime.now(timezone.utc)
    with Store(path) as writer:
        run = writer.start_ingestion_run('jsonl', started_at=now)
        writer.record_event_bundle(PacketEvent(now, '192.0.2.1', '198.51.100.1', 'TCP', byte_count=100), [], [], run_id=run)
        writer.finish_ingestion_run(run, 'source_exhausted', finished_at=now)
        with TrafficDashboardStore(path) as reader:
            handler = type('SnapshotHandler',(DashboardHandler,),{'store':reader})
            server = ThreadingHTTPServer(('127.0.0.1',0),handler)
            thread = Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
            def request(target, method='GET'):
                conn=HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                try:
                    conn.request(method,target);res=conn.getresponse()
                    return res.status,dict(res.getheaders()),res.read()
                finally:conn.close()
            try:
                before=writer.summary()
                status,headers,body=request('/api/hud-snapshot')
                assert status==200 and headers['Cache-Control']=='no-store'
                assert json.loads(body)['events']==1
                assert b'192.0.2' not in body and len(body)<=16384
                assert request('/api/hud-snapshot?database=other')[0]==400
                assert request('/api/hud-snapshot','POST')[0]==405
                assert writer.summary()==before
                handler.store=object()
                status,_,body=request('/api/hud-snapshot')
                assert status==503 and json.loads(body)=={'error':'HUD summary unavailable'}
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)


def test_local_export_preview_download_failure_and_overlap():
    from megalodon.dashboard_snapshot import SNAPSHOT_LOCAL_JS, SNAPSHOT_VALIDATOR_JS
    node=shutil.which('node')
    if not node:pytest.skip('Node needed for browser behavior')
    script=r'''
const vm=require('node:vm'),assert=require('node:assert/strict');let input='';process.stdin.on('data',v=>input+=v);process.stdin.on('end',async()=>{
 const nodes=new Map(), clicks=[], revokes=[];let requests=0,release;
 const element=()=>({textContent:'',hidden:false,disabled:false,addEventListener(){},click(){clicks.push(this);}});
 const context={Date,TextEncoder,Blob,URL:{createObjectURL:()=> 'blob:local',revokeObjectURL:url=>revokes.push(url)},setTimeout:fn=>fn(),
 byId:id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);},document:{createElement:element},
 requestBoundedJSON:async(path,limit)=>{assert.equal(path,'/api/hud-snapshot');assert.equal(limit,16384);requests++;return new Promise(resolve=>release=resolve);}};
 vm.createContext(context);vm.runInContext(input,context);const run=s=>vm.runInContext(s,context);
 const value={schema:'megalodon-hud-snapshot-v1',generated_at:'2026-09-20T12:00:00Z',start:'2026-09-20T11:00:00Z',end:'2026-09-20T12:00:00Z',events:1,findings:0,reported_bytes:'100',lanes:[1,0,0],timeline:[1,0,0,0,0,0,0,0,0,0,0,0],protocols:[1,0,0,0,0,0,0,0],sources:[1,0],severities:[0,0,0,0],detectors:[0,0,0],limited:false,quality:'unknown'};
 const pending=run('prepareHudExport()');await run('prepareHudExport()');assert.equal(requests,1);assert.equal(nodes.get('hud-export-clear').disabled,true);release(value);await pending;
 const held=nodes.get('hud-export-preview').textContent;assert.deepEqual(JSON.parse(held),value);assert.equal(nodes.get('hud-export-download').disabled,false);
 run('downloadHudExport()');assert.equal(clicks[0].download,'megalodon-hud-summary.json');assert.deepEqual(revokes,['blob:local']);
 context.requestBoundedJSON=async()=>{throw Error('PRIVATE error');};await run('prepareHudExport()');assert.equal(nodes.get('hud-export-preview').textContent,held);assert.match(nodes.get('hud-export-status').textContent,/prior held preview/);
 run('clearHudExport()');assert.equal(nodes.get('hud-export-preview').hidden,true);assert.equal(nodes.get('hud-export-download').disabled,true);
 await run('prepareHudExport()');assert.match(nodes.get('hud-export-status').textContent,/unavailable/);assert.doesNotMatch(nodes.get('hud-export-status').textContent,/PRIVATE/);
}).catch(error=>{console.error(error);process.exitCode=1;});
'''.replace("process.stdin.on('end',async()=>{", "process.stdin.on('end',()=>{(async()=>{").replace("}).catch(error=>{console.error(error);process.exitCode=1;});", "})().catch(error=>{console.error(error);process.exitCode=1;});});")
    subprocess.run([node,'-e',script],input=SNAPSHOT_VALIDATOR_JS+SNAPSHOT_LOCAL_JS,text=True,check=True,timeout=10)
