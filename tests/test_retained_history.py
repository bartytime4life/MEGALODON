"""Cross-segment chart paging shares source selection with visual reports."""
import pytest
from megalodon.retained_history import RetainedEvidenceReader
from megalodon.evidence_storage import utc
from test_packet_compaction import manager, _source, _compact


def test_history_reaches_multiple_segments_without_recounting_compact_copy(manager):
    first=_source(manager,count=200)
    second=_source(manager,count=5,with_finding=False)
    _compact(manager)
    reader=RetainedEvidenceReader(manager)
    cursor=None;count=0;ids=[]
    for _ in range(20):
        page=reader.history_page(utc(manager.clock()-60),utc(manager.clock()+1),cursor)
        for row in page['records']:
            if row['data'].get('kind') in {'packet_v1','conversation_v1'}:
                count+=row['data']['packet_count'];ids.append(row['id'])
        cursor=page['next_cursor']
        if cursor is None:break
    assert count==205
    assert len(ids)==len(set(ids))


def test_history_expired_cursor_and_invalid_query_are_explicit(manager):
    reader=RetainedEvidenceReader(manager)
    page=reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'f'*32+':12')
    assert page['truncated'] and 'expired' in page['gaps'][0]
    with pytest.raises(ValueError):reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'../store:0')


def test_reports_exclude_sample_ingestion(manager):
    from datetime import datetime,timezone
    from megalodon.models import PacketEvent
    from megalodon.reporting import ReportService
    writer=manager.packet_writer();run=writer.start_ingestion_run('sample')
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'192.0.2.1','198.51.100.1','TCP',1,443),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    value=ReportService(manager,clock=manager.clock)._aggregate('audit',manager.clock()-60,manager.clock()+1)
    assert value['summary']['packet_records']==0
    assert manager.compact_step()
    source=next(e for e in manager._catalog['entries'] if e['category']=='packets')
    assert source['compaction_state']=='ineligible' and manager._path(source).exists()
    value=ReportService(manager,clock=manager.clock)._aggregate('after',manager.clock()-60,manager.clock()+1)
    assert value['summary']['packet_records']==0


def test_history_http_qualifies_rows_and_refuses_paths(manager):
    from http.client import HTTPConnection
    from http.server import ThreadingHTTPServer
    from threading import Thread
    from urllib.parse import urlencode
    import json
    from megalodon.dashboard import DashboardHandler
    _source(manager,count=3,with_finding=False)
    handler=type('RetainedHistoryHandler',(DashboardHandler,),{'evidence':manager})
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    worker=Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);worker.start()
    query=urlencode(dict(start=utc(manager.clock()-60),end=utc(manager.clock()+1)))
    try:
        for suffix,expected in [('?'+query,200),('?'+query+'&path=/etc/passwd',422),('?'+query+'&cursor=../bad',422),('?'+query+'&start=x',422)]:
            connection=HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            connection.request('GET','/api/traffic-history-v2'+suffix,headers={'X-Megalodon-Check':'1'})
            response=connection.getresponse();raw=response.read();connection.close()
            assert response.status==expected
            assert len(raw)<=256*1024
            if expected==200:
                value=json.loads(raw);assert value['schema']=='megalodon-traffic-history-v2'
                assert len(value['records'])==3
                assert all(r['id'].count(':')==1 for r in value['records'])
    finally:
        server.shutdown();server.server_close();worker.join(2)


def test_history_browser_uses_retained_data_and_clears_old_findings():
    import json,shutil,subprocess
    from megalodon.dashboard_history import HISTORY_JS
    node=shutil.which('node')
    if not node:pytest.skip('Node required for retained history behavior')
    source=HISTORY_JS+r'''
const assert=require('node:assert/strict');
const nodes=new Map();function textNode(tag,text='',cls=''){return {tag,textContent:text,children:[],append(...v){this.children.push(...v)},replaceChildren(...v){this.children=v},setAttribute(){}}}
function byId(id){if(!nodes.has(id))nodes.set(id,textNode('div'));return nodes.get(id)}
function roomStamp(v){return Number.isFinite(Date.parse(v))}
function roomBars(panel,rows,unit){panel.append({rows,unit})}
function roomVisual(parent,title){const p=textNode('article',title);parent.append(p);return p}
function roomCounts(values){return values.map(x=>[x,1])}function renderRoomControls(){}
const stamp='2026-09-30T10:00:00Z',start=Date.parse(stamp),end=start+60000;
const page={schema:'megalodon-traffic-history-v2',records:[{id:'a'.repeat(32)+':1',observed_at:stamp,source:'capture',category:'packets',data:{kind:'packet_v1',packet_count:1,byte_count:90,protocol:'TCP',src_ip:'192.0.2.1',dst_ip:'198.51.100.1',findings:[]}}],range:{start:stamp,end:new Date(end).toISOString()},candidate_count:1,source_segments:['a'.repeat(32)],next_cursor:null,truncated:false,gaps:[]};
const roomState={managedHistory:validateManagedHistory(page,{start,end}),history:{start,end,previous:[]}};
byId('room-findings-table').append(textNode('p','stale old finding'));renderManagedHistory();
assert.equal(byId('hud-records').textContent,'1');assert.equal(byId('hud-bytes').textContent,'90');
assert.equal(byId('room-findings-table').children[0].tag,'table');
assert.equal(byId('room-activity-table').children[0].children[1].tag,'thead');
assert.throws(()=>validateManagedHistory({...page,next_cursor:'../escape'},{start,end}));
'''
    result=subprocess.run([node,'-e',source],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
