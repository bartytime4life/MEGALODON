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


def test_history_cursor_does_not_recount_source_compacted_mid_paging(manager):
    start=utc(manager.clock()-60)
    first=_source(manager,count=200)
    manager.test_clock[0]+=1
    _source(manager,count=5,with_finding=False)
    second=next(e for e in manager._catalog['entries'] if e['category']=='packets' and e['id']!=first['id'])
    manager.test_clock[0]+=1  # The summary is created after the next raw segment.
    reader=RetainedEvidenceReader(manager)
    cursor=None;count=0;ids=[]
    for _ in range(20):
        page=reader.history_page(start,utc(manager.clock()+1),cursor)
        for row in page['records']:
            if row['data'].get('kind') in {'packet_v1','conversation_v1'}:
                count+=row['data']['packet_count'];ids.append(row['id'])
        cursor=page['next_cursor']
        if cursor and cursor.startswith(second['id']) and first.get('compaction_state')!='complete':
            for _ in range(100):  # Only the earlier segment finishes.
                if first.get('compaction_state')=='complete' or not manager.compact_step():break
            rollup=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
            assert rollup['created_at']>second['created_at']
        if cursor is None:break
    assert first['compaction_state']=='complete'
    assert count==205 and len(ids)==len(set(ids))


def test_history_expired_cursor_and_invalid_query_are_explicit(manager):
    reader=RetainedEvidenceReader(manager)
    page=reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'f'*32+':12')
    assert page['truncated'] and 'expired' in page['gaps'][0]
    with pytest.raises(ValueError):reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'../store:0')


def test_history_cursor_and_case_ids_beyond_sqlite_integers_are_invalid(manager):
    first=_source(manager,count=5,with_finding=False)
    with pytest.raises(ValueError):manager.history(cursor=first['id']+':'+str(2**63))
    assert manager.history(cursor=first['id']+':'+str(2**63-1))['records']
    for number in (2**63-1,10**19-1):
        with pytest.raises(ValueError):manager.save_case([first['id']+':'+str(number)])


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


def test_raw_packet_history_page_passes_the_real_hud_timestamp_check(manager):
    import json,shutil,subprocess
    from datetime import datetime,timezone
    from megalodon.control_room_assets import ROOM_JS
    from megalodon.dashboard_history import HISTORY_JS
    node=shutil.which('node')
    if not node:pytest.skip('Node required for retained history behavior')
    _source(manager,count=3,with_finding=False)
    now=int(manager.clock())
    start=datetime.fromtimestamp(now-60,timezone.utc);end=datetime.fromtimestamp(now+1,timezone.utc)
    page=RetainedEvidenceReader(manager).history_page(start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),end.strftime('%Y-%m-%dT%H:%M:%S.000Z'))
    # Raw packets are stored with "+00:00"; the HUD accepts only a trailing Z.
    assert page['records'] and all(r['observed_at'].endswith('Z') for r in page['records'])
    stamp_check=ROOM_JS[ROOM_JS.index('function roomStamp(value)'):ROOM_JS.index('function validateTraffic')]
    validator=HISTORY_JS[HISTORY_JS.index('function validateManagedHistory'):HISTORY_JS.index('function renderManagedHistory')]
    script=stamp_check+validator+"\nconst p=JSON.parse(require('fs').readFileSync(0,'utf8'));validateManagedHistory(p.page,p.request);"
    request=dict(start=int(start.timestamp()*1000),end=int(end.timestamp()*1000))
    result=subprocess.run([node,'-e',script],input=json.dumps(dict(page=page,request=request)),capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr


@pytest.mark.parametrize('start_offset,end_offset,partial,expected_count,expected_bytes',[
    (100,250,True,'At least 1','At least 100'),
    (-1,150,True,'Unknown','Unknown'),
    (100,140,True,'Unknown','Unknown'),
    (0,200,True,'At least 1','At least 100'),
    (200,250,True,'Unknown','Unknown'),
    (0,201,False,'202','20200'),
    (-1,250,False,'202','20200'),
    (250,280,False,'0','0'),
])
def test_compact_history_interval_counts_remain_qualified(manager,start_offset,end_offset,partial,expected_count,expected_bytes):
    import json,shutil,subprocess
    from datetime import datetime,timedelta,timezone
    from megalodon.control_room_assets import ROOM_JS
    from megalodon.dashboard_history import HISTORY_JS
    from megalodon.models import PacketEvent
    begin=(int(manager.clock())//300-1)*300
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    for index in range(201):
        # Offset-bearing observations must reach the HUD as canonical UTC too.
        writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(begin+index,timezone(timedelta(hours=-6))),
            '10.0.0.2','1.1.1.1','TCP',50000,443,byte_count=100),[],[],run_id=run)
    # A distinct, wholly contained conversation remains an exact lower bound
    # when the longer conversation crosses the requested start.
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(begin+150,timezone.utc),
        '10.0.0.2','1.1.1.1','TCP',50001,443,byte_count=100),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    _compact(manager)
    page=RetainedEvidenceReader(manager).history_page(utc(begin+start_offset),utc(begin+end_offset))
    assert all(r['observed_at'].endswith('Z') for r in page['records'])
    markers=[r for r in page['records'] if r['data'].get('kind')=='partial_interval']
    assert bool(markers)==partial
    assert page['truncated'] is partial
    assert page['next_cursor'] is None
    if partial:
        assert any('crossed the requested interval boundary' in gap for gap in page['gaps'])
        assert all('packet_count' not in r['data'] and 'byte_count' not in r['data'] for r in markers)
    else:
        assert not page['gaps']
        assert sum(r['data'].get('packet_count',0) for r in page['records'])==int(expected_count)
    node=shutil.which('node')
    if not node:pytest.skip('Node required for retained history behavior')
    stamp_check=ROOM_JS[ROOM_JS.index('function roomStamp(value)'):ROOM_JS.index('function validateTraffic')]
    script=stamp_check+HISTORY_JS+r'''
const assert=require('node:assert/strict'),input=JSON.parse(require('fs').readFileSync(0,'utf8'));
const nodes=new Map();function textNode(tag,text=''){return {tag,textContent:text,children:[],append(...v){this.children.push(...v)},replaceChildren(...v){this.children=v},setAttribute(){}}}
function byId(id){if(!nodes.has(id))nodes.set(id,textNode('div'));return nodes.get(id)}
function roomBars(){}function roomVisual(parent,title){const p=textNode('article',title);parent.append(p);return p}
function roomCounts(values){return values.map(x=>[x,1])}function renderRoomControls(){}function clearRoomEvidence(){}
const roomEvidenceState={buttons:new Map()};
const roomState={managedHistory:validateManagedHistory(input.page,input.request),history:{...input.request,previous:[]}};
renderManagedHistory();
assert.equal(byId('hud-records').textContent,input.expected_count);
assert.equal(byId('hud-bytes').textContent,input.expected_bytes);
assert.equal(byId('room-coverage').textContent,input.partial?'Partial page':'End of retained range');
if(input.partial){
  assert.match(byId('room-notice').textContent,/packet and byte totals cannot be assigned/);
  const rows=byId('room-activity-table').children[0].children[2].children;
  assert(rows.some(r=>r.children.some(c=>c.textContent==='Conversation crosses selected interval')));
}
'''
    request=dict(start=(begin+start_offset)*1000,end=(begin+end_offset)*1000)
    result=subprocess.run([node,'-e',script],input=json.dumps(dict(page=page,request=request,partial=partial,
        expected_count=expected_count,expected_bytes=expected_bytes)),capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr


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
const roomEvidenceState={key:'selected',signature:'prior-page',context:'latest',buttons:new Map()};
let evidenceMessage='';function clearRoomEvidence(message){roomEvidenceState.key=null;evidenceMessage=message;}
const stamp='2026-09-30T10:00:00Z',start=Date.parse(stamp),end=start+60000;
const page={schema:'megalodon-traffic-history-v2',records:[{id:'a'.repeat(32)+':1',observed_at:stamp,source:'capture',category:'packets',data:{kind:'packet_v1',packet_count:1,byte_count:90,protocol:'TCP',src_ip:'192.0.2.1',dst_ip:'198.51.100.1',findings:[]}}],range:{start:stamp,end:new Date(end).toISOString()},candidate_count:1,source_segments:['a'.repeat(32)],next_cursor:null,truncated:false,gaps:[]};
const roomState={managedHistory:validateManagedHistory(page,{start,end}),history:{start,end,previous:[]}};
byId('room-findings-table').append(textNode('p','stale old finding'));renderManagedHistory();
assert.equal(roomEvidenceState.key,null);assert.match(evidenceMessage,/Retained history/);
assert.equal(roomEvidenceState.signature,null);assert.equal(roomEvidenceState.buttons.size,0);
assert.equal(byId('hud-records').textContent,'1');assert.equal(byId('hud-bytes').textContent,'90');
assert.equal(byId('room-findings-table').children[0].tag,'table');
assert.equal(byId('room-activity-table').children[0].children[1].tag,'thead');
assert.throws(()=>validateManagedHistory({...page,next_cursor:'../escape'},{start,end}));
'''
    result=subprocess.run([node,'-e',source],capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr
