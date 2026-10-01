"""Sensor provenance, transactional admission and honest cumulative live views."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace
import time

import pytest

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage,GIB,utc
from megalodon.flow_ingestion import FlowIngestor,normalize_suricata,normalize_zeek,READ_BYTES,MAX_ALERT_METADATA
from megalodon.live_connections import LiveConnections,MAX_TRACKED,MAX_CONNECTIONS


def eve(index=1,*,end=None,start=None,sent=100,received=200,spackets=10,rpackets=20,state='established'):
    end=time.time()-1 if end is None else end
    start=end-30 if start is None else start
    return dict(timestamp=utc(end),event_type='flow',flow_id=index,src_ip='10.0.0.3',dest_ip='198.18.0.3',
                src_port=40000,dest_port=443,proto='TCP',flow=dict(start=utc(start),end=utc(end),state=state,
                    bytes_toserver=sent,bytes_toclient=received,pkts_toserver=spackets,pkts_toclient=rpackets))


def zeek(index=1,*,end=None):
    end=time.time()-1 if end is None else end
    return {'ts':end-30,'duration':30,'uid':f'C{index:015d}','id.orig_h':'10.0.0.3','id.resp_h':'198.18.0.3',
            'id.orig_p':40000,'id.resp_p':443,'proto':'tcp','orig_ip_bytes':100,'resp_ip_bytes':200,
            'orig_bytes':50,'resp_bytes':70,'orig_pkts':10,'resp_pkts':20,'conn_state':'SF'}


@pytest.fixture
def evidence(tmp_path):
    tmp_path.chmod(0o700)
    manager=EvidenceStorage(Settings(db_path=tmp_path/'legacy.db'),home=tmp_path,segment_bytes=4*1024*1024)
    manager.apply(manager.preview(dict(profile='server',retention_days=7,cap_bytes=GIB))['preview_id'])
    yield manager
    manager.close()


def write(path,rows,mode='w'):
    with path.open(mode) as stream:
        for row in rows:stream.write(json.dumps(row,separators=(',',':'))+'\n')
    path.chmod(0o600)


def reader(evidence,path,on_flow=None):
    return FlowIngestor(evidence,home=evidence.home,eve_path=path,on_flow=on_flow)


def all_history(evidence):
    rows=[];cursor=None
    while True:
        page=evidence.history(limit=100,cursor=cursor)
        rows.extend(page['records'])
        cursor=page['next_cursor']
        if cursor is None:return rows


def test_sensor_normalizers_preserve_provenance_directions_and_completed_state():
    category,record=normalize_suricata(eve(state='closed'))
    assert category=='flows' and record['source']=='suricata-eve'
    assert record['data']['sent_bytes']==100 and record['data']['received_bytes']==200
    assert record['data']['completed'] is True
    assert normalize_suricata(eve())[1]['data']['completed'] is False
    category,record=normalize_zeek(zeek())
    assert category=='flows' and record['source']=='zeek-conn'
    assert record['data']['completed'] is True and record['data']['byte_basis']=='ip_bytes'
    assert record['data']['sent_bytes']==100 and record['data']['received_bytes']==200
    alert=eve();alert['event_type']='alert';alert['alert']=dict(signature='Synthetic review finding',signature_id=123,severity=2)
    category,record=normalize_suricata(alert)
    assert category=='findings' and 'not an admitted core detector finding' in record['data']['observation']
    assert normalize_suricata({'event_type':'stats'}) is None


def test_missing_zeek_measurements_stay_unknown_with_explicit_byte_basis():
    value=zeek()
    for field in ('orig_ip_bytes','resp_ip_bytes'):value.pop(field)
    record=normalize_zeek(value)[1]
    assert record['data']['byte_basis']=='payload_bytes' and record['data']['sent_bytes']==50
    for field in ('orig_bytes','resp_bytes','orig_pkts','resp_pkts'):value.pop(field)
    data=normalize_zeek(value)[1]['data']
    assert data['byte_basis']=='unknown'
    assert all(data[key] is None for key in ('sent_bytes','received_bytes','sent_packets','received_packets'))


def test_findings_preserve_structured_alert_and_flow_context_without_raw_event_content():
    raw=eve(2**63+4);raw.update(event_type='alert',app_proto='tls',payload='captured bytes are excluded',packet='excluded')
    raw['alert']=dict(signature='Synthetic finding',signature_id=2001,severity=2,gid=1,rev=8,action='allowed',
                      category='Synthetic category',metadata={'affected_product':['Synthetic system'],'confidence':['High']},
                      source={'ip':'10.0.0.3','port':40000},target={'ip':'198.18.0.3','port':443})
    category,record=normalize_suricata(raw);data=record['data']
    assert category=='findings' and record['source']=='suricata-eve' and data['source_id']==str(2**63+4)
    assert data['alert_metadata']==raw['alert'] and data['alert_metadata'] is not raw['alert']
    assert data['app_proto']=='tls' and data['flow_context']==dict(sent_bytes=100,received_bytes=200,sent_packets=10,
        received_packets=20,first_seen=raw['flow']['start'],last_seen=raw['flow']['end'],state='established',byte_basis='ip_bytes')
    assert data['src_ip']=='10.0.0.3' and data['dst_port']==443
    assert record['observed_at']==raw['timestamp'] and 'structured metadata only' in data['observation']
    assert 'payload' not in data and 'packet' not in data
    raw['alert']['metadata']['confidence'].append('mutated')
    assert data['alert_metadata']['metadata']['confidence']==['High']


@pytest.mark.parametrize('bad',[{'nested':{'payload':'raw bytes'}},{'packet':'base64'}, {'number':float('nan')}, {'number':float('inf')}, {1:'non-string key'}])
def test_malformed_or_raw_alert_metadata_is_rejected(bad):
    raw=eve();raw.update(event_type='alert',alert=dict(signature='Synthetic finding',signature_id=2001,severity=2,metadata=bad))
    with pytest.raises(ValueError):normalize_suricata(raw)


def test_oversized_alert_metadata_is_counted_without_blocking_following_valid_finding(evidence,tmp_path):
    invalid=eve();invalid.update(event_type='alert',alert=dict(signature='Too large',signature_id=1,severity=2,metadata={'detail':'x'*MAX_ALERT_METADATA}))
    good=eve(2);good.update(event_type='alert',alert=dict(signature='Valid next finding',signature_id=2,severity=2))
    path=tmp_path/'eve.json';write(path,[invalid,good]);worker=reader(evidence,path)
    assert worker.poll('suricata')==1 and worker.snapshot()['rejected']==1
    assert worker.snapshot()['imported_findings']==1
    stored=evidence.history(category='findings')['records'][0]
    assert stored['data']['alert_metadata']==good['alert'] and stored['data']['source_id']=='2'
    assert evidence.checkpoint('flow_suricata')['offset']==path.stat().st_size


def test_partial_finding_flow_context_keeps_missing_counters_unknown():
    raw=eve();raw.update(event_type='alert',alert=dict(signature='Partial context',signature_id=1,severity=2),
                         flow={'bytes_toserver':0,'start':raw['flow']['start']})
    context=normalize_suricata(raw)[1]['data']['flow_context']
    assert context['sent_bytes']==0 and 'received_bytes' not in context and 'last_seen' not in context


@pytest.mark.parametrize('normalizer,factory',[(normalize_suricata,eve),(normalize_zeek,zeek)])
@pytest.mark.parametrize('bad',[None,[],{},1,True])
def test_malformed_protocols_are_rejected_as_data_not_crash(normalizer,factory,bad):
    value=factory();value['proto']=bad
    with pytest.raises(ValueError):normalizer(value)


@pytest.mark.parametrize('field,bad',[('bytes_toserver',True),('bytes_toserver',-1),('pkts_toserver',2**53),('bytes_toclient',1.5)])
def test_sensor_counters_are_bounded_integers(field,bad):
    value=eve();value['flow'][field]=bad
    with pytest.raises(ValueError):normalize_suricata(value)


def test_checkpoint_resume_and_partial_line_preserve_exact_admission(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve(1)])
    callback=[];worker=reader(evidence,path,callback.append)
    assert worker.poll('suricata')==1
    assert worker.poll('suricata')==0
    text=json.dumps(eve(2))
    with path.open('a') as stream:stream.write(text[:30])
    assert worker.poll('suricata')==0
    with path.open('a') as stream:stream.write(text[30:]+'\n')
    assert worker.poll('suricata')==1
    again=reader(evidence,path,callback.append)
    assert again.poll('suricata')==0
    assert len(callback)==2
    assert {r['data']['source_id'] for r in all_history(evidence)}=={'1','2'}
    assert evidence.checkpoint('flow_suricata')['offset']==path.stat().st_size


def test_failed_later_batch_resumes_after_committed_batch_without_duplicates(evidence,tmp_path,monkeypatch):
    path=tmp_path/'eve.json';write(path,[eve(1)])
    worker=reader(evidence,path);assert worker.poll('suricata')==1
    write(path,[eve(i) for i in range(2,402)],'a')
    original=evidence.append_records;calls=[0]
    def fail_later(*args,**kwargs):
        calls[0]+=1
        if calls[0]==2:raise ValueError('Synthetic interrupted writer')
        return original(*args,**kwargs)
    monkeypatch.setattr(evidence,'append_records',fail_later)
    with pytest.raises(ValueError):worker.poll('suricata')
    assert evidence.history()['total']==257
    monkeypatch.setattr(evidence,'append_records',original)
    worker.poll('suricata')
    records=all_history(evidence)
    assert len(records)==401 and len({r['data']['source_id'] for r in records})==401


def test_rejected_sensor_lines_cannot_poison_following_valid_records(evidence,tmp_path):
    path=tmp_path/'eve.json';bad=eve(2);bad['proto']={'unexpected':'object'}
    write(path,[eve(1),bad,{'event_type':'stats'},eve(3)])
    worker=reader(evidence,path)
    assert worker.poll('suricata')==2
    assert worker.snapshot()['rejected']==1
    assert evidence.history()['total']==2
    assert evidence.checkpoint('flow_suricata')['offset']==path.stat().st_size


def test_skipped_flows_keep_findings_without_cross_source_volume(evidence,tmp_path):
    alert=eve(2);alert.update(event_type='alert',alert=dict(signature='Synthetic sensor finding',signature_id=2,severity=3))
    path=tmp_path/'eve.json';write(path,[eve(1),alert])
    callback=[];worker=reader(evidence,path,callback.append)
    assert worker.poll('suricata',include_flows=False)==1
    assert callback==[] and worker.snapshot()['imported_flows']==0
    rows=all_history(evidence)
    assert len(rows)==1 and rows[0]['category']=='findings'


def test_secondary_findings_do_not_claim_waiting_primary_flow_source_is_connected(evidence,tmp_path):
    path=tmp_path/'eve.json';worker=reader(evidence,path)
    assert worker.select_source(force=True)==('zeek','sample')
    before=worker.snapshot();alert=eve();alert.update(event_type='alert',alert=dict(signature='Separate finding',signature_id=1,severity=2))
    write(path,[alert]);assert worker.poll('suricata',include_flows=False)==1
    after=worker.snapshot()
    assert after['state']=='waiting' and after['source']=='zeek' and after['source_detail']=='sample'
    assert after['message']==before['message'] and after['imported_findings']==1


def test_unaccepted_rows_are_not_reported_as_persisted_or_sent_to_live_view(evidence,tmp_path,monkeypatch):
    path=tmp_path/'eve.json';write(path,[eve(1)])
    callback=[];worker=reader(evidence,path,callback.append)
    monkeypatch.setattr(evidence,'append_records',lambda *a,**k:0)
    with pytest.raises(ValueError,match='not fully admitted'):
        worker.poll('suricata')
    assert callback==[] and worker.snapshot()['accepted']==0
    assert evidence.checkpoint('flow_suricata') is None


def test_first_attach_to_large_old_file_reports_admission_gap(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve(i) for i in range(1000)])
    assert path.stat().st_size>READ_BYTES
    worker=reader(evidence,path);accepted=worker.poll('suricata')
    assert 0<accepted<1000 and worker.snapshot()['gaps']>=1
    assert worker.snapshot()['accepted']==accepted


def test_rotated_input_reports_gap_and_imports_new_identity(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve(1)])
    worker=reader(evidence,path);worker.poll('suricata')
    path.rename(tmp_path/'eve-old.json');write(path,[eve(2)])
    assert worker.poll('suricata')==1
    assert worker.snapshot()['rotations']==1 and worker.snapshot()['gaps']==1
    assert len(all_history(evidence))==2


class Geo:
    def snapshot(self):return {'anchor':None}
    def lookup(self,address):return None


def cache():
    value=LiveConnections(Geo());value._local={'10.0.0.3'}
    return value


def snapshot(value):return value.snapshot({'state':'running'},{'enabled':True})


def summary(**kwargs):return normalize_suricata(eve(**kwargs))[1]


def test_repeated_and_out_of_order_cumulative_updates_never_double_count():
    value=cache();end=time.time()-1;start=end-30
    first=summary(start=start,end=end-5)
    latest=summary(start=start,end=end,sent=140,received=280,spackets=14,rpackets=28)
    value.observe_summary(first)
    assert snapshot(value)['timeline']==[], 'The first cumulative baseline does not establish a rate bin.'
    value.observe_summary(latest);value.observe_summary(deepcopy(latest));value.observe_summary(first);value.observe_summary(latest)
    data=snapshot(value)
    assert data['totals']['bytes']==420 and data['totals']['packets']==42
    assert len(data['connections'])==1
    row=data['connections'][0]
    assert row['a_to_b']['bytes']==140 and row['b_to_a']['bytes']==280
    assert sum(p['sent_bytes']+p['received_bytes']+p['unattributed_bytes'] for p in data['timeline'])==120


def test_counter_regression_cannot_create_a_second_delta_when_prior_totals_return():
    value=cache();end=time.time()-1;start=end-30
    high=summary(start=start,end=end-1,sent=140,received=280,spackets=14,rpackets=28)
    value.observe_summary(high)
    value.observe_summary(summary(start=start,end=end,sent=1,received=2,spackets=1,rpackets=1))
    value.observe_summary(high)
    assert snapshot(value)['totals']['bytes']==420
    assert snapshot(value)['timeline']==[]


def test_fresh_unknown_counter_source_clears_previous_source_projection():
    value=cache();value.observe_summary(summary())
    raw=zeek()
    for key in ('orig_ip_bytes','resp_ip_bytes','orig_bytes','resp_bytes'):raw.pop(key)
    value.observe_summary(normalize_zeek(raw)[1]);data=snapshot(value)
    assert data['connections']==[] and data['totals']['bytes']==0 and data['totals']['packets']==0


def test_changed_counter_byte_basis_establishes_new_baseline_without_false_delta():
    value=cache();end=time.time()-1;start=end-30
    first=summary(start=start,end=end-2);value.observe_summary(first)
    changed=summary(start=start,end=end-1,sent=400,received=500);changed['data']['byte_basis']='payload_bytes'
    value.observe_summary(changed)
    data=snapshot(value)
    assert data['totals']['bytes']==900 and data['timeline']==[]
    latest=summary(start=start,end=end,sent=450,received=550);latest['data']['byte_basis']='payload_bytes'
    value.observe_summary(latest)
    assert sum(p['sent_bytes']+p['received_bytes'] for p in snapshot(value)['timeline'])==100


def test_completed_and_stale_summaries_cannot_animate_as_live():
    value=cache();value.observe_summary(summary(state='closed'))
    data=snapshot(value)
    assert data['connections'][0]['state']=='closed' and not data['connections'][0]['active']
    assert data['totals']['active']==0
    older=cache();older.observe_summary(summary(end=time.time()-120,state='closed'))
    assert snapshot(older)['connections']==[]


def test_source_switch_clears_prior_summary_counts_for_same_tuple():
    value=cache();value.observe_summary(summary(sent=100,received=200))
    record=normalize_zeek(zeek())[1];record['data'].update(sent_bytes=1000,received_bytes=2000)
    value.observe_summary(record)
    data=snapshot(value)
    assert len(data['connections'])==1 and data['totals']['bytes']==3000
    assert data['connections'][0]['source']=='zeek-conn'
    assert data['timeline']==[]


def test_unknown_summary_measurements_remain_persistable_without_numeric_live_claims(evidence):
    raw=zeek()
    for key in ('orig_ip_bytes','resp_ip_bytes','orig_bytes','resp_bytes','orig_pkts','resp_pkts'):raw.pop(key)
    record=normalize_zeek(raw)[1]
    assert evidence.append_records('flows',[record])==1
    value=cache();value.observe_summary(record)
    assert snapshot(value)['connections']==[]
    assert evidence.history(category='flows')['records'][0]['data']['sent_bytes'] is None


def test_many_summary_identities_remain_bounded_and_report_projection_drops():
    value=cache();end=time.time()-1
    for index in range(MAX_TRACKED+30):
        raw=eve(index,end=end);raw['src_port']=2000+index
        value.observe_summary(normalize_suricata(raw)[1])
    data=snapshot(value)
    assert len(data['connections'])<=MAX_CONNECTIONS and data['totals']['truncated']
    assert data['totals']['evicted']>=30
    assert len(json.dumps(data).encode())<=256*1024


def test_final_unchanged_counters_close_the_flow_without_a_false_delta():
    value=cache();end=time.time()-1;start=end-30
    value.observe_summary(summary(start=start,end=end-1))
    assert snapshot(value)['connections'][0]['active']
    value.observe_summary(summary(start=start,end=end,state='closed'))
    data=snapshot(value)
    assert data['connections'][0]['state']=='closed' and not data['connections'][0]['active']
    assert data['totals']['bytes']==300 and data['timeline']==[]


def test_summary_delta_records_its_interval_instead_of_implying_packet_timing():
    value=cache();end=time.time()-1;start=end-50
    value.observe_summary(summary(start=start,end=end-20))
    value.observe_summary(summary(start=start,end=end,sent=200,received=400,spackets=20,rpackets=40))
    point=snapshot(value)['timeline'][0]
    assert point['basis']=='flow_summary_delta'
    assert point['timing']=='summary_interval_not_packet_arrival'
    assert point['interval_start']==utc(end-20) and point['interval_end']==utc(end)
    assert point['source']=='suricata-eve' and point['summary_updates']==1


def test_expired_summary_cache_does_not_keep_old_numeric_totals():
    clock=[0];value=LiveConnections(Geo(),clock=lambda:clock[0])
    value.observe_summary(summary());clock[0]=61
    data=snapshot(value)
    assert data['connections']==[] and data['totals']['bytes']==0 and data['totals']['packets']==0


def test_large_flow_identity_is_preserved_as_string_and_mixed_byte_units_are_not_added():
    value=eve(2**63+8)
    assert normalize_suricata(value)[1]['data']['source_id']==str(2**63+8)
    value=zeek();value.pop('resp_ip_bytes')
    data=normalize_zeek(value)[1]['data']
    assert data['byte_basis']=='payload_bytes' and data['sent_bytes']==50 and data['received_bytes']==70


def test_empty_file_checkpoint_prevents_later_backlog_tail_loss(evidence,tmp_path):
    path=tmp_path/'eve.json';path.touch()
    worker=reader(evidence,path);assert worker.poll('suricata')==0
    write(path,[eve(i) for i in range(1000)])
    for _ in range(5):worker.poll('suricata')
    assert evidence.history()['total']==1000 and worker.snapshot()['gaps']==0


def test_oversized_line_advances_restartable_discard_checkpoint_and_recovers(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve(1)])
    worker=reader(evidence,path);worker.poll('suricata')
    with path.open('ab') as stream:stream.write(b'x'*(READ_BYTES*2+16)+b'\n'+json.dumps(eve(2)).encode()+b'\n')
    assert worker.poll('suricata')==0
    assert evidence.checkpoint('flow_suricata')['discarding'] is True
    again=reader(evidence,path)
    for _ in range(4):again.poll('suricata')
    assert {r['data']['source_id'] for r in all_history(evidence)}=={'1','2'}
    assert evidence.checkpoint('flow_suricata')['offset']==path.stat().st_size
    assert worker.snapshot()['rejected']==1 and worker.snapshot()['gaps']==1


def test_out_of_retention_row_is_rejected_without_blocking_following_row(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve(1,end=time.time()-31*86400),eve(2)])
    worker=reader(evidence,path)
    assert worker.poll('suricata')==1 and worker.snapshot()['rejected']==1
    assert evidence.history()['total']==1


def test_primary_source_requires_readable_recent_flow_records(evidence,tmp_path):
    eve_path=tmp_path/'eve.json';write(eve_path,[eve(1)])
    worker=reader(evidence,eve_path)
    assert worker.select_source(force=True)==('suricata','file')
    write(eve_path,[eve(1,end=time.time()-3600)])
    assert worker.select_source(force=True)==('zeek','sample')
    worker.paths['zeek'].parent.mkdir(parents=True)
    write(worker.paths['zeek'],[zeek()])
    assert worker.select_source(force=True)==('zeek','file')
    eve_path.unlink();eve_path.symlink_to(worker.paths['zeek'])
    assert worker.select_source(force=True)==('zeek','file')
    eve_path.unlink();write(eve_path,[dict(event_type='stats',timestamp=utc())])
    assert worker.select_source(force=True)==('zeek','file')


def sample_args():
    return dict(sample_id='a'*32,interface='eth0',started_at=utc(time.time()-10),finished_at=utc())


def test_zeek_sample_ingestion_is_deduplicated_source_qualified_and_explicitly_gapped(evidence,tmp_path):
    worker=reader(evidence,tmp_path/'missing-eve.json');callback=[];worker.on_flow=callback.append
    raw=b'\n'.join(json.dumps(zeek(i)).encode() for i in range(3))
    args=sample_args()
    assert worker.ingest_zeek_sample(raw,**args)==3
    assert worker.ingest_zeek_sample(raw,**args)==0
    restarted=reader(evidence,tmp_path/'missing-eve.json');assert restarted.ingest_zeek_sample(raw,**args)==0
    rows=all_history(evidence)
    assert len(rows)==len(callback)==3 and all(row['source']=='zeek-sample' for row in rows)
    coverage=rows[0]['data']['sampling']
    assert coverage['continuous'] is False and coverage['max_frames']==2000 and coverage['snapshot_bytes']==256
    assert worker.snapshot()['sampling_gaps']==1 and worker.snapshot()['samples']==1


def test_zeek_sample_does_not_duplicate_recent_primary_eve_or_packet_mode(evidence,tmp_path):
    path=tmp_path/'eve.json';write(path,[eve()]);worker=reader(evidence,path);raw=json.dumps(zeek()).encode()
    assert worker.ingest_zeek_sample(raw,**sample_args())==0
    assert evidence.history()['total']==0
    path.unlink();worker.select_source(force=True)
    evidence.apply(evidence.preview(dict(profile='home',retention_days=7,cap_bytes=GIB))['preview_id'])
    assert worker.ingest_zeek_sample(raw,**sample_args())==0
    assert evidence.history()['total']==0


def test_sample_retry_resumes_after_committed_batch(evidence,tmp_path,monkeypatch):
    worker=reader(evidence,tmp_path/'missing-eve.json')
    raw=b'\n'.join(json.dumps(zeek(i)).encode() for i in range(300));args=sample_args()
    original=evidence.append_records;calls=[0]
    def failing(*a,**kw):
        calls[0]+=1
        if calls[0]==2:raise ValueError('Synthetic partial sample failure')
        return original(*a,**kw)
    monkeypatch.setattr(evidence,'append_records',failing)
    with pytest.raises(ValueError):worker.ingest_zeek_sample(raw,**args)
    assert evidence.history()['total']==256
    monkeypatch.setattr(evidence,'append_records',original)
    assert worker.ingest_zeek_sample(raw,**args)==44
    assert evidence.history()['total']==300 and worker.snapshot()['accepted']==300
    assert len({row['data']['source_id'] for row in all_history(evidence)})==300
