"""Real synthetic storage; retained counts remain separate from learned counts."""
from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

from megalodon.config import Settings
from megalodon.endpoint_hour_counts import read_hour_counts, SCHEMA, SOURCE
from megalodon.evidence_storage import EvidenceStorage, GIB, utc, epoch
from megalodon.intelligence import IntelligenceService
from megalodon.models import PacketEvent
from megalodon.retained_history import RetainedEvidenceReader

START = 1790812800


@pytest.fixture
def evidence(private_tmp_path):
    clock = [START + 3 * 3600]
    value = EvidenceStorage(Settings(db_path=private_tmp_path/'old.db'), home=private_tmp_path,
                            clock=lambda:clock[0], monotonic=lambda:clock[0])
    value.apply(value.preview(dict(profile='home', retention_days=14, cap_bytes=20*GIB))['preview_id'])
    value.test_clock = clock
    yield value
    value.close()


def append(evidence, *, count=5, source='zeek-conn', interface='eth0', ip='192.0.2.8', peer='198.51.100.4', start=START):
    evidence.append_records('flows', [dict(observed_at=utc(start+10+i), source=source,
        data=dict(src_ip=ip, dst_ip=peer, protocol='TCP', src_port=50000, dst_port=443,
            interface=interface, source_id='one-connection', first_seen=utc(start+5))) for i in range(count)])


def for_subject(result, ip='192.0.2.8'):
    assert result['state']=='available', result
    return [value for value in result['summaries'] if value['subject']==ip]


def test_counts_updates_and_both_endpoints_without_writes(evidence):
    append(evidence)
    before=evidence.history(category='baselines')['total']
    first=read_hour_counts(evidence, START)
    summary=for_subject(first)[0]
    assert summary['schema']==SCHEMA and summary['count']==5
    assert summary['basis']=='retained_record_count' and summary['eligible'] is True
    assert summary['capture_complete'] is False
    assert summary['start']==START and summary['end']==START+3600
    assert for_subject(first, '198.51.100.4')[0]['count']==5
    assert len(summary['read_sources'])==1 and summary['read_sources'][0]['watermark']==5
    assert summary['source_segments']==[summary['read_sources'][0]['id']]
    assert len(summary['read_sha256'])==64
    evidence.test_clock[0]+=1
    assert for_subject(read_hour_counts(evidence, START))[0]['id']==summary['id']
    assert evidence.history(category='baselines')['total']==before
    assert 'one-connection' not in json.dumps(first)


def test_sources_interfaces_segments_and_ipv6_never_combined(evidence):
    append(evidence, count=2)
    append(evidence, count=3, source='suricata-eve')
    append(evidence, count=1, interface='eth1')
    append(evidence, count=4, ip='2001:db8::8')
    with evidence.lock:
        entry=evidence._generic.pop('flows');evidence._seal(entry)
    append(evidence, count=1)
    result=read_hour_counts(evidence, START)
    groups=for_subject(result)
    assert sorted(value['count'] for value in groups)==[1,1,2,3]
    assert len({(v['source'],v['kind'],v['scope_id']) for v in groups})==4
    assert for_subject(result, '2001:db8::8')[0]['count']==4


def test_self_exchange_is_counted_once_and_interval_is_half_open(evidence):
    append(evidence, count=1, peer='192.0.2.8')
    append(evidence, count=1, start=START-20)  # Before the hour.
    append(evidence, count=1, start=START+3590)  # Exactly at its exclusive end.
    assert for_subject(read_hour_counts(evidence, START))[0]['count']==1


@pytest.mark.parametrize('start', [True, START+1, START+.5, START+3*3600, float('nan'), float('inf'), -3600])
def test_ineligible_hours_have_no_summary(evidence, start):
    append(evidence)
    assert read_hour_counts(evidence,start)==dict(state='unavailable',reason='incomplete_hours',summaries=[])


def test_missing_is_not_zero(evidence):
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='no_baseline',summaries=[])
    append(evidence, start=START+3600)
    assert read_hour_counts(evidence,START)['summaries']==[]


@pytest.mark.parametrize('fault', ['unknown_source','invalid_interface','invalid_peer'])
def test_one_malformed_row_withholds_all_hour_counts(evidence, fault):
    append(evidence)
    append(evidence, count=1, source='unqualified' if fault=='unknown_source' else 'zeek-conn',
        interface='not an interface' if fault=='invalid_interface' else 'eth0',
        peer='not-an-ip' if fault=='invalid_peer' else '198.51.100.4')
    result=read_hour_counts(evidence,START)
    assert result==dict(state='unavailable',reason='incomplete_hours',summaries=[])


@pytest.mark.parametrize('fault', ['recovered_incomplete','sensor_disagreement','cancelled'])
def test_incomplete_reads_never_generate_eligible_counts(evidence, monkeypatch, fault):
    append(evidence)
    if fault=='recovered_incomplete':
        evidence._generic['flows']['recovered_incomplete']=True
    elif fault=='sensor_disagreement':
        original=RetainedEvidenceReader._sources
        def sources(*args,**kwargs):
            values,gaps=original(*args,**kwargs);return values,gaps+['sensor_disagreement']
        monkeypatch.setattr(RetainedEvidenceReader,'_sources',sources)
    def check():
        if fault=='cancelled':raise ValueError('PRIVATE_CANCELLATION_DETAIL')
    assert read_hour_counts(evidence,START,check=check)==dict(state='unavailable',reason='incomplete_hours',summaries=[])


@pytest.mark.parametrize('fault', ['append','retire','policy'])
def test_source_changes_during_scan_withhold_every_summary(evidence, monkeypatch, fault):
    append(evidence)
    original=RetainedEvidenceReader._pages
    def pages(*args,**kwargs):
        yield from original(*args,**kwargs)
        if fault=='append':append(evidence,count=1)
        elif fault=='retire':evidence._generic['flows']['state']='retired'
        else:evidence._catalog['policy']['retention_days']=7
    monkeypatch.setattr(RetainedEvidenceReader,'_pages',pages)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='incomplete_hours',summaries=[])


@pytest.mark.parametrize('offset', [-1,0,1])
def test_fresh_expiry_check_after_final_binding(evidence, monkeypatch, offset):
    from megalodon import endpoint_hour_counts
    append(evidence)
    entry=evidence._generic['flows']
    expires=int(epoch(entry['first_at'])+evidence.retention_days*86400)
    original=endpoint_hour_counts._bindings
    calls=[]
    def bindings(*args,**kwargs):
        result=original(*args,**kwargs);calls.append(1)
        if len(calls)==2:evidence.test_clock[0]=expires+offset
        return result
    monkeypatch.setattr(endpoint_hour_counts,'_bindings',bindings)
    result=read_hour_counts(evidence,START)
    if offset<0:assert for_subject(result)[0]['count']==5
    else:assert result==dict(state='unavailable',reason='source_expired',summaries=[])


def test_scan_and_group_bounds_do_not_store_prefix_counts(evidence, monkeypatch):
    from megalodon import endpoint_hour_counts
    append(evidence)
    monkeypatch.setattr(endpoint_hour_counts,'MAX_RECORDS',4)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='truncated',summaries=[])
    monkeypatch.setattr(endpoint_hour_counts,'MAX_RECORDS',20000)
    monkeypatch.setattr(endpoint_hour_counts,'MAX_GROUPS',1)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='truncated',summaries=[])
    monkeypatch.setattr(endpoint_hour_counts,'MAX_GROUPS',128)
    monkeypatch.setattr(endpoint_hour_counts,'MAX_SOURCES',0)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='truncated',summaries=[])


def test_clock_reversal_during_final_check_cannot_qualify_a_future_hour(evidence,monkeypatch):
    from megalodon import endpoint_hour_counts
    append(evidence)
    original=endpoint_hour_counts._bindings
    calls=[]
    def bindings(*args,**kwargs):
        result=original(*args,**kwargs);calls.append(1)
        if len(calls)==2:evidence.test_clock[0]=START+3599
        return result
    monkeypatch.setattr(endpoint_hour_counts,'_bindings',bindings)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='incomplete_hours',summaries=[])


@pytest.mark.parametrize('source', ['jsonl','sample'])
def test_packet_qualification_and_packet_flow_separation(evidence, source):
    writer=evidence.packet_writer();run=writer.start_ingestion_run(source)
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(START+30,timezone.utc),
        '192.0.2.8','198.51.100.4','TCP',50000,443,tcp_flags=frozenset({'SYN'})),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    append(evidence)
    result=read_hour_counts(evidence,START)
    if source=='sample':
        assert result==dict(state='unavailable',reason='incomplete_hours',summaries=[])
    else:
        assert {(v['kind'],v['count']) for v in for_subject(result)}=={('packets',1),('flows',5)}
        assert any('qualification_sha256' in value for value in result['summaries'][0]['read_sources'])


def service_for(evidence):
    return IntelligenceService(evidence,SimpleNamespace(for_pattern=lambda rule:[]),
        SimpleNamespace(settings=Settings()),model=lambda *a,**kw:pytest.fail('Count receipt invoked a model'))


def test_processing_persists_receipts_without_adopting_or_restoring_them_as_learned_counts(evidence):
    append(evidence)
    service=service_for(evidence)
    restarted=None
    try:
        service.process_hour(START)
        rows=evidence.history(category='baselines',limit=100)['records']
        receipts=[row for row in rows if row['source']==SOURCE]
        assert len(receipts)==2
        assert {row['data']['count'] for row in receipts}=={5}
        assert {value['count'] for value in service.baselines.values()}=={1}
        assert all('key' not in row['data'] for row in receipts)
        coverage=next(row for row in rows if row['source']=='pattern-hour-coverage-v1')
        assert coverage['data']['endpoint_counts']==dict(state='available')
        restarted=service_for(evidence)
        assert set(restarted.baselines)==set(service.baselines)
        assert restarted.context_for_device('192.0.2.8')['comparison']['state']=='unavailable'
        evidence._generic['flows']['state']='retired'
        assert not [row for row in evidence.history(category='baselines',limit=100)['records'] if row['source']==SOURCE]
    finally:
        if restarted is not None:restarted.close()
        service.close()


def test_count_persistence_failure_does_not_advance_hour_checkpoint(evidence, monkeypatch):
    append(evidence)
    service=service_for(evidence)
    original=evidence.append_records
    def persist(category,records,**kwargs):
        if any(row['source']==SOURCE for row in records):raise OSError('synthetic full disk')
        return original(category,records,**kwargs)
    monkeypatch.setattr(evidence,'append_records',persist)
    try:
        with pytest.raises(OSError):service.process_hour(START)
        assert evidence.checkpoint('patterns_hour') is None
        monkeypatch.setattr(evidence,'append_records',original)
        service.process_hour(START)
        assert evidence.checkpoint('patterns_hour')['end']==START+3600
    finally:service.close()


def test_count_receipts_do_not_consume_learned_restore_quota(evidence,monkeypatch):
    from megalodon import intelligence
    append(evidence)
    service=service_for(evidence)
    restarted=None
    try:
        service.process_hour(START)
        assert len(evidence.history(category='baselines')['records'])==4
        # One learned baseline and its existing coverage row fit this quota.
        # Two new count receipts must be excluded before counting scanned rows.
        monkeypatch.setattr(intelligence,'MAX_HISTORY',2)
        restarted=service_for(evidence)
        assert set(restarted.baselines)==set(service.baselines)
        assert restarted.error is None and restarted.gaps==[]
        assert restarted.scanned==2
    finally:
        if restarted is not None:restarted.close()
        service.close()


def test_unavailable_counts_preserve_existing_hour_processing(evidence):
    append(evidence)
    append(evidence,count=1,source='unqualified')
    service=service_for(evidence)
    try:
        service.process_hour(START)
        assert service.baselines and evidence.checkpoint('patterns_hour')['end']==START+3600
        rows=evidence.history(category='baselines',limit=100)['records']
        assert not [row for row in rows if row['source']==SOURCE]
        coverage=next(row for row in rows if row['source']=='pattern-hour-coverage-v1')
        assert coverage['data']['endpoint_counts']==dict(state='unavailable',reason='incomplete_hours')
    finally:service.close()


def test_packet_receipt_revoked_after_scan_withholds_counts(evidence,monkeypatch):
    writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(START+30,timezone.utc),
        '192.0.2.8','198.51.100.4','TCP',50000,443),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    entry=next(value for value in evidence._catalog['entries'] if value['category']=='packets')
    original=RetainedEvidenceReader._pages
    def pages(*args,**kwargs):
        yield from original(*args,**kwargs)
        with evidence.lock,evidence._writer_db(entry) as db:
            db.execute("UPDATE ingestion_runs SET source='sample'");db.commit()
    monkeypatch.setattr(RetainedEvidenceReader,'_pages',pages)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='incomplete_hours',summaries=[])


def test_initial_expiry_and_work_deadline_have_no_prefix_counts(evidence,monkeypatch):
    from megalodon import endpoint_hour_counts
    append(evidence)
    entry=evidence._generic['flows']
    first=entry['first_at'];entry['first_at']=utc(evidence.clock()-15*86400)
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='source_expired',summaries=[])
    entry['first_at']=first
    ticks=iter([10,19])
    monkeypatch.setattr(endpoint_hour_counts.time,'monotonic',lambda:next(ticks))
    assert read_hour_counts(evidence,START)==dict(state='unavailable',reason='incomplete_hours',summaries=[])
