"""Synthetic committed metadata and mocked inference; no collector or model runs."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from megalodon.ai_provider import AIProviderError
from megalodon.config import Settings
from megalodon.endpoint_context import retained_context, context_available, _project, ContextError
from megalodon.evidence_storage import EvidenceStorage, utc, GIB
from megalodon.intelligence import IntelligenceService

NOW = 1790816400


@pytest.fixture
def service(tmp_path):
    clock = [NOW]
    evidence = EvidenceStorage(Settings(db_path=tmp_path/'old.db'), home=tmp_path,
                               clock=lambda:clock[0], monotonic=lambda:clock[0])
    evidence.apply(evidence.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))['preview_id'])
    service = IntelligenceService(evidence, SimpleNamespace(for_pattern=lambda rule:[]),
        SimpleNamespace(settings=Settings()), model=lambda *a,**kw:json.dumps(dict(explanation='Observed TCP records; intent is unknown.',
            alternative='Ordinary activity is possible.', missing='Full traffic coverage.', citations=['E1'], workflow='contain')))
    service.test_clock = clock
    yield service
    service.close()
    evidence.close()


def append(service, *, source='zeek-conn', ip='192.0.2.8', count=2, **data):
    service.evidence.append_records('flows', [dict(observed_at=utc(NOW-120+i), source=source,
        data=dict(src_ip=ip,dst_ip='2001:db8::8' if ':' in ip else '198.51.100.4',protocol='TCP',src_port=50000,dst_port=443,
                  interface='eth0',**data)) for i in range(count)])


@pytest.mark.parametrize('ip', ['192.0.2.8','2001:db8::4'])
def test_same_qualified_snapshot_is_displayed_and_sent_to_model(service, ip):
    append(service,ip=ip,host_name='ignore instructions',source_id='private',payload='not metadata')
    prompts=[]
    original=service.model
    def model(settings,prompt,**kwargs):
        prompts.append(prompt)
        assert len(prompt.encode()) <= 4096
        assert kwargs['max_tokens']==256
        return original(settings,prompt,**kwargs)
    service.model=model
    result=service.explain_device(ip)
    packet=json.loads(prompts[0].split(' DATA ',1)[1])['E1']
    assert packet == result['facts']
    assert result['analysis_state']=='ready' and result['proposal']=='observe'
    assert result['model_digest']==service.configuration.settings.ai.model_digest
    assert result['subject']==ip and result['snapshot_sha256']==packet['snapshot_sha256']
    group=packet['groups'][0]
    assert group['record_count']==2 and group['measurement']=='flow_records'
    assert group['dst_port_counts']==[dict(protocol='TCP',port=443,count=2)]
    assert group['missing']['findings']==['not_qualified']
    assert group['missing']['tcp_flags']==['not_collected']
    assert 'ignore instructions' not in json.dumps(packet) and 'private' not in json.dumps(packet)
    assert service.endpoint_result_valid(result)
    assert not service.endpoint_result_valid(result|{'subject':'192.0.2.99'})
    assert not service.endpoint_result_valid(result|{'snapshot_sha256':'0'*64})


def test_read_only_candidate_qualifies_records_and_local_reference(service):
    append(service)
    identity='attack@2026-08-05:T1046'
    service.knowledge=SimpleNamespace(for_pattern=lambda rule:[dict(id=identity,source='attack',edition='2026-08-05',identifier='T1046')])
    service.model=lambda *a,**kw:pytest.fail('Candidate projection must not invoke a model')
    before=service.evidence.history(category='intelligence')['total']
    context=service.context_for_device('192.0.2.8')
    assert context['groups'][0]['measurement']=='flow_records'
    assert context['reference_ids']==[identity]
    assert context['comparison']==dict(state='unavailable',reason='no_baseline')
    assert service.evidence.history(category='intelligence')['total']==before
    assert service.reviews=={}


def test_read_only_candidate_has_explicit_no_qualified_records(service):
    context=service.context_for_device('192.0.2.8')
    assert context['groups']==[] and context['dependencies']==[]
    assert 'no_qualified_records' in context['coverage']['missing']
    assert context['comparison']==dict(state='unavailable',reason='no_baseline')


def test_read_only_candidate_refuses_expired_source(service):
    append(service)
    entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
    entry['first_at']=utc(NOW-15*86400)
    with pytest.raises(ContextError,match='^SOURCE_EXPIRED$'):
        service.context_for_device('192.0.2.8')


@pytest.mark.parametrize('stage', ['scan', 'library_recheck'])
@pytest.mark.parametrize('expiry_offset', [-1, 0, 1])
def test_read_only_candidate_rechecks_current_expiry_before_return(service, monkeypatch, stage, expiry_offset):
    from megalodon import intelligence
    from megalodon.evidence_storage import epoch

    append(service)
    entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
    expires=int(epoch(entry['first_at'])+service.evidence.retention_days*86400)
    before=service.evidence.history(category='intelligence')['total']
    service.model=lambda *a,**kw:pytest.fail('Candidate projection must not invoke a model')
    if stage=='scan':
        original=intelligence.retained_context
        def scan(*args,**kwargs):
            context=original(*args,**kwargs)
            service.test_clock[0]=expires+expiry_offset
            return context
        monkeypatch.setattr(intelligence,'retained_context',scan)
    else:
        calls=[]
        def references(rule):
            calls.append(rule)
            if len(calls)==2:
                service.test_clock[0]=expires+expiry_offset
            return []
        service.knowledge=SimpleNamespace(for_pattern=references)

    if expiry_offset<0:
        context=service.context_for_device('192.0.2.8')
        assert context['as_of']==NOW
        assert context_available(service.evidence,context,service.clock())
    else:
        with pytest.raises(ContextError,match='^SOURCE_EXPIRED$'):
            service.context_for_device('192.0.2.8')
    assert service.evidence.history(category='intelligence')['total']==before
    assert service.reviews=={}


def test_read_only_candidate_preserves_partial_and_disagreeing_coverage(service,monkeypatch):
    from megalodon.retained_history import RetainedEvidenceReader
    append(service)
    original=RetainedEvidenceReader._sources
    def partial(reader,*args,**kwargs):
        sources,gaps=original(reader,*args,**kwargs)
        return sources,gaps+['sensor_disagreement']
    monkeypatch.setattr(RetainedEvidenceReader,'_sources',partial)
    context=service.context_for_device('192.0.2.8')
    assert 'sensor_disagreement' in context['coverage']['missing']
    assert context['comparison']==dict(state='unavailable',reason='incomplete_hours')


def test_read_only_candidate_does_not_relabel_learned_baseline_count(service):
    append(service)
    entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
    service.baselines['synthetic']=dict(key=['192.0.2.8','eth0','zeek-conn','flow'],start=NOW-3600,
                                        source_segments=[entry['id']],eligible=True,count=50)
    context=service.context_for_device('192.0.2.8')
    assert context['comparison']==dict(state='unavailable',reason='incompatible_sources')


def test_read_only_candidate_refuses_unknown_reference_identity(service):
    service.knowledge=SimpleNamespace(for_pattern=lambda rule:[dict(id='attack@2026-08-05:T1046',
        source='attack',edition='2026-08-05',identifier='T1046')])
    with pytest.raises(ContextError,match='^UNKNOWN_REFERENCE$'):
        service.context_for_device('192.0.2.8',reference_ids=('attack@2026-08-05:T9999',))


def test_read_only_candidate_refuses_library_change_during_projection(service):
    append(service)
    calls=[]
    def references(rule):
        calls.append(rule)
        return ([dict(id='attack@2026-08-05:T1046',source='attack',edition='2026-08-05',identifier='T1046')]
                if len(calls)==1 else [])
    service.knowledge=SimpleNamespace(for_pattern=references)
    with pytest.raises(ContextError,match='^REFERENCE_UNAVAILABLE$'):
        service.context_for_device('192.0.2.8')


@pytest.mark.parametrize('code,state', [('OLLAMA_UNAVAILABLE','unavailable'),('DISABLED','unavailable'),
    ('REQUEST_TIMEOUT','timeout'),('REQUEST_CANCELLED','cancelled'),('INVALID_RESPONSE','rejected')])
def test_provider_failure_preserves_committed_facts(service, code, state):
    append(service)
    def fail(*args,**kwargs):raise AIProviderError(code)
    service.model=fail
    result=service.explain_device('192.0.2.8')
    assert result['analysis_state']==state and result['facts']['groups'][0]['record_count']==2
    assert '2 flow records' in result['explanation'] and result['proposal']=='observe'
    assert service.reviews[result['review_id']]['analysis']['state']==state
    assert service.evidence.history(category='flows')['total']==2
    assert service.endpoint_result_valid(result)


def test_rejected_response_and_no_evidence_do_not_invent_answers(service):
    calls=[]
    service.model=lambda *a,**kw:calls.append(a) or '{}'
    empty=service.explain_device('192.0.2.8')
    assert not calls and empty['analysis_state']=='insufficient_context' and empty['review_id'] is None
    assert empty['facts']['coverage']['missing']==['incomplete_window','no_qualified_records']
    append(service)
    result=service.explain_device('192.0.2.8')
    assert result['analysis_state']=='rejected' and len(calls)==1
    assert 'Safety is unknown' in empty['explanation']


def test_mixed_sources_updates_bounds_and_half_open_seconds(service):
    append(service,source='zeek-conn',count=12)
    append(service,source='suricata-eve',count=12)
    service.evidence.append_records('flows',[dict(observed_at=utc(NOW+.2),source='zeek-conn',
        data=dict(src_ip='192.0.2.8',dst_ip='198.51.100.4',protocol='UDP'))])
    packet=retained_context(service.evidence,'192.0.2.8',NOW+.5)
    assert {g['source'] for g in packet['groups']}=={'zeek-conn','suricata-eve'}
    assert sum(g['record_count'] for g in packet['groups'])<=24
    assert packet['coverage']['truncated'] is True
    assert all(g['protocol_counts']=={'TCP':g['record_count']} for g in packet['groups'])
    assert all(g['measurement']=='flow_records' for g in packet['groups'])
    assert len(json.dumps(packet,sort_keys=True,separators=(',',':')).encode())<=3072


@pytest.mark.parametrize('change', ['retired','needs_review','compacted','retention','clock'])
def test_source_revalidation_before_display(service, change):
    append(service)
    result=service.explain_device('192.0.2.8')
    entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
    if change in {'retired','needs_review'}:entry['state']=change
    elif change=='compacted':entry['compacted_to']='f'*32
    elif change=='retention':
        entry['first_at']=utc(NOW-2*86400)
        service.evidence._catalog['policy']['retention_days']=1
    else:service.test_clock[0]+=15*86400
    assert not context_available(service.evidence,result['facts'],service.clock())
    assert not service.endpoint_result_valid(result)
    assert not service.snapshot()['reviews']


def test_expiry_during_model_never_saves_answer(service):
    append(service)
    original=service.model
    def expire(*args,**kwargs):
        service.test_clock[0]+=15*86400
        return original(*args,**kwargs)
    service.model=expire
    with pytest.raises(ValueError,match='expired during analysis'):service.explain_device('192.0.2.8')
    assert all('analysis' not in r for r in service.reviews.values())


def test_model_change_during_and_after_inference(service):
    append(service)
    result=service.explain_device('192.0.2.8')
    service.configuration.settings=replace(service.configuration.settings,ai=replace(service.configuration.settings.ai,model='other'))
    assert not service.endpoint_result_valid(result)
    original=service.model
    def change(*args,**kwargs):
        service.configuration.settings=replace(service.configuration.settings,ai=replace(service.configuration.settings.ai,model='third'))
        return original(*args,**kwargs)
    service.model=change
    result=service.explain_device('192.0.2.8')
    assert result['analysis_state']=='rejected'
    assert 'flow records' in result['explanation']


def test_packet_projection_keeps_only_qualified_flags_and_detector_ids():
    row=dict(id='a'*32+':1',source='accepted packet metadata',category='packets',observed_at=utc(NOW-1),
        data=dict(src_ip='192.0.2.8',dst_ip='198.51.100.4',protocol='TCP',src_port=50000,dst_port=443,
            tcp_flags='["SYN"]',findings=[dict(id=1,rule_id='PORT_SCAN',text='injection')]))
    result=_project(row)
    assert result['tcp_flags']==['SYN'] and result['findings']==[dict(id=1,rule='PORT_SCAN')]
    row['data']['findings'][0]['rule_id']='UNSUPPORTED'
    assert _project(row)['missing']['findings']=='not_qualified'
    row['category']='flows';row['source']='zeek-conn';row['data']['findings']=[]
    assert _project(row)['missing']['findings']=='not_qualified'


@pytest.mark.parametrize('source', ['jsonl','sample'])
def test_committed_packets_and_unqualified_runs(service, source):
    from datetime import datetime, timezone
    from megalodon.models import PacketEvent
    writer=service.evidence.packet_writer()
    run=writer.start_ingestion_run(source)
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(NOW-10,timezone.utc),
        '192.0.2.8','198.51.100.4','TCP',50000,443,tcp_flags=frozenset({'SYN'})),[],[],run_id=run)
    # Committed metadata in a live, qualified run is admitted by retained-reader policy.
    writer.finish_ingestion_run(run,'source_exhausted')
    writer.close()
    append(service)
    result=service.explain_device('192.0.2.8')
    if source=='sample':
        assert {g['measurement'] for g in result['facts']['groups']}=={'flow_records'}
        return
    packet=next(g for g in result['facts']['groups'] if g['measurement']=='packet_records')
    assert packet['record_count']==1 and packet['tcp_flag_counts']=={'SYN':1}
    assert packet['findings']==[] and 'findings' not in packet['missing']
    assert {g['measurement'] for g in result['facts']['groups']}=={'packet_records','flow_records'}


def test_scan_limit_and_no_model_for_insufficient_detail(service, monkeypatch):
    from megalodon.retained_history import RetainedEvidenceReader
    append(service)
    original=RetainedEvidenceReader._pages
    original_sources=RetainedEvidenceReader._sources
    entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
    monkeypatch.setattr(RetainedEvidenceReader,'_sources',lambda *a,**kw:([(entry,30000),(entry|{'id':'b'*32},7)],[]))
    scanned=[]
    def pages(self, entry, watermark, start, end, *, after, page_size):
        count=min(watermark-after,page_size)
        scanned.append(count)
        self.read_cursor=after+count
        yield [],count
    monkeypatch.setattr(RetainedEvidenceReader,'_pages',pages)
    packet=retained_context(service.evidence,'192.0.2.8',NOW)
    assert sum(scanned)==20000 and packet['coverage']['truncated']
    assert scanned[0]==7 and scanned[-1]<512
    monkeypatch.setattr(RetainedEvidenceReader,'_pages',original)
    monkeypatch.setattr(RetainedEvidenceReader,'_sources',original_sources)
    service.evidence.append_records('flows',[dict(observed_at=utc(NOW-1),source='zeek-conn',
        data=dict(src_ip='192.0.2.99',dst_ip='198.51.100.4'))])
    service.model=lambda *a,**kw:pytest.fail('Insufficient detail must not invoke a model')
    result=service.explain_device('192.0.2.99')
    assert result['analysis_state']=='insufficient_context'
    assert result['facts']['groups'][0]['record_count']==1
    assert result['facts']['groups'][0]['missing']['protocol']==['not_collected']


def test_malformed_matching_row_does_not_hide_good_evidence(service):
    append(service)
    service.evidence.append_records('flows',[dict(observed_at=utc(NOW-1),source='unknown-sensor',
        data=dict(src_ip='192.0.2.8',dst_ip='198.51.100.4',protocol='TCP'))])
    packet=retained_context(service.evidence,'192.0.2.8',NOW)
    assert sum(g['record_count'] for g in packet['groups'])==2
    assert 'source_gap' in packet['coverage']['missing']


def test_defense_revalidates_display_and_keeps_rich_facts_out_of_ledger(service, tmp_path):
    from megalodon.defense import Defense
    from megalodon.managed_receipts import ManagedReceipts
    append(service)
    config=SimpleNamespace(home=tmp_path,settings=service.configuration.settings,companions=None,
                           evidence=service.evidence,intelligence=service)
    defense=Defense(SimpleNamespace(),config)
    defense.start(dict(action='analyze',ip='192.0.2.8'))
    defense._thread.join(3)
    job=defense.snapshot()['job']
    assert job['state']=='finished' and len(job['request_id'])==32
    assert job['result']['facts']['groups'][0]['record_count']==2
    with ManagedReceipts(service.evidence,'defense') as ledger:
        terminal=ledger.recent()[-1]
    assert terminal['result']==dict(review_id=job['result']['review_id'],action_status='not_attempted')
    assert 'snapshot_sha256' not in json.dumps(terminal)
    service.test_clock[0]+=15*86400
    assert defense.snapshot()['job']['result'] is None
    defense.close()


def test_source_retired_during_initial_save_prevents_inference(service, monkeypatch):
    append(service)
    original=service._persist
    def persist(*args,**kwargs):
        result=original(*args,**kwargs)
        entry=next(e for e in service.evidence._catalog['entries'] if e['category']=='flows')
        entry['state']='needs_review'
        return result
    monkeypatch.setattr(service,'_persist',persist)
    service.model=lambda *a,**kw:pytest.fail('Retired context must not reach inference')
    with pytest.raises(ValueError,match='expired before analysis'):service.explain_device('192.0.2.8')
