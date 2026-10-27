"""Selected finding facts and fake AI/Defense only: no host or provider effects."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import time
from threading import Event, RLock
from types import SimpleNamespace

import pytest

from megalodon.config import AISettings, Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, ManagedDashboardReader, utc
from megalodon.findings_review import FindingsReview, FindingsBusy, validate_action
from megalodon.models import ActionRecord, DetectionResult, PacketEvent


class FakeDefense:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.eligible = {'1.1.1.1'}
        self.job = dict(state='idle', action=None, result=None, message='Synthetic response authority')
        self.plans = []

    def _target(self, ip):
        if ip not in self.eligible:
            raise ValueError('This address is protected or lacks a current observed connection.')
        return dict(ip=ip, ports=[dict(protocol='TCP', port=443, hint='HTTPS')], services=[])

    def snapshot(self, include_token=False):
        return dict(schema='megalodon-defense-v1', job=deepcopy(self.job), plans=deepcopy(self.plans),
                    active=[], recent=[], audit_ready=True, scope=dict(nmap_target='127.0.0.1/32', scan_folders=['Downloads']),
                    **({'token': 'd'*32} if include_token else {}))

    def start(self, body):
        self.calls.append(deepcopy(body))
        result = None
        if body['action'] == 'plan_containment':
            self._target(body['ip'])
            result = dict(id='e'*32, ip=body['ip'], duration_seconds=300, expires_at=utc(self.clock()+60),
                          effect='Synthetic local block preview', impact='Shared services may disconnect.')
            self.plans = [result]
        self.job = dict(state='finished', action=body['action'], result=result, message='Synthetic job only', request_id='f'*32)
        return self.snapshot()


@pytest.fixture
def service(private_tmp_path):
    clock = [datetime.now(timezone.utc).timestamp()]
    evidence = EvidenceStorage(Settings(db_path=private_tmp_path/'legacy.db'), home=private_tmp_path,
                               clock=lambda: clock[0], monotonic=lambda: clock[0])
    evidence.apply(evidence.preview(dict(profile='home', retention_days=14, cap_bytes=GIB))['preview_id'])
    configuration = SimpleNamespace(settings=Settings(ai=AISettings(enabled=True)))
    intelligence = SimpleNamespace(lock=RLock(), reviews={}, _valid=lambda item, ids=None: set(item['source_segments']) <= (ids if ids is not None else evidence.available_sources()))
    knowledge = SimpleNamespace(for_pattern=lambda rule: [])
    calls = []
    def model(settings, prompt, **kwargs):
        calls.append((settings, prompt, kwargs))
        facts = json.loads(prompt.split(' DATA ', 1)[1])['E1']
        return json.dumps(dict(explanation=f"The recorded {facts['rule']} finding concerns {facts.get('src_ip') or facts.get('device')}; intent is unknown.", alternative='Authorized inventory is possible.',
                               missing='Complete sensor coverage is unavailable.', citations=['E1'], workflow='contain'))
    defense = FakeDefense(lambda: clock[0])
    value = FindingsReview(evidence, intelligence, knowledge, configuration, defense, clock=lambda: clock[0], model=model)
    value.test_clock, value.model_calls = clock, calls
    yield value
    value.close(); evidence.close()


def packet(service, *, count=1, finding=True, completed=True):
    writer = service.evidence.packet_writer()
    run = writer.start_ingestion_run('jsonl')
    stamp = datetime.fromtimestamp(service.clock()-30, timezone.utc)
    bundles = []
    for index in range(count):
        event = PacketEvent(stamp, '10.0.0.2', '1.1.1.1', 'TCP', 50000, 443, byte_count=100, interface='eth0')
        detections = [DetectionResult(stamp, 'PORT_SCAN', 'MEDIUM', event.src_ip, event.dst_ip, 'Synthetic detection',
                                    evidence=dict(distinct_ports=30, window_seconds=10))] if finding and index == 0 else []
        actions = [ActionRecord(stamp, 'alert', event.src_ip, 'not_attempted', 'Synthetic review only')] if detections else []
        bundles.append((event, detections, actions))
    for start in range(0, len(bundles), 256):
        writer.record_event_bundles(bundles[start:start+256], run_id=run)
    if completed:
        writer.finish_ingestion_run(run, 'source_exhausted'); writer.close()
    return writer


def selected(service, identifier=None):
    first = service.snapshot()
    identifier = identifier or first['items'][0]['id']
    return service.snapshot(selected=identifier)['selected']


def review(service, detail):
    service.action(dict(action='analyze', finding_id=detail['finding']['id'], context_sha256=detail['context_sha256']))
    service.worker.join(5)
    assert not service.worker.is_alive()
    return selected(service, detail['finding']['id'])


def test_feed_reads_finding_outside_newest_500_packets_without_provider_or_actions(service):
    packet(service, count=600)
    assert ManagedDashboardReader(service.evidence).traffic()['findings'] == []
    feed = service.snapshot()
    assert feed['state'] == 'available'
    assert len(feed['items']) == 1 and feed['items'][0]['kind'] == 'detector'
    detail = selected(service)
    assert detail['facts']['recorded_evidence'] == dict(distinct_ports=30, window_seconds=10)
    assert detail['impact']['targets'][0]['eligible'] is False
    assert detail['impact']['targets'][1]['ip'] == '1.1.1.1' and detail['impact']['targets'][1]['eligible']
    assert service.model_calls == [] and service.defense.calls == []


def test_real_managed_eve_intake_reaches_findings_and_saved_report(service):
    from megalodon.flow_ingestion import FlowIngestor
    from megalodon.reporting import ReportService
    path=service.evidence.home/'synthetic-eve.json'
    event=dict(timestamp=utc(service.clock()-20),event_type='alert',flow_id=7003,
        src_ip='192.0.2.10',dest_ip='198.51.100.20',src_port=40000,dest_port=443,proto='TCP',
        alert=dict(signature='Synthetic end-to-end sensor witness',signature_id=7003,severity=1))
    path.write_text(json.dumps(event)+'\n')
    worker=FlowIngestor(service.evidence,home=service.evidence.home,eve_path=path)
    assert worker.poll('suricata',include_flows=False)==1
    assert worker.poll('suricata',include_flows=False)==0
    feed=service.snapshot(source='sensor')
    assert feed['page']['returned']==1 and feed['items'][0]['severity']=='high'
    detail=service.snapshot(selected=feed['items'][0]['id'])['selected']
    assert 'Synthetic end-to-end sensor witness' in json.dumps(detail['facts'])
    report=ReportService(service.evidence)
    try:
        job=report.create(dict(start=utc(service.clock()-60),end=utc(service.clock())))
        report.worker.join(20)
        assert report.job['state']=='ready'
        value=report.report(job['id'])
        assert value['summary']['finding_count']==1
        _,html=report.download(job['id'],'html')
        assert b'Synthetic end-to-end sensor witness' in html
    finally:report.close()
    assert service.model_calls==[] and service.defense.calls==[]


def test_sources_keep_separate_roles_and_patterns_do_not_invent_severity(service):
    packet(service)
    service.evidence.append_records('findings', [dict(observed_at=utc(service.clock()-20), source='suricata-eve',
        data=dict(signature='Synthetic sensor alert', signature_id=42, severity=1,
                  src_ip='1.1.1.1', dst_ip='10.0.0.2', src_port=443, dst_port=50000, protocol='TCP'))])
    dependency = next(e['id'] for e in service.evidence._catalog['entries'] if e['category'] == 'packets')
    service.intelligence.reviews['a'*32] = dict(id='a'*32, rule='PROTOCOL_SHIFT', sensor='accepted packet metadata',
        device='10.0.0.2', start=utc(service.clock()-100), end=utc(service.clock()-10), source_start=utc(service.clock()-100),
        source_segments=[dependency], evidence_refs=[dependency+':1'], facts=dict(tcp=20, udp=30),
        measurement='source-qualified records', what_happened='The recorded transport mix changed.', missing_information=['Coverage incomplete.'])
    feed = service.snapshot()
    assert {i['kind'] for i in feed['items']} == {'detector', 'sensor', 'pattern'}
    assert next(i for i in feed['items'] if i['kind'] == 'pattern')['severity'] == 'unknown'
    assert next(i for i in feed['items'] if i['kind'] == 'sensor')['severity'] == 'high'
    assert service.snapshot(source='sensor', severity='high')['page']['returned'] == 1
    assert service.snapshot(source='pattern', severity='critical')['state'] == 'empty'


def test_compaction_preserves_finding_identity_without_duplicates(service):
    packet(service, count=200)
    before = service.snapshot()['items'][0]['id']
    for _ in range(100):
        service.evidence.compact_step()
        if all(e.get('compaction_state') == 'complete' for e in service.evidence._catalog['entries'] if e['category'] == 'packets'):
            break
    service._read_cache = None
    feed = service.snapshot()
    assert [r['id'] for r in feed['items']] == [before]
    assert 'compaction' in feed['items'][0]['source_role']


def test_review_uses_exact_selected_facts_and_manual_priority_and_persists(service):
    packet(service)
    detail = selected(service)
    answer = review(service, detail)
    assert answer['analysis']['state'] == 'ready'
    assert answer['analysis']['citations'] == [detail['finding']['id']]
    assert answer['analysis']['workflow'] == 'device_changes', 'Model cannot upgrade a selected review to containment'
    settings, prompt, kwargs = service.model_calls[0]
    assert kwargs['priority'] == 'manual' and kwargs['owner'].startswith('finding-')
    packet_text = json.loads(prompt.split(' DATA ', 1)[1])
    assert packet_text['E1'] == detail['facts']
    assert prompt.startswith('Analyze ONE recorded finding in DATA.E1')
    assert 'not a definition' in prompt and 'do not invent missing tools or configuration' in prompt
    assert 'Explain a local security review' not in prompt
    assert answer['analysis']['model'] == settings.model and answer['analysis']['model_digest'] == settings.model_digest
    assert service.defense.calls == []
    restarted = FindingsReview(service.evidence, service.intelligence, service.knowledge, service.configuration, service.defense)
    try:
        assert selected(restarted, detail['finding']['id'])['analysis']['state'] == 'ready'
    finally:
        restarted.close()


def test_unrelated_capture_writes_preserve_context_and_model_change_invalidates_review(service):
    writer = packet(service, completed=False)
    detail = selected(service)
    answer = review(service, detail)
    event = PacketEvent(datetime.fromtimestamp(service.clock()-1, timezone.utc), '10.0.0.2', '1.1.1.1', 'TCP', 50001, 443, byte_count=120)
    writer.record_event_bundle(event, [], [], run_id=1)
    service._read_cache = None
    current = selected(service, detail['finding']['id'])
    assert current['context_sha256'] == detail['context_sha256']
    assert current['analysis']['state'] == answer['analysis']['state'] == 'ready'
    service.configuration.settings = replace(service.configuration.settings,
        ai=replace(service.configuration.settings.ai, compute_mode='auto'))
    assert selected(service, detail['finding']['id'])['analysis']['state'] == 'invalidated'
    writer.finish_ingestion_run(1, 'source_exhausted'); writer.close()


def test_changed_evidence_invalidates_review_and_malformed_ai_preserves_facts(service):
    packet(service)
    detail = selected(service)
    service.model = lambda *a, **k: json.dumps(dict(explanation='Bad answer', alternative='Unknown', missing='Unknown', citations=['INVENTED'], workflow='contain'))
    assert review(service, detail)['analysis']['state'] == 'failed'
    assert selected(service)['facts'] == detail['facts']
    entry = next(e for e in service.evidence._catalog['entries'] if e['category'] == 'packets')
    with service.evidence._writer_db(entry) as db:
        db.execute('UPDATE detections SET evidence_json=?', (json.dumps(dict(distinct_ports=99)),)); db.commit()
    service._read_cache = None
    assert selected(service)['context_sha256'] != detail['context_sha256']
    with pytest.raises(ValueError, match='changed'):
        service.action(dict(action='analyze', finding_id=detail['finding']['id'], context_sha256=detail['context_sha256']))


def test_generic_selected_answer_fails_without_hiding_recorded_facts(service, monkeypatch):
    packet(service)
    detail = selected(service)
    monkeypatch.setattr('megalodon.intelligence.ai_provider.reject_response', lambda settings: None)
    service.model = lambda *a, **k: json.dumps(dict(
        explanation='It involves examining local device configurations, user permissions, and system settings.',
        alternative='A local security review identifies possible configuration risks.',
        missing='More tools and configuration values are needed.', citations=['E1'], workflow='evidence_summary'))
    answer = review(service, detail)
    assert answer['analysis']['state'] == 'failed'
    assert answer['analysis']['explanation'] is None
    assert answer['facts'] == detail['facts'] and service.defense.calls == []


def test_saved_selected_answer_requires_current_grounding_contract(service):
    packet(service)
    detail = selected(service)
    assert review(service, detail)['analysis']['state'] == 'ready'
    service.reviews[detail['finding']['id']]['analysis'].pop('explanation_contract')
    answer = selected(service, detail['finding']['id'])
    assert answer['analysis']['state'] == 'invalidated'
    assert answer['analysis']['explanation'] is None and answer['facts'] == detail['facts']


def test_expired_source_never_serves_review_or_allows_action(service):
    packet(service)
    detail = selected(service)
    review(service, detail)
    service.test_clock[0] += 15*86400
    assert service.snapshot()['items'] == []
    with pytest.raises(ValueError, match='expired|outside'):
        service.action(dict(action='analyze', finding_id=detail['finding']['id'], context_sha256=detail['context_sha256']))
    assert service.defense.calls == []


def test_cancel_is_owner_bound_single_worker_and_does_not_cancel_other_ai(service, monkeypatch):
    packet(service)
    detail = selected(service)
    entered, release = Event(), Event()
    def model(*args, **kwargs):
        entered.set(); release.wait(3)
        return json.dumps(dict(explanation='Recorded activity.', alternative='Routine task.', missing='Coverage.', citations=['E1'], workflow='evidence_summary'))
    service.model = model
    cancelled = []
    monkeypatch.setattr('megalodon.findings_review.ai_provider.cancel_current', lambda **kw: cancelled.append(kw))
    body = dict(action='analyze', finding_id=detail['finding']['id'], context_sha256=detail['context_sha256'])
    service.action(body); assert entered.wait(2)
    with pytest.raises(FindingsBusy): service.action(body)
    service.action(dict(action='cancel'))
    assert cancelled == [dict(owner=service.job['id'])]
    release.set(); service.worker.join(3)
    assert selected(service)['analysis']['state'] == 'cancelled'
    service.action(dict(action='cancel'))
    assert len(cancelled) == 1


def test_cursor_is_scope_bound_and_changed_window_requires_restart(service):
    for n in range(3):
        service.evidence.append_records('findings', [dict(observed_at=utc(service.clock()-n), source='suricata-eve', data=dict(signature='Alert '+str(n), severity=2))])
    first = service.snapshot(limit='1')
    assert first['page']['next_cursor']
    second = service.snapshot(limit='1', cursor=first['page']['next_cursor'])
    assert second['items'][0]['id'] != first['items'][0]['id']
    with pytest.raises(ValueError, match='scope'):
        service.snapshot(limit='1', source='detector', cursor=first['page']['next_cursor'])
    with pytest.raises(ValueError, match='expired|changed'):
        service.snapshot(cursor=first['page']['next_cursor']+'x')


def test_preview_is_context_bound_acknowledged_separate_and_rechecked(service):
    packet(service)
    detail = selected(service)
    base = dict(finding_id=detail['finding']['id'], context_sha256=detail['context_sha256'])
    service.action(dict(action='plan_containment', target_ip='1.1.1.1', **base))
    assert service.defense.calls == [dict(action='plan_containment', ip='1.1.1.1')]
    with pytest.raises(ValueError): service.action(dict(action='apply_containment', plan_id='e'*32))
    with pytest.raises(ValueError): service.action(dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=False))
    service.defense.eligible.clear()
    with pytest.raises(ValueError): service.action(dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True))
    assert len(service.defense.calls) == 1
    service.defense.eligible.add('1.1.1.1')
    service.action(dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True))
    assert service.defense.calls[-1] == dict(action='apply_containment', plan_id='e'*32)
    assert not service.plan_bindings


def test_preview_refuses_model_or_arbitrary_targets_and_expiry(service):
    packet(service)
    detail = selected(service)
    base = dict(finding_id=detail['finding']['id'], context_sha256=detail['context_sha256'])
    with pytest.raises(ValueError): service.action(dict(action='plan_containment', target_ip='8.8.8.8', **base))
    assert service.defense.calls == []
    service.action(dict(action='plan_containment', target_ip='1.1.1.1', **base))
    service.test_clock[0] += 61
    with pytest.raises(ValueError, match='expired'):
        service.action(dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True))
    assert len(service.defense.calls) == 1


def test_feedback_is_not_resolution_or_detector_configuration(service):
    packet(service)
    detail = selected(service)
    service.action(dict(action='feedback', finding_id=detail['finding']['id'], context_sha256=detail['context_sha256'], choice='expected'))
    assert selected(service)['finding']['review_state'] == 'expected'
    assert service.defense.calls == [] and service.model_calls == []
    assert ManagedDashboardReader(service.evidence).summary()['detections'] == 1


def test_interrupted_review_restore_is_not_ready_or_automatically_replayed(service):
    packet(service)
    record = service._resolve(service.snapshot()['items'][0]['id'])
    service._persist(record, 'selected-finding-review-v1', dict(settings_identity=service._settings_identity(),
        reference_rule='PORT_SCAN', references_identity=__import__('megalodon.findings_review', fromlist=['digest']).digest([]),
        analysis=dict(state='running', model=service.configuration.settings.ai.model,
                      model_digest=service.configuration.settings.ai.model_digest, message='Requested', citations=[], references=[])))
    restarted = FindingsReview(service.evidence, service.intelligence, service.knowledge, service.configuration, service.defense,
                               model=lambda *a, **k: pytest.fail('Restoration must never invoke a model'))
    try:
        detail = selected(restarted, record['finding']['id'])
        assert detail['analysis']['state'] == 'failed'
        assert 'previous HUD stopped' in detail['analysis']['message']
        assert restarted.job['state'] == 'idle'
    finally:
        restarted.close()


def test_preserved_pattern_does_not_inherit_generic_legacy_ai_explanation(service):
    packet(service)
    dependency = next(e['id'] for e in service.evidence._catalog['entries'] if e['category'] == 'packets')
    service.intelligence.reviews['a'*32] = dict(id='a'*32, rule='SYN_FLOOD', sensor='preserved finding',
        device='1.1.1.1', start=utc(service.clock()-100), end=utc(service.clock()-10), source_start=utc(service.clock()-100),
        source_segments=[dependency], evidence_refs=[dependency+':1'], facts=dict(preserved_finding=True),
        measurement='preserved reference', what_happened='An earlier detector finding was preserved.', missing_information=[],
        analysis=dict(state='ready', explanation='Generic legacy definition; do not inherit this.'))
    detail = selected(service, 'pattern:'+'a'*32)
    assert detail['analysis']['state'] == 'not_requested'
    assert 'counts, thresholds and window are unavailable' in detail['facts']['coverage'][0]
    assert detail['facts']['recorded_evidence'] == {'preserved_finding': True}
    assert service.model_calls == []
    service.model = lambda *a, **k: json.dumps(dict(
        explanation='A SYN flood finding reference for 1.1.1.1 was preserved; intent remains unknown.',
        alternative='An authorized load test or retransmissions could explain the earlier observation.',
        missing='Original counts, thresholds and evaluation window are unavailable.', citations=['E1'], workflow='contain'))
    answer = review(service, detail)
    assert answer['analysis']['state'] == 'ready'
    assert answer['facts']['recorded_evidence'] == {'preserved_finding': True}
    assert answer['analysis']['workflow'] == 'evidence_summary' and service.defense.calls == []


@pytest.mark.parametrize('change', ['model', 'reference'])
def test_selected_review_rejects_model_or_reference_change_during_inference(service, change):
    packet(service)
    reference = dict(id='test-reference', source='test', edition='one', identifier='T1046',
                     title='Synthetic reference', url='https://example.invalid/reference', excerpt='Reference context only.', context_only=True)
    current = [reference]
    service.knowledge.for_pattern = lambda rule: deepcopy(current)
    detail = selected(service)
    def model(*args, **kwargs):
        if change == 'model':
            service.configuration.settings = replace(service.configuration.settings,
                ai=replace(service.configuration.settings.ai, compute_mode='auto'))
        else:
            current[0] = dict(reference, edition='two')
        return json.dumps(dict(explanation='The recorded PORT_SCAN finding reports 30 distinct ports; intent is unknown.', alternative='Authorized inventory.',
                               missing='Complete coverage.', citations=['E1', 'K1'], workflow='contain'))
    service.model = model
    answer = review(service, detail)
    assert service.job['state'] == 'failed'
    assert answer['analysis']['state'] == 'invalidated'
    assert answer['facts'] == detail['facts']
    assert service.defense.calls == []


def test_many_packet_segments_have_bounded_fast_finding_reads(service, capsys):
    # 32 source segments and 19,200 packet records, with each finding deliberately
    # outside its segment's latest 500 packets. Only detector rows are queried.
    for _ in range(32):
        packet(service, count=600)
    before = time.monotonic()
    feed = service.snapshot(limit='50')
    elapsed = time.monotonic()-before
    before = time.monotonic()
    service.snapshot(start=feed['scope']['start'], end=feed['scope']['end'], limit='50')
    second = time.monotonic()-before
    assert len(feed['items']) == 32
    assert elapsed < 4.5, 'Finding read must obey its bounded work deadline'
    assert service.model_calls == [] and service.defense.calls == []
    print(json.dumps(dict(synthetic=True, source_segments=32, packet_records=19200, findings=32,
                          first_read_seconds=round(elapsed, 4), repeated_scope_seconds=round(second, 4))))


@pytest.mark.parametrize('body', [
    {'action': 'execute', 'command': 'anything'}, {'action': 'apply_containment', 'plan_id': 'a'*32, 'acknowledge_disruption': 1},
    {'action': 'analyze', 'finding_id': 'pattern:'+'a'*32, 'context_sha256': 'b'*64, 'command': 'anything'},
    {'action': 'feedback', 'finding_id': 'pattern:'+'a'*32, 'context_sha256': 'b'*64, 'choice': []},
])
def test_closed_request_shape(body):
    with pytest.raises(ValueError): validate_action(body)
