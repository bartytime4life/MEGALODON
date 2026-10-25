"""Selected IDs remain actionable independently of list-work caps. Fake AI/Defense only."""
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from megalodon.evidence_storage import epoch, utc
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from test_findings_review import service, packet


def narrow(service, observed, identifier):
    return service.snapshot(start=utc(epoch(observed)-1), end=utc(epoch(observed)+1), selected=identifier)['selected']


def exercise_selected_actions(service, detail):
    base = dict(finding_id=detail['finding']['id'], context_sha256=detail['context_sha256'])
    service.action(dict(action='feedback', choice='investigate', **base))
    service.action(dict(action='analyze', **base))
    service.worker.join(5)
    assert service.job['state'] == 'ready'
    service.action(dict(action='plan_containment', target_ip='1.1.1.1', **base))
    assert service.defense.calls[-1] == dict(action='plan_containment', ip='1.1.1.1')
    assert all(call['action'] != 'apply_containment' for call in service.defense.calls)


def test_narrow_selected_source_resolves_after_129_newer_segments(service):
    packet(service)
    first = service.snapshot()['items'][0]
    for _ in range(129):
        service.test_clock[0] += 2
        packet(service)
    detail = narrow(service, first['observed_at'], first['id'])
    assert detail is not None
    exercise_selected_actions(service, detail)


@pytest.mark.parametrize('kind', ['detector', 'sensor'])
def test_narrow_selected_record_resolves_after_600_newer_finding_rows(service, kind):
    old = service.clock()-30
    if kind == 'detector':
        writer = packet(service, completed=False)
        first = service.snapshot()['items'][0]
        stamp = datetime.fromtimestamp(service.clock()-5, timezone.utc)
        event = PacketEvent(stamp, '10.0.0.2', '1.1.1.1', 'TCP', 50000, 443, byte_count=100)
        finding = DetectionResult(stamp, 'PORT_SCAN', 'MEDIUM', event.src_ip, event.dst_ip,
                                  'Synthetic finding', evidence=dict(distinct_ports=30))
        action = ActionRecord(stamp, 'alert', event.src_ip, 'not_attempted', 'Synthetic audit only')
        for _ in range(3):
            writer.record_event_bundles([(event, [finding], [action]) for _ in range(200)], run_id=1)
        writer.finish_ingestion_run(1, 'source_exhausted'); writer.close()
    else:
        data = dict(signature='Synthetic sensor finding', signature_id=42, severity=2,
                    src_ip='10.0.0.2', dst_ip='1.1.1.1', src_port=50000, dst_port=443, protocol='TCP')
        service.evidence.append_records('findings', [dict(observed_at=utc(old), source='suricata-eve', data=data)])
        first = service.snapshot()['items'][0]
        for _ in range(3):
            service.evidence.append_records('findings', [dict(observed_at=utc(service.clock()-5), source='suricata-eve', data=data) for _ in range(200)])
    service._read_cache = None
    detail = narrow(service, first['observed_at'], first['id'])
    assert detail is not None
    exercise_selected_actions(service, detail)


def test_exact_compacted_lookup_keeps_original_id_and_qualification(service):
    packet(service, count=200)
    first = service.snapshot()['items'][0]
    for _ in range(100):
        service.evidence.compact_step()
        if all(e.get('compaction_state') == 'complete' for e in service.evidence._catalog['entries'] if e['category'] == 'packets'):
            break
    record = service._resolve(first['id'])
    assert record['finding']['id'] == first['id']
    assert 'compaction' in record['finding']['source_role']
    rollup = next(e for e in service.evidence._catalog['entries'] if e['category'] == 'packet_rollups')
    with service.evidence._writer_db(rollup) as db:
        db.execute("DELETE FROM records WHERE source='preserved-capture-receipt'"); db.commit()
    with pytest.raises(ValueError):
        service._resolve(first['id'])


def test_model_settings_change_invalidates_server_bound_preview(service):
    packet(service)
    first = service.snapshot()['items'][0]
    detail = narrow(service, first['observed_at'], first['id'])
    service.action(dict(action='plan_containment', finding_id=first['id'],
                        context_sha256=detail['context_sha256'], target_ip='1.1.1.1'))
    service.configuration.settings = replace(service.configuration.settings,
        ai=replace(service.configuration.settings.ai, compute_mode='auto'))
    with pytest.raises(ValueError, match='model settings changed'):
        service.action(dict(action='apply_containment', plan_id='e'*32, acknowledge_disruption=True))
    assert service.defense.calls == [dict(action='plan_containment', ip='1.1.1.1')]


@pytest.mark.parametrize('kind', ['detector', 'sensor'])
def test_exact_resolver_rejects_out_of_storage_range_id_before_sql(service, kind):
    packet(service)
    source = service.snapshot()['items'][0]['id'].split(':')[1]
    with pytest.raises(ValueError, match='storage bound'):
        service._resolve(kind+':'+source+':9999999999999999999')
    assert service.model_calls == [] and service.defense.calls == []
