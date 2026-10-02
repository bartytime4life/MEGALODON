"""Reports use synthetic local evidence and an explicit clock, never live traffic."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import time
from zoneinfo import ZoneInfo

import pytest

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc
from megalodon.models import PacketEvent
from megalodon.reporting import ReportService, latest_slot, schedule_value, _resource_mean, _csv_safe

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Local Linux managed reports')


@pytest.fixture
def report_service(tmp_path):
    tmp_path.chmod(0o700)
    stamp = [datetime(2026, 9, 30, 18, tzinfo=timezone.utc).timestamp()]
    manager = EvidenceStorage(Settings(db_path=tmp_path/'old.db'), home=tmp_path, clock=lambda:stamp[0], monotonic=lambda:stamp[0])
    policy = manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))
    manager.apply(policy['preview_id'])
    service = ReportService(manager, zone=ZoneInfo('America/Chicago'))
    service.test_clock = stamp
    yield service
    service.close()
    manager.close()


def add(service, category, data, source='fixture', age=60):
    return service.evidence.append_records(category,[dict(observed_at=utc(service.clock()-age),source=source,data=data)])


def make(service, start=None, end=None):
    job = service.create(dict(start=utc(start or service.clock()-86400),end=utc(end or service.clock())))
    service.worker.join(20)
    assert service.job['state']=='ready', service.job
    return service.report(job['id'])


def test_empty_report_is_saved_with_explicit_missing_data(report_service):
    value = make(report_service)
    assert value['summary']['packet_records']==0
    assert value['coverage']['partial']
    assert any('No retained evidence' in v for v in value['coverage']['gaps'])
    assert report_service.snapshot()['reports'][0]['id']==value['id']
    assert report_service.evidence.history(category='reports')['total']>0


def test_all_segments_more_than_dashboard_window_and_report_exclusion(report_service):
    manager=report_service.evidence
    writer=manager.packet_writer()
    run=writer.start_ingestion_run('jsonl')
    for n in range(601):
        event=PacketEvent(datetime.fromtimestamp(report_service.clock()-60,timezone.utc),'192.0.2.1','198.51.100.1','TCP',40000,443,byte_count=100)
        writer.record_event_bundle(event,[],[],run_id=run)
        if n==299:writer.rotate()
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    first=make(report_service)
    second=make(report_service)
    assert first['summary']['packet_records']==601
    assert first['summary']['packet_bytes']==60100
    assert second['summary']['packet_records']==601
    assert second['coverage']['processed_records']==601


def test_flow_counters_are_deduplicated_and_sources_separate(report_service):
    base=dict(source_id='1',first_seen=utc(report_service.clock()-120),byte_basis='ip_bytes',sent_bytes=100,received_bytes=200)
    add(report_service,'flows',base,source='suricata-eve')
    add(report_service,'flows',dict(base,sent_bytes=150),source='suricata-eve')
    add(report_service,'flows',base,source='zeek-conn')
    value=make(report_service)
    groups={r['source']:r for r in value['flow_sources']}
    assert groups['suricata-eve']['connections']==1
    assert groups['suricata-eve']['records']==2
    assert groups['suricata-eve']['sent_bytes']==150
    assert groups['zeek-conn']['sent_bytes']==100
    assert value['summary']['packet_records']==0


def test_findings_html_and_csv_are_inert_and_paginated(report_service):
    for n in range(3):
        add(report_service,'findings',dict(signature='<script>alert(1)</script>',severity='=2+2',src_ip='192.0.2.1',dst_ip='198.51.100.1'))
    value=make(report_service)
    mime,html=report_service.download(value['id'],'html')
    assert '<script>' not in html.decode()
    assert '&lt;script&gt;' in html.decode()
    assert 'http://' not in html.decode() and 'https://' not in html.decode()
    mime,csv=report_service.download(value['id'],'csv')
    assert "'=2+2" in csv.decode()
    page=report_service.findings(value['id'],offset=1,limit=1)
    assert page['total']==3 and len(page['records'])==1 and page['truncated']
    assert value['findings'][0]['evidence_reference'].count(':')==1


def test_resource_sample_formats_match_host_sampler(report_service):
    add(report_service,'resources',dict(system={'cpu_percent':10},suite={'cpu_percent':2,'memory_percent':3},network={'interfaces':[{'name':'eth0','rx_bps':125000,'tx_bps':250000}]}))
    value=make(report_service)
    sample=value['resources'][0]
    assert sample['suite_cpu_percent']==2
    assert sample['interfaces']['eth0']['receive_bytes_per_second']==125000
    assert sample['interfaces']['eth0']['send_bytes_per_second']==250000
    assert 'eth0' in report_service.download(value['id'],'html')[1].decode()


def test_report_integrity_and_source_expiry(report_service):
    add(report_service,'network',{'nodes':[]},age=86400)
    value=make(report_service)
    report_service.test_clock[0]+=14*86400
    with pytest.raises(ValueError,match='expired'):report_service.report(value['id'])


def test_partial_report_work_limit(report_service,monkeypatch):
    add(report_service,'network',{'nodes':[]})
    monkeypatch.setattr('megalodon.reporting.MAX_RECORDS',0)
    value=make(report_service)
    assert any('work limit' in x for x in value['coverage']['gaps'])


def test_cancel_preserves_ready_reports_and_single_job(report_service,monkeypatch):
    saved=make(report_service)
    original=report_service._aggregate
    def held(*args):
        while not report_service.cancel_event.wait(.01):pass
        report_service._check()
    monkeypatch.setattr(report_service,'_aggregate',held)
    request={'start':utc(report_service.clock()-120),'end':utc(report_service.clock())}
    first=report_service.create(request)
    assert report_service.create(request)['id']==first['id']
    with pytest.raises(ValueError,match='already'):report_service.create({})
    report_service.cancel();report_service.worker.join(3)
    assert report_service.job['state']=='cancelled'
    assert report_service.report(saved['id'])['id']==saved['id']


def test_daily_catchup_is_once_and_survives_restart(report_service):
    add(report_service,'network',{'nodes':[]},age=4*3600)
    report_service.tick();report_service.worker.join(20)
    assert report_service.job['state']=='ready'
    identifier=report_service.job['report_id']
    report_service.tick()
    assert report_service.job['report_id']==identifier
    new=ReportService(report_service.evidence,zone=report_service.zone)
    new.tick()
    assert new.job['state']=='idle'
    assert new.settings['completed_slot']==report_service.settings['completed_slot']
    new.close()


def test_completion_checkpoint_recovers_settings_write_failure(report_service,monkeypatch):
    # Manifest+checkpoint precede the operational settings rename.
    original=report_service._save_settings
    attempts=[0]
    def fail_completion():
        attempts[0]+=1
        if attempts[0]>2:raise OSError('interrupted rename')
        return original()
    monkeypatch.setattr(report_service,'_save_settings',fail_completion)
    report_service.tick();report_service.worker.join(20)
    assert len(report_service.manifests())==1
    new=ReportService(report_service.evidence,zone=report_service.zone)
    new.tick()
    assert new.job['state']=='idle'
    new.close()


@pytest.mark.parametrize('day,expected',[
    ('2026-03-08T08:45:00+00:00','2026-03-08T08:30:00+00:00'),
    ('2026-11-01T09:00:00+00:00','2026-11-01T08:30:00+00:00'),
])
def test_dst_nonexistent_or_standard_slot(day,expected):
    schedule=dict(enabled=True,time='02:30',frequency='daily',weekday=0)
    identity,stamp=latest_slot(schedule,datetime.fromisoformat(day).timestamp(),ZoneInfo('America/Chicago'))
    assert stamp==datetime.fromisoformat(expected).timestamp()


def test_dst_repeated_hour_uses_first_fold():
    schedule=dict(enabled=True,time='01:30',frequency='daily',weekday=0)
    zone=ZoneInfo('America/Chicago')
    first=latest_slot(schedule,datetime(2026,11,1,6,45,tzinfo=timezone.utc).timestamp(),zone)
    repeated=latest_slot(schedule,datetime(2026,11,1,7,45,tzinfo=timezone.utc).timestamp(),zone)
    assert first==repeated


def test_weekly_and_clock_backwards_do_not_duplicate(report_service):
    report_service.configure(dict(enabled=True,time='09:00',frequency='weekly',weekday=0))
    report_service.tick();report_service.worker.join(20)
    saved=report_service.settings['completed_slot']
    report_service.test_clock[0]-=7*86400
    report_service.tick()
    assert report_service.settings['completed_slot']==saved


@pytest.mark.parametrize('value',[{}, {'enabled':1,'time':'09:00','frequency':'daily'}, {'enabled':True,'time':'25:00','frequency':'daily'}, {'enabled':True,'time':'09:00','frequency':'hourly'}, {'enabled':True,'time':'09:00','frequency':'weekly','weekday':True}])
def test_schedule_validation(value):
    with pytest.raises(ValueError):schedule_value(value)


def test_schedule_change_syncs_file_and_directory(report_service,monkeypatch):
    import os
    import stat
    seen=[];original=os.fsync
    def sync(descriptor):
        seen.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
        original(descriptor)
    monkeypatch.setattr('megalodon.reporting.os.fsync',sync)
    report_service.configure(dict(enabled=False,time='09:00',frequency='daily',weekday=0))
    assert seen==[False,True]


@pytest.mark.parametrize('identifier',['../catalog.json','a'*31,'A'*32, '%2e%2e',None])
def test_download_identifiers_are_not_paths(report_service,identifier):
    with pytest.raises(ValueError):report_service.report(identifier)


def test_report_uses_exact_chunk_references_and_marks_eviction(report_service):
    value=make(report_service)
    manifest=report_service._manifest_values()[0]
    assert manifest['references'] and manifest['references'][0]['first']>0
    # Remove a referenced chunk's identity from the catalog without touching a
    # user source; the same condition occurs after oldest-first expiry.
    identity=manifest['references'][0]['segment']
    assert report_service.report(value['id'])['id']==value['id']
    # Preserve the manifest but simulate a missing chunk row.
    entry=next(e for e in report_service.evidence._catalog['entries'] if e['id']==identity)
    with report_service.evidence.lock, report_service.evidence._db(entry,write=True) as db:
        db.execute('DELETE FROM records WHERE id=?',(manifest['references'][0]['first'],));db.commit()
    with pytest.raises(ValueError,match='incomplete'):report_service.report(value['id'])


def test_resource_means_preserve_missing_sample_weights():
    a=_resource_mean([{'system':{'cpu_percent':10}},{'system':{'cpu_percent':None}}])
    b=_resource_mean([a,{'system':{'cpu_percent':20}}])
    assert b['system_cpu_percent']==15
    assert b['metric_samples']['system_cpu_percent']==2


@pytest.mark.parametrize('value',[' =1+2','\ufeff@SUM(A1)','\x00text','\ttext','\n=1',' -2'])
def test_csv_formula_guard_handles_prefixes(value):
    assert _csv_safe(value).startswith("'")


def test_csv_preserves_zero():
    assert _csv_safe(0)=='0'


def test_readable_chart_labels_units_times_empty_states(report_service):
    add(report_service,'resources',dict(system={'cpu_percent':10},suite={'cpu_percent':2,'memory_percent':3},network={'interfaces':[{'name':'eth0','rx_bps':125000,'tx_bps':250000}]}))
    value=make(report_service)
    html=report_service.download(value['id'],'html')[1].decode()
    assert 'Peak interval receive: 1 Mbps' in html
    assert 'Mbps · average of retained samples' in html
    assert '14 days · 20.0 GiB maximum · detailed packet metadata' in html
    assert 'Sep 30, 2026' in html and 'CDT' in html
    assert 'No packet records were returned for this time range' in html
    assert 'No connection summaries were retained' in html
    assert '<th scope="col">Interval begins</th>' in html
    assert "{'profile':" not in html
    assert report_service.manifests()[0]['state']=='ready'
    assert value['coverage']['partial'] and value['coverage']['aggregation_complete']


def test_core_findings_and_action_links_remain_qualified(report_service):
    from megalodon.models import DetectionResult,ActionRecord
    manager=report_service.evidence;writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    stamp=datetime.fromtimestamp(report_service.clock()-60,timezone.utc)
    packet=PacketEvent(stamp,'192.0.2.1','198.51.100.1','TCP',40000,443,byte_count=100)
    finding=DetectionResult(stamp,'TEST','HIGH',packet.src_ip,packet.dst_ip,'Synthetic high finding')
    action=ActionRecord(stamp,'ALERT',packet.src_ip,'not_attempted','Synthetic observation')
    writer.record_event_bundle(packet,[finding],[action],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    value=make(report_service)
    assert value['summary']['finding_count']==1
    assert value['summary']['response_count']==1
    assert value['findings'][0]['id'].count(':')==2
    assert value['responses'][0]['state']=='not_attempted'
    html=report_service.download(value['id'],'html')[1].decode()
    assert '1 high-priority finding needs review' in html
    assert 'MEGALODON / HIGH' in html
    assert 'Packet records per interval' in html


def test_mobile_and_print_chart_labels_keep_intrinsic_size(report_service):
    from megalodon.reporting import REPORT_CSS
    html=report_service.download(make(report_service)['id'],'html')[1].decode()
    assert '.chart-scroll .chart{min-width:640px}' in REPORT_CSS
    assert '.chart-scroll .chart,.chart-scroll .topology-chart{min-width:0;height:auto}' in REPORT_CSS
    assert 'height:160px' not in REPORT_CSS and 'height:150px' not in REPORT_CSS
    assert 'tabindex="0" role="region" aria-label="Report chart' not in html  # Empty charts remain plain messages.


def test_operator_cancellation_skips_only_that_scheduled_occurrence(report_service,monkeypatch):
    def held(*args):
        while not report_service.cancel_event.wait(.01):pass
        report_service._check()
    monkeypatch.setattr(report_service,'_aggregate',held)
    report_service.tick();report_service.cancel();report_service.worker.join(3)
    identity=report_service.job['id'];report_service.test_clock[0]+=600
    report_service.tick()
    assert report_service.job['id']==identity and report_service.job['state']=='cancelled'


def test_pattern_report_escapes_text_and_expires_with_dependencies(report_service):
    from types import SimpleNamespace
    from megalodon.security_patterns import candidate
    add(report_service,'flows',dict(src_ip='192.0.2.1',dst_ip='198.51.100.1'))
    segment=next(e['id'] for e in report_service.evidence._catalog['entries'] if e['category']=='flows')
    review=candidate('REGULAR_INTERVAL',('192.0.2.1','fixture0','zeek','flow'),report_service.clock()-60,report_service.clock()-1,
                     {'label':'<script>alert(1)</script>'},[segment+':1'],[segment])
    review['analysis']=dict(explanation='<img src=x onerror=alert(1)>',references=[],alternative='Scheduled backup',missing='Full visibility')
    report_service.intelligence=SimpleNamespace(report_context=lambda *a:dict(reviews=[review],dependencies=[segment],coverage='Synthetic fixture',truncated=False))
    value=make(report_service)
    raw=report_service.download(value['id'],'html')[1].decode()
    assert '<img src=x' not in raw and '&lt;img' in raw and '&lt;script&gt;' in raw
    assert 'What happened' in raw and 'What you can do' in raw
    manifest=next(v for v in report_service.evidence.history(category='reports')['records'] if v['source']=='report-manifest')
    report_service.evidence.save_case([manifest['id']])
    with report_service.evidence.lock:
        next(e for e in report_service.evidence._catalog['entries'] if e['id']==segment)['state']='needs_review'
    assert report_service.manifests()[0]['state']=='expired'
    assert not report_service.evidence.history(category='cases')['records']
    with pytest.raises(ValueError,match='expired'):report_service.report(value['id'])
