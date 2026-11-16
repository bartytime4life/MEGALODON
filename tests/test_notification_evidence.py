"""Notification hooks see committed findings only; no desktop helper is used."""
from datetime import datetime, timezone
import json
import sqlite3
import time

import pytest

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc
from megalodon.models import ActionRecord, DetectionResult, PacketEvent


@pytest.fixture
def evidence(private_tmp_path):
    clock = [float(int(time.time()))]
    calls = []
    manager = EvidenceStorage(Settings(db_path=private_tmp_path/'legacy.db'), home=private_tmp_path,
                              clock=lambda: clock[0], monotonic=lambda: clock[0],
                              finding_observer=lambda scope, cursor, **kwargs: calls.append((scope,cursor,kwargs)))
    manager.apply(manager.preview(dict(profile='home',retention_days=14,cap_bytes=GIB))['preview_id'])
    manager.test_clock, manager.test_notifications = clock, calls
    yield manager
    manager.close()


def bundle(evidence, *, event_age=0, detection_age=None, suppressed=None, severity='MEDIUM'):
    event = PacketEvent(datetime.fromtimestamp(evidence.clock()-event_age,timezone.utc),
                        '192.0.2.2','198.51.100.3','TCP',40000,443,byte_count=100)
    detection = DetectionResult(datetime.fromtimestamp(evidence.clock()-(event_age if detection_age is None else detection_age),timezone.utc),
                                'PORT_SCAN',severity,event.src_ip,event.dst_ip,'Synthetic private detail',
                                evidence=dict(private_value='not sent to the callback'),
                                suppressed_reason=suppressed)
    action=ActionRecord(detection.detected_at,'alert',event.src_ip,'not_attempted','Synthetic notification fixture')
    return event,[detection],[action]


def sensor(evidence, *, age=0, severity=1, source='suricata-eve'):
    return dict(observed_at=utc(evidence.clock()-age),source=source,
                data=dict(severity=severity,signature='Synthetic private detail',
                          src_ip='192.0.2.2',dst_ip='198.51.100.3'))


def test_core_notification_follows_committed_transaction_and_forced_catalog_save(evidence):
    writer = evidence.packet_writer()
    run = writer.start_ingestion_run('jsonl')
    observed = []

    def callback(scope,cursor,**kwargs):
        catalog = json.loads(evidence.catalog_path.read_bytes())
        entry = next(row for row in catalog['entries'] if row['id']==writer.entry['id'])
        assert entry['records']==2
        with sqlite3.connect(evidence._path(entry)) as connection:
            assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]==2
            assert connection.execute('SELECT COUNT(*) FROM detections').fetchone()[0]==2
            assert not connection.in_transaction
        observed.append((scope,cursor,kwargs))

    evidence.finding_observer = callback
    result = writer.record_event_bundles([bundle(evidence),bundle(evidence)],run_id=run)
    assert result==[1,2]
    assert observed==[('detector:'+writer.entry['id'],2,dict(count=2))]


def test_sensor_notification_follows_commit_and_durable_catalog_and_uses_record_cursor(evidence):
    observed = []

    def callback(scope,cursor,**kwargs):
        catalog = json.loads(evidence.catalog_path.read_bytes())
        entry = next(row for row in catalog['entries'] if row['id']==scope.split(':')[1])
        assert entry['records']==3
        with sqlite3.connect(evidence._path(entry)) as connection:
            assert connection.execute('SELECT MAX(id) FROM records').fetchone()[0]==3
            assert connection.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0]==1
        observed.append((scope,cursor,kwargs))

    evidence.finding_observer = callback
    rows = [sensor(evidence,severity=3),sensor(evidence,severity=1),sensor(evidence,severity=2)]
    assert evidence.append_records('findings',rows,checkpoint=('test-checkpoint',dict(offset=10)))==3
    assert observed==[('sensor:'+evidence._generic['findings']['id'],3,dict(count=2))]


@pytest.mark.parametrize('changes,expected', [({},1), ({'event_age':120},1), ({'event_age':-60},1),
                                             ({'event_age':121},0), ({'event_age':-61},0),
                                             ({'suppressed':'rate_limit'},0), ({'suppressed':''},0),
                                             ({'severity':'LOW'},1), ({'severity':'CRITICAL'},1)])
def test_core_freshness_and_suppression_filter(evidence,changes,expected):
    writer = evidence.packet_writer()
    run = writer.start_ingestion_run('jsonl')
    writer.record_event_bundles([bundle(evidence,**changes)],run_id=run)
    assert len(evidence.test_notifications)==expected


@pytest.mark.parametrize('changes,expected', [({},1), ({'severity':2},1), ({'severity':3},0),
                                             ({'severity':4},0), ({'severity':True},0),
                                             ({'severity':'1'},0), ({'severity':None},0),
                                             ({'source':'zeek-conn'},0), ({'source':'other'},0),
                                             ({'age':120},1), ({'age':121},0), ({'age':-60},1)])
def test_sensor_freshness_source_and_integer_severity_filter(evidence,changes,expected):
    evidence.append_records('findings',[sensor(evidence,**changes)])
    assert len(evidence.test_notifications)==expected


def test_non_finding_categories_never_notify(evidence):
    evidence.append_records('flows',[sensor(evidence)])
    evidence.append_records('network',[sensor(evidence)])
    assert evidence.test_notifications==[]


def test_batch_includes_only_eligible_findings_and_preserves_stable_scoped_cursors(evidence):
    writer = evidence.packet_writer()
    run = writer.start_ingestion_run('jsonl')
    writer.record_event_bundles([bundle(evidence),bundle(evidence,suppressed='rate_limit'),
                                bundle(evidence,event_age=121)],run_id=run)
    writer.record_event_bundles([bundle(evidence)],run_id=run)
    evidence.append_records('findings',[sensor(evidence,severity=3)])
    evidence.append_records('findings',[sensor(evidence),sensor(evidence,age=121)],
                            checkpoint=('first',dict(offset=10)))
    evidence.append_records('findings',[sensor(evidence,severity=2)],
                            checkpoint=('second',dict(offset=20)))
    assert evidence.test_notifications==[
        ('detector:'+writer.entry['id'],3,dict(count=1)),
        ('detector:'+writer.entry['id'],4,dict(count=1)),
        ('sensor:'+evidence._generic['findings']['id'],3,dict(count=1)),
        ('sensor:'+evidence._generic['findings']['id'],4,dict(count=1)),
    ]


def test_rotation_separates_equal_cursors_into_new_scopes(evidence):
    writer = evidence.packet_writer()
    run = writer.start_ingestion_run('jsonl')
    writer.record_event_bundles([bundle(evidence)],run_id=run)
    evidence.append_records('findings',[sensor(evidence)])
    evidence.test_clock[0]+=3601
    writer.record_event_bundles([bundle(evidence)],run_id=run)
    evidence.append_records('findings',[sensor(evidence)])
    assert len(evidence.test_notifications)==4
    assert len({scope for scope,_,_ in evidence.test_notifications})==4
    assert all(cursor==1 for _,cursor,_ in evidence.test_notifications)


@pytest.mark.parametrize('kind',['core','sensor'])
def test_callback_failure_does_not_fail_or_reclassify_committed_ingestion(evidence,kind):
    attempts = []

    def fail(scope,cursor,**kwargs):
        attempts.append((scope,cursor,kwargs))
        raise OSError('Private notification failure')

    evidence.finding_observer=fail
    before=evidence._write_metrics['write_failures']
    if kind=='core':
        writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
        assert writer.record_event_bundles([bundle(evidence)],run_id=run)==[1]
        assert writer.store.connection.execute('SELECT COUNT(*) FROM detections').fetchone()[0]==1
    else:
        assert evidence.append_records('findings',[sensor(evidence)])==1
        assert evidence.history(category='findings')['total']==1
    assert len(attempts)==1
    assert evidence._write_metrics['write_failures']==before


@pytest.mark.parametrize('kind',['core','sensor'])
def test_failed_write_cannot_emit_a_hint(evidence,kind,monkeypatch):
    if kind=='core':
        writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
        def fail(*args,**kwargs):
            raise sqlite3.OperationalError('Synthetic write failure')
        monkeypatch.setattr(writer.store,'record_event_bundles',fail)
        with pytest.raises(sqlite3.OperationalError):
            writer.record_event_bundles([bundle(evidence)],run_id=run)
        assert writer.store.connection.execute('SELECT COUNT(*) FROM detections').fetchone()[0]==0
    else:
        # An invalid checkpoint is rejected after INSERT but before COMMIT.
        with pytest.raises(ValueError):
            evidence.append_records('findings',[sensor(evidence)],checkpoint=('INVALID',dict(offset=1)))
        with evidence._db(evidence._generic['findings']) as connection:
            assert connection.execute('SELECT COUNT(*) FROM records').fetchone()[0]==0
    assert evidence.test_notifications==[]


@pytest.mark.parametrize('kind',['core','sensor'])
def test_failed_catalog_save_after_sqlite_commit_does_not_emit_a_hint(evidence,kind,monkeypatch):
    # Establish the segment before replacing _save, so failure occurs after the
    # relevant transaction rather than during its initial catalog enrollment.
    if kind=='core':
        writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
    else:
        evidence.append_records('findings',[sensor(evidence,severity=3)])
    original=evidence._save

    def fail(*args,**kwargs):
        raise OSError('Synthetic catalog failure')

    monkeypatch.setattr(evidence,'_save',fail)
    try:
        with pytest.raises(OSError):
            if kind=='core':
                writer.record_event_bundles([bundle(evidence)],run_id=run)
            else:
                evidence.append_records('findings',[sensor(evidence)])
        assert evidence.test_notifications==[]
    finally:
        monkeypatch.setattr(evidence,'_save',original)


@pytest.mark.parametrize('kind',['core','sensor'])
def test_freshness_is_checked_after_catalog_save(evidence,kind,monkeypatch):
    if kind=='core':
        writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
    else:
        evidence.append_records('findings',[sensor(evidence,severity=3)])
    original=evidence._save

    def slow_save(*args,**kwargs):
        original(*args,**kwargs)
        evidence.test_clock[0]+=121

    monkeypatch.setattr(evidence,'_save',slow_save)
    if kind=='core':
        writer.record_event_bundles([bundle(evidence)],run_id=run)
    else:
        evidence.append_records('findings',[sensor(evidence)])
    assert evidence.test_notifications==[]


def test_restart_does_not_scan_or_notify_retained_history(evidence):
    evidence.append_records('findings',[sensor(evidence)])
    assert len(evidence.test_notifications)==1
    evidence.close()
    calls=[]
    reopened=EvidenceStorage(evidence.settings,home=evidence.home,clock=evidence.clock,
                             finding_observer=lambda *args,**kwargs:calls.append((args,kwargs)))
    try:
        assert reopened.history(category='findings')['total']==1
        assert calls==[]
        reopened.append_records('findings',[sensor(reopened)])
        assert len(calls)==1
    finally:
        reopened.close()


def test_observer_is_optional_and_rejects_non_callback_before_storage(private_tmp_path):
    settings=Settings(db_path=private_tmp_path/'legacy.db')
    with pytest.raises(ValueError,match='trusted local callback'):
        EvidenceStorage(settings,home=private_tmp_path,finding_observer='/usr/bin/notify-send')
    assert not (private_tmp_path/'.local').exists()
    value=EvidenceStorage(settings,home=private_tmp_path)
    try:
        assert value.finding_observer is None
    finally:
        value.close()
