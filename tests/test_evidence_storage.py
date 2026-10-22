from datetime import datetime, timezone
from pathlib import Path
import json
import os
import sqlite3

import pytest

pytestmark=pytest.mark.skipif(os.name != "posix",reason="Local Linux managed evidence")

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, policy_value, GIB, utc
from megalodon.models import PacketEvent


@pytest.fixture
def manager(tmp_path):
    tmp_path.chmod(0o700)
    stamp=[datetime.now(timezone.utc).timestamp()]
    value=EvidenceStorage(Settings(db_path=tmp_path/'old.db'),home=tmp_path,clock=lambda:stamp[0],monotonic=lambda:stamp[0],segment_bytes=65536)
    value.test_clock=stamp
    yield value
    value.close()


def enable(manager,days=14,cap=20*GIB):
    preview=manager.preview(dict(profile='home',retention_days=days,cap_bytes=cap))
    return manager.apply(preview['preview_id'])


def row(manager,n=1):
    return dict(observed_at=utc(manager.clock()),source='fixture',data={'bytes':n})


@pytest.mark.parametrize('reported', ['verified-anchor', 'other-anchor', 'other-path'])
def test_reader_accepts_only_its_verified_connection_anchor(manager,monkeypatch,reported):
    from urllib.parse import unquote, urlsplit
    from megalodon.storage import StorageSchemaError

    enable(manager)
    manager.append_records('network',[row(manager)])
    entry=manager._generic['network']
    real_connect=sqlite3.connect
    connections=[]

    class ReportedPath:
        def __init__(self,connection,filename):
            self.connection=connection;self.filename=filename;self.closed=False
        def execute(self,statement,*args,**kwargs):
            if statement=='PRAGMA database_list':
                return type('Rows',(),{'fetchall':lambda _: [(0,'main',self.filename)]})()
            return self.connection.execute(statement,*args,**kwargs)
        def close(self):
            self.closed=True;self.connection.close()
        def __getattr__(self,name):
            return getattr(self.connection,name)

    def connect(database,*args,**kwargs):
        anchor=unquote(urlsplit(database).path)
        filename=(anchor if reported=='verified-anchor' else
                  '/dev/fd/999999' if reported=='other-anchor' else str(manager.root/'other.db'))
        connection=ReportedPath(real_connect(database,*args,**kwargs),filename)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3,'connect',connect)
    if reported=='verified-anchor':
        with manager._db(entry) as reader:
            assert reader.execute('SELECT COUNT(*) FROM records').fetchone()[0]==1
            assert reader.execute('PRAGMA query_only').fetchone()[0]==1
    else:
        with pytest.raises(StorageSchemaError,match='^EVIDENCE:DATABASE_CHANGED$'):
            with manager._db(entry):
                pytest.fail('Unrelated connection path was accepted')
    assert len(connections)==1 and connections[0].closed


def test_policy_is_reviewed_and_validated(manager):
    assert not manager.enabled
    assert manager.append_records('network',[row(manager)])==0
    for days in [6,31,True,14.1]:
        with pytest.raises(ValueError):policy_value(dict(profile='home',retention_days=days,cap_bytes=GIB))
    with pytest.raises(ValueError):manager.apply('not-a-preview')
    result=enable(manager)
    assert result['enabled'] and result['policy']['retention_days']==14
    assert result['policy']['recording_mode']=='packet_metadata'


def test_rotation_history_cursor_and_age_cleanup(manager):
    enable(manager,days=7)
    for n in range(3):
        manager.append_records('network',[row(manager,n)])
        manager.test_clock[0]+=3601
    first=manager.history(limit=1)
    assert first['records'][0]['data']['bytes']==2
    second=manager.history(limit=1,cursor=first['next_cursor'])
    assert second['records'][0]['data']['bytes']==1
    manager.test_clock[0]+=7*86400
    # Active units are sealed before sweeping.
    for entry in list(manager._generic.values()):manager._seal(entry)
    manager._generic.clear();manager._ensure_space()
    assert manager.history()['records']==[]
    assert manager.snapshot()['evicted_records']==3
    assert list(manager.root.glob('*.db'))==[]
    assert manager.history(cursor=first['next_cursor'])['gaps']


def test_size_eviction_reclaims_physical_file_and_reports_shortfall(manager):
    enable(manager,cap=GIB)
    manager.append_records('cases',[row(manager)])
    entry=manager._generic.pop('cases');manager._seal(entry)
    before=manager._size(entry)
    # A large reservation models pressure without a giant fixture.
    manager._ensure_space(GIB-before//2)
    assert not manager._path(entry).exists()
    assert manager.snapshot()['evicted_records']==1


def test_identity_swap_and_symlink_are_never_deleted(manager,tmp_path):
    enable(manager)
    manager.append_records('cases',[row(manager)])
    entry=manager._generic.pop('cases');manager._seal(entry)
    path=manager._path(entry);other=tmp_path/'other';other.write_text('keep');other.chmod(0o600)
    path.unlink();path.symlink_to(other)
    manager.test_clock[0]+=31*86400
    with pytest.raises(ValueError):manager._ensure_space()
    assert other.read_text()=='keep'


def test_packet_rotation_preserves_linked_run_receipts(manager):
    enable(manager)
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    event=PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'10.0.0.2','1.1.1.1','TCP',50000,443,byte_count=123)
    writer.record_event_bundle(event,[],[],run_id=run)
    manager.test_clock[0]+=3601
    event=PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'10.0.0.2','1.1.1.1','TCP',50000,443,byte_count=234)
    writer.record_event_bundle(event,[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    assert len(manager._catalog['entries'])==2
    page=manager.history()
    assert [r['data']['byte_count'] for r in page['records']]==[234,123]
    assert len({r['id'].split(':')[0] for r in page['records']})==2
    for entry in manager._catalog['entries']:
        with manager._db(entry) as db:
            assert db.execute('SELECT processed_count FROM ingestion_runs').fetchone()[0]==1
            assert db.execute('PRAGMA foreign_key_check').fetchall()==[]


@pytest.mark.parametrize('reason,failure',[('interrupted','INTERRUPTED'),('failed','CAPTURE_ERROR'),('source_exhausted',None)])
def test_capacity_rotation_keeps_the_sessions_final_outcome(manager,reason,failure):
    enable(manager,cap=GIB)
    event=lambda:PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'10.0.0.2','1.1.1.1','TCP',1,443,byte_count=1)
    older=manager.packet_writer();older.record_event_bundle(event(),[],[],run_id=older.start_ingestion_run('jsonl'))
    older.finish_ingestion_run(1,'source_exhausted');older.close();manager.test_clock[0]+=60
    prior={e['id'] for e in manager._catalog['entries']}
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    writer.record_event_bundle(event(),[],[],run_id=run)
    # The 30-second maintenance pass crosses the cap and seals the active unit mid-session.
    with manager.lock:manager._ensure_space(GIB-manager._used()+1)
    assert writer.store is None
    writer.finish_ingestion_run(run,reason,failure_code=failure);writer.close()
    receipts=[]
    for entry in sorted((e for e in manager._catalog['entries'] if e['id'] not in prior),key=lambda e:e['created_at']):
        with manager._db(entry) as db:
            receipts+=db.execute('SELECT status,termination_reason,failure_code,processed_count FROM ingestion_runs').fetchall()
    status={'interrupted':'failed','failed':'failed','source_exhausted':'completed'}[reason]
    # The rotated unit's receipt covers its share; the stop or failure is never dropped.
    assert [tuple(r) for r in receipts]==[('completed','source_exhausted',None,1),(status,reason,failure,0)]


def test_restart_reconciles_generic_committed_counts(manager):
    enable(manager)
    manager.append_records('network',[row(manager)])
    # Simulate process exit after committed data, before sealing its segment.
    os.close(manager._lease_fd);manager._lease_fd=None
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    assert again.history()['total']==1
    assert again._catalog['entries'][0]['state']=='closed'
    again.close()


def test_clock_rollback_stops_cleanup(manager):
    enable(manager)
    manager.test_clock[0]-=600
    with pytest.raises(ValueError,match='clock'):manager._ensure_space()


def test_expired_preview_does_not_change_policy(manager):
    p=manager.preview(dict(profile='server',retention_days=30,cap_bytes=500*GIB))
    manager.test_clock[0]+=301
    with pytest.raises(ValueError):manager.apply(p['preview_id'])
    assert not manager.enabled


@pytest.mark.parametrize('days',range(7,31))
def test_every_supported_age_boundary_is_enforced(manager,days):
    enable(manager,days=days)
    manager.append_records('cases',[row(manager)])
    entry=manager._generic.pop('cases');manager._seal(entry)
    manager.test_clock[0]+=days*86400-1
    manager._ensure_space();assert manager.history()['total']==1
    manager.test_clock[0]+=1
    manager._ensure_space();assert manager.history()['total']==0


def test_legacy_preview_includes_and_preserves_all_evidence_until_apply(manager):
    from megalodon.storage import Store,DashboardStore
    from megalodon.models import DetectionResult,ActionRecord
    stamp=datetime.fromtimestamp(manager.clock()-20*86400,timezone.utc)
    event=PacketEvent(stamp,'10.0.0.2','1.1.1.1','TCP')
    with Store(manager.settings.db_path) as db:
        run=db.start_ingestion_run('jsonl')
        db.record_event_bundle(event,[DetectionResult(stamp,'TEST','LOW',event.src_ip,event.dst_ip,'retained relationship')],[ActionRecord(stamp,'alert',event.src_ip,'not_attempted','synthetic')],run_id=run)
        db.finish_ingestion_run(run,'source_exhausted')
    preview=manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))
    assert preview['eligible_records']==1 and preview['eligible_bytes']>0
    assert manager.settings.db_path.exists() and not manager.enabled
    # Read-only preview is a recoverable transition; the original schema and
    # findings remain readable with the prior application's reader.
    with DashboardStore(manager.settings.db_path) as old_reader:
        assert old_reader.summary()['detections']==1
    manager.apply(preview['preview_id'])
    assert not manager.settings.db_path.exists()
    assert manager.snapshot()['evicted_records']==1


def test_legacy_current_evidence_relationship_survives_enrollment(manager):
    from megalodon.storage import Store
    from megalodon.models import DetectionResult,ActionRecord
    stamp=datetime.fromtimestamp(manager.clock(),timezone.utc)
    event=PacketEvent(stamp,'10.0.0.2','1.1.1.1','TCP')
    with Store(manager.settings.db_path) as db:
        run=db.start_ingestion_run('jsonl')
        db.record_event_bundle(event,[DetectionResult(stamp,'TEST','LOW',event.src_ip,event.dst_ip,'synthetic finding')],[ActionRecord(stamp,'alert',event.src_ip,'not_attempted','synthetic')],run_id=run)
        db.finish_ingestion_run(run,'source_exhausted')
    enable(manager)
    result=manager.history()['records'][0]
    assert result['data']['findings'][0]['message']=='synthetic finding'
    assert manager.settings.db_path.exists()
    assert len(result['id'].split(':')[0])==32


@pytest.mark.parametrize('late_write',['event','action','event-older-catalog'])
def test_legacy_database_written_after_enrollment_is_retained_for_review(manager,late_write):
    from megalodon.storage import Store
    from megalodon.models import ActionRecord
    old=datetime.fromtimestamp(manager.clock()-10*86400,timezone.utc)
    with Store(manager.settings.db_path) as db:
        run=db.start_ingestion_run('jsonl')
        db.record_event_bundle(PacketEvent(old,'10.0.0.2','1.1.1.1','TCP'),[],[],run_id=run)
        db.finish_ingestion_run(run,'source_exhausted')
    enable(manager)
    # A command-line run or firewall action still writes to the enrolled
    # legacy path; retention must not delete those rows unseen.
    now=datetime.fromtimestamp(manager.clock(),timezone.utc)
    with Store(manager.settings.db_path) as db:
        if late_write.startswith('event'):
            run=db.start_ingestion_run('jsonl')
            db.record_event_bundle(PacketEvent(now,'10.0.0.3','1.1.1.1','TCP'),[],[],run_id=run)
            db.finish_ingestion_run(run,'source_exhausted')
        else:
            db.record_action(ActionRecord(now,'block','10.0.0.3','applied','synthetic'))
    if late_write=='event-older-catalog':
        # Catalogs enrolled before content was recorded compare event counts.
        next(e for e in manager._catalog['entries'] if e.get('legacy')).pop('content_sha256')
    manager.test_clock[0]+=5*86400
    manager._ensure_space()
    assert manager.settings.db_path.exists()
    legacy=next(e for e in manager._catalog['entries'] if e.get('legacy'))
    assert legacy['state']=='needs_review'
    assert manager.snapshot()['evicted_records']==0
    snapshot=manager.snapshot()
    assert snapshot['state']=='needs_review' and 'changed after enrollment' in snapshot['message']


def test_ai_receipt_ledger_written_after_enrollment_is_retained_for_review(manager):
    from megalodon.ai_broker import ReceiptStore
    path=manager.settings.db_path.parent/'megalodon-ai-receipts.db'
    def receipt(state):
        return {'state':state,'tool':'megalodon.ai.doctor','authority_level':0,'authorization_source':'operator_cli',
                'model':'fixture','model_request':'none','validated_arguments':{},'result':{'checked':True},
                'error_code':None,'duration_ms':0,'evidence_references':[]}
    from uuid import uuid4
    with ReceiptStore(path) as ledger:ledger.append(str(uuid4()),receipt('observed'))
    enable(manager,days=7)
    with ReceiptStore(path) as ledger:ledger.append(str(uuid4()),receipt('observed'))
    manager.test_clock[0]+=8*86400
    manager._ensure_space()
    assert path.exists()
    assert next(e for e in manager._catalog['entries'] if e.get('legacy'))['state']=='needs_review'


def test_changed_deletion_impact_requires_new_review(manager):
    enable(manager)
    manager.append_records('network',[row(manager)])
    manager.test_clock[0]+=15*86400
    p=manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))
    manager.append_records('network',[row(manager)])
    with pytest.raises(ValueError,match='changed'):manager.apply(p['preview_id'])
    assert manager.history()['total']>=1


def test_recovered_delete_intent_preserves_loss_accounting(manager):
    enable(manager)
    manager.append_records('cases',[row(manager)])
    entry=manager._generic.pop('cases');manager._seal(entry)
    size=manager._size(entry)
    entry.update(state='deleting',deletion_bytes=size,deletion_records=1,deletion_at=utc(manager.clock()))
    manager._save();manager._path(entry).unlink()
    os.close(manager._lease_fd);manager._lease_fd=None
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:
        assert again.snapshot()['evicted_records']==1
        assert again.snapshot()['evicted_bytes']==size
        assert again.history()['total']==0
    finally:again.close()
    manager._catalog=again._catalog


def test_checkpoint_generation_recovers_interleaved_source_categories(manager):
    enable(manager)
    manager.append_records('flows',[row(manager)],checkpoint=('flow_suricata',dict(identity=[1,2],offset=100)))
    manager.append_records('findings',[row(manager)],checkpoint=('flow_suricata',dict(identity=[1,2],offset=200)))
    manager.append_records('flows',[row(manager)],checkpoint=('flow_suricata',dict(identity=[1,2],offset=300)))
    os.close(manager._lease_fd);manager._lease_fd=None
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:assert again.checkpoint('flow_suricata')['offset']==300
    finally:again.close()
    manager._catalog=again._catalog;manager._generic.clear()


def test_failed_constructor_releases_lease(manager):
    enable(manager);manager.close()
    valid=manager.catalog_path.read_bytes()
    manager.catalog_path.write_bytes(b'{broken')
    with pytest.raises(ValueError):EvidenceStorage(manager.settings,home=manager.home)
    manager.catalog_path.write_bytes(valid)
    again=EvidenceStorage(manager.settings,home=manager.home)
    again.close()


def test_disk_exhaustion_refuses_write_without_deleting_uncertain_data(manager,monkeypatch):
    from collections import namedtuple
    from megalodon.storage import StorageCapacityError
    enable(manager)
    usage=namedtuple('usage','total used free')
    monkeypatch.setattr('megalodon.evidence_storage.shutil.disk_usage',lambda _:usage(100*GIB,100*GIB,0))
    with pytest.raises(StorageCapacityError):manager.append_records('network',[row(manager)])
    assert manager.history()['total']==0


def test_oldest_history_paging_total_and_saved_case_expiry(manager):
    enable(manager,days=7)
    for n in range(5):manager.append_records('network',[row(manager,n)])
    first=manager.history(order='oldest',limit=2)
    second=manager.history(order='oldest',limit=2,cursor=first['next_cursor'])
    assert [r['data']['bytes'] for r in first['records']+second['records']]==[0,1,2,3]
    assert first['total']==second['total']==5
    assert manager.save_case([first['records'][0]['id']])['saved']==1
    case=manager.history(category='cases')['records'][0]
    assert case['observed_at']==first['records'][0]['observed_at']
    manager.test_clock[0]+=7*86400
    for entry in list(manager._generic.values()):manager._seal(entry)
    manager._generic.clear();manager._ensure_space()
    assert manager.history(category='cases')['total']==0


def test_a_retired_source_removes_only_the_case_copied_from_it(manager):
    enable(manager)
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'10.0.0.2','1.1.1.1','TCP',1,443,byte_count=1),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    packets=[e for e in manager._catalog['entries'] if e['category']=='packets'][0]
    manager.append_records('baselines',[dict(observed_at=utc(manager.clock()),source='fixture',data={'source_segments':[packets['id']]})])
    manager.append_records('network',[row(manager,7)])
    derived=manager.history(category='baselines')['records'][0]['id']
    unrelated=manager.history(category='network')['records'][0]['id']
    # Two cases saved in the same hour.
    manager.save_case([unrelated]);manager.save_case([derived])
    for entry in list(manager._generic.values()):manager._seal(entry)
    manager._generic.clear()
    retired=list(manager._cascade(manager._catalog['entries'],[packets]))
    gone={e['id'] for e in retired}
    cases=[e for e in manager._catalog['entries'] if e['category']=='cases']
    assert len(cases)==2
    # Only the case that copied packet-derived evidence leaves with its source.
    assert sum(e['id'] in gone for e in cases)==1


def test_managed_receipt_chain_retained_boundary_and_crash_recovery(manager):
    from megalodon.managed_receipts import ManagedReceipts
    enable(manager,days=7)
    ledger=ManagedReceipts(manager,'defense')
    ledger.append('one',dict(state='not_attempted',action='analyze'))
    assert ledger.verify_chain()['incomplete_count']==1
    ledger.append('one',dict(state='observed',action='analyze',result={'synthetic':True}))
    head=ledger.verify_chain()['head']
    manager.test_clock[0]+=3601
    ledger.append('two',dict(state='not_attempted',action='analyze'))
    # Restart after a committed audit start before any terminal receipt.
    os.close(manager._lease_fd);manager._lease_fd=None
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:
        recovered=ManagedReceipts(again,'defense')
        assert recovered.verify_chain()['incomplete_count']==1
        recovered.reconcile_interrupted()
        assert recovered.latest('two')['outcome']=='unknown_after_restart'
        assert recovered.verify_chain()['incomplete_count']==0
        manager.test_clock[0]+=7*86400-3601
        again._ensure_space()
        verified=recovered.verify_chain()
        assert verified['retained_boundary']==head
        assert len(recovered.recent())==2
    finally:again.close()
    manager._catalog=again._catalog;manager._generic.clear()


def test_abrupt_forward_clock_change_preserves_evidence(manager):
    enable(manager);manager.append_records('network',[row(manager)])
    fixed=manager.monotonic()
    manager.monotonic=lambda:fixed
    manager.test_clock[0]+=31*86400
    with pytest.raises(ValueError,match='clock'):manager._ensure_space()
    assert manager.history()['total']==1


def test_interrupted_core_run_is_recovered_as_incomplete_with_coverage(manager):
    enable(manager)
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    event=PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'10.0.0.2','1.1.1.1','TCP',byte_count=90)
    writer.record_event_bundle(event,[],[],run_id=run)
    writer.store.close();writer.store=None;manager._writers.clear()
    os.close(manager._lease_fd);manager._lease_fd=None
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:
        page=again.history()
        assert page['total']==1 and page['gaps']
        assert again.snapshot()['oldest_at'] is not None
        assert page['records'][0]['data']['ingestion'][0]['status']=='failed'
        assert page['records'][0]['data']['ingestion'][0]['termination_reason']=='interrupted'
    finally:again.close()
    manager._catalog=again._catalog


def test_working_space_is_accounted_and_reservations_release(manager):
    enable(manager)
    root=manager.home/'.local/share/megalodon/support/sensor-samples/zeek-test'
    from megalodon.local_install import _owned_directory
    _owned_directory(root,private=True)
    (root/'conn.log').write_bytes(b'x'*1000)
    assert manager._working_bytes()==1000
    assert manager.snapshot()['categories'][-1]['bytes']==1000
    with manager.working_reservation(4*1024**2):
        assert manager.snapshot()['working_reserved_bytes']==4*1024**2
    assert manager.snapshot()['working_reserved_bytes']==0


def test_pending_audit_remains_recoverable_after_orderly_close(manager):
    from megalodon.managed_receipts import ManagedReceipts
    enable(manager)
    ManagedReceipts(manager,'defense').append('pending',dict(state='not_attempted',action='analyze'))
    segment=manager._generic['audit']['id']
    manager.close()
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:
        assert again._generic['audit']['id']==segment
        ledger=ManagedReceipts(again,'defense');ledger.reconcile_interrupted()
        assert ledger.verify_chain()['incomplete_count']==0
        assert again._generic['audit']['pending_receipts']==0
    finally:again.close()


def test_growth_uses_net_allocation_and_evictions_not_repeated_wal_expansion(manager):
    enable(manager)
    manager._catalog['growth_samples']=[]
    manager._sample_growth(10000)
    manager.test_clock[0]+=450;manager._sample_growth(100000)
    manager.test_clock[0]+=450;manager._sample_growth(10000)
    assert manager.snapshot()['growth_bytes_per_day'] is None
    # The same physical footprint after oldest-first reclamation still records
    # the new capacity that was required to replace expired bytes.
    manager._catalog['evicted_bytes']=90000
    manager.test_clock[0]+=900;manager._sample_growth(10000)
    assert manager.snapshot()['growth_bytes_per_day']==pytest.approx(90000*86400/1800)
