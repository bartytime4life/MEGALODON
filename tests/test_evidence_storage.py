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
