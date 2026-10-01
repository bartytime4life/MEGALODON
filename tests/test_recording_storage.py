from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc


@pytest.fixture
def storage(tmp_path):
    clock=[datetime.now(timezone.utc).timestamp()]
    manager=EvidenceStorage(Settings(db_path=tmp_path/'old.db'),home=tmp_path,
                            clock=lambda:clock[0],monotonic=lambda:clock[0])
    manager.test_clock=clock
    manager.apply(manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))['preview_id'])
    yield manager
    manager.close()


def row(storage,n=1):
    return dict(observed_at=utc(storage.clock()),source='test',data={'count':n})


def test_generic_writer_reused_and_catalog_counters_coalesced(storage):
    storage.append_records('network',[row(storage)])
    entry=storage._generic['network'];db=storage._write_dbs[entry['id']][1]
    with patch('megalodon.evidence_storage._atomic_write') as save:
        for n in range(5):storage.append_records('network',[row(storage,n)])
        assert save.call_count==0
        assert storage._write_dbs[entry['id']][1] is db
        assert db.execute('PRAGMA synchronous').fetchone()[0]==2
        assert db.execute('PRAGMA wal_autocheckpoint').fetchone()[0]==0
        assert Path(str(storage._path(entry))+'-wal').stat().st_size>0
        storage.test_clock[0]+=31
        storage.append_records('network',[row(storage)])
        assert save.call_count==1


def test_seal_reclaims_wal_and_closes_connection(storage):
    storage.append_records('network',[row(storage)])
    entry=storage._generic.pop('network')
    storage._seal(entry)
    assert entry['id'] not in storage._write_dbs
    assert not Path(str(storage._path(entry))+'-wal').exists()
    assert entry['state']=='closed'


def test_committed_checkpoint_recovers_despite_delayed_catalog(storage):
    storage.append_records('flows',[row(storage)],checkpoint=('flow_test',{'offset':42}))
    # A new segment's initial catalog does not contain the subsequent commit.
    persisted=json.loads(storage.catalog_path.read_text())
    assert persisted['checkpoints'].get('flow_test') is None
    for context,_ in storage._write_dbs.values():context.__exit__(None,None,None)
    storage._write_dbs.clear()
    os.close(storage._lease_fd);storage._lease_fd=None
    with_patch=EvidenceStorage(storage.settings,home=storage.home)
    try:
        assert with_patch.checkpoint('flow_test')['offset']==42
        assert with_patch.history(category='flows')['total']==1
    finally:with_patch.close()


def test_checkpoint_reader_pressure_is_visible_and_bounded(storage):
    storage.append_records('flows',[row(storage)])
    entry=storage._generic['flows'];db=storage._write_dbs[entry['id']][1]
    with storage._db(entry) as reader:
        reader.execute('BEGIN');reader.execute('SELECT * FROM records').fetchall()
        storage.append_records('flows',[row(storage,2)])
        storage.test_clock[0]+=61
        storage._checkpoint(entry,db)
        assert storage.disk_activity()['checkpoint_busy']==1
        reader.rollback()
    storage._checkpoint(entry,db,force=True)
    assert storage.disk_activity()['last_checkpoint_at']


def test_reused_large_wal_does_not_checkpoint_every_batch(storage):
    large=dict(observed_at=utc(storage.clock()),source='test',data={'payload':'x'*24000})
    for _ in range(3):storage.append_records('flows',[large]*128)
    entry=storage._generic['flows'];db=storage._write_dbs[entry['id']][1]
    statements=[];db.set_trace_callback(statements.append)
    storage.append_records('flows',[row(storage)])  # crosses 8 MiB, then reuses WAL
    assert Path(str(storage._path(entry))+'-wal').stat().st_size>=8*1024**2
    assert sum('wal_checkpoint' in s for s in statements)==1
    for _ in range(5):storage.append_records('flows',[row(storage)])
    assert sum('wal_checkpoint' in s for s in statements)==1
    storage.test_clock[0]+=61
    storage._checkpoint(entry,db)
    assert sum('wal_checkpoint' in s for s in statements)==2


def test_failed_packet_admission_is_counted_before_sqlite_write(storage):
    from megalodon.models import PacketEvent
    writer=storage.packet_writer();writer.start_ingestion_run('jsonl')
    event=PacketEvent(datetime.now(timezone.utc),'10.0.0.2','1.1.1.1','UDP')
    with patch.object(storage,'_ensure_space',side_effect=ValueError('budget full')):
        with pytest.raises(ValueError,match='budget full'):writer.record_event_bundles([(event,[],[])])
    assert storage.disk_activity()['write_failures']==1
    assert writer.store.summary()['events']==0
    writer.finish_ingestion_run(1,'source_exhausted');writer.close()


def test_disk_counter_projection_preserves_unknown_apps(storage):
    class Sampler:
        def snapshot(self):
            return {'apps':[{'process_count':1,'write_bps':100}, {'process_count':1,'write_bps':None}]}
    storage.telemetry=Sampler()
    storage._recording={'write_failures':1}
    storage._write_metrics['write_failures']=3
    status=storage.disk_activity()
    assert status['write_failures']==3
    assert status['buffer_write_failures']==1
    assert status['current_write_bytes_per_second']==100
    assert status['unavailable_app_counters']==1
    assert status['estimated_write_bytes_per_day']==8640000
    assert 'wear is not measured' in status['measurement_note']
