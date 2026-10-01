"""Preserved evidence and truthful reports after bounded packet compaction."""
from datetime import datetime, timezone
import json
import os

import pytest

pytestmark=pytest.mark.skipif(os.name!='posix',reason='Local Linux evidence storage')

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc
from megalodon.models import ActionRecord, DetectionResult, PacketEvent
from megalodon.reporting import ReportService


@pytest.fixture
def manager(tmp_path):
    tmp_path.chmod(0o700)
    stamp=[datetime.now(timezone.utc).timestamp()]
    manager=EvidenceStorage(Settings(db_path=tmp_path/'old.db'),home=tmp_path,
                            clock=lambda:stamp[0],monotonic=lambda:stamp[0],segment_bytes=512*1024**2)
    manager.test_clock=stamp
    preview=manager.preview(dict(profile='home',retention_days=14,cap_bytes=GIB))
    manager.apply(preview['preview_id'])
    yield manager
    manager.close()


def _source(manager, *, with_finding=True, count=200):
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    stamp=datetime.fromtimestamp(manager.clock(),timezone.utc)
    for index in range(count):
        event=PacketEvent(stamp,'10.0.0.2','1.1.1.1','TCP',50000,443,byte_count=100+index,
                          interface='eth0')
        findings=[DetectionResult(stamp,'TEST','HIGH',event.src_ip,event.dst_ip,'retained finding')] if with_finding and index==5 else []
        actions=[ActionRecord(stamp,'alert',event.src_ip,'not_attempted','synthetic')] if findings else []
        writer.record_event_bundle(event,findings,actions,run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    return next(e for e in manager._catalog['entries'] if e['category']=='packets')


def _compact(manager):
    for _ in range(100):
        if not manager.compact_step():break
        if all(e.get('compaction_state')=='complete' for e in manager._catalog['entries'] if e['category']=='packets'):
            return
    raise AssertionError('compact evidence did not finish')


def test_compaction_keeps_counts_findings_actions_and_replaces_raw_under_pressure(manager):
    source=_source(manager)
    _compact(manager)
    rollup=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
    assert rollup['state']=='closed' and rollup['source_segment']==source['id']
    assert manager._size(rollup)<manager._size(source)
    with manager._db(rollup) as db:
        rows=[json.loads(row[0]) for row in db.execute('SELECT data FROM records')]
    assert sum(r.get('packet_count',0) for r in rows)==200
    assert sum(r.get('byte_count',0) for r in rows)==sum(100+i for i in range(200))
    assert len([r for r in rows if r['kind']=='finding_v1'])==1
    assert len([r for r in rows if r['kind']=='action_v1'])==1
    assert len([r for r in rows if r['kind']=='run_v1'])==1
    service=ReportService(manager,clock=manager.clock)
    before_rotation=service._aggregate('before',manager.clock()-60,manager.clock()+1)
    assert before_rotation['summary']['packet_records']==200, 'raw and compact copies must not double-count'
    before=manager._size(source)
    manager._ensure_space(GIB-before//2)
    assert source not in manager._catalog['entries']
    assert manager._path(rollup).exists()
    report=service._aggregate('test',manager.clock()-60,manager.clock()+1)
    assert report['summary']['packet_records']==200
    assert report['summary']['packet_bytes']==sum(100+i for i in range(200))
    assert report['summary']['finding_count']==1
    assert report['summary']['response_count']==1
    assert report['coverage']['compacted_packet_records']==200


def test_high_cardinality_source_keeps_original_when_summary_is_not_smaller(manager):
    writer=manager.packet_writer();run=writer.start_ingestion_run('jsonl')
    stamp=datetime.fromtimestamp(manager.clock(),timezone.utc)
    for index in range(50):
        event=PacketEvent(stamp,'10.0.0.2','198.51.100.'+str(index+1),'TCP',50000+index,443,byte_count=80)
        writer.record_event_bundle(event,[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    source=next(e for e in manager._catalog['entries'] if e['category']=='packets')
    for _ in range(10):
        manager.compact_step()
        if source.get('compaction_state')=='inefficient':break
    assert source['state']=='closed' and source.get('compaction_state')=='inefficient'
    assert manager._path(source).exists()
    assert not any(e['category']=='packet_rollups' for e in manager._catalog['entries'])


def test_existing_packet_history_compacts_after_switch_to_server_recording(manager):
    source=_source(manager,with_finding=False)
    preview=manager.preview(dict(profile='server',retention_days=7,cap_bytes=GIB))
    manager.apply(preview['preview_id'])
    _compact(manager)
    assert source['compaction_state']=='complete'


def test_interrupted_target_needing_review_does_not_spawn_another_copy(manager):
    source=_source(manager,with_finding=False)
    assert manager.compact_step()
    target=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
    target['state']='needs_review'
    with pytest.raises(ValueError,match='needs review'):
        manager.compact_step()
    assert source['state']=='closed'
    assert sum(e['category']=='packet_rollups' for e in manager._catalog['entries'])==1


def test_damaged_summary_cannot_authorize_original_deletion(manager):
    source=_source(manager)
    _compact(manager)
    target=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
    with manager._db(target,write=True) as db:
        db.execute("DELETE FROM checkpoints WHERE key='packet_compaction'")
        db.commit()
    with pytest.raises(ValueError,match='Compact history'):
        manager._ensure_space(GIB-manager._size(source)//2)
    assert manager._path(source).exists()


def test_missing_compact_conversation_cannot_authorize_original_deletion(manager):
    source=_source(manager)
    _compact(manager)
    target=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
    with manager._db(target,write=True) as db:
        db.execute("DELETE FROM records WHERE id=(SELECT MIN(id) FROM records WHERE source='packet-conversation-summary')")
        db.commit()
    with pytest.raises(ValueError,match='Compact history totals changed'):
        manager._ensure_space(GIB-manager._size(source)//2)
    assert manager._path(source).exists()


def test_interrupted_build_resumes_without_duplicate_conversations(manager):
    source=_source(manager,with_finding=False,count=1030)
    assert manager.compact_step()
    target=next(e for e in manager._catalog['entries'] if e['category']=='packet_rollups')
    with manager._db(target) as db:
        assert json.loads(db.execute("SELECT value FROM checkpoints WHERE key='packet_compaction'").fetchone()[0])['processed_count']==1024
    manager.close()
    again=EvidenceStorage(manager.settings,home=manager.home,clock=manager.clock,monotonic=manager.monotonic)
    try:
        _compact(again)
        rollup=next(e for e in again._catalog['entries'] if e['category']=='packet_rollups')
        with again._db(rollup) as db:
            assert sum(json.loads(r[0]).get('packet_count',0) for r in db.execute('SELECT data FROM records'))==1030
    finally:again.close()
