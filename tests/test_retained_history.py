"""Cross-segment chart paging shares source selection with visual reports."""
import pytest
from megalodon.retained_history import RetainedEvidenceReader
from megalodon.evidence_storage import utc
from test_packet_compaction import manager, _source, _compact


def test_history_reaches_multiple_segments_without_recounting_compact_copy(manager):
    first=_source(manager,count=200)
    second=_source(manager,count=5,with_finding=False)
    _compact(manager)
    reader=RetainedEvidenceReader(manager)
    cursor=None;count=0;ids=[]
    for _ in range(20):
        page=reader.history_page(utc(manager.clock()-60),utc(manager.clock()+1),cursor)
        for row in page['records']:
            if row['data'].get('kind') in {'packet_v1','conversation_v1'}:
                count+=row['data']['packet_count'];ids.append(row['id'])
        cursor=page['next_cursor']
        if cursor is None:break
    assert count==205
    assert len(ids)==len(set(ids))


def test_history_expired_cursor_and_invalid_query_are_explicit(manager):
    reader=RetainedEvidenceReader(manager)
    page=reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'f'*32+':12')
    assert page['truncated'] and 'expired' in page['gaps'][0]
    with pytest.raises(ValueError):reader.history_page(utc(manager.clock()-60),utc(manager.clock()),'../store:0')


def test_reports_exclude_sample_ingestion(manager):
    from datetime import datetime,timezone
    from megalodon.models import PacketEvent
    from megalodon.reporting import ReportService
    writer=manager.packet_writer();run=writer.start_ingestion_run('sample')
    writer.record_event_bundle(PacketEvent(datetime.fromtimestamp(manager.clock(),timezone.utc),'192.0.2.1','198.51.100.1','TCP',1,443),[],[],run_id=run)
    writer.finish_ingestion_run(run,'source_exhausted');writer.close()
    value=ReportService(manager,clock=manager.clock)._aggregate('audit',manager.clock()-60,manager.clock()+1)
    assert value['summary']['packet_records']==0
