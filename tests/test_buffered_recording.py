from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import sqlite3
import subprocess
import sys

import pytest

from megalodon.buffered_recording import BufferedRecording
from megalodon.config import Settings, DetectionSettings
from megalodon.models import PacketEvent
from megalodon.storage import Store, IngestionRunError


def event(n=0, **values):
    return PacketEvent(datetime.now(timezone.utc)+timedelta(microseconds=n),
                       '10.0.0.2', '1.1.1.1', values.pop('protocol','TCP'), **values)


@pytest.fixture
def recorder(tmp_path):
    settings=Settings(db_path=tmp_path/'recording.db',detection=DetectionSettings(dns_query_length=10))
    with Store(settings.db_path) as store:
        run=store.start_ingestion_run('jsonl')
        clock=[0.0]
        recorder=BufferedRecording(settings,store,run_id=run,monotonic=lambda:clock[0])
        recorder.clock=clock
        yield recorder


def test_batch_is_invisible_until_two_second_durable_commit(recorder):
    recorder.process(event())
    assert recorder.store.summary()['events']==0
    assert recorder.snapshot()['pending_records']==1
    assert recorder.service.detector.source_high_watermarks=={}
    recorder.clock[0]=1.99;recorder.flush_due()
    assert recorder.store.summary()['events']==0
    recorder.clock[0]=2;recorder.flush_due()
    assert recorder.store.summary()['events']==1
    assert recorder.snapshot()['saved_records']==1
    assert recorder.service.detector.source_high_watermarks
    assert recorder.store.connection.execute('PRAGMA synchronous').fetchone()[0]==2


def test_finding_flushes_prior_traffic_and_linked_receipts_immediately(recorder):
    recorder.process(event())
    results=recorder.process(event(protocol='DNS',dns_query_length=12,dst_port=53))
    assert results
    assert recorder.store.summary()['events']==2
    assert recorder.store.summary()['detections']==1
    assert recorder.store.summary()['actions']==1
    assert recorder.snapshot()['pending_records']==0
    assert recorder.store.connection.execute('PRAGMA foreign_key_check').fetchall()==[]


def test_256_events_are_one_commit(recorder):
    with patch.object(recorder.store,'_connection_commit',wraps=recorder.store._connection_commit) as commit:
        for n in range(256):recorder.process(event(n))
        assert commit.call_count==1
    assert recorder.store.summary()['events']==256


def test_failed_write_preserves_committed_detector_and_no_partial_rows(recorder):
    recorder.process(event())
    original=recorder.store._insert_event
    count=[0]
    def fail_second(values):
        count[0]+=1
        if count[0]==2:raise OSError('disk failed')
        return original(values)
    recorder.process(event())
    with patch.object(recorder.store,'_insert_event',side_effect=fail_second):
        with pytest.raises(OSError):recorder.flush()
    assert recorder.service.detector.source_high_watermarks=={}
    assert recorder.store.summary()['events']==0
    assert recorder.snapshot()['write_failures']==1
    assert recorder.snapshot()['unconfirmed_records']==2


def test_invalid_batch_is_atomic(recorder):
    with pytest.raises(Exception):
        recorder.store.record_event_bundles([(event(),[],[]),(event(),['invalid'],[])],run_id=recorder.run_id)
    assert recorder.store.summary()['events']==0


def test_size_flush_and_explicit_shutdown_flush(recorder):
    recorder.MAX_BYTES=500
    for n in range(8):recorder.process(event(n))
    assert recorder.commits>0
    recorder.flush()
    assert recorder.store.summary()['events']==8
    assert recorder.snapshot()['pending_bytes']==0


def test_failed_commit_rolls_back_evidence_and_detector(recorder):
    recorder.process(event())
    with patch.object(recorder.store,'_connection_commit',side_effect=sqlite3.OperationalError('database or disk is full')):
        with pytest.raises(IngestionRunError,match='RECONCILIATION_REQUIRED'):recorder.flush()
    assert recorder.store.summary()['events']==0
    assert recorder.service.detector.source_high_watermarks=={}
    assert recorder.snapshot()['unconfirmed_records']==1


def test_sudden_exit_keeps_committed_batch_and_loses_only_pending(tmp_path):
    path=tmp_path/'abrupt.db'
    program='''
import os,sys
from datetime import datetime,timezone
from pathlib import Path
from megalodon.config import Settings
from megalodon.storage import Store
from megalodon.buffered_recording import BufferedRecording
from megalodon.models import PacketEvent
settings=Settings(db_path=Path(sys.argv[1]))
store=Store(settings.db_path)
recorder=BufferedRecording(settings,store,run_id=store.start_ingestion_run('jsonl'))
event=PacketEvent(datetime.now(timezone.utc),'10.0.0.2','1.1.1.1','UDP')
recorder.process(event);recorder.process(event);recorder.flush()
recorder.process(event)
os._exit(0)
'''
    subprocess.run([sys.executable,'-c',program,str(path)],check=True,timeout=10)
    with sqlite3.connect(path) as connection:
        assert connection.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]==2
        assert connection.execute('PRAGMA foreign_key_check').fetchall()==[]
