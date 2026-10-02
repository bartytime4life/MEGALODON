#!/usr/bin/env python3
"""Identical synthetic recording replay with pattern reads off/on; no capture sockets."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import resource
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from megalodon.buffered_recording import BufferedRecording
from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc
from megalodon.intelligence import IntelligenceService
from megalodon.knowledge import KnowledgeLibrary
from megalodon.models import PacketEvent


def counters():
    return {k:int(v) for k,v in (line.split(':') for line in Path('/proc/self/io').read_text().splitlines())}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--enabled',action='store_true')
    parser.add_argument('--records',type=int,default=10000)
    args=parser.parse_args()
    if not 256<=args.records<=100000:parser.error('Use 256–100000 records')
    with tempfile.TemporaryDirectory(prefix='megalodon-intelligence-benchmark-') as directory:
        home=Path(directory);now=time.time();completed=int(now//3600)*3600
        settings=Settings(db_path=home/'old.db')
        evidence=EvidenceStorage(settings,home=home,clock=lambda:now)
        evidence.apply(evidence.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))['preview_id'])
        # Eight completed hours of identical sensor observations for both modes.
        for hour in range(8):
            start=completed-(8-hour)*3600
            for batch in range(4):
                evidence.append_records('flows',[dict(observed_at=utc(start+(batch*256+i)*3),source='synthetic-zeek',
                    data=dict(src_ip='192.0.2.10',dst_ip='198.51.100.10',protocol='TCP',dst_port=443,src_port=40000,
                              interface='fixture0',app_proto='tls')) for i in range(256)])
        knowledge=KnowledgeLibrary(home)
        intelligence=IntelligenceService(evidence,knowledge,SimpleNamespace(settings=settings)) if args.enabled else None
        errors=[];times=[];reads=[];stop=threading.Event()
        def query():
            while not stop.wait(.02):
                started=time.perf_counter()
                try:evidence.history(limit=10,category='packets');knowledge.search('network service')
                except Exception as exc:errors.append(type(exc).__name__)
                times.append(1000*(time.perf_counter()-started))
        def patterns():
            for hour in range(8):
                started=time.perf_counter()
                try:intelligence.process_hour(completed-(8-hour)*3600)
                except Exception as exc:errors.append(type(exc).__name__)
                reads.append(time.perf_counter()-started)
        writer=evidence.packet_writer();run=writer.start_ingestion_run('jsonl')
        recorder=BufferedRecording(settings,writer,run_id=run)
        reader=threading.Thread(target=query);analysis=threading.Thread(target=patterns) if intelligence else None
        before=counters();started=time.perf_counter();reader.start()
        if analysis:analysis.start()
        stamp=datetime.fromtimestamp(now-60,timezone.utc)
        try:
            for n in range(args.records):
                recorder.process(PacketEvent(stamp+timedelta(microseconds=n),'192.0.2.10','198.51.100.10','UDP',40000,443,byte_count=128))
            recorder.flush();writer.finish_ingestion_run(run,'source_exhausted');writer.close()
            recording_seconds=time.perf_counter()-started
            if analysis:analysis.join()
        finally:
            stop.set();reader.join()
        total_seconds=time.perf_counter()-started
        retained=evidence.history(category='packets')['total'];snapshot=recorder.snapshot()
        used=evidence.snapshot()['used_bytes'];reviews=len(intelligence.reviews) if intelligence else 0
        if intelligence:intelligence.close()
        knowledge.close();evidence.close();after=counters();times.sort()
        result=dict(enabled=args.enabled,records=args.records,retained=retained,recording_seconds=recording_seconds,
                    recording_per_second=args.records/recording_seconds,total_seconds=total_seconds,
                    pattern_hours=len(reads),pattern_seconds=sum(reads),reviews=reviews,query_count=len(times),
                    query_p95_ms=times[min(len(times)-1,int(len(times)*.95))] if times else None,
                    peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    os_write_bytes=after['write_bytes']-before['write_bytes'],write_syscalls=after['syscw']-before['syscw'],
                    managed_bytes=used,recording=snapshot,errors=errors,
                    benchmark_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    limits='Synthetic finite metadata replay; no network capture or inference. OS writes are not physical drive wear.')
        print(json.dumps(result,indent=2))
        if retained!=args.records or errors or snapshot['unconfirmed_records']:raise SystemExit(1)


if __name__=='__main__':main()
