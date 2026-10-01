"""Finite local write-efficiency comparison; creates no capture sockets."""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import statistics
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def load_baseline(directory):
    for name in ('storage','evidence_storage'):
        spec=importlib.util.spec_from_file_location('megalodon.'+name,Path(directory)/(name+'.py'))
        module=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=module
        spec.loader.exec_module(module)


def io_bytes():
    return {key:int(value) for key,value in (line.split(':') for line in Path('/proc/self/io').read_text().splitlines())}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--baseline-dir')
    parser.add_argument('--records',type=int,default=10000)
    parser.add_argument('--kind',choices=['packets','summaries'],default='packets')
    args=parser.parse_args()
    if not 1<=args.records<=100000:parser.error('Use 1–100000 records.')
    if args.baseline_dir:load_baseline(args.baseline_dir)
    from megalodon.config import Settings
    from megalodon.evidence_storage import EvidenceStorage, GIB, utc
    from megalodon.models import PacketEvent
    from megalodon.service import MegalodonService
    if not args.baseline_dir:from megalodon.buffered_recording import BufferedRecording
    queries=[];errors=[];stop=threading.Event()
    with tempfile.TemporaryDirectory(prefix='megalodon-write-benchmark-') as folder:
        home=Path(folder)
        settings=Settings(db_path=home/'old.db')
        manager=EvidenceStorage(settings,home=home)
        manager.apply(manager.preview(dict(profile='home',retention_days=14,cap_bytes=GIB))['preview_id'])
        writer=manager.packet_writer() if args.kind=='packets' else None
        run=writer.start_ingestion_run('jsonl') if writer else None
        service=(MegalodonService(settings,writer) if args.baseline_dir else
                 BufferedRecording(settings,writer,run_id=run)) if writer else None
        def read():
            while not stop.wait(.02):
                start=time.perf_counter()
                try:manager.history(limit=10,category='packets' if writer else 'flows')
                except Exception as exc:errors.append(type(exc).__name__)
                queries.append((time.perf_counter()-start)*1000)
        reader=threading.Thread(target=read);reader.start()
        before=io_bytes();start=time.perf_counter();stamp=datetime.now(timezone.utc)
        for n in range(args.records):
            if writer:
                event=PacketEvent(stamp+timedelta(microseconds=n),'10.0.0.2','1.1.1.1','UDP',50000,443,byte_count=128)
                service.process(event,run_id=run)
            elif n%256==0:
                rows=[dict(observed_at=utc(),source='synthetic',data=dict(flow_id=k,bytes=128))
                      for k in range(n,min(n+256,args.records))]
                manager.append_records('flows',rows,checkpoint=('benchmark',{'offset':min(n+256,args.records)}))
        if writer:
            if not args.baseline_dir:service.flush()
            writer.finish_ingestion_run(run,'source_exhausted');writer.close()
        else:
            for entry in list(manager._generic.values()):manager._seal(entry)
            manager._generic.clear()
        duration=time.perf_counter()-start
        stop.set();reader.join()
        total=manager.history(category='packets' if writer else 'flows')['total']
        disk=manager.snapshot()['used_bytes']
        manager.close()
        after=io_bytes()
        values=sorted(queries)
        measured=Path(args.baseline_dir) if args.baseline_dir else ROOT/'megalodon'
        result=dict(mode='before' if args.baseline_dir else 'balanced',kind=args.kind,
                    records=args.records,retained=total,seconds=duration,records_per_second=args.records/duration,
                    os_write_bytes=after['write_bytes']-before['write_bytes'],
                    write_syscalls=after['syscw']-before['syscw'],managed_bytes=disk,
                    query_count=len(queries),query_errors=errors,
                    query_p95_ms=values[min(len(values)-1,int(len(values)*.95))] if values else None,
                    max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    implementation_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                                           for p in (measured/'storage.py',measured/'evidence_storage.py')},
                    limits='Finite synthetic local recording; OS writes are not flash-cell writes or lifetime estimates.')
        print(json.dumps(result,indent=2))
        if total!=args.records or errors:raise SystemExit(1)


if __name__=='__main__':main()
