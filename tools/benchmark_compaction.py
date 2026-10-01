"""Finite synthetic compact-history measurement; never reads host evidence."""
import argparse
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import resource
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage,GIB
from megalodon.buffered_recording import BufferedRecording
from megalodon.models import PacketEvent
from megalodon.reporting import ReportService


def main():
    p=argparse.ArgumentParser();p.add_argument('--records',type=int,default=50000);a=p.parse_args()
    if not 256<=a.records<=100000:p.error('Use 256–100000 synthetic records')
    with tempfile.TemporaryDirectory(prefix='megalodon-compact-benchmark-') as folder:
        home=Path(folder);settings=Settings(db_path=home/'old.db');store=EvidenceStorage(settings,home=home)
        store.apply(store.preview(dict(profile='home',retention_days=14,cap_bytes=GIB))['preview_id'])
        writer=store.packet_writer();run=writer.start_ingestion_run('jsonl');recording=BufferedRecording(settings,writer,run_id=run)
        stamp=datetime.now(timezone.utc)-timedelta(minutes=1)
        for n in range(a.records):recording.process(PacketEvent(stamp+timedelta(microseconds=n),'10.0.0.2','198.51.100.'+str(1+n%16),'UDP',50000,443,byte_count=128,interface='synthetic0'))
        recording.flush();writer.finish_ingestion_run(run,'source_exhausted');writer.close()
        original=next(e for e in store._catalog['entries'] if e['category']=='packets')
        before=store._used();peak=before;steps=0;begin=time.perf_counter()
        while store.compact_step():
            steps+=1;peak=max(peak,store._used())
            if steps>1000:raise RuntimeError('Compaction work bound exceeded')
        elapsed=time.perf_counter()-begin;raw=store._size(original)
        compact=next(e for e in store._catalog['entries'] if e['category']=='packet_rollups')
        compact_bytes=store._size(compact)
        report=ReportService(store)._aggregate('synthetic',stamp.timestamp()-1,time.time()+1)
        assert report['summary']['packet_records']==a.records
        # Synthetic capacity pressure only. Original is verified before eviction.
        store._ensure_space(GIB-raw//2)
        after=store.snapshot();assert original not in store._catalog['entries']
        result=dict(schema='megalodon-compaction-benchmark-v1',records=a.records,seconds=elapsed,records_per_second=a.records/elapsed,
                    batches=steps,source_bytes=raw,compact_bytes=compact_bytes,peak_extra_bytes=peak-before,
                    reclaimed_detail_bytes=after['compaction']['reclaimed_detail_bytes'],peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    verified_represented_records=report['summary']['packet_records'],backlog_sources_after=after['compaction']['building_sources'],
                    limits='Synthetic sixteen-peer UDP metadata; throughput excludes ingestion; no physical drive wear or live sensor capacity claim.')
        store.close()
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
