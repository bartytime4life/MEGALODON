#!/usr/bin/env python3
"""Reproducible LOCAL FILE benchmark; never opens a network or capture socket.

Examples (run with the repository virtual environment):
  python tools/benchmark_flow_ingestion.py --connections 10000 100000 --output /tmp/megalodon-flow-benchmark.json
  python tools/benchmark_flow_ingestion.py --connections 10000 --source zeek
  python tools/benchmark_flow_ingestion.py --connections 100000 --mode sustained --arrival-rate 3000

Each case runs in a fresh process and owner-private temporary home. Synthetic
connection intervals overlap; the benchmark measures admitted summaries and
bounded queries, not simultaneous sockets or physical packet capacity.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
from threading import Event, Thread
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage,GIB,utc
from megalodon.flow_ingestion import FlowIngestor
from megalodon.live_connections import LiveConnections


class NoGeography:
    """No lookups: synthetic addresses intentionally carry no world location."""
    def snapshot(self):return {'anchor':None}
    def lookup(self,address):return None


def rss_bytes():
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith('VmRSS:'):return int(line.split()[1])*1024
    return None


def latency(values):
    ordered=sorted(values)
    if not ordered:return dict(samples=0,p50_ms=None,p95_ms=None,max_ms=None)
    return dict(samples=len(ordered),p50_ms=round(statistics.median(ordered),3),
                p95_ms=round(ordered[max(0,math.ceil(len(ordered)*.95)-1)],3),max_ms=round(ordered[-1],3))


def synthetic(index,source,stamp,first_seen=None):
    # RFC 2544 benchmarking space and RFC 1918 local address. No network calls.
    peer=f'198.{18+(index//65536)%2}.{(index//256)%256}.{index%256}'
    sport=10000+index%50000
    first_seen=stamp-30 if first_seen is None else first_seen
    if source=='suricata':
        return dict(timestamp=utc(stamp),event_type='flow',flow_id=index+1,src_ip='10.255.0.1',dest_ip=peer,
                    src_port=sport,dest_port=443,proto='TCP',flow=dict(start=utc(first_seen),end=utc(stamp),state='established',
                        bytes_toserver=1024+index%1024,bytes_toclient=4096+index%4096,pkts_toserver=12,pkts_toclient=32))
    return {'ts':first_seen,'duration':stamp-first_seen,'uid':f'C{index:015d}','id.orig_h':'10.255.0.1','id.resp_h':peer,
            'id.orig_p':sport,'id.resp_p':443,'proto':'tcp','orig_ip_bytes':1024+index%1024,'resp_ip_bytes':4096+index%4096,
            'orig_pkts':12,'resp_pkts':32,'conn_state':'SF'}


def worker(connections,source,query_interval,segment_mib,mode='burst',arrival_rate=3000):
    code_digest={name:hashlib.sha256((ROOT/'megalodon'/name).read_bytes()).hexdigest() for name in ('flow_ingestion.py','live_connections.py','evidence_storage.py')}
    with tempfile.TemporaryDirectory(prefix='megalodon-flow-benchmark-') as temporary:
        home=Path(temporary);home.chmod(0o700)
        evidence=EvidenceStorage(Settings(db_path=home/'legacy.db'),home=home,segment_bytes=segment_mib*1024**2)
        cache=LiveConnections(NoGeography());cache._local={'10.255.0.1'}
        stop=Event();producer_done=Event();samples=[];errors=[];producer_errors=[];peak_rss=[rss_bytes() or 0];callbacks=[0]
        produced=[1];producer_finished=[None];arrival_lateness=[];polls=[0]
        def admitted(record):callbacks[0]+=1;cache.observe_summary(record)
        input_path=home/'synthetic-input.jsonl'
        collector=FlowIngestor(evidence,home=home,eve_path=input_path if source=='suricata' else home/'absent-eve.json',on_flow=admitted)
        collector.paths[source]=input_path
        original_poll=collector.poll
        def counted_poll(*args,**kwargs):
            result=original_poll(*args,**kwargs);polls[0]+=1;return result
        collector.poll=counted_poll
        reader=producer=None
        try:
            evidence.apply(evidence.preview(dict(profile='server',retention_days=7,cap_bytes=GIB))['preview_id'])
            stamp=time.time()-1;first_seen=stamp-30
            def write_rows(start,end,file_mode,observed_at=stamp):
                with input_path.open(file_mode) as stream:
                    for index in range(start,end):stream.write(json.dumps(synthetic(index,source,observed_at,first_seen),separators=(',',':'))+'\n')
                input_path.chmod(0o600)
            # Prime admission on one real line before appending the large backlog.
            # Fresh attachment to an old large input intentionally imports only a
            # bounded tail and reports an admission gap; that is a separate test.
            write_rows(0,1,'w');assert collector.poll(source)==1
            polls[0]=0
            if mode=='burst':write_rows(1,connections,'a');produced[0]=connections
            baseline_rss=rss_bytes();peak_backlog_bytes=0;peak_backlog_records=0
            peak_backlog_at_seconds=0;backlog_samples=0
            def query_during_ingest():
                while not stop.is_set():
                    started=time.perf_counter()
                    try:
                        page=evidence.history(limit=50,category='flows')
                        if page['gaps']:errors.extend(page['gaps'])
                    except Exception as exc:errors.append(type(exc).__name__)
                    samples.append((time.perf_counter()-started)*1000)
                    peak_rss[0]=max(peak_rss[0],rss_bytes() or 0)
                    stop.wait(query_interval)
            reader=Thread(target=query_during_ingest,name='synthetic-evidence-query',daemon=True);reader.start()
            start_cpu=time.process_time();start=time.perf_counter()
            arrival_batch=max(1,round(arrival_rate*.02))
            def append_paced():
                try:
                    for index in range(1,connections,arrival_batch):
                        end=min(connections,index+arrival_batch)
                        due=start+(end-1)/arrival_rate
                        if stop.wait(max(0,due-time.perf_counter())):return
                        write_rows(index,end,'a',time.time()-1)
                        produced[0]=end
                        arrival_lateness.append(max(0,time.perf_counter()-due)*1000)
                except Exception as exc:producer_errors.append(type(exc).__name__+': '+str(exc))
                finally:producer_finished[0]=time.perf_counter();producer_done.set()
            if mode=='sustained':
                producer=Thread(target=append_paced,name='synthetic-source-arrivals',daemon=True);producer.start();collector.start()
            else:producer_finished[0]=start;producer_done.set()
            deadline=start+600
            while True:
                source_bytes=input_path.stat().st_size
                # This immutable checkpoint reference is replaced only after a
                # committed batch. Reading it avoids an extra catalog DB query.
                checkpoint=collector._positions.get(source)
                backlog=max(0,source_bytes-(checkpoint or {}).get('offset',0))
                backlog_samples+=1
                if backlog>peak_backlog_bytes:peak_backlog_bytes=backlog;peak_backlog_at_seconds=time.perf_counter()-start
                peak_backlog_records=max(peak_backlog_records,max(0,produced[0]-callbacks[0]))
                if producer_errors:raise RuntimeError('Synthetic source writer failed: '+repr(producer_errors))
                if producer_done.is_set() and checkpoint and checkpoint['offset']>=source_bytes:break
                if time.perf_counter()>deadline:raise RuntimeError('Synthetic ingestion exceeded ten minutes')
                if mode=='burst':collector.poll(source)
                else:stop.wait(.02)
            elapsed=time.perf_counter()-start;cpu=time.process_time()-start_cpu
            stop.set();reader.join(5)
            if producer:producer.join(5)
            collector.close()
            status=collector.snapshot();storage=evidence.snapshot()
            after=[]
            for _ in range(25):
                then=time.perf_counter();page=evidence.history(limit=50,category='flows');after.append((time.perf_counter()-then)*1000)
                if page['gaps']:errors.extend(page['gaps'])
            # Verify every persisted source identity with read-only managed DB
            # handles after timing, without copying 100k rows into a Python list.
            sources=Counter();persisted=0;unique_ids=0;identity_index=0;identity_mismatches=0;sqlite_settings=None
            for entry in evidence._catalog['entries']:
                if entry['category']!='flows':continue
                with evidence._db(entry) as db:
                    persisted+=db.execute('SELECT COUNT(*) FROM records').fetchone()[0]
                    unique_ids+=db.execute("SELECT COUNT(DISTINCT json_extract(data,'$.source_id')) FROM records").fetchone()[0]
                    sources.update({row[0]:row[1] for row in db.execute('SELECT source,COUNT(*) FROM records GROUP BY source')})
                    for row in db.execute("SELECT json_extract(data,'$.source_id') FROM records ORDER BY id"):
                        expected=str(identity_index+1) if source=='suricata' else f'C{identity_index:015d}'
                        identity_mismatches+=int(row[0]!=expected);identity_index+=1
                    if sqlite_settings is None:sqlite_settings=dict(journal_mode=db.execute('PRAGMA journal_mode').fetchone()[0],synchronous=db.execute('PRAGMA synchronous').fetchone()[0])
            projection=cache.snapshot(dict(state='running'),dict(enabled=True))
            files=[path for path in evidence.root.rglob('*') if path.is_file()]
            result=dict(code_sha256=code_digest,concurrent_connection_identities=connections,input_summary_records=connections,source=source,mode=mode,
                measured_records=connections-1,priming_records=1,ingest_wall_seconds=round(elapsed,6),ingest_cpu_seconds=round(cpu,6),
                summary_records_per_second=round((connections-1)/elapsed,2),source_input_bytes=source_bytes,
                source_megabytes_per_second=round(source_bytes/elapsed/1024**2,3),polls=polls[0],
                importer_schedule='production worker: 100 ms backlog / 1 s idle' if mode=='sustained' else 'direct poll: drain pre-existing backlog without worker sleeps',
                arrival=dict(target_records_per_second=arrival_rate if mode=='sustained' else None,records_produced=produced[0],
                    batch_records=arrival_batch if mode=='sustained' else connections-1,
                    wall_seconds=round(producer_finished[0]-start,6),
                    actual_records_per_second=round((connections-1)/(producer_finished[0]-start),2) if mode=='sustained' else None,
                    batch_lateness=latency(arrival_lateness),errors=producer_errors),
                backlog=dict(sample_interval_seconds=.02 if mode=='sustained' else None,samples=backlog_samples,
                    sampled_peak_bytes=peak_backlog_bytes,sampled_peak_records=peak_backlog_records,
                    peak_at_seconds=round(peak_backlog_at_seconds,3),final_bytes=status['backlog_bytes'],
                    final_records=produced[0]-callbacks[0],drain_after_arrival_seconds=round(max(0,start+elapsed-producer_finished[0]),6)),
                concurrent_query_latency=latency(samples),post_ingest_query_latency=latency(after),query_errors=errors[:20],
                rss_baseline_bytes=baseline_rss,rss_sampled_peak_bytes=max(peak_rss[0],rss_bytes() or 0),
                process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                managed_disk_logical_bytes=sum(p.stat().st_size for p in files),managed_disk_allocated_bytes=sum(p.stat().st_blocks*512 for p in files),
                storage_reported_bytes=storage['used_bytes'],input_file_bytes_excluded_from_managed_storage=source_bytes,
                segment_count=len(evidence._catalog['entries']),segment_target_bytes=segment_mib*1024**2,sqlite=sqlite_settings,
                persisted_records=persisted,unique_source_ids_within_segments=unique_ids,source_identity_sequence_mismatches=identity_mismatches,provenance=dict(sources),
                collector=status,live_callback_records=callbacks[0],storage_evicted_records=storage['evicted_records'],
                live_projection=dict(returned=projection['totals']['returned'],evicted=projection['totals']['evicted'],
                    truncated=projection['totals']['truncated'],max_returned=projection['limits']['max_connections'],
                    max_tracked=projection['limits']['tracked_connections']),
                correctness=dict(all_records_persisted=persisted==connections,all_source_identities_persisted=identity_index==connections and identity_mismatches==0,
                    no_record_rejections=status['rejected']==0,no_input_admission_gaps=status['gaps']==0,no_query_errors=not errors,
                    all_callbacks=callbacks[0]==connections,no_producer_errors=not producer_errors,source_completed=produced[0]==connections,
                    no_final_backlog=status['backlog_bytes']==0,no_storage_evictions=storage['evicted_records']==0),
                temporary_files_removed=True)
            if not all(result['correctness'].values()):raise RuntimeError('Synthetic ingestion lost source admission: '+json.dumps(result))
            return result
        finally:
            stop.set()
            if reader:reader.join(5)
            if producer:producer.join(5)
            collector.close();evidence.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--connections',type=int,nargs='+',default=[10000,100000])
    parser.add_argument('--source',choices=['suricata','zeek'],default='suricata')
    parser.add_argument('--mode',choices=['burst','sustained'],default='burst')
    parser.add_argument('--arrival-rate',type=int,default=3000,help='Synthetic sustained source records/second (default: 3000).')
    parser.add_argument('--query-interval',type=float,default=.02)
    parser.add_argument('--segment-mib',type=int,default=16)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if any(count<2 or count>100000 for count in args.connections) or not .005<=args.query_interval<=1 or not 1<=args.segment_mib<=512:parser.error('Use 2–100000 identities, query intervals .005–1 seconds, and 1–512 MiB segments.')
    if not 500<=args.arrival_rate<=20000:parser.error('Use a sustained arrival rate of 500–20000 records/second.')
    if args.worker:
        if len(args.connections)!=1:parser.error('A worker runs one case.')
        print(json.dumps(worker(args.connections[0],args.source,args.query_interval,args.segment_mib,args.mode,args.arrival_rate),sort_keys=True));return
    results=[]
    for count in args.connections:
        command=[sys.executable,str(Path(__file__).resolve()),'--worker','--connections',str(count),'--source',args.source,'--mode',args.mode,
                 '--arrival-rate',str(args.arrival_rate),'--query-interval',str(args.query_interval),'--segment-mib',str(args.segment_mib)]
        completed=subprocess.run(command,check=True,text=True,capture_output=True,timeout=660)
        result=json.loads(completed.stdout);results.append(result)
        print(f'{count:,} synthetic {args.source} {args.mode} summaries: {result["summary_records_per_second"]:,.0f}/s; concurrent history p95 {result["concurrent_query_latency"]["p95_ms"]} ms; {result["persisted_records"]:,} persisted.',file=sys.stderr,flush=True)
    report=dict(schema='megalodon-synthetic-flow-benchmark-v2',measured_at=utc(),python=platform.python_version(),platform=platform.system(),machine=platform.machine(),
                benchmark_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                code_sha256={name:hashlib.sha256((ROOT/'megalodon'/name).read_bytes()).hexdigest() for name in ('flow_ingestion.py','live_connections.py','evidence_storage.py')},
                workload='Unique synthetic connection summaries with overlapping observation intervals, local JSONL source, one writer plus concurrent bounded 50-row history reader.',
                limitations=['Local-file summary admission throughput; not packet capture throughput, simultaneous operating-system sockets, or network-wire capacity.',
                    'One priming record is outside the measured interval. Burst mode prewrites the backlog; sustained mode appends paced batches while the production importer worker runs.',
                    'Sustained arrival throughput includes source generation, configured production polling delays and final backlog drain; finite duration does not establish a 24/7 capacity guarantee.',
                    'Backlog peaks are sampled at 20 ms in sustained mode and before each direct burst poll; a transient peak between samples can be missed.',
                    'Live visuals deliberately retain a bounded subset; live projection evictions are reported separately from persisted evidence loss.',
                    'No external network traffic or geolocation lookup is generated. Inputs and managed stores are private temporary files removed after each case.',
                    'Measured on the current workstation with concurrent background activity; results are not a sustained server capacity guarantee.'],results=results)
    encoded=json.dumps(report,indent=2,sort_keys=True)+'\n'
    if args.output:
        args.output.write_text(encoded);args.output.chmod(0o600)
    print(encoded,end='')

if __name__=='__main__':main()
