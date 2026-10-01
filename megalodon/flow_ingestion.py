"""Bounded, checkpointed local flow/alert imports; never packet payloads.

One primary flow source is selected for a collection session. Suricata alerts
remain their own evidence class, not inferred MEGALODON detector findings.
"""
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import hashlib
import math
import re
import os
from pathlib import Path
import stat
import sqlite3
from threading import Event, Lock, RLock, Thread
import time

from .evidence_storage import utc, epoch

MAX_LINE=65536
READ_BYTES=256*1024
MAX_ALERT_METADATA=8*1024
RAW_CONTENT_FIELDS=frozenset({'payload','payload_printable','packet','packet_base64','raw_packet','raw_payload','http_body','file_data'})


def count(value):
    if type(value) is not int or not 0<=value<=2**53-1:raise ValueError('Invalid flow counter.')
    return value


def flow_identity(value):
    if type(value) is not int or not 0<=value<2**64:raise ValueError('Invalid flow identity.')
    return str(value)


def address(value):
    if type(value) is not str:raise ValueError('Invalid flow address.')
    return str(ip_address(value))


def port(value):
    if value is None:return None
    result=count(value)
    if result>65535:raise ValueError('Invalid transport port.')
    return result


def metadata_label(value,limit=64):
    if type(value) is not str or not 1<=len(value)<=limit or not value.isprintable():raise ValueError('Invalid sensor metadata label.')
    return value


def alert_metadata(value):
    """Retain the bounded structured alert object, never encoded raw content."""
    def validate(item,depth=0):
        if depth>16:raise ValueError('Sensor alert metadata is too deeply nested.')
        if type(item) is dict:
            for key,child in item.items():
                if type(key) is not str or key.casefold() in RAW_CONTENT_FIELDS:raise ValueError('Raw content is outside the finding metadata contract.')
                validate(child,depth+1)
        elif type(item) is list:
            for child in item:validate(child,depth+1)
        elif item is not None and type(item) not in (str,int,float,bool):raise ValueError('Invalid sensor alert metadata value.')
        elif type(item) is float and not math.isfinite(item):raise ValueError('Invalid sensor alert metadata number.')
    validate(value)
    encoded=json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8')
    if len(encoded)>MAX_ALERT_METADATA:raise ValueError('Sensor alert metadata exceeds 8 KiB.')
    return json.loads(encoded)


def alert_flow_context(value):
    if type(value) is not dict:raise ValueError('Invalid sensor alert flow context.')
    result={}
    for original,normalized in (('bytes_toserver','sent_bytes'),('bytes_toclient','received_bytes'),
                                ('pkts_toserver','sent_packets'),('pkts_toclient','received_packets')):
        if original in value:result[normalized]=count(value[original])
    for original,normalized in (('start','first_seen'),('end','last_seen')):
        if original in value:result[normalized]=utc(epoch(value[original]))
    if 'first_seen' in result and 'last_seen' in result and epoch(result['first_seen'])>epoch(result['last_seen']):raise ValueError('Invalid alert flow interval.')
    for key in ('state','reason'):
        if key in value:result[key]=metadata_label(value[key])
    if 'sent_bytes' in result or 'received_bytes' in result:result['byte_basis']='ip_bytes'
    return result


def normalize_suricata(value):
    if type(value) is not dict:raise ValueError('Expected a sensor object.')
    kind=value.get('event_type')
    if kind not in {'flow','alert'}:return None
    stamp=utc(epoch(value['timestamp']))
    if type(value.get('proto','OTHER')) is not str:raise ValueError('Invalid protocol label.')
    proto=value.get('proto','OTHER').upper()
    if proto not in {'TCP','UDP','ICMP','ICMPV6','SCTP'}:proto='OTHER'
    data=dict(src_ip=address(value['src_ip']),dst_ip=address(value['dest_ip']),src_port=port(value.get('src_port')),
              dst_port=port(value.get('dest_port')),protocol=proto,source_id=flow_identity(value['flow_id']))
    if kind=='flow':
        flow=value['flow']
        if type(flow) is not dict:raise ValueError('Invalid flow summary.')
        data.update(sent_bytes=count(flow['bytes_toserver']),received_bytes=count(flow['bytes_toclient']),
                    sent_packets=count(flow['pkts_toserver']),received_packets=count(flow['pkts_toclient']),
                    first_seen=utc(epoch(flow['start'])),last_seen=utc(epoch(flow['end'])),
                    observation='completed or periodic flow summary',byte_basis='ip_bytes',
                    completed=flow.get('state') not in {'established','new'} or flow.get('reason') in {'timeout','shutdown','forced'})
        if epoch(data['first_seen'])>epoch(data['last_seen']):raise ValueError('Invalid flow interval.')
    else:
        alert=value['alert']
        if type(alert) is not dict:raise ValueError('Invalid sensor alert.')
        title=alert.get('signature')
        if type(title) is not str or not 1<=len(title)<=256 or not title.isprintable():raise ValueError('Invalid sensor signature.')
        severity=count(alert['severity'])
        if not 1<=severity<=4:raise ValueError('Invalid sensor severity.')
        data.update(signature=title,signature_id=count(alert['signature_id']),severity=severity,
                    alert_metadata=alert_metadata(alert),
                    observation='Suricata sensor finding; structured metadata only; not an admitted core detector finding')
        if 'app_proto' in value:data['app_proto']=metadata_label(value['app_proto'])
        if 'flow' in value:data['flow_context']=alert_flow_context(value['flow'])
    return ('flows' if kind=='flow' else 'findings',dict(observed_at=stamp,source='suricata-eve',data=data))


def normalize_zeek(value):
    if type(value) is not dict:return None
    uid=value.get('uid')
    if type(uid) is not str or not 1<=len(uid)<=64 or not uid.isalnum():raise ValueError('Invalid Zeek identity.')
    start=value['ts'];duration=value.get('duration',0)
    if type(start) not in (int,float) or type(duration) not in (int,float) or not 0<=duration<=30*86400:raise ValueError('Invalid Zeek time.')
    if type(value.get('proto','other')) is not str:raise ValueError('Invalid protocol label.')
    proto=value.get('proto','other').upper()
    if proto not in {'TCP','UDP','ICMP','ICMPV6'}:proto='OTHER'
    basis='ip_bytes' if 'orig_ip_bytes' in value and 'resp_ip_bytes' in value else 'payload_bytes' if 'orig_bytes' in value and 'resp_bytes' in value else 'unknown'
    byte_fields=('orig_ip_bytes','resp_ip_bytes') if basis=='ip_bytes' else ('orig_bytes','resp_bytes') if basis=='payload_bytes' else (None,None)
    data=dict(source_id=uid,src_ip=address(value['id.orig_h']),dst_ip=address(value['id.resp_h']),
              src_port=port(value.get('id.orig_p')),dst_port=port(value.get('id.resp_p')),protocol=proto,
              sent_bytes=count(value[byte_fields[0]]) if byte_fields[0] else None,
              received_bytes=count(value[byte_fields[1]]) if byte_fields[1] else None,
              sent_packets=count(value['orig_pkts']) if 'orig_pkts' in value else None,received_packets=count(value['resp_pkts']) if 'resp_pkts' in value else None,
              byte_basis=basis,
              completed=True,first_seen=utc(start),last_seen=utc(start+duration),observation='Zeek connection summary')
    return 'flows',dict(observed_at=utc(start+duration),source='zeek-conn',data=data)


class FlowIngestor:
    def __init__(self,evidence,*,home=None,eve_path=Path('/var/log/suricata/eve.json'),on_flow=None,enabled=lambda:True):
        self.evidence=evidence;self.home=Path.home() if home is None else Path(home)
        self.paths={'suricata':Path(eve_path),'zeek':self.home/'.local/share/megalodon/support/zeek/conn.log'}
        self.on_flow=on_flow;self.enabled=enabled
        self._lock=Lock();self._work_lock=RLock();self._stop=Event();self._thread=None
        self._state=dict(state='stopped',source=None,source_detail=None,accepted=0,rejected=0,imported_flows=0,imported_findings=0,
                         backlog_bytes=0,rotations=0,gaps=0,sampling_gaps=0,samples=0,updated_at=None,message='Flow collection is stopped.')
        self._positions={};self._primary=None;self._select_at=0

    def snapshot(self):
        with self._lock:
            result=dict(self._state)
        if result['state']=='connected' and result['updated_at'] and self.evidence.clock()-epoch(result['updated_at'])>120:
            result.update(state='stale',message='No recent sensor summary update; current source coverage is unknown.')
        return result

    def start(self):
        if self._thread and self._thread.is_alive():return
        self._stop.clear();self._thread=Thread(target=self._run,daemon=True,name='megalodon-flow-ingestion');self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread:self._thread.join(4)
        if self._thread and self._thread.is_alive():raise ValueError('Flow collector is still finishing its checkpoint.')

    def _recent_source(self,source):
        """Read a bounded tail; existence alone is never source readiness."""
        try:
            fd=os.open(self.paths[source],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):return False
                offset=max(0,info.st_size-READ_BYTES);os.lseek(fd,offset,os.SEEK_SET);raw=os.read(fd,READ_BYTES)
            finally:os.close(fd)
            if offset:raw=raw.partition(b'\n')[2]
            raw=raw.rpartition(b'\n')[0]
            normalizer=normalize_suricata if source=='suricata' else normalize_zeek
            for line in reversed(raw.splitlines()[-2000:]):
                try:
                    if len(line)>MAX_LINE:continue
                    record=normalizer(json.loads(line))
                    if record and record[0]=='flows' and -5<=self.evidence.clock()-epoch(record[1]['data']['last_seen'])<=120:
                        return True
                except (ValueError,KeyError,TypeError,OverflowError,RecursionError):continue
        except (OSError,ValueError):pass
        return False

    def select_source(self,*,force=False):
        with self._work_lock:
            if not force and self._primary is not None and time.monotonic()<self._select_at:return self._primary
            selected=('suricata','file') if self._recent_source('suricata') else ('zeek','file') if self._recent_source('zeek') else ('zeek','sample')
            self._select_at=time.monotonic()+5
            if selected!=self._primary:
                self._primary=selected
                with self._lock:self._state.update(source=selected[0],source_detail=selected[1],state='waiting',
                    message='Using recent readable EVE flow records.' if selected[0]=='suricata' else
                        'Using recent Zeek connection records.' if selected[1]=='file' else 'Waiting for bounded Zeek samples; continuous flow coverage is unavailable.')
            return selected

    def _run(self):
        while not self._stop.is_set():
            if self.evidence.enabled and self.enabled():
                try:
                    primary,detail=self.select_source()
                    if detail=='file':self.poll(primary,include_flows=self.evidence.recording_mode=='connection_summaries')
                    if primary!='suricata':
                        try:self.poll('suricata',include_flows=False)
                        except (OSError,ValueError,sqlite3.Error):pass  # optional alert source
                except (OSError,ValueError,KeyError,TypeError,OverflowError,sqlite3.Error):
                    with self._lock:self._state.update(state='unavailable',message='Local sensor input or evidence storage unavailable. Check Sensors and Storage.')
            self._stop.wait(.1 if self.snapshot()['backlog_bytes'] else 1)

    def _checkpoint(self,source,position):
        if self._positions.get(source)!=position:
            self.evidence.checkpoint('flow_'+source,position)
            self._positions[source]=position

    def poll(self,source,*,include_flows=True):
        with self._work_lock:return self._poll(source,include_flows=include_flows)

    def _poll(self,source,*,include_flows=True):
        if source not in self.paths:raise ValueError('Unknown fixed sensor source.')
        key='flow_'+source;path=self.paths[source]
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):raise ValueError('Sensor input must be a regular file.')
            position=self._positions.get(source) or self.evidence.checkpoint(key)
            identity=[info.st_dev,info.st_ino]
            if not position or position['identity']!=identity or position['offset']>info.st_size:
                offset=max(0,info.st_size-READ_BYTES);discarding=False
                with self._lock:
                    self._state['gaps']+=int(offset>0 or position is not None)
                    self._state['rotations']+=int(position is not None)
                if offset:
                    os.lseek(fd,offset,os.SEEK_SET);prefix=os.read(fd,READ_BYTES);split=prefix.find(b'\n')
                    offset+=len(prefix) if split<0 else split+1;discarding=split<0
                position=dict(identity=identity,offset=offset,discarding=discarding)
            os.lseek(fd,position['offset'],os.SEEK_SET);raw=os.read(fd,READ_BYTES)
        finally:os.close(fd)
        offset=position['offset'];rejected=0
        if position.get('discarding'):
            split=raw.find(b'\n')
            if split<0:
                self._checkpoint(source,dict(identity=identity,offset=offset+len(raw),discarding=True))
                with self._lock:self._state['backlog_bytes']=max(0,info.st_size-offset-len(raw))
                return 0
            offset+=split+1;raw=raw[split+1:]
        end=raw.rfind(b'\n')
        batch=[];category=None;accepted=0;has_flows=False;last_checkpoint=dict(identity=identity,offset=offset,discarding=False)
        normalizer=normalize_suricata if source=='suricata' else normalize_zeek
        for line in raw[:end+1].splitlines(keepends=True) if end>=0 else []:
            offset+=len(line);checkpoint=dict(identity=identity,offset=offset,discarding=False);item=None
            try:
                if len(line)>MAX_LINE:raise ValueError('Oversized sensor record.')
                item=normalizer(json.loads(line))
                if item and item[0]=='flows' and not include_flows:item=None
                if item and not self.evidence.clock()-self.evidence.retention_days*86400<=epoch(item[1]['observed_at'])<=self.evidence.clock()+60:raise ValueError('Sensor time outside retention.')
            except (ValueError,KeyError,TypeError,OverflowError,RecursionError):rejected+=1;item=None
            if item and (category is not None and category!=item[0] or len(batch)>=256):
                accepted+=self._commit(source,category,batch,last_checkpoint);batch=[]
            if item:category=item[0];batch.append(item[1]);has_flows=has_flows or item[0]=='flows'
            last_checkpoint=checkpoint
        if batch:accepted+=self._commit(source,category,batch,last_checkpoint)
        else:self._checkpoint(source,last_checkpoint)
        trailing=raw[end+1:]
        if len(trailing)>MAX_LINE:
            rejected+=1;offset+=len(trailing)
            self._checkpoint(source,dict(identity=identity,offset=offset,discarding=True))
            with self._lock:self._state['gaps']+=1
        with self._lock:
            self._state.update(updated_at=utc(),backlog_bytes=max(0,info.st_size-offset))
            if has_flows and (self._primary is None or self._primary==(source,'file')):
                self._state.update(state='connected',message='Source-qualified metadata is retained; input rotations and skipped intervals are reported as gaps.')
            if self._state['source'] is None:
                self._state.update(source=source,source_detail='file' if include_flows else 'alerts')
                if not has_flows:self._state.update(state='waiting',message='Waiting for connection summaries. Sensor findings are retained separately when available.')
            self._state['rejected']+=rejected
        return accepted

    def _commit(self,source,category,batch,checkpoint):
        accepted=self.evidence.append_records(category,batch,checkpoint=('flow_'+source,checkpoint))
        if accepted!=len(batch):raise ValueError('Sensor batch was not fully admitted; its checkpoint will be reviewed.')
        self._positions[source]=checkpoint
        with self._lock:
            self._state['imported_'+category]+=accepted;self._state['accepted']+=accepted
        if category=='flows' and self.on_flow:
            for row in batch:self.on_flow(row)
        return accepted

    def ingest_zeek_sample(self,raw,*,sample_id,interface,started_at,finished_at):
        """Admit finite sampled Zeek JSON, with persisted per-sample checkpoints."""
        if not self.evidence.enabled or not self.enabled() or self.evidence.recording_mode!='connection_summaries':return 0
        if not isinstance(raw,bytes) or len(raw)>2*1024*1024 or not isinstance(sample_id,str) or not re.fullmatch(r'[a-f0-9]{32}',sample_id):
            raise ValueError('Invalid bounded Zeek sample.')
        if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',interface) or not 0<=epoch(finished_at)-epoch(started_at)<=60:
            raise ValueError('Invalid Zeek sample scope.')
        lines=raw.splitlines()
        if len(lines)>4000:raise ValueError('Zeek sample exceeds row bound.')
        with self._work_lock:
            if self.select_source()!=('zeek','sample'):return 0
            checkpoint=self.evidence.checkpoint('flow_zeek_sample') or {}
            if sample_id in checkpoint.get('recent',[]):return 0
            digest=hashlib.sha256(raw).hexdigest();start=0
            if checkpoint.get('sample_id')==sample_id:
                if checkpoint.get('digest')!=digest:raise ValueError('Zeek sample identity changed.')
                start=checkpoint['offset']
            recent=list(checkpoint.get('recent',[]))[-15:]
            accepted=rejected=0;batch=[]
            sampling=dict(kind='bounded_sample',continuous=False,interface=interface,started_at=started_at,finished_at=finished_at,
                          max_frames=2000,snapshot_bytes=256,nominal_interval_seconds=60)
            last=dict(sample_id=sample_id,digest=digest,offset=start,recent=recent)
            for index,line in enumerate(lines[start:],start):
                try:
                    if len(line)>MAX_LINE:raise ValueError('Oversized sample record.')
                    item=normalize_zeek(json.loads(line))
                    if item is None or not self.evidence.clock()-self.evidence.retention_days*86400<=epoch(item[1]['observed_at'])<=self.evidence.clock()+60:raise ValueError('Invalid sample time.')
                    record=item[1];record['source']='zeek-sample';record['data']['sampling']=sampling;record['data']['sample_id']=sample_id
                    batch.append(record)
                except (ValueError,KeyError,TypeError,OverflowError,RecursionError):rejected+=1
                last=dict(sample_id=sample_id,digest=digest,offset=index+1,recent=recent)
                if len(batch)>=256:accepted+=self._commit('zeek_sample','flows',batch,last);batch=[]
            last=dict(sample_id=sample_id,digest=digest,offset=len(lines),recent=[*recent,sample_id])
            if batch:accepted+=self._commit('zeek_sample','flows',batch,last)
            else:self._checkpoint('zeek_sample',last)
            with self._lock:
                self._state.update(state='connected',source='zeek',source_detail='sample',updated_at=utc(),
                    message='Bounded Zeek samples retained. Sampling gaps and 256-byte snapshots limit coverage; these are not continuous packet observations.')
                self._state['rejected']+=rejected;self._state['samples']+=1;self._state['sampling_gaps']+=1
            return accepted
