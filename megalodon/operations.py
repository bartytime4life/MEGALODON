"""Bounded passive IP context for the local visual operations HUD."""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
import time

from .managed_capture import now

PORT_HINTS = {22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',123:'NTP',443:'HTTPS',445:'SMB',
              465:'SMTPS',587:'Submission',853:'DNS over TLS',993:'IMAPS',3389:'RDP',5353:'mDNS'}
# Endpoints serving DNS, SSH or RDP are never contained (see defense._target).
PROTECTED_SERVICE_PORTS = frozenset({22, 53, 853, 3389})


def address_scope(value):
    address = ip_address(value)
    for label, match in [('Loopback',address.is_loopback),('Multicast',address.is_multicast),
                         ('Link local',address.is_link_local),('Unspecified',address.is_unspecified),
                         ('Private / reserved',not address.is_global)]:
        if match:
            return label
    return 'Public'


def recent_context(path=Path('/var/log/suricata/eve.json')):
    """Read names/alerts from a bounded local tail; never DNS/WHOIS network queries.

    Source names are untrusted observations. A DNS question does not identify
    the DNS server as that hostname; only explicit A/AAAA answers map names.
    """
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Invalid sensor log')
        offset = max(0,info.st_size-256*1024)
        os.lseek(fd,offset,os.SEEK_SET)
        raw = os.read(fd,256*1024)
    finally:
        os.close(fd)
    if offset:
        raw = raw.partition(b'\n')[2]
    raw = raw.rpartition(b'\n')[0]
    result = {}
    def peer(value):
        key = str(ip_address(value))
        if key not in result and len(result)>=256:
            raise ValueError('Context address bound')
        return result.setdefault(key,dict(names=[],findings=[],services=[]))
    def name(address,value,source,stamp):
        if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}',value):
            return
        rows = peer(address)['names']
        if len(rows)<5 and not any(r['name']==value.lower() for r in rows):
            rows.append(dict(name=value.lower(),source=source,observed_at=stamp))
    def service(address,label,role,remote,stamp):
        if not isinstance(label,str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,40}',label):return
        rows=peer(address)['services']
        remote=str(ip_address(remote))
        item=dict(name=label,role=role,peer=remote,source='Suricata application protocol',observed_at=stamp)
        if len(rows)<8 and not any((r['name'],r['role'],r['peer'])==(label,role,remote) for r in rows):rows.append(item)
    for line in reversed(raw.splitlines()[-1000:]):
        try:
            row = json.loads(line)
            stamp = datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None or not -5 <= (datetime.now(timezone.utc)-stamp).total_seconds() <= 120:
                continue
            stamp = stamp.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
            kind = row.get('event_type')
            label=row.get('app_proto') or (kind if kind in {'tls','http','dns','ssh','smb','rdp','quic'} else None)
            if label and label not in {'failed','unknown'}:
                try:
                    service(row.get('src_ip'),label,'originator' if kind=='flow' else 'observed endpoint',row.get('dest_ip'),stamp)
                    service(row.get('dest_ip'),label,'responder' if kind=='flow' else 'observed endpoint',row.get('src_ip'),stamp)
                except (ValueError,TypeError):pass
            if kind=='tls':
                name(row.get('dest_ip'),row.get('tls',{}).get('sni'),'Observed TLS SNI',stamp)
            elif kind=='http':
                name(row.get('dest_ip'),row.get('http',{}).get('hostname'),'Observed HTTP hostname',stamp)
            elif kind=='dns':
                answers = row.get('dns',{}).get('answers',[])
                if type(answers) is list:
                    for answer in answers[:32]:
                        if answer.get('rrtype') in ('A','AAAA'):
                            name(answer.get('rdata'),answer.get('rrname'),'Observed DNS answer',stamp)
            elif kind=='alert':
                alert = row['alert']
                title = alert.get('signature')
                severity = alert.get('severity')
                if type(title) is str and title.isprintable() and 0<len(title)<=160 and type(severity) is int and 1<=severity<=4:
                    for key in ('src_ip','dest_ip'):
                        findings = peer(row[key])['findings']
                        if len(findings)<5:
                            findings.append(dict(signature=title,severity=severity,observed_at=stamp,source='Suricata EVE (sensor context)'))
        except (ValueError,KeyError,TypeError,AttributeError):
            continue
    return result


class Operations:
    def __init__(self,configuration,*,context_reader=recent_context):
        self.configuration = configuration
        self.context_reader = context_reader
        self._lock = Lock()
        self._next = 0
        self._cached = None

    def snapshot(self):
        with self._lock:
            if self._cached is not None and time.monotonic()<self._next:
                return deepcopy(self._cached)
            live = self.configuration.live_snapshot()
            try:
                context = self.context_reader()
                sensor = 'Recent local Suricata names and findings are available; sensor context is separate from admitted detections.'
            except (OSError,ValueError):
                context = {}
                sensor = 'Sensor name and alert context is unavailable.'
            peers, protocols = {}, {}
            sent = received = unattributed = total_packets = total_bytes = 0
            for flow in live['connections']:
                a,b = flow['a'],flow['b']
                ab,ba = flow['a_to_b'],flow['b_to_a']
                size = ab['bytes']+ba['bytes']
                packets = ab['packets']+ba['packets']
                total_packets += packets; total_bytes += size
                if a['local'] != b['local']:
                    sent += ab['bytes'] if a['local'] else ba['bytes']
                    received += ba['bytes'] if a['local'] else ab['bytes']
                else:
                    unattributed += size
                proto = protocols.setdefault(flow['protocol'],dict(name=flow['protocol'],bytes=0,packets=0))
                proto['bytes']+=size;proto['packets']+=packets
                for endpoint,outbound,inbound in ((a,ab,ba),(b,ba,ab)):
                    key = endpoint['ip']
                    row = peers.setdefault(key,dict(ip=key,scope=address_scope(key),version=ip_address(key).version,
                        local=endpoint['local'],connections=0,active_connections=0,packets=0,bytes=0,sent_bytes=0,received_bytes=0,
                        first_seen=flow['first_seen'],last_seen=flow['last_seen'],ports=[],names=context.get(key,{}).get('names',[]),
                        findings=context.get(key,{}).get('findings',[]),services=context.get(key,{}).get('services',[]),location=endpoint['location'],flags=[]))
                    row['connections']+=1;row['active_connections']+=int(flow['active'])
                    row['packets']+=packets;row['bytes']+=size
                    # Per-IP sent/received means this endpoint's direction.
                    row['sent_bytes']+=outbound['bytes'];row['received_bytes']+=inbound['bytes']
                    row['first_seen']=min(row['first_seen'],flow['first_seen']);row['last_seen']=max(row['last_seen'],flow['last_seen'])
                    row['flags']=sorted(set(row['flags'])|set(flow.get('flags',[])))[:8]
                    for label in flow.get('services',[])[:8]:
                        if not isinstance(label,str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,40}',label):continue
                        other=b if endpoint is a else a
                        item=dict(name=label,role='observed endpoint',peer=other['ip'],
                                  source=flow.get('source','Sensor flow summary'),observed_at=flow['last_seen'])
                        if len(row['services'])<8 and item not in row['services']:row['services'].append(item)
                    port = endpoint['port']
                    item = dict(protocol=flow['protocol'],port=port,hint=PORT_HINTS.get(port))
                    if port is not None and item not in row['ports']:
                        if len(row['ports'])<12:
                            row['ports'].append(item)
                        elif port in PROTECTED_SERVICE_PORTS:
                            # Containment refuses endpoints serving these ports, so the
                            # bounded list must never drop one in favour of other ports.
                            for index in range(len(row['ports'])-1,-1,-1):
                                if row['ports'][index]['port'] not in PROTECTED_SERVICE_PORTS:
                                    row['ports'][index]=item
                                    break
            endpoints = sorted(peers.values(),key=lambda r:(not r['local'],-r['bytes']))[:64]
            settings = self.configuration.settings
            storage = dict(status='unavailable',used_bytes=None,limit_bytes=settings.storage.max_database_bytes,percent=None)
            try:
                # The writer enforces descriptor-based identity. These are read-only file size counters.
                used = 0
                for suffix in ('','-wal','-shm','-journal'):
                    path = Path(str(settings.db_path)+suffix)
                    try: info = path.lstat()
                    except FileNotFoundError: continue
                    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid():
                        raise ValueError('Untrusted storage counter')
                    used += info.st_size
                storage.update(status='ready',used_bytes=used,percent=round(used/settings.storage.max_database_bytes*100,1))
            except (OSError,ValueError):
                pass
            result = dict(schema='megalodon-operations-v1',observed_at=now(),capture=live['capture'],background=live['background'],
                summary=dict(peers=len(peers),active_connections=sum(r['active'] for r in live['connections']),packets=total_packets,
                             bytes=total_bytes,sent_bytes=sent,received_bytes=received,unattributed_bytes=unattributed),
                sensor_endpoints=[dict(ip=ip,**value) for ip,value in list(context.items())[:128]],
                timeline=live.get('timeline',[]),protocols=sorted(protocols.values(),key=lambda r:-r['bytes']),endpoints=endpoints,storage=storage,
                coverage=dict(window_seconds=60,max_endpoints=64,unmapped=live['totals']['unmapped'],truncated=live['totals']['truncated'] or len(peers)>64,
                    notes=['Retained observed connections, up to 60 seconds; capture gaps and drops are unknown.',
                           'The timeline uses five-second bins of accepted packet metadata. Endpoint sent/received is relative to that IP.',
                           'Port names are registry hints, not identified applications. Observed hostnames do not establish ownership or safety.',sensor]))
            evidence=getattr(self.configuration,'evidence',None)
            if evidence is not None:
                result['recording_mode']=evidence.recording_mode
                managed=evidence.snapshot()
                result['storage']=dict(storage,status='ready',used_bytes=managed['used_bytes'],limit_bytes=managed['policy']['cap_bytes'],percent=managed['percent'],
                    actual_days=managed['actual_days'],estimated_days=managed['estimated_days'],retention_days=managed['policy']['retention_days'],warnings=managed['warnings'])
                result['coverage']['notes'].append('Live packet projections are bounded recent observations. Selected historical dates use retained segments and verified compact summaries with pagination and coverage limits.')
                if evidence.recording_mode=='connection_summaries':
                    result['coverage']['notes'][:2]=['Retained sensor connection summaries; counts are reported by the selected primary sensor.',
                        'Timeline bins show flow-summary updates, not packet arrival times or wire speed. Use interface speeds for measured throughput.']
            flow_ingestor=getattr(self.configuration,'flow_ingestor',None)
            if flow_ingestor is not None:result['sensor_ingestion']=flow_ingestor.snapshot()
            self._cached=result;self._next=time.monotonic()+2
            return deepcopy(result)

    def endpoint(self,ip):
        canonical = str(ip_address(ip))
        value = self.snapshot()
        if value['capture']['state']!='running':
            raise ValueError('Monitoring must be running to use a current IP observation.')
        row = next((r for r in value['endpoints'] if r['ip']==canonical),None)
        if row is None or row['active_connections']<1:
            raise ValueError('Select an IP with a current observed connection.')
        return row
