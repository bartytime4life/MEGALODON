"""Bounded recent captured conversations, independent of historical chart pages."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
from threading import Lock
import time

from .companion_automation import _run_fixed

IDLE_SECONDS = 15
RETENTION_SECONDS = 60
MAX_CONNECTIONS = 128
MAX_TRACKED = 512
MAX_RESPONSE_BYTES = 256 * 1024


def interface_addresses(interface):
    """Exact addresses assigned to the selected interface, never inferred subnets."""
    from .support_config import valid_interface
    valid_interface(interface)
    raw, code = _run_fixed(['/usr/sbin/ip','-j','address','show','dev',interface],65536,3)
    if code:
        return set()
    addresses = set()
    for row in json.loads(raw):
        if row.get('ifname') == interface:
            for info in row.get('addr_info', [])[:32]:
                try:
                    address = ip_address(info.get('local'))
                    if not address.is_loopback and not address.is_link_local:
                        addresses.add(str(address))
                except ValueError:
                    pass
    return addresses


class LiveConnections:
    def __init__(self, geography, *, clock=time.monotonic):
        self.geography, self.clock = geography, clock
        self._lock = Lock()
        self._flows = {}
        self._local = set()
        self._packets = self._bytes = 0
        self._evicted = 0
        self._timeline = {}
        self._interface = None
        self._summary_counts = {}
        self._flow_source = None

    def begin(self, interface):
        try:
            local = interface_addresses(interface)
        except (OSError, ValueError, TypeError):
            local = set()
        with self._lock:
            if self._interface != interface:
                self._timeline.clear()
            self._interface = interface
            self._local = local
            # A new capture can reuse transport tuples; do not splice its counters.
            self._flows.clear()
            self._summary_counts.clear();self._flow_source=None
            self._packets = self._bytes = 0
            self._evicted = 0

    def observe(self, event):
        stamp = self.clock()
        src, dst = str(event.src_ip), str(event.dst_ip)
        a, b = (src, event.src_port), (dst, event.dst_port)
        with self._lock:
            reverse = ((dst in self._local and src not in self._local) or
                       ((src in self._local)==(dst in self._local) and (dst,b[1] or 0)<(src,a[1] or 0)))
            if reverse:
                a, b = b, a
            key = (event.protocol, a, b)
            if key in self._flows and self._flows[key]['state']=='closed' and 'SYN' in event.tcp_flags:
                del self._flows[key]
            for old in [k for k,v in self._flows.items() if stamp-v['_seen']>RETENTION_SECONDS]:
                del self._flows[old]
            if key not in self._flows:
                if len(self._flows)>=MAX_TRACKED:
                    del self._flows[min(self._flows,key=lambda k:self._flows[k]['_seen'])]
                    self._evicted += 1
                empty = dict(packets=0, bytes=0, last_seen=None)
                observed = event.observed_at.isoformat().replace('+00:00','Z')
                self._flows[key] = dict(id=hashlib.sha256(repr(key).encode()).hexdigest()[:20], protocol=event.protocol,
                    a=dict(ip=a[0],port=a[1],local=a[0] in self._local), b=dict(ip=b[0],port=b[1],local=b[0] in self._local),
                    a_to_b=dict(empty), b_to_a=dict(empty), first_seen=observed, last_seen=observed, state='recent', flags=[], _seen=stamp)
            row = self._flows[key]
            direction = row['b_to_a' if reverse else 'a_to_b']
            direction['packets'] += 1
            direction['bytes'] += event.byte_count or 0
            direction['last_seen'] = event.observed_at.isoformat().replace('+00:00','Z')
            row['last_seen'], row['_seen'] = direction['last_seen'], stamp
            row['flags'] = sorted(set(row['flags']) | set(event.tcp_flags))[:8]
            if 'RST' in event.tcp_flags:
                row['state'] = 'closed'
            elif 'FIN' in event.tcp_flags:
                row['state'] = 'closing'
            self._packets += 1
            self._bytes += event.byte_count or 0
            bucket = int(event.observed_at.timestamp()) // 5 * 5
            if bucket not in self._timeline:
                self._timeline[bucket] = dict(at=datetime.fromtimestamp(bucket,timezone.utc).isoformat().replace('+00:00','Z'),
                    sent_bytes=0,received_bytes=0,unattributed_bytes=0,packets=0,_seen=stamp)
            point = self._timeline[bucket]
            lane = ('sent_bytes' if src in self._local and dst not in self._local else
                    'received_bytes' if dst in self._local and src not in self._local else 'unattributed_bytes')
            point[lane] += event.byte_count or 0
            point['packets'] += 1
            point['_seen'] = stamp
            self._timeline = {k:v for k,v in sorted(self._timeline.items())[-24:] if stamp-v['_seen']<=60}

    def observe_summary(self,record):
        """Latest sensor counters; only measured deltas can animate or enter bins."""
        value=record['data']
        totals=tuple(value[k] for k in ('sent_bytes','received_bytes','sent_packets','received_packets'))
        stamp=datetime.fromisoformat(value['last_seen'].replace('Z','+00:00'))
        age=max(0,(datetime.now(timezone.utc)-stamp).total_seconds())
        if age>RETENTION_SECONDS:return
        identity=(record['source'],value['source_id'],value['first_seen'])
        with self._lock:
            if getattr(self,'_flow_source',None)!=record['source']:
                self._flows.clear();self._timeline.clear();self._summary_counts.clear()
                self._flow_source=record['source'];self._packets=0;self._bytes=0
            if any(type(v) is not int or v<0 for v in totals):return
            prior=self._summary_counts.get(identity)
            byte_basis=value.get('byte_basis','unknown')
            if prior and (len(prior)<4 or prior[3]!=byte_basis):
                # Counter units changed: establish a new baseline, never a delta.
                prior=None;self._timeline.clear()
            if prior and (value['last_seen']<prior[1] or any(v<p for v,p in zip(totals,prior[0]))):return
            completed=bool(value.get('completed',True) or (prior and len(prior)>2 and prior[2]))
            if prior and totals==prior[0] and completed==prior[2]:return
            self._summary_counts[identity]=(totals,value['last_seen'],completed,byte_basis)
            if len(self._summary_counts)>MAX_TRACKED:self._summary_counts.pop(next(iter(self._summary_counts)))
            for old in [k for k,v in self._flows.items() if self.clock()-v['_seen']>RETENTION_SECONDS]:del self._flows[old]
            if identity not in self._flows and len(self._flows)>=MAX_TRACKED:
                del self._flows[min(self._flows,key=lambda k:self._flows[k]['_seen'])];self._evicted+=1
            reverse=value['dst_ip'] in self._local and value['src_ip'] not in self._local
            endpoints=[dict(ip=value['src_ip'],port=value['src_port'],local=value['src_ip'] in self._local),
                       dict(ip=value['dst_ip'],port=value['dst_port'],local=value['dst_ip'] in self._local)]
            if reverse:endpoints.reverse()
            delta=tuple(v-p for v,p in zip(totals,prior[0])) if prior else None
            directions=[]
            for index in range(2):
                directions.append(dict(bytes=totals[index],packets=totals[index+2],
                    last_seen=value['last_seen'] if delta and (delta[index] or delta[index+2]) and not completed else None))
            if reverse:directions.reverse()
            self._flows[identity]=dict(id=hashlib.sha256(repr(identity).encode()).hexdigest()[:20],protocol=value['protocol'],
                a=endpoints[0],b=endpoints[1],a_to_b=directions[0],b_to_a=directions[1],
                first_seen=value['first_seen'],last_seen=value['last_seen'],state='closed' if completed else 'recent',
                flags=[],_seen=self.clock()-age,source=record['source'],observation='flow summary',byte_basis=value.get('byte_basis','unknown'))
            self._packets=sum(r['a_to_b']['packets']+r['b_to_a']['packets'] for r in self._flows.values())
            self._bytes=sum(r['a_to_b']['bytes']+r['b_to_a']['bytes'] for r in self._flows.values())
            if delta and any(delta):
                bucket=int(stamp.timestamp())//5*5
                point=self._timeline.setdefault(bucket,dict(at=datetime.fromtimestamp(bucket,timezone.utc).isoformat().replace('+00:00','Z'),
                    sent_bytes=0,received_bytes=0,unattributed_bytes=0,packets=0,_seen=self.clock()))
                if endpoints[0]['local']!=endpoints[1]['local']:
                    point['sent_bytes']+=delta[1] if reverse else delta[0]
                    point['received_bytes']+=delta[0] if reverse else delta[1]
                else:point['unattributed_bytes']+=delta[0]+delta[1]
                point['packets']+=delta[2]+delta[3];point['_seen']=self.clock()
                point['basis']='flow_summary_delta';point['timing']='summary_interval_not_packet_arrival'
                point['interval_start']=min(point.get('interval_start',prior[1]),prior[1])
                point['interval_end']=max(point.get('interval_end',value['last_seen']),value['last_seen'])
                point['summary_updates']=point.get('summary_updates',0)+1
                point['source']=record['source']
            self._timeline={k:v for k,v in sorted(self._timeline.items())[-24:] if self.clock()-v['_seen']<=60}

    def snapshot(self, capture, background):
        now = self.clock()
        with self._lock:
            retained = sorted((r for r in self._flows.values() if now-r['_seen']<=RETENTION_SECONDS),key=lambda r:r['_seen'],reverse=True)
            active = sum(now-r['_seen']<=IDLE_SECONDS and r['state']!='closed' for r in retained) if capture['state']=='running' else 0
            rows = deepcopy(retained[:MAX_CONNECTIONS])
            if self._flow_source is not None:
                self._packets=sum(r['a_to_b']['packets']+r['b_to_a']['packets'] for r in retained)
                self._bytes=sum(r['a_to_b']['bytes']+r['b_to_a']['bytes'] for r in retained)
            packets, byte_count, evicted = self._packets, self._bytes, self._evicted
            timeline = [{k:v for k,v in point.items() if k!='_seen'} for _,point in sorted(self._timeline.items()) if now-point['_seen']<=60]
        geo = self.geography.snapshot()
        anchor = geo['anchor']
        unmapped = 0
        for row in rows:
            row['active'] = capture['state']=='running' and now-row.pop('_seen')<=IDLE_SECONDS and row['state']!='closed'
            for key in ('a','b'):
                endpoint = row[key]
                endpoint['location'] = deepcopy(anchor) if endpoint['local'] else self.geography.lookup(endpoint['ip'])
            if not row['a']['location'] or not row['b']['location']:
                unmapped += 1
        value = dict(schema='megalodon-live-connections-v1', generated_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
                    capture=capture, background=background, geography=geo, connections=rows,timeline=timeline,
                    totals=dict(active=active,returned=len(rows),unmapped=unmapped,truncated=len(retained)>len(rows) or evicted>0,packets=packets,bytes=byte_count,evicted=evicted),
                    limits=dict(idle_seconds=IDLE_SECONDS,retention_seconds=RETENTION_SECONDS,max_connections=MAX_CONNECTIONS,tracked_connections=MAX_TRACKED))
        while rows and len(json.dumps(value).encode()) > MAX_RESPONSE_BYTES:
            removed = rows.pop()
            value['totals']['returned'] = len(rows)
            value['totals']['truncated'] = True
            value['totals']['unmapped'] -= int(not removed['a']['location'] or not removed['b']['location'])
        return value
