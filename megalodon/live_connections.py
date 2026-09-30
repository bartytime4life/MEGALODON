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

    def begin(self, interface):
        try:
            local = interface_addresses(interface)
        except (OSError, ValueError, TypeError):
            local = set()
        with self._lock:
            self._local = local
            # A new capture can reuse transport tuples; do not splice its counters.
            self._flows.clear()
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
                    a_to_b=dict(empty), b_to_a=dict(empty), first_seen=observed, last_seen=observed, state='recent', _seen=stamp)
            row = self._flows[key]
            direction = row['b_to_a' if reverse else 'a_to_b']
            direction['packets'] += 1
            direction['bytes'] += event.byte_count or 0
            direction['last_seen'] = event.observed_at.isoformat().replace('+00:00','Z')
            row['last_seen'], row['_seen'] = direction['last_seen'], stamp
            if 'RST' in event.tcp_flags:
                row['state'] = 'closed'
            elif 'FIN' in event.tcp_flags:
                row['state'] = 'closing'
            self._packets += 1
            self._bytes += event.byte_count or 0

    def snapshot(self, capture, background):
        now = self.clock()
        with self._lock:
            retained = sorted((r for r in self._flows.values() if now-r['_seen']<=RETENTION_SECONDS),key=lambda r:r['_seen'],reverse=True)
            active = sum(now-r['_seen']<=IDLE_SECONDS and r['state']!='closed' for r in retained) if capture['state']=='running' else 0
            rows = deepcopy(retained[:MAX_CONNECTIONS])
            packets, byte_count, evicted = self._packets, self._bytes, self._evicted
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
                    capture=capture, background=background, geography=geo, connections=rows,
                    totals=dict(active=active,returned=len(rows),unmapped=unmapped,truncated=len(retained)>len(rows) or evicted>0,packets=packets,bytes=byte_count,evicted=evicted),
                    limits=dict(idle_seconds=IDLE_SECONDS,retention_seconds=RETENTION_SECONDS,max_connections=MAX_CONNECTIONS,tracked_connections=MAX_TRACKED))
        while rows and len(json.dumps(value).encode()) > MAX_RESPONSE_BYTES:
            removed = rows.pop()
            value['totals']['returned'] = len(rows)
            value['totals']['truncated'] = True
            value['totals']['unmapped'] -= int(not removed['a']['location'] or not removed['b']['location'])
        return value
