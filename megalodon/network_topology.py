"""Bounded local network observations and explicitly configured host discovery.

The passive sampler never probes a network. Nmap runs only for saved, presently
on-link private scopes, under the HUD user's existing permissions.
"""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, ip_interface
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from threading import Event, Lock, Thread
import time
import xml.etree.ElementTree as ET

from .companion_automation import _run_fixed

SCHEMA = 'megalodon-network-v1'
INTERVAL_SECONDS = 900
PASSIVE_SECONDS = 10
MAX_HOSTS = 4096
MAX_NODES = 4608
MAX_SCOPES = 64
MAX_RESPONSE_BYTES = 256 * 1024
PRIVATE_V4 = tuple(ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
PRIVATE_V6 = tuple(ip_network(value) for value in ('fc00::/7','fe80::/10'))


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


def _stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace('+00:00','Z')


def _text(value, limit=128):
    return value if isinstance(value,str) and 0 < len(value) <= limit and value.isprintable() else None


def _interface(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',value):
        raise ValueError('Invalid interface')
    return value


def _group(name, kind=None):
    if name == 'lo': return 'loopback'
    if kind in {'wireguard','tun','tap','gre','sit','ip6tnl','vti'} or name.startswith(('tailscale','wg','tun','tap','ppp')): return 'vpn'
    if kind in {'veth','bridge','vxlan'} or name.startswith(('docker','br-','veth','virbr','cni','podman')): return 'container'
    return 'lan'


def _private(network):
    return any(network.subnet_of(boundary) for boundary in (PRIVATE_V4 if network.version == 4 else PRIVATE_V6))


def _node_id(address, interface):
    return 'ip-' + hashlib.sha256((address+'|'+interface).encode()).hexdigest()[:18]


def _scope(address):
    value = ip_address(address)
    if value.is_loopback: return 'Loopback'
    if value.is_link_local: return 'Link local'
    return 'Public' if value.is_global else 'Private / reserved'


def _node(address, interface, role, source, stamp, **extra):
    return dict(id=_node_id(address,interface),ip=address,name='This PC' if role=='pc' else ('Gateway' if role=='gateway' else address),
                interface=interface,group=interface or 'unattributed',role=role,mac=None,source=source,
                first_seen=stamp,last_seen=stamp,discovered=False,observed=False,sent_bytes=None,received_bytes=None,
                packets=None,ports=[],names=[],findings=[],services=[],protocols=[],on_link=True,scope=_scope(address),local=role=='pc',active_connections=0,**extra)


def _strict_pairs(pairs):
    result = {}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate configuration field')
        result[key]=value
    return result


def parse_inventory(addresses, routes, neighbors, stamp):
    """Turn bounded ip JSON into interface facts; a neighbor is not a flow."""
    if any(type(value) is not list for value in (addresses,routes,neighbors)):
        raise ValueError('Invalid local network response')
    groups, nodes, edges, networks, known6 = {}, {}, [], [], set()
    if len(addresses)>128 or len(routes)>2048 or len(neighbors)>4096:
        raise ValueError('Local network table exceeds bounds')
    for row in addresses:
        try:
            name = _interface(row['ifname'])
            kind = _group(name,row.get('linkinfo',{}).get('info_kind'))
            groups[name]=dict(id=name,label=name,kind=kind)
            info = row.get('addr_info',[])
            if type(info) is not list or len(info)>64: raise ValueError('Address bound')
            for address in info:
                iface = ip_interface(f"{address['local']}/{address['prefixlen']}")
                if iface.ip.is_unspecified or iface.ip.is_multicast: continue
                text=str(iface.ip)
                item=_node(text,name,'pc','Local interface',stamp)
                if _text(row.get('address'),32): item['mac']=row['address']
                nodes[item['id']]=item
                if _private(iface.network) and kind!='loopback': networks.append((iface.network,name))
        except (KeyError,ValueError,TypeError,AttributeError):
            continue
    for row in routes:
        try:
            name=_interface(row['dev'])
            if name not in groups: continue
            gateway=str(ip_address(row['gateway']))
            if ip_address(gateway).is_unspecified or ip_address(gateway).is_multicast: continue
            item=_node(gateway,name,'gateway','Kernel route',stamp)
            if item['id'] not in nodes: nodes[item['id']]=item
            for local in list(nodes.values()):
                if local['interface']==name and local['role']=='pc' and ip_address(local['ip']).version==ip_address(gateway).version:
                    edges.append(dict(id='route-'+local['id']+'-'+item['id'],source=local['id'],target=item['id'],kind='route',sent_bytes=None,received_bytes=None,active=False))
            if ip_address(gateway).version==6: known6.add((gateway,name))
        except (KeyError,ValueError,TypeError): continue
    for row in neighbors:
        try:
            name=_interface(row['dev'])
            if name not in groups: continue
            address=ip_address(row['dst'])
            if address.is_unspecified or address.is_multicast or address.is_loopback: continue
            states=row.get('state',[])
            if isinstance(states,str): states=[states]
            if not states or any(value in {'FAILED','INCOMPLETE','NONE'} for value in states): continue
            item=_node(str(address),name,'device','Neighbor cache (reachability may be stale)',stamp)
            previous=nodes.get(item['id'])
            if previous is not None: item=previous
            if _text(row.get('lladdr'),32): item['mac']=row['lladdr']
            nodes[item['id']]=item
            if address.version==6: known6.add((str(address),name))
        except (KeyError,ValueError,TypeError): continue
    return dict(groups=groups,nodes=nodes,edges=list({row['id']:row for row in edges}.values()),networks=networks,known6=known6)


def discovery_jobs(scopes, inventory):
    """Validate explicit choices against current on-link facts and split IPv4."""
    if type(scopes) is not list or not scopes or len(scopes)>MAX_SCOPES:
        raise ValueError('Choose 1–64 private on-link discovery scopes.')
    jobs, selected, total = [], [], 0
    for text in scopes:
        if not isinstance(text,str) or len(text)>64 or '/' not in text:
            raise ValueError('Use explicit private CIDR scopes.')
        try: network=ip_network(text,strict=True)
        except ValueError: raise ValueError('Use canonical CIDR scopes with a network prefix.') from None
        if str(network)!=text or not _private(network):
            raise ValueError('Discovery is limited to private on-link scopes.')
        if any(network.version==old.version and network.overlaps(old) for old in selected):
            raise ValueError('Discovery scopes must not overlap.')
        if network.version==6:
            if network.prefixlen!=128: raise ValueError('IPv6 discovery accepts known individual /128 peers only.')
            candidates=[name for address,name in inventory['known6'] if address==str(network.network_address)]
        else:
            candidates=[name for available,name in inventory['networks'] if available.version==4 and network.subnet_of(available)]
        if not candidates: raise ValueError('A selected scope is no longer on a local interface.')
        total+=network.num_addresses
        if total>MAX_HOSTS: raise ValueError('Discovery is limited to 4096 addresses in total.')
        interface=sorted(candidates)[0]
        selected.append(network)
        segments=network.subnets(new_prefix=24) if network.version==4 and network.prefixlen<24 else [network]
        jobs.extend((str(segment),interface) for segment in segments)
    return jobs


def parse_discovery(raw, target, interface, stamp):
    """Nmap XML carries discovery evidence, never an inferred connection."""
    if len(raw)>2*1024*1024:raise ValueError('Discovery report exceeds bounds')
    # Native Nmap emits this inert declaration. No internal/external DTD or
    # entity declaration is accepted; ElementTree never fetches the stylesheet.
    raw=re.sub(rb'<!DOCTYPE\s+nmaprun\s*>',b'',raw,count=1)
    if len(raw)>2*1024*1024 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('Discovery report exceeds bounds')
    try: root=ET.fromstring(raw)
    except ET.ParseError: raise ValueError('Discovery report is invalid') from None
    if root.tag!='nmaprun': raise ValueError('Discovery report is invalid')
    hosts=root.findall('host')
    if len(hosts)>256: raise ValueError('Discovery report exceeds host bound')
    network=ip_network(target)
    result={}
    for host in hosts:
        status=host.find('status')
        if status is None or status.get('state')!='up': continue
        for address in host.findall('address')[:8]:
            if address.get('addrtype') not in {'ipv4','ipv6'}: continue
            try: ip=ip_address(address.get('addr'))
            except ValueError: continue
            if ip.version!=network.version or ip not in network: continue
            item=_node(str(ip),interface,'device','Nmap host discovery',stamp)
            item['discovered']=True
            mac=next((value.get('addr') for value in host.findall('address') if value.get('addrtype')=='mac'),None)
            if _text(mac,32): item['mac']=mac
            item['last_discovered_at']=stamp
            result[item['id']]=item
    return result


class NetworkTopology:
    def __init__(self,configuration,operations,*,home=None,run=_run_fixed,evidence=None):
        self.configuration,self.operations,self.run,self.evidence=configuration,operations,run,evidence
        self.home=Path.home() if home is None else Path(home)
        self.profile=self.home/'.config/megalodon/network-config.json'
        self.token=secrets.token_urlsafe(24)
        self._lock=Lock();self._cancel=Event();self._wake=Event();self._job_cancel=Event()
        self._thread=None;self._discovery_thread=None;self._started=False
        self._inventory=dict(groups={},nodes={},edges=[],networks=[],known6=set())
        self._discovered={};self._observed_at=None;self._state='warming'
        self._message='Reading local interfaces, routes and neighbor observations.'
        self._coverage=[];self._settings=dict(scopes=[],enabled=False,interval_seconds=INTERVAL_SECONDS)
        self._discovery=dict(state='disabled',last_run_at=None,next_run_at=None,message='Host discovery is off. Passive local observations remain available.')
        self._next_discovery=0;self._generation=0;self._last_evidence=0
        self._persistence=dict(state='waiting',last_saved_at=None,message='Waiting for a network observation.')
        self._restore()

    def _restore(self):
        if not os.path.lexists(self.profile): return
        try:
            from .local_install import _owned_directory,_regular_owned_file
            _owned_directory(self.profile.parent,private=True)
            if self.profile.lstat().st_mode&0o077: raise ValueError('Broad profile permissions')
            value=json.loads(_regular_owned_file(self.profile,maximum=8192),object_pairs_hook=_strict_pairs)
            if type(value) is not dict or set(value)!={'schema','scopes','enabled'} or value['schema']!=SCHEMA or type(value['enabled']) is not bool or type(value['scopes']) is not list:
                raise ValueError('Invalid saved configuration')
            # Shape checks here; current on-link validation occurs before any probe.
            if len(value['scopes'])>MAX_SCOPES or any(not isinstance(s,str) or len(s)>64 for s in value['scopes']): raise ValueError('Invalid scopes')
            self._settings.update(scopes=value['scopes'],enabled=value['enabled'])
            if value['enabled']: self._discovery.update(state='waiting',message='Saved discovery will validate current on-link scopes before running.')
        except (OSError,ValueError):
            self._discovery.update(state='needs_setup',message='Saved discovery settings could not be validated. Configure discovery again.')

    def start(self):
        with self._lock:
            if self._started: return
            self._started=True
            self._thread=Thread(target=self._loop,name='megalodon-network',daemon=True)
            self._thread.start()

    def _refresh_passive(self):
        values=[];failed=[]
        commands=(('/usr/sbin/ip','-j','address','show'),('/usr/sbin/ip','-j','route','show','table','all'),('/usr/sbin/ip','-6','-j','route','show','table','all'),('/usr/sbin/ip','-j','neigh','show'))
        for index,argv in enumerate(commands):
            try:
                raw,code=self.run(list(argv),2*1024*1024,4,self._cancel)
                if code: raise ValueError('Local table unavailable')
                data=json.loads(raw)
                if type(data) is not list: raise ValueError('Invalid local table')
                values.append(data)
            except (OSError,ValueError,TypeError): values.append([]);failed.append(index)
            if self._cancel.is_set(): return
        stamp=_now()
        try: inventory=parse_inventory(values[0],values[1]+values[2],values[3],stamp)
        except (ValueError,TypeError): inventory=dict(groups={},nodes={},edges=[],networks=[],known6=set());failed=list(range(4))
        with self._lock:
            old=self._inventory['nodes']
            for key,node in inventory['nodes'].items():
                if key in old: node['first_seen']=old[key]['first_seen']
            self._inventory=inventory;self._observed_at=stamp
            self._state='unavailable' if 0 in failed else ('partial' if failed else 'ready')
            self._message='Local network inventory unavailable.' if 0 in failed else 'Logical topology from local interface, route and neighbor observations.'
            self._coverage=['Local interface data unavailable.' if 0 in failed else 'Local interfaces sampled.',
                'Route coverage is partial.' if 1 in failed or 2 in failed else 'IPv4 and IPv6 kernel routes sampled.',
                'Neighbor data unavailable.' if 3 in failed else 'Neighbor cache entries may be stale and do not establish active traffic.']

    def configure(self,value):
        if type(value) is not dict or set(value)!={'action','scopes','enabled'} or value.get('action')!='configure' or type(value.get('enabled')) is not bool or type(value.get('scopes')) is not list:
            raise ValueError('Invalid network configuration')
        with self._lock:
            if value['scopes']: discovery_jobs(value['scopes'],self._inventory)
            elif value['enabled']: raise ValueError('Select a private on-link scope before enabling discovery.')
            from .local_install import _owned_directory,_regular_owned_file,_atomic_write
            _owned_directory(self.profile.parent,private=True)
            if os.path.lexists(self.profile): _regular_owned_file(self.profile,maximum=8192)
            saved=dict(schema=SCHEMA,scopes=list(value['scopes']),enabled=value['enabled'])
            _atomic_write(self.profile,json.dumps(saved,sort_keys=True).encode(),0o600)
            self._settings.update(scopes=saved['scopes'],enabled=saved['enabled'])
            self._generation+=1;self._job_cancel.set();self._next_discovery=0
            self._discovery.update(state='waiting' if saved['enabled'] else 'disabled',next_run_at=None,
                message='Configured discovery is queued.' if saved['enabled'] else 'Host discovery is off. Passive observations remain available.')
        self._wake.set()
        return self.snapshot()

    def _discover(self):
        with self._lock:
            if not self._settings['enabled'] or time.monotonic()<self._next_discovery: return
            generation=self._generation
            try: jobs=discovery_jobs(self._settings['scopes'],self._inventory)
            except ValueError:
                self._next_discovery=time.monotonic()+INTERVAL_SECONDS
                self._discovery.update(state='needs_setup',message='A saved scope is unavailable or outside current discovery limits. Review Setup.',next_run_at=_stamp(time.time()+INTERVAL_SECONDS))
                return
            cancel=Event();self._job_cancel=cancel
            self._discovery.update(state='running',message=f'Discovering configured scopes in {len(jobs)} bounded batch(es).',next_run_at=None)
        found={};failures=0;stamp=_now();started=time.monotonic();started_wall=time.time()
        for target,interface in jobs:
            if self._cancel.is_set() or cancel.is_set(): break
            remaining=600-(time.monotonic()-started)
            if remaining<=0:
                failures+=1
                break
            with self._lock:
                try:
                    current=discovery_jobs([target],self._inventory)
                    if (target,interface) not in current: raise ValueError('Interface changed')
                except ValueError:
                    failures+=1
                    continue
            argv=['/usr/bin/nmap','-sn','-n','--max-retries','1','--host-timeout','5s','-oX','-']
            if ip_network(target).version==6: argv.extend(['-6','-e',interface])
            argv.append(target)
            try:
                raw,code=self.run(argv,2*1024*1024,max(1,min(90,int(remaining))),cancel)
                if code: raise ValueError('Discovery unavailable')
                found.update(parse_discovery(raw,target,interface,stamp))
            except (OSError,ValueError,TypeError): failures+=1
        with self._lock:
            if generation!=self._generation or self._cancel.is_set() or cancel.is_set(): return
            for key,node in found.items():
                if key in self._discovered: node['first_seen']=self._discovered[key]['first_seen']
            # Keep prior identities for a day, with their actual last response time.
            retained={key:node for key,node in self._discovered.items() if started_wall-datetime.fromisoformat(node['last_seen'].replace('Z','+00:00')).timestamp()<86400}
            retained.update(found)
            self._discovered=dict(sorted(retained.items(),key=lambda item:item[1]['last_seen'],reverse=True)[:MAX_HOSTS])
            self._next_discovery=started+INTERVAL_SECONDS
            self._discovery.update(state='partial' if failures else 'ready',last_run_at=stamp,next_run_at=_stamp(started_wall+INTERVAL_SECONDS),
                message=f'{len(found)} responding device(s). '+('Some discovery batches were unavailable; absence is unknown.' if failures else 'Discovery is not complete network visibility.'))

    def _loop(self):
        while not self._cancel.is_set():
            try:
                self._refresh_passive()
                with self._lock:
                    due=self._settings['enabled'] and time.monotonic()>=self._next_discovery
                    idle=self._discovery_thread is None or not self._discovery_thread.is_alive()
                    if due and idle:
                        self._discovery_thread=Thread(target=self._discover,name='megalodon-network-discovery',daemon=True)
                        self._discovery_thread.start()
                if self.evidence is not None and time.monotonic()-self._last_evidence>=60:
                    self._persist_observations()
                    self._last_evidence=time.monotonic()
            except (OSError,ValueError,TypeError):
                with self._lock: self._state='partial';self._message='Some network observations are unavailable; last known inventory is retained.'
            self._wake.wait(PASSIVE_SECONDS);self._wake.clear()

    def _persist_observations(self):
        """One compact row per returned device, with bounded batches and no tokens."""
        try:
            if not self.evidence.enabled:
                self._persistence.update(state='disabled',message='Enable managed history in Setup to retain device observations.');return
            first=self.snapshot(include_token=False,limit=200,view='devices')
            rows=[];stamp=_now()
            for offset in range(0,min(first['total'],MAX_NODES),200):
                page=first if offset==0 else self.snapshot(include_token=False,limit=200,offset=offset,view='devices')
                rows.extend(dict(observed_at=stamp,source='network-device-observation',data=dict(node=node,window_seconds=60,coverage='Sensor-visible traffic only; window counters overlap across observations.')) for node in page['nodes'])
                if rows:self.evidence.append_records('network',rows)
                rows=[]
            self._persistence=dict(state='saved',last_saved_at=stamp,message='Device observations saved at most once per minute under Storage & history limits.')
        except (OSError,ValueError,TypeError):
            self._persistence=dict(state='error',last_saved_at=self._persistence['last_saved_at'],message='Network history could not be saved. Check managed storage; current observations remain visible.')

    def device_history(self,ip,interface='',cursor=None,limit=20):
        address=str(ip_address(ip))
        if interface:_interface(interface)
        if type(limit) is not int or not 1<=limit<=50:raise ValueError('Invalid history limit')
        result=[];gaps=[];next_cursor=cursor;scanned=0
        if self.evidence is None or not self.evidence.enabled:return dict(schema='megalodon-device-history-v1',records=[],next_cursor=None,truncated=False,gaps=['Managed history unavailable.'])
        while scanned<500 and len(result)<limit:
            page=self.evidence.history(category='network',limit=min(100,limit-len(result)),cursor=next_cursor)
            scanned+=len(page['records']);gaps.extend(page['gaps'])
            for record in page['records']:
                data=record['data'];nodes=[data['node']] if record['source']=='network-device-observation' and isinstance(data.get('node'),dict) else data.get('nodes',[])
                for node in nodes[:200]:
                    if node.get('ip')==address and (not interface or node.get('interface')==interface):
                        result.append(dict(id=record['id'],observed_at=record['observed_at'],source=record['source'],node=node));break
            next_cursor=page['next_cursor']
            if not next_cursor or not page['records']:break
        while result and len(json.dumps(result).encode())>240*1024:
            result.pop()
            next_cursor=result[-1]['id'] if result else cursor
        return dict(schema='megalodon-device-history-v1',records=result,next_cursor=next_cursor,truncated=bool(next_cursor or gaps),gaps=list(dict.fromkeys(gaps)),scanned=scanned)

    @staticmethod
    def _direction_active(direction,flow,live):
        if not flow.get('active') or live.get('capture',{}).get('state')!='running':return False
        if 'last_seen' not in direction:return bool(direction.get('bytes'))
        try:return -5<time.time()-datetime.fromisoformat(direction['last_seen'].replace('Z','+00:00')).timestamp()<=15
        except (ValueError,AttributeError,TypeError):return False

    def _overlay(self,inventory,discovered):
        nodes=inventory['nodes'];edges=inventory['edges'];groups=inventory['groups']
        for key,row in discovered.items():
            if row['interface'] not in groups: continue
            if key in nodes:
                nodes[key]['discovered']=True
                nodes[key]['last_discovered_at']=row.get('last_discovered_at',row['last_seen'])
                if not nodes[key]['mac']: nodes[key]['mac']=row['mac']
            else: nodes[key]=row
        try: live=self.configuration.live_snapshot();ops=self.operations.snapshot()
        except (OSError,ValueError,KeyError,TypeError): return inventory,True
        context={r['ip']:r for r in ops.get('sensor_endpoints',[])[:128]}
        context.update({r['ip']:{**context.get(r['ip'],{}),**r} for r in ops.get('endpoints',[])[:64]})
        selected=live.get('capture',{}).get('interface')
        if selected not in groups: selected='unattributed'
        groups.setdefault('unattributed',dict(id='unattributed',label='Observed peers / route unknown',kind='other'))
        for flow in live.get('connections',[])[:128]:
            pair=[]
            try:
                ab,ba=flow['a_to_b'],flow['b_to_a']
                for side in ('a','b'):
                    endpoint=flow[side];parsed=ip_address(endpoint['ip']);address=str(parsed)
                    if parsed.is_unspecified or parsed.is_multicast:raise ValueError('Not a unicast device')
                    matches=[row for row in nodes.values() if row['ip']==address and (not endpoint.get('local') or row['role']=='pc')]
                    row=next((r for r in matches if r['interface']==selected),matches[0] if matches else None)
                    if row is None:
                        row=_node(address,selected,'pc' if endpoint.get('local') else 'device','Observed packet metadata',flow['last_seen'])
                        nodes[row['id']]=row
                    row['on_link']=row['role'] in {'pc','gateway'} or any(parsed.version==network.version and parsed in network and name==row['interface'] for network,name in inventory['networks'])
                    if not row['observed']:
                        row.update(sent_bytes=0,received_bytes=0,packets=0,active_connections=0)
                    outgoing,incoming=(ab,ba) if side=='a' else (ba,ab)
                    row['sent_bytes']+=outgoing['bytes'];row['received_bytes']+=incoming['bytes']
                    row['packets']+=outgoing['packets']+incoming['packets']
                    row['active_connections']+=int(flow['active'] and live['capture']['state']=='running')
                    row['observed']=True;row['source']='Observed packet metadata' if not row['discovered'] else 'Observed packet metadata + Nmap discovery'
                    row['last_seen']=max(row['last_seen'],flow['last_seen']);row['first_seen']=min(row['first_seen'],flow['first_seen'])
                    detail=context.get(address)
                    if detail:
                        for key in ('ports','names','findings','services'):
                            row[key]=deepcopy(detail.get(key,row[key]))
                    protocol=flow.get('protocol')
                    if protocol and protocol not in row['protocols'] and len(row['protocols'])<16:row['protocols'].append(protocol)
                    port=endpoint.get('port')
                    if isinstance(port,int) and 0<=port<=65535:
                        from .operations import PORT_HINTS
                        item=dict(protocol=protocol or 'OTHER',port=port,hint=PORT_HINTS.get(port))
                        if item not in row['ports'] and len(row['ports'])<12:row['ports'].append(item)
                    pair.append(row)
                edges.append(dict(id='flow-'+str(flow['id']),source=pair[0]['id'],target=pair[1]['id'],kind='observed',
                    sent_bytes=ab['bytes'],received_bytes=ba['bytes'],active=bool(flow['active'] and live['capture']['state']=='running'),
                    sent_active=self._direction_active(ab,flow,live),received_active=self._direction_active(ba,flow,live)))
            except (ValueError,KeyError,TypeError): continue
        for row in nodes.values():
            detail=context.get(row['ip'],{})
            for key in ('names','findings','services'):
                if detail.get(key):row[key]=deepcopy(detail[key])
        # Discovery and neighbor placement is a schematic relationship, never observed traffic.
        linked={row['target'] for row in edges}
        for row in list(nodes.values()):
            if row['role']=='pc' or row['id'] in linked: continue
            local=next((n for n in nodes.values() if n['role']=='pc' and n['interface']==row['interface'] and ip_address(n['ip']).version==ip_address(row['ip']).version),None)
            if local: edges.append(dict(id='known-'+row['id'],source=local['id'],target=row['id'],kind='discovered',sent_bytes=None,received_bytes=None,active=False))
        return inventory,bool(live.get('totals',{}).get('truncated'))

    def snapshot(self,include_token=True,offset=0,limit=50,query='',group='',view='devices'):
        if view not in {'devices','all'}:raise ValueError('Choose devices or all peers')
        if type(offset) is not int or not 0<=offset<=MAX_NODES or type(limit) is not int or not 1<=limit<=200 or type(query) is not str or len(query)>128 or type(group) is not str or len(group)>32:
            raise ValueError('Invalid topology page')
        with self._lock:
            inventory=deepcopy(self._inventory);discovered=deepcopy(self._discovered)
            settings=deepcopy(self._settings);discovery=deepcopy(self._discovery)
            stamp,state,message,coverage=self._observed_at,self._state,self._message,list(self._coverage)
        available=[]
        for network,interface in inventory['networks']:
            if network.version==4: available.append(dict(cidr=str(network),interface=interface,label=f'{interface} · on-link IPv4'))
        for address,interface in sorted(inventory['known6']):
            network=ip_network(address+'/128')
            if _private(network): available.append(dict(cidr=str(network),interface=interface,label=f'{interface} · known IPv6 peer'))
        inventory,flow_partial=self._overlay(inventory,discovered)
        rows=sorted(inventory['nodes'].values(),key=lambda r:(r['role']!='pc',r['role']!='gateway',not r.get('on_link',True),not r['discovered'],not r['observed'],r['group'],r['ip']))
        filtered=[r for r in rows[:MAX_NODES] if (view=='all' or r.get('on_link',True)) and (not group or r['group']==group) and (not query or query.casefold() in (r['ip']+' '+r['name']+' '+r['interface']+' '+str(r['mac'] or '')+' '+json.dumps(r['names'])+' '+json.dumps(r['services'])).casefold())]
        selected=filtered[offset:offset+limit];ids={r['id'] for r in selected}
        edges=[r for r in inventory['edges'] if r['source'] in ids and r['target'] in ids][:1024]
        value=dict(schema=SCHEMA,view=view,persistence=deepcopy(self._persistence),observed_at=stamp,state=state,message=message,settings=settings,available_scopes=available[:MAX_SCOPES],
            groups=list(inventory['groups'].values())[:129],nodes=selected,edges=edges,total=len(filtered),offset=offset,limit=limit,
            truncated=len(rows)>MAX_NODES or len(inventory['edges'])>1024 or offset+len(selected)<len(filtered) or flow_partial,discovery=discovery,
            coverage=coverage+['Map and list show the returned page. Dashed relationships are logical placement, not measured physical links.',
                'Traffic edges show sensor-visible packet or flow observations retained for up to 60 seconds. Other devices need router, mirrored-port or endpoint coverage.',
                'Discovery runs every 15 minutes for saved scopes. Previously discovered identities remain for 24 hours; an absent response is not proof that a device is offline.'])
        if include_token: value['token']=self.token
        while selected and len(json.dumps(value,separators=(',',':')).encode())>MAX_RESPONSE_BYTES:
            selected.pop();ids={r['id'] for r in selected};value['edges']=[r for r in edges if r['source'] in ids and r['target'] in ids];value['truncated']=True
        return value

    def close(self):
        self._cancel.set();self._job_cancel.set();self._wake.set()
        if self._thread is not None: self._thread.join(timeout=6)
        if self._discovery_thread is not None: self._discovery_thread.join(timeout=3)
