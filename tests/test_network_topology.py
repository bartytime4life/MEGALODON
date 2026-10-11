"""Bounded local topology, explicit discovery, cancellation and truthful edges."""
from copy import deepcopy
import json
from pathlib import Path
from threading import Event
import time
from types import SimpleNamespace

import pytest
from megalodon.network_topology import NetworkTopology,parse_inventory,discovery_jobs,parse_discovery,SCHEMA

STAMP='2026-09-30T23:00:00Z'
ADDRESSES=[dict(ifname='eth0',address='02:00:00:00:00:01',addr_info=[dict(local='192.168.2.10',prefixlen=20),dict(local='fd00::10',prefixlen=64)]),dict(ifname='docker0',linkinfo=dict(info_kind='bridge'),addr_info=[dict(local='172.17.0.1',prefixlen=16)])]
ROUTES=[dict(dev='eth0',gateway='192.168.2.1'),dict(dev='eth0',gateway='192.168.2.1'),dict(dev='eth0',gateway='fd00::1')]
NEIGHBORS=[dict(dev='eth0',dst='192.168.2.20',lladdr='02:00:00:00:00:20',state=['STALE']),dict(dev='eth0',dst='fd00::20',state=['REACHABLE']),dict(dev='eth0',dst='192.168.2.21',state=['FAILED'])]

def inventory(): return parse_inventory(deepcopy(ADDRESSES),deepcopy(ROUTES),deepcopy(NEIGHBORS),STAMP)

def live():
    return dict(capture=dict(state='running',interface='eth0'),connections=[dict(id='f1',a=dict(ip='192.168.2.10',local=True),b=dict(ip='192.168.2.20',local=False),first_seen=STAMP,last_seen=STAMP,active=True,a_to_b=dict(bytes=100,packets=1),b_to_a=dict(bytes=200,packets=2))],totals=dict(truncated=False))

def run_inventory(argv,limit,timeout,cancel):
    assert argv[0]=='/usr/sbin/ip' and limit<=2*1024*1024 and timeout==4
    if 'address' in argv: value=ADDRESSES
    elif 'neigh' in argv: value=NEIGHBORS
    elif '-6' in argv: value=[]
    else: value=ROUTES
    return json.dumps(value).encode(),0

@pytest.fixture
def topology(tmp_path):
    home=tmp_path/'home';home.mkdir(mode=0o700)
    cfg=SimpleNamespace(live_snapshot=live)
    ops=SimpleNamespace(snapshot=lambda:dict(endpoints=[dict(ip='192.168.2.20',sent_bytes=200,received_bytes=100,packets=3,ports=[],names=[],findings=[],active_connections=1)]))
    value=NetworkTopology(cfg,ops,home=home,run=run_inventory)
    value._refresh_passive()
    yield value
    value.close()


def test_passive_inventory_has_no_implied_packets_or_duplicate_routes():
    value=inventory()
    assert value['groups']['docker0']['kind']=='container'
    assert len(value['edges'])==2
    rows=list(value['nodes'].values())
    assert not any(r['ip']=='192.168.2.21' for r in rows)
    assert all(not r['observed'] and r['packets'] is None for r in rows)
    assert ('fd00::20','eth0') in value['known6']
    assert all(r['active'] is False and r['kind']=='route' for r in value['edges'])


@pytest.mark.parametrize('scopes',[
 [],['8.8.8.0/24'],['192.168.8.0/21','192.168.8.0/24'],['192.168.32.0/24'],['172.17.0.0/16'],['fd00::/64'],['fd00::99/128'],['192.168.2.1/24'],['192.168.2.0/24;id'],['127.0.0.1/32'],['192.168.0.0/19'],['192.168.0.0/20','172.17.0.0/24'],['fd00::20'],[None]
])
def test_invalid_discovery_never_becomes_argv(scopes):
    with pytest.raises(ValueError): discovery_jobs(scopes,inventory())


def test_maximum_scope_is_batched_and_known_v6_remains_one_host():
    jobs=discovery_jobs(['192.168.0.0/20'],inventory())
    assert len(jobs)==16 and all(target.endswith('/24') and iface=='eth0' for target,iface in jobs)
    assert discovery_jobs(['fd00::20/128'],inventory())==[('fd00::20/128','eth0')]


def test_snapshot_overlays_directions_only_on_observed_edges_and_pages(topology):
    value=topology.snapshot()
    assert value['schema']==SCHEMA and len(value['token'])==32
    assert value['settings']['enabled'] is False
    observed=[r for r in value['edges'] if r['kind']=='observed']
    assert len(observed)==1 and observed[0]['sent_bytes']==100 and observed[0]['received_bytes']==200 and observed[0]['active']
    assert all(not r['active'] and r['sent_bytes'] is None for r in value['edges'] if r['kind']!='observed')
    peer=next(r for r in value['nodes'] if r['ip']=='192.168.2.20')
    assert peer['observed'] and peer['sent_bytes']==200 and peer['active_connections']==1
    page=topology.snapshot(offset=1,limit=1,query='eth0',group='eth0')
    assert len(page['nodes'])==1 and page['total']>1 and page['truncated']
    assert not page['edges']
    assert 'token' not in topology.snapshot(include_token=False)


def test_configuration_persists_explicit_scopes_but_does_not_probe_in_request(topology):
    calls=[]
    topology.run=lambda *args:calls.append(args) or (b'',0)
    result=topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    assert calls==[] and result['discovery']['state']=='waiting'
    assert topology.profile.stat().st_mode&0o777==0o600
    again=NetworkTopology(topology.configuration,topology.operations,home=topology.home)
    assert again.snapshot()['settings']['enabled'] and again.snapshot()['discovery']['state']=='waiting'
    # Restore never probes until current inventory has established on-link scope.
    again.run=lambda *args:pytest.fail('Restored unavailable scope must not probe')
    again._discover()
    assert again.snapshot()['discovery']['state']=='needs_setup'


def test_discovery_uses_fixed_unprivileged_argv_and_rejects_out_of_scope_xml(topology):
    calls=[]
    raw=b'<nmaprun><host><status state="up"/><address addr="192.168.2.30" addrtype="ipv4"/></host><host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/></host></nmaprun>'
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    topology.run=lambda *args:calls.append(args) or (raw,0)
    topology._discover()
    assert calls[0][0]==['/usr/bin/nmap','-sn','-n','--max-retries','1','--host-timeout','5s','-oX','-','192.168.2.0/24']
    rows=[r for r in topology.snapshot()['nodes'] if r['discovered']]
    assert [r['ip'] for r in rows]==['192.168.2.30'] and rows[0]['packets'] is None and not rows[0]['observed']
    assert topology.snapshot()['discovery']['state']=='ready'
    assert parse_discovery(b'<!DOCTYPE nmaprun><nmaprun/>','192.168.2.0/24','eth0',STAMP)=={}
    with pytest.raises(ValueError): parse_discovery(b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun/>','192.168.2.0/24','eth0',STAMP)


def test_discovery_can_be_disabled_while_its_scope_is_off_link(topology):
    import megalodon.network_topology as module
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    # Away from that network: the saved scope is on no current interface.
    topology._inventory=parse_inventory([dict(ifname='eth0',addr_info=[dict(local='10.0.0.5',prefixlen=24)])],[],[],STAMP)
    # The Setup form re-sends the saved scopes with the unchecked box.
    result=topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=False))
    assert result['settings']['scopes']==['192.168.2.0/24'] and result['settings']['enabled'] is False
    assert json.loads(topology.profile.read_text())['enabled'] is False
    # A different network that reuses the range is never scanned.
    topology._inventory=parse_inventory([dict(ifname='wlan0',addr_info=[dict(local='192.168.2.77',prefixlen=24)])],[],[],STAMP)
    topology.run=lambda *args:pytest.fail('Disabled discovery must not run Nmap')
    topology._next_discovery=0;topology._discover()
    # Enabling still requires the scope to be on-link now.
    topology._inventory=parse_inventory([dict(ifname='eth0',addr_info=[dict(local='10.0.0.5',prefixlen=24)])],[],[],STAMP)
    with pytest.raises(ValueError,match='no longer on a local interface'):
        topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    for bad in (['8.8.8.0/24'],['192.168.2.1/24'],['192.168.2.0/24','192.168.2.0/25']):
        with pytest.raises(ValueError):
            topology.configure(dict(action='configure',scopes=bad,enabled=False))
    assert module.discovery_jobs(['192.168.2.0/24'],topology._inventory,on_link=False)==[]


def test_discovered_identities_leave_the_inventory_after_a_day_without_a_run(topology,monkeypatch):
    import megalodon.network_topology as module
    raw=b'<nmaprun><host><status state="up"/><address addr="192.168.2.30" addrtype="ipv4"/></host></nmaprun>'
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    topology.run=lambda *args:(raw,0)
    monkeypatch.setattr(module,'_now',lambda:'2026-01-01T00:00:00Z')
    topology._discover()
    monkeypatch.undo()
    topology.run=run_inventory
    # Discovery off: no run prunes, but the snapshot still honors the 24 hours.
    topology.configure(dict(action='configure',scopes=[],enabled=False))
    topology._refresh_passive()
    assert '192.168.2.30' not in [r['ip'] for r in topology.snapshot(view='all')['nodes']]


def test_failed_and_cancelled_discovery_do_not_claim_success(topology):
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    topology.run=lambda *args:(b'',1)
    topology._discover()
    assert topology.snapshot()['discovery']['state']=='partial'
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    def cancel(argv,limit,timeout,event):
        topology.configure(dict(action='configure',scopes=[],enabled=False))
        assert event.is_set()
        return b'<nmaprun/>',0
    topology.run=cancel;topology._discover()
    assert topology.snapshot()['discovery']['state']=='disabled'


def test_never_follow_saved_profile_symlink(topology,tmp_path):
    topology.profile.parent.mkdir(parents=True,exist_ok=True)
    target=tmp_path/'other';target.write_text('preserve')
    topology.profile.symlink_to(target)
    with pytest.raises(ValueError): topology.configure(dict(action='configure',scopes=[],enabled=False))
    assert target.read_text()=='preserve'


def test_unavailable_tables_do_not_claim_complete_inventory(topology):
    topology.run=lambda *args:(b'',1)
    topology._refresh_passive()
    value=topology.snapshot()
    assert value['state']=='unavailable'
    assert value['nodes'] and all(r['observed'] for r in value['nodes'])
    assert any('unavailable' in note for note in value['coverage'])


def test_background_discovery_does_not_block_passive_sampler(topology,monkeypatch):
    import megalodon.network_topology as module
    entered,release=Event(),Event();calls=[]
    def run(argv,limit,timeout,cancel):
        if argv[0]=='/usr/bin/nmap':
            entered.set()
            while not release.wait(.01):
                if cancel.is_set(): raise ValueError('cancelled')
            return b'<nmaprun/>',0
        calls.append(argv)
        return run_inventory(argv,limit,timeout,cancel)
    topology.run=run
    topology.configure(dict(action='configure',scopes=['192.168.2.0/24'],enabled=True))
    monkeypatch.setattr(module,'PASSIVE_SECONDS',.02)
    topology.start();assert entered.wait(2)
    before=len(calls);time.sleep(.1)
    assert len(calls)>before
    topology.close();assert not topology._discovery_thread.is_alive()


def test_local_devices_are_not_displaced_by_public_peers_or_unspecified_addresses(topology):
    current=live();public=deepcopy(current['connections'][0]);public['id']='public';public['b']['ip']='8.8.8.8'
    invalid=deepcopy(public);invalid['id']='unspecified';invalid['b']['ip']='0.0.0.0'
    current['connections'] += [public,invalid];topology.configuration.live_snapshot=lambda:current
    assert '8.8.8.8' not in {n['ip'] for n in topology.snapshot()['nodes']}
    all_nodes=topology.snapshot(view='all')['nodes']
    assert '8.8.8.8' in {n['ip'] for n in all_nodes} and '0.0.0.0' not in {n['ip'] for n in all_nodes}
    assert not next(n for n in all_nodes if n['ip']=='8.8.8.8')['on_link']


def test_direction_animation_requires_recent_measured_direction(topology):
    from datetime import datetime,timezone,timedelta
    current=live();flow=current['connections'][0]
    flow['a_to_b']['last_seen']=datetime.now(timezone.utc).isoformat()
    flow['b_to_a']['last_seen']=(datetime.now(timezone.utc)-timedelta(seconds=30)).isoformat()
    topology.configuration.live_snapshot=lambda:current
    edge=next(e for e in topology.snapshot()['edges'] if e['kind']=='observed')
    assert edge['sent_active'] and not edge['received_active']


def test_native_nmap_declaration_does_not_enable_dtd_or_entities():
    raw=b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="192.168.2.30" addrtype="ipv4"/></host></nmaprun>'
    assert len(parse_discovery(raw,'192.168.2.0/24','eth0',STAMP))==1
    for declaration in (b'<!DOCTYPE nmaprun SYSTEM "http://example.test/dtd">',b'<!DOCTYPE nmaprun [<!ENTITY x "bad">]>',b'<!DOCTYPE nmaprun><!DOCTYPE nmaprun>'):
        with pytest.raises(ValueError):parse_discovery(declaration+b'<nmaprun/>','192.168.2.0/24','eth0',STAMP)


def test_per_device_history_is_bounded_saved_and_survives_a_new_reader(topology,tmp_path):
    from megalodon.config import Settings
    from megalodon.evidence_storage import EvidenceStorage,GIB
    manager=EvidenceStorage(Settings(db_path=tmp_path/'old.db'),home=tmp_path)
    try:
        preview=manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB));manager.apply(preview['preview_id'])
        topology.evidence=manager
        topology._persist_observations();topology._persist_observations()
        assert topology.snapshot()['persistence']['state']=='saved'
        rows=manager.history(category='network',limit=100)['records']
        assert len(rows)>2 and all(len(json.dumps(r['data']).encode())<32768 for r in rows)
        assert all('token' not in r['data'] and r['source']=='network-device-observation' for r in rows)
        first=topology.device_history('192.168.2.20',interface='eth0',limit=1)
        assert len(first['records'])==1 and first['next_cursor']
        other=NetworkTopology(topology.configuration,topology.operations,home=topology.home,evidence=manager)
        second=other.device_history('192.168.2.20',interface='eth0',cursor=first['next_cursor'],limit=1)
        assert len(second['records'])==1 and second['records'][0]['id']!=first['records'][0]['id']
        assert first['records'][0]['node']['sent_bytes']==200
    finally:manager.close()


def test_history_failure_does_not_mark_passive_inventory_failed(topology):
    def fail(*args):raise ValueError('full')
    topology.evidence=SimpleNamespace(enabled=True,append_records=fail)
    topology._persist_observations()
    value=topology.snapshot()
    assert value['state']=='ready' and value['persistence']['state']=='error'


def test_persistence_saves_every_device_when_snapshot_pages_are_trimmed(tmp_path):
    # Large sensor context makes a 200-node snapshot page exceed its response
    # bound; trimming a page must never drop devices from history.
    addresses=[dict(ifname='eth0',address='02:00:00:00:00:01',addr_info=[dict(local='192.168.0.10',prefixlen=20)])]
    neighbors=[dict(dev='eth0',dst=f'192.168.{1+n//250}.{1+n%250}',lladdr='02:00:00:00:%02x:%02x'%(n//256,n%256),state=['REACHABLE']) for n in range(300)]
    def run(argv,limit,timeout,cancel):
        return json.dumps(addresses if 'address' in argv else neighbors if 'neigh' in argv else []).encode(),0
    def context(ip):
        return dict(ip=ip,names=[dict(name=f'host-{ip.replace(".","-")}-{k}.corp.example.internal',source='Suricata DNS answer',observed_at=STAMP) for k in range(5)],
            findings=[dict(signature='ET POLICY Suspicious outbound connection sample signature text',severity=2,observed_at=STAMP,source='Suricata EVE (sensor context)') for _ in range(5)],
            services=[dict(name=s,role='server',peer='192.168.0.10',source='Suricata application protocol',observed_at=STAMP) for s in ('http','tls','dns','ssh','smb','rdp','ldap','ntp')])
    ips=[n['dst'] for n in neighbors]
    ops=SimpleNamespace(snapshot=lambda:dict(sensor_endpoints=[context(ip) for ip in ips[:128]],endpoints=[]))
    cfg=SimpleNamespace(live_snapshot=lambda:dict(capture=dict(state='stopped',interface='eth0'),connections=[],totals=dict(truncated=False)))
    batches=[]
    home=tmp_path/'home';home.mkdir(mode=0o700)
    value=NetworkTopology(cfg,ops,home=home,run=run,evidence=SimpleNamespace(enabled=True,append_records=lambda category,rows:batches.append(rows)))
    try:
        value._refresh_passive()
        assert len(value.snapshot(include_token=False,limit=200)['nodes'])<200
        value._persist_observations()
        saved=[r['data']['node']['ip'] for rows in batches for r in rows]
        assert sorted(saved)==sorted(['192.168.0.10',*ips])
        assert all(len(rows)<=200 for rows in batches)
        assert len({r['observed_at'] for rows in batches for r in rows})==1
        assert value.snapshot()['persistence']['state']=='saved'
    finally:value.close()


def test_broadcast_and_non_unicast_flows_never_become_devices_or_count(topology):
    current=live()
    def flow(identifier,a,b,sent=240):
        return dict(id=identifier,protocol='UDP',a=dict(ip=a,port=138,local=a=='192.168.2.10'),b=dict(ip=b,port=138,local=False),first_seen=STAMP,last_seen=STAMP,active=True,a_to_b=dict(bytes=sent,packets=1),b_to_a=dict(bytes=0,packets=0))
    refused=['192.168.15.255','192.168.0.0','255.255.255.255','172.17.255.255','172.17.0.0']
    current['connections']+=[flow(f'b{n}','192.168.2.10',ip) for n,ip in enumerate(refused)]
    # Side b is refused after side a would already have been counted.
    current['connections']+=[flow('m1','192.168.2.20','224.0.0.251'),flow('b9','192.168.2.20','192.168.15.255')]
    # Inside a /20, x.x.1.255 is an ordinary host address.
    current['connections']+=[flow('host','192.168.2.10','192.168.1.255',sent=7)]
    topology.configuration.live_snapshot=lambda:current
    value=topology.snapshot(view='all',limit=200)
    ips={n['ip'] for n in value['nodes']}
    assert not ips&set(refused) and '224.0.0.251' not in ips and '192.168.1.255' in ips
    pc=next(n for n in value['nodes'] if n['ip']=='192.168.2.10')
    assert pc['sent_bytes']==107 and pc['packets']==4 and pc['active_connections']==2
    peer=next(n for n in value['nodes'] if n['ip']=='192.168.2.20')
    assert peer['sent_bytes']==200 and peer['received_bytes']==100 and peer['packets']==3 and peer['active_connections']==1
    assert {e['id'] for e in value['edges'] if e['kind']=='observed'}=={'flow-f1','flow-host'}


def test_public_subnet_broadcast_is_refused_like_a_private_one(topology):
    # Discovery scopes list only private subnets; broadcast refusal covers
    # every local IPv4 interface.
    topology._inventory=parse_inventory([dict(ifname='eth0',addr_info=[dict(local='8.8.8.10',prefixlen=24)])],[],[],STAMP)
    assert topology._inventory['networks']==[]
    def flow(identifier,b):
        return dict(id=identifier,protocol='UDP',a=dict(ip='8.8.8.10',port=138,local=True),b=dict(ip=b,port=138,local=False),first_seen=STAMP,last_seen=STAMP,active=True,a_to_b=dict(bytes=240,packets=1),b_to_a=dict(bytes=0,packets=0))
    current=live();current['connections']=[flow('bcast','8.8.8.255'),flow('net','8.8.8.0'),flow('peer','8.8.8.20')]
    topology.configuration.live_snapshot=lambda:current
    value=topology.snapshot(view='all',limit=200)
    ips={n['ip'] for n in value['nodes']}
    assert '8.8.8.255' not in ips and '8.8.8.0' not in ips and '8.8.8.20' in ips
    assert {e['id'] for e in value['edges'] if e['kind']=='observed'}=={'flow-peer'}
    assert next(n for n in value['nodes'] if n['ip']=='8.8.8.10')['sent_bytes']==240


def test_device_history_reads_fixed_pages_and_cursor_is_exact(tmp_path):
    from datetime import datetime,timezone
    from megalodon.config import Settings
    from megalodon.evidence_storage import EvidenceStorage,GIB
    manager=EvidenceStorage(Settings(db_path=tmp_path/'old.db'),home=tmp_path)
    try:
        preview=manager.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB));manager.apply(preview['preview_id'])
        stamp=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        # Newest first: 150 other devices, then matches spread across pages.
        targets={n for n in range(100) if n%7==0}
        rows=[dict(observed_at=stamp,source='network-device-observation',data=dict(node=dict(ip='192.168.2.20' if n in targets else f'192.168.3.{n%250}',interface='eth0'),window_seconds=60)) for n in range(250)]
        for start in range(0,250,125):manager.append_records('network',rows[start:start+125])
        calls=[]
        def history(**options):
            calls.append(options['limit']);return manager.history(**options)
        home=tmp_path/'home';home.mkdir(mode=0o700)
        value=NetworkTopology(SimpleNamespace(),SimpleNamespace(),home=home,run=run_inventory,evidence=SimpleNamespace(enabled=True,history=history))
        first=value.device_history('192.168.2.20',interface='eth0',limit=1)
        assert len(first['records'])==1 and len(calls)==2 and first['next_cursor']
        expected=[];cursor=None
        while True:
            page=manager.history(category='network',limit=100,cursor=cursor)
            expected+=[r['id'] for r in page['records'] if r['data']['node']['ip']=='192.168.2.20']
            cursor=page['next_cursor']
            if not cursor:break
        assert len(expected)==len(targets) and first['records'][0]['id']==expected[0]
        for limit in (1,2,3):
            seen=[];cursor=None
            while True:
                page=value.device_history('192.168.2.20',interface='eth0',cursor=cursor,limit=limit)
                assert len(page['records'])<=limit
                seen+=[r['id'] for r in page['records']];cursor=page['next_cursor']
                if not cursor:break
            assert seen==expected
    finally:manager.close()
