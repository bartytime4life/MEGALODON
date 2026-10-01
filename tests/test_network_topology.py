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
    with pytest.raises(ValueError): parse_discovery(b'<!DOCTYPE nmaprun><nmaprun/>','192.168.2.0/24','eth0',STAMP)


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
