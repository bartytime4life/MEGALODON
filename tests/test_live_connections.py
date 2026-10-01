from datetime import datetime, timezone
from ipaddress import ip_address
from types import SimpleNamespace
import time

from megalodon.background_monitor import BackgroundMonitor
from megalodon.live_connections import LiveConnections, MAX_CONNECTIONS, MAX_TRACKED
from megalodon.models import PacketEvent
from megalodon.offline_locations import OfflineLocations


LOCATION=dict(latitude=38.9137,longitude=-94.6712,label='Approximate test region',country='US',accuracy_radius_km=None,source='DB-IP City Lite',approximate=True)


class Geo:
    def snapshot(self):
        return {'anchor':dict(LOCATION)}
    def lookup(self, address):
        return dict(LOCATION) if ip_address(address).is_global else None
    def refresh(self):
        pass


def packet(src='10.0.0.3',dst='8.8.8.8',sport=40000,dport=443,flags=frozenset(),size=100):
    return PacketEvent(datetime.now(timezone.utc),src,dst,'TCP',sport,dport,tcp_flags=flags,byte_count=size)


def snapshot(cache,state='running'):
    return cache.snapshot({'state':state},{'enabled':True})


def test_directions_come_from_observed_packets_and_exact_local_addresses():
    clock=[0]
    cache=LiveConnections(Geo(),clock=lambda:clock[0])
    cache._local={'10.0.0.3'}
    cache.observe(packet())
    row=snapshot(cache)['connections'][0]
    assert row['a']['local'] and row['a']['location']['latitude']==38.9137
    assert row['a_to_b']['packets']==1 and row['b_to_a']['packets']==0
    cache.observe(packet('8.8.8.8','10.0.0.3',443,40000,size=60))
    data=snapshot(cache)
    assert len(data['connections'])==1
    row=data['connections'][0]
    assert row['b_to_a']['packets']==1 and row['b_to_a']['bytes']==60
    assert data['totals']['bytes']==160
    cache.observe(packet('10.0.0.4','8.8.4.4'))
    other=snapshot(cache)['connections'][1]
    assert not other['a']['local'] and other['a']['location'] is None


def test_idle_closed_and_stopped_flows_do_not_claim_activity():
    clock=[0]
    cache=LiveConnections(Geo(),clock=lambda:clock[0])
    cache.observe(packet())
    assert snapshot(cache)['totals']['active']==1
    assert snapshot(cache,'stopped')['totals']['active']==0
    assert not snapshot(cache,'failed')['connections'][0]['active']
    clock[0]=16
    assert not snapshot(cache)['connections'][0]['active']
    cache.observe(packet(flags=frozenset({'RST'})))
    assert snapshot(cache)['connections'][0]['state']=='closed'
    assert snapshot(cache)['totals']['active']==0
    cache.observe(packet(flags=frozenset({'SYN'})))
    assert snapshot(cache)['connections'][0]['a_to_b']['packets']==1
    clock[0]=77
    assert snapshot(cache)['connections']==[]


def test_ipv6_reverse_packets_share_one_flow_and_unknown_peers_stay_unmapped():
    cache=LiveConnections(Geo())
    cache._local={'fd00::3'}
    cache.observe(packet('fd00::3','2606:4700:4700::1111'))
    cache.observe(packet('2606:4700:4700::1111','fd00::3',443,40000))
    data=snapshot(cache)
    assert len(data['connections'])==1
    assert data['connections'][0]['a']['ip']=='fd00::3'
    cache.observe(packet('fd00::3','fd00::4'))
    assert snapshot(cache)['totals']['unmapped']==1


def test_live_cache_and_response_are_bounded():
    clock=[0]
    cache=LiveConnections(Geo(),clock=lambda:clock[0])
    for i in range(MAX_TRACKED+50):
        clock[0]+=0.001
        cache.observe(packet(sport=2000+i))
    data=snapshot(cache)
    assert len(cache._flows)==MAX_TRACKED
    assert len(data['connections'])==MAX_CONNECTIONS
    assert data['totals']['truncated']
    import json
    assert len(json.dumps(data).encode())<256*1024


def test_long_unicode_location_names_cannot_expand_http_response_past_limit():
    class LongGeo(Geo):
        def lookup(self,address):
            return dict(LOCATION,label='🌐'*162)
    cache=LiveConnections(LongGeo())
    for i in range(MAX_CONNECTIONS):
        cache.observe(packet('1.1.1.1','8.8.8.8',sport=2000+i))
    import json
    data=snapshot(cache)
    assert len(json.dumps(data).encode())<=256*1024
    assert data['totals']['truncated']


def test_location_detail_preserves_provider_coordinates_without_five_degree_snapping():
    reader=SimpleNamespace(get=lambda ip: {'location':{'latitude':38.9137,'longitude':-94.6712},'country':{'iso_code':'US','names':{'en':'United States'}},'city':{'names':{'en':'Test city'}}})
    locations=OfflineLocations(reader)
    assert locations.detail('8.8.8.8')['latitude']==38.9137
    assert locations.detail('8.8.8.8')['accuracy_radius_km'] is None
    assert locations.detail('10.0.0.3') is None
    # The legacy history/CSV contract retains its existing coarse behavior.
    assert locations.lookup(['8.8.8.8'])['locations']['8.8.8.8']['latitude']==40


def test_background_retries_only_finite_success_and_stops_on_failure():
    class Capture:
        def __init__(self): self.state='stopped';self.starts=0
        def snapshot(self): return {'state':self.state}
        def start(self, interface): self.starts+=1; self.state='failed'
        def stop(self): self.state='stopped'
    capture=Capture()
    monitor=BackgroundMonitor(capture,Geo())
    monitor.start('eth0')
    monitor._thread.join(3)
    assert capture.starts==1
    assert monitor.snapshot()['state']=='failed'
    monitor.stop()
    assert not monitor.snapshot()['enabled']


def test_stop_during_background_warmup_cannot_later_start_capture():
    capture=SimpleNamespace(snapshot=lambda:{'state':'idle'},start=lambda iface: (_ for _ in ()).throw(AssertionError('late capture')),stop=lambda:None)
    monitor=BackgroundMonitor(capture,Geo())
    monitor.start('eth0')
    monitor.stop()
    assert not monitor._thread.is_alive()
    assert monitor.snapshot()['state']=='stopped'
