"""Address evidence stays offline, bounded and separate from identity claims."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
from threading import Thread
from unittest.mock import Mock

import pytest

from megalodon.address_investigation import investigate
from megalodon.dashboard import DashboardHandler
from megalodon.operations import Operations


def endpoint(ip='8.8.8.8'):
    return dict(ip=ip, first_seen='2026-10-23T12:00:00Z', last_seen='2026-10-23T12:01:00Z',
                location=None, connections=2, active_connections=0, packets=3, bytes=350,
                sent_bytes=250, received_bytes=100, protocols=['UDP','TCP'], flags=['ACK'],
                measurement_sources=[dict(source='Accepted packet metadata',byte_basis='reported_bytes')],
                ports=[dict(protocol='UDP', port=51820), dict(protocol='TCP', port=443)],
                names=[dict(name='<img src=x>', source='Observed TLS SNI', observed_at='2026-10-23T12:01:00Z')])


def test_port_clues_never_establish_relay_origin_or_person(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Offline investigation crossed an I/O boundary')
    monkeypatch.setattr('socket.getaddrinfo', forbidden)
    monkeypatch.setattr('socket.socket', forbidden)
    monkeypatch.setattr('subprocess.Popen', forbidden)
    value = investigate(dict(endpoint(), original_address='192.0.2.99', owner='forged identity'))
    assert value['relay_clues'] == [dict(protocol='UDP', port=51820, label='WireGuard-associated port')]
    assert value['relay_status'] == value['origin_status'] == 'not_established'
    assert value['original_address'] is value['person_identity'] is value['network_holder'] is None
    assert value['action_authority'] == 'none' and value['network_access_performed'] is False
    assert value['registry_search_url'] == 'https://search.arin.net/rdap/'
    assert '8.8.8.8' not in value['registry_search_url']


@pytest.mark.parametrize('ip', ['192.168.1.1','127.0.0.1','192.0.2.1','100.64.0.1','169.254.1.1','224.0.0.1','::1','fe80::1','2001:db8::1','::ffff:8.8.8.8'])
def test_private_reserved_and_shared_addresses_have_no_public_lookup(ip):
    value = investigate(endpoint(ip))
    assert value['public_address'] is False and value['registry_search_url'] is None
    assert value['traffic']['packets'] == 3 and value['traffic']['bytes'] == 350
    assert value['original_address'] is None  # Retention needs neither attribution nor a map point.


def test_unknown_counts_remain_unknown_and_observed_zero_remains_zero():
    value = investigate(dict(endpoint(), connections=None, packets=True, bytes=-1,
                             sent_bytes=2**53, received_bytes=0))
    assert all(value['traffic'][key] is None for key in ('connections','packets','bytes','sent_bytes'))
    assert value['traffic']['received_bytes'] == value['traffic']['active_connections'] == 0
    assert value['observation_context'] == dict(recording_mode='not_recorded',window_seconds=None,
                                               truncated=None,capture_gaps='unknown',notes=[])


def test_evidence_provenance_and_coverage_are_bounded_without_claiming_completeness():
    value = investigate(dict(endpoint(), protocols=['ICMP']*30,flags=['SYN','ACK']*10,
                             measurement_sources=[dict(source='zeek-conn',byte_basis='payload_bytes')]*30),
                        recording_mode='connection_summaries',
                        coverage=dict(window_seconds=60,truncated=True,notes=['Sensor coverage is partial.']*30))
    assert value['traffic']['protocols'] == ['ICMP'] and value['traffic']['tcp_flags'] == ['ACK','SYN']
    assert len(value['traffic']['measurement_sources']) == len(value['observation_context']['notes']) == 8
    assert value['observation_context']['recording_mode'] == 'connection_summaries'
    assert value['observation_context']['window_seconds'] == 60 and value['observation_context']['truncated'] is True
    assert value['observation_context']['capture_gaps'] == 'unknown'


def test_input_bounds_and_unknown_provenance_do_not_invent_facts():
    value = investigate(dict(endpoint(), ports=[dict(protocol='UDP',port=i) for i in range(100)],
                             names=[dict(name='x',source='sensor',observed_at='invalid')]*100,
                             first_seen='2026-10-23T12:00:00',last_seen=None))
    assert len(value['observed_ports']) == 32 and len(value['observed_names']) == 5
    assert value['first_seen'] is value['last_seen'] is value['observed_names'][0]['observed_at'] is None


def test_retained_investigation_does_not_weaken_running_endpoint_action_gate():
    operations = Operations(None)
    operations.snapshot = lambda: dict(capture=dict(state='failed'), observed_at='2026-10-23T12:02:00Z', endpoints=[endpoint()],
                                       recording_mode='packet_metadata',coverage=dict(window_seconds=60,truncated=True,notes=['Retained observations.']))
    note = operations.investigate('8.8.8.8')
    assert note['capture_state'] == 'failed' and note['traffic']['packets'] == 3
    assert note['observation_context']['recording_mode'] == 'packet_metadata'
    assert note['observation_context']['truncated'] is True
    assert operations.investigate('1.1.1.1') is None
    with pytest.raises(ValueError, match='Monitoring must be running'):
        operations.endpoint('8.8.8.8')


@pytest.fixture
def investigation_http():
    value = dict(investigate(endpoint()), snapshot_at='2026-10-23T12:02:00Z', capture_state='failed')
    operations = Mock()
    operations.investigate.side_effect = lambda ip: value if ip == '8.8.8.8' else None
    handler = type('InvestigationHandler', (DashboardHandler,), dict(operations=operations))
    server = ThreadingHTTPServer(('127.0.0.1',0),handler)
    worker = Thread(target=server.serve_forever, daemon=True); worker.start()
    def request(path, explicit=True, method='GET', host=None):
        connection = HTTPConnection('127.0.0.1',server.server_port,timeout=2)
        headers = {'Host':host or f'127.0.0.1:{server.server_port}'}
        if explicit: headers['X-Megalodon-Check']='1'
        connection.request(method,path,headers=headers)
        response=connection.getresponse(); raw=response.read(); connection.close()
        return response.status,dict(response.getheaders()),raw
    yield operations, request
    server.shutdown();server.server_close();worker.join(2)


def test_http_investigation_is_local_explicit_and_read_only(investigation_http):
    operations,request=investigation_http
    path='/api/address-investigation?ip=8.8.8.8'
    assert request(path,explicit=False)[0]==403
    assert request(path,host='example.invalid')[0]==400
    assert not operations.investigate.called
    status,headers,body=request(path)
    assert status==200 and headers['Cache-Control']=='no-store'
    assert json.loads(body)['original_address'] is None
    assert json.loads(body)['traffic']['packets'] == 3 and len(body) <= 16384
    assert request('/api/address-investigation?ip=1.1.1.1')[0]==404
    calls=operations.investigate.call_count
    assert request(path,method='POST')[0] not in range(200,300)
    assert operations.investigate.call_count==calls


@pytest.mark.parametrize('query',['','ip=example.com','ip=8.8.8.8&ip=1.1.1.1','ip=8.8.8.8&refresh=1','ip=fe80%3A%3A1%25eth0','ip=008.008.008.008','ip=8.8.8.8%0A'])
def test_http_invalid_queries_never_reach_observations(investigation_http,query):
    operations,request=investigation_http
    assert request('/api/address-investigation?'+query)[0]==422
    assert not operations.investigate.called


def test_browser_note_review_export_and_selection_safety():
    from megalodon.dashboard_address_investigation import INVESTIGATION_JS
    node=shutil.which('node')
    if node is None:
        pytest.skip('Node required for investigation interaction')
    fixture=dict(investigate(endpoint()),snapshot_at='2026-10-23T12:02:00Z',capture_state='failed')
    result=subprocess.run([node,str(Path(__file__).with_name('address_investigation_browser.cjs'))],
        input=json.dumps(dict(code=INVESTIGATION_JS,fixture=fixture)),text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr
