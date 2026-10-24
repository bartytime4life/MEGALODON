"""Location is local context with explicit unknowns, not physical attribution."""
import hashlib
import gzip
from io import BytesIO
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
from threading import Thread
from unittest.mock import Mock

import pytest

from megalodon.address_location import project
from megalodon.dashboard import DashboardHandler
from megalodon.dashboard_address_map import ASSETS, MAP_JS, asset
from megalodon.hud_password import PasswordVerifier
from megalodon.operations import Operations

STAMP='2026-10-24T12:00:00Z'


def endpoint(ip='8.8.8.8', **location):
    point=dict(latitude=37.5,longitude=-97.5,label='<img src=x> Synthetic region',source='Synthetic offline fixture',
               country='us',approximate=True,accuracy_radius_km=50)
    point.update(location)
    return dict(ip=ip,first_seen=STAMP,last_seen=STAMP,location=point)


def note(row=None, **context):
    return project(row or endpoint(),snapshot_at=STAMP,capture_state='failed',**context)


def test_local_region_requires_no_origin_identity_or_network(monkeypatch):
    def forbidden(*args,**kwargs):pytest.fail('Location projection attempted I/O')
    monkeypatch.setattr('socket.socket',forbidden)
    monkeypatch.setattr('socket.getaddrinfo',forbidden)
    monkeypatch.setattr('subprocess.Popen',forbidden)
    value=note(geography_context=dict(source='Synthetic offline fixture',build_date=STAMP,updated_at=STAMP))
    assert value['status']=='mapped' and value['capture_state']=='failed'
    assert value['location']['database_build_at']==STAMP
    assert value['location']['country']=='US' and value['location']['accuracy_radius_km']==50
    assert value['original_address'] is value['physical_address'] is value['person_identity'] is None
    assert value['network_access_performed'] is False and value['action_authority']=='none'


@pytest.mark.parametrize('ip',['10.0.0.1','127.0.0.1','100.64.0.1','192.0.2.1','224.0.0.1','::1','fe80::1','2001:db8::1','::ffff:8.8.8.8'])
def test_private_reserved_and_mapped_addresses_never_inherit_a_public_exit_position(ip):
    value=note(endpoint(ip))
    assert value['status']=='unmapped' and value['location'] is None


@pytest.mark.parametrize('changes',[dict(latitude=True),dict(latitude=float('nan')),dict(latitude=91),dict(longitude=float('inf')),dict(longitude=-181),dict(approximate=False),dict(source=''),dict(label='x'*161)])
def test_invalid_location_stays_unmapped(changes):
    assert note(endpoint(**changes))['location'] is None


@pytest.mark.parametrize('radius',[None,0,-1,True,float('nan'),float('inf'),20001])
def test_unknown_accuracy_is_not_replaced_by_a_small_default(radius):
    value=note(endpoint(accuracy_radius_km=radius),geography_context=dict(source='different source',build_date=STAMP))
    assert value['status']=='mapped' and value['location']['accuracy_radius_km'] is None
    assert value['location']['database_build_at'] is None


def test_retained_location_does_not_enable_current_endpoint_actions():
    operations=Operations(None)
    operations.snapshot=lambda:dict(endpoints=[endpoint()],observed_at=STAMP,capture=dict(state='failed'))
    assert operations.address_location('8.8.8.8')['status']=='mapped'
    assert operations.address_location('1.1.1.1') is None
    with pytest.raises(ValueError,match='Monitoring must be running'):operations.endpoint('8.8.8.8')


@pytest.fixture
def local_map_http():
    operations=Mock();operations.address_location.side_effect=lambda ip:note() if ip=='8.8.8.8' else None
    handler=type('MapHandler',(DashboardHandler,),dict(operations=operations))
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    worker=Thread(target=server.serve_forever,daemon=True);worker.start()
    def request(path,explicit=True,host=None,method='GET'):
        connection=HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        headers={'Host':host or f'127.0.0.1:{server.server_port}'}
        if explicit:headers['X-Megalodon-Check']='1'
        connection.request(method,path,headers=headers);response=connection.getresponse()
        raw=response.read();result=response.status,dict(response.getheaders()),raw;connection.close();return result
    yield operations,handler,request
    server.shutdown();server.server_close();worker.join(2)


def test_http_map_read_retains_host_explicit_session_and_size_boundaries(local_map_http):
    operations,handler,request=local_map_http
    assert request('/api/address-map?ip=8.8.8.8',explicit=False)[0]==403
    assert request('/api/address-map?ip=8.8.8.8',host='foreign.invalid')[0]==400
    assert not operations.address_location.called
    code,headers,raw=request('/api/address-map?ip=8.8.8.8')
    assert code==200 and len(raw)<=8192 and headers['Cache-Control']=='no-store'
    assert json.loads(raw)['physical_address'] is None
    assert request('/api/address-map?ip=1.1.1.1')[0]==404
    calls=operations.address_location.call_count
    for query in ['', 'ip=host.example','ip=8.8.8.8&ip=1.1.1.1','ip=8.8.8.8&extra=1','ip=fe80%3A%3A1%25eth0']:
        assert request('/api/address-map?'+query)[0]==422
    assert request('/api/address-map?ip=8.8.8.8',method='POST')[0] not in range(200,300)
    assert operations.address_location.call_count==calls
    handler.http_password_verifier=PasswordVerifier.from_password('synthetic-map-password')
    for path in ['/api/address-map?ip=8.8.8.8','/address-map','/assets/address-map/maplibre-gl-worker.mjs']:
        assert request(path)[0]==401


def test_only_map_document_allows_same_origin_workers_and_embedding(local_map_http):
    _,_,request=local_map_http
    code,headers,_=request('/')
    assert code==200 and "worker-src 'none'" in headers['Content-Security-Policy'] and headers['X-Frame-Options']=='DENY'
    code,headers,body=request('/address-map')
    policy=headers['Content-Security-Policy']
    assert code==200 and "worker-src 'self'" in policy and "frame-ancestors 'self'" in policy
    assert "img-src 'none'" in policy and "connect-src 'self'" in policy and 'blob:' not in policy and 'unsafe-' not in policy
    assert headers['X-Frame-Options']=='SAMEORIGIN' and b'/assets/address-map/viewer.mjs' in body
    for name in ASSETS:
        code,headers,raw=request('/assets/address-map/'+name)
        assert code==200 and raw==asset(name)[1] and len(raw)<=2*1024*1024
        assert "worker-src 'none'" in headers['Content-Security-Policy']
    assert request('/assets/address-map/../../pyproject.toml')[0]==404
    assert request('/assets/address-map/unknown.mjs')[0]==404


def test_vendored_library_and_land_match_their_pinned_manifests():
    value=json.loads(asset('manifest.json')[1])
    assert value['version']=='6.15.0' and value['license']=='BSD-3-Clause'
    for name,record in value['files'].items():
        raw=asset(name)[1]
        assert len(raw)==record['bytes'] and hashlib.sha256(raw).hexdigest()==record['sha256']
    raw=asset('land.geojson')[1]
    assert len(raw)==value['land']['bytes'] and hashlib.sha256(raw).hexdigest()==value['land']['sha256']
    for name,record in value['boundaries'].items():
        raw=asset(name)[1]
        assert len(raw)==record['bytes'] and hashlib.sha256(raw).hexdigest()==record['sha256']


@pytest.mark.parametrize('raw',[gzip.compress(b'x'*(2*1024*1024+1),mtime=0),b'not gzip'])
def test_compressed_assets_refuse_invalid_or_excessive_inflation(monkeypatch,raw):
    class Resource:
        def joinpath(self,*args):return self
        def open(self,*args):return BytesIO(raw)
    asset.cache_clear()
    monkeypatch.setattr('megalodon.dashboard_address_map.files',lambda _:Resource())
    try:
        with pytest.raises(ValueError):asset('land.geojson')
    finally:
        asset.cache_clear()


def test_map_interactions_geometry_and_graphics_failure():
    node=shutil.which('node')
    if node is None:pytest.skip('Node required for map interaction contracts')
    path=Path(__file__).with_name('address_map_browser.cjs')
    result=subprocess.run([node,str(path)],input=json.dumps(dict(code=MAP_JS,fixture=note(),
        geometry=str(Path(__file__).parents[1]/'megalodon/assets/address-map/geometry.mjs'),
        viewer=asset('viewer.mjs')[1].decode())),text=True,capture_output=True,timeout=15)
    assert result.returncode==0,result.stderr
