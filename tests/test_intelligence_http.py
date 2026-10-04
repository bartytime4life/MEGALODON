from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Lock,Thread
from types import SimpleNamespace
import pytest
from megalodon.dashboard import DashboardHandler


@pytest.fixture
def local_api(monkeypatch):
    calls=[]
    provider=SimpleNamespace(token='a'*32,snapshot=lambda **kwargs:{'state':'ready'},
                             search=lambda query:calls.append(query) or [],action=lambda body:calls.append(body) or {'state':'ready'})
    handler=type('IntelligenceHandler',(DashboardHandler,),dict(knowledge=provider,intelligence=provider,
        maintenance_lock=Lock(),http_read_password=None,http_password_verifier=None))
    monkeypatch.setattr('megalodon.dashboard._tool_management_user',lambda:True)
    server=ThreadingHTTPServer(('127.0.0.1',0),handler);worker=Thread(target=server.serve_forever,daemon=True);worker.start()
    def request(method,path,body=None,omit=(),extra=()):
        raw=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None
        host=f'127.0.0.1:{server.server_port}'
        headers=[('Host',host),('X-Megalodon-Check','1')] if method=='GET' else [('Host',host),('Origin','http://'+host),('Content-Type','application/json'),('X-Megalodon-Intelligence-Token',provider.token),('Content-Length',str(len(raw or b'')))]
        conn=HTTPConnection('127.0.0.1',server.server_port,timeout=2);conn.putrequest(method,path,skip_host=True)
        for k,v in headers:
            if k not in omit:conn.putheader(k,v)
        for k,v in extra:conn.putheader(k,v)
        conn.endheaders(raw);r=conn.getresponse();result=(r.status,r.read());conn.close();return result
    yield SimpleNamespace(request=request,calls=calls,handler=handler,provider=provider)
    server.shutdown();server.server_close();worker.join(2)


def test_protected_status_search_and_action(local_api):
    assert local_api.request('GET','/api/knowledge')[0]==200
    assert local_api.request('GET','/api/intelligence')[0]==200
    assert local_api.request('GET','/api/knowledge/search?q=network')[0]==200
    assert local_api.request('POST','/api/knowledge',{'action':'update'})[0]==200
    assert local_api.calls==['network',{'action':'update'}]


@pytest.mark.parametrize('header',['Host','Origin','Content-Type','X-Megalodon-Intelligence-Token'])
def test_missing_authorization(local_api,header):
    assert local_api.request('POST','/api/intelligence',{'action':'cancel'},omit=[header])[0] in {400,403}
    assert not local_api.calls


@pytest.mark.parametrize('extra',[[('Origin','http://evil.test')],[('X-Megalodon-Intelligence-Token','a'*32)],[('Content-Encoding','gzip')],[('Transfer-Encoding','chunked')]])
def test_ambiguous_headers(local_api,extra):
    assert local_api.request('POST','/api/knowledge',{'action':'update'},extra=extra)[0]==403
    assert not local_api.calls


@pytest.mark.parametrize('body',[b'{"action":"update","action":"rollback"}',b'{"x":NaN}',b'[]',b'null'])
def test_invalid_requests(local_api,body):
    assert local_api.request('POST','/api/knowledge',body)[0]==422
    assert not local_api.calls


def test_reads_require_explicit_local_header(local_api):
    assert local_api.request('GET','/api/knowledge',omit=['X-Megalodon-Check'])[0]==403
    assert local_api.request('GET','/api/knowledge/search?q=a&q=b')[0]==422


@pytest.mark.parametrize('query',['','?device=','?device=not-an-ip','?device=192.0.2.1&device=192.0.2.2',
    '?device=192.0.2.1&action=analyze','?device=fe80::1%25eth0','?device='+('a'*65)])
def test_context_query_is_closed_before_projection(local_api,query):
    local_api.provider.context_for_device=lambda address:pytest.fail('Invalid query reached evidence projection')
    assert local_api.request('GET','/api/intelligence/context'+query)[0]==422
    assert not local_api.calls


def test_context_read_authorization_and_concurrency(local_api):
    local_api.provider.context_for_device=lambda address:local_api.calls.append(address) or {'subject':address}
    path='/api/intelligence/context?device=192.0.2.1'
    assert local_api.request('GET',path,omit=['X-Megalodon-Check'])[0]==403
    assert local_api.request('GET',path,extra=[('X-Megalodon-Check','1')])[0]==403
    local_api.handler.http_read_password='test-only'
    assert local_api.request('GET',path)[0]==401
    local_api.handler.http_read_password=None
    with local_api.handler.context_read_lock:
        assert local_api.request('GET',path)[0]==409
    assert not local_api.calls
    with local_api.handler.maintenance_lock:
        assert local_api.request('GET',path)[0]==200
    assert local_api.calls==['192.0.2.1']
    assert local_api.request('POST',path,{'action':'analyze'})[0]==405


def test_context_failure_releases_lock_and_keeps_error_finite(local_api):
    def unavailable(address):raise ValueError('PRIVATE_SOURCE_PATH')
    local_api.provider.context_for_device=unavailable
    path='/api/intelligence/context?device=192.0.2.1'
    status,raw=local_api.request('GET',path)
    assert status==422 and b'PRIVATE_SOURCE_PATH' not in raw
    local_api.provider.context_for_device=lambda address:{'subject':address}
    assert local_api.request('GET',path)[0]==200


@pytest.mark.parametrize('address',['192.0.2.8','2001:db8::8'])
def test_context_http_reads_real_evidence_without_inference_or_review(local_api,private_tmp_path,address):
    from megalodon.config import Settings
    from megalodon.evidence_storage import EvidenceStorage,utc,GIB
    from megalodon.intelligence import IntelligenceService

    clock=[1790816400]
    evidence=EvidenceStorage(Settings(db_path=private_tmp_path/'old.db'),home=private_tmp_path,
        clock=lambda:clock[0],monotonic=lambda:clock[0])
    evidence.apply(evidence.preview(dict(profile='home',retention_days=14,cap_bytes=20*GIB))['preview_id'])
    evidence.append_records('flows',[dict(observed_at=utc(clock[0]-10),source='zeek-conn',
        data=dict(src_ip=address,dst_ip='198.51.100.1',protocol='TCP',src_port=55000,dst_port=443,interface='eth0'))])
    service=IntelligenceService(evidence,SimpleNamespace(for_pattern=lambda rule:[]),
        SimpleNamespace(settings=Settings()),model=lambda *a,**kw:pytest.fail('Read-only route invoked AI'))
    local_api.handler.intelligence=service
    before=evidence.history(category='intelligence')['total']
    try:
        status,raw=local_api.request('GET','/api/intelligence/context?device='+address)
        context=json.loads(raw)
        assert status==200 and len(raw)<=3072
        assert context['subject']==address and context['groups'][0]['record_count']==1
        assert context['comparison']==dict(state='unavailable',reason='no_baseline')
        assert 'incomplete_window' in context['coverage']['missing']
        assert service.reviews=={} and evidence.history(category='intelligence')['total']==before
        entry=next(e for e in evidence._catalog['entries'] if e['category']=='flows')
        entry['state']='retired'
        status,raw=local_api.request('GET','/api/intelligence/context?device='+address)
        assert status==200 and json.loads(raw)['groups']==[]
        assert 'no_qualified_records' in json.loads(raw)['coverage']['missing']
    finally:
        service.close();evidence.close()
