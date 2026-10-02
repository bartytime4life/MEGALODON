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
    yield SimpleNamespace(request=request,calls=calls)
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
