from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Thread
from types import SimpleNamespace
import pytest

from megalodon import dashboard


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(dashboard,'_tool_management_user',lambda:True)
    calls=[]
    defense=SimpleNamespace(token='x'*32,snapshot=lambda **kw:{'schema':'megalodon-defense-v1'},start=lambda body:calls.append(body) or {'state':'running'})
    operations=SimpleNamespace(snapshot=lambda:{'schema':'megalodon-operations-v1'})
    handler=type('DefenseHandler',(dashboard.DashboardHandler,),{'defense':defense,'operations':operations})
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    thread=Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    try:yield server,calls,handler
    finally:server.shutdown();server.server_close();thread.join(2)


def request(endpoint,*,method='POST',path='/api/defense',body=b'{"action":"scan_files"}',omit=(),extra=()):
    server,_,_=endpoint;origin=f'http://127.0.0.1:{server.server_port}'
    headers=[('Host',origin[7:]),('Origin',origin),('Content-Type','application/json'),('Content-Length',str(len(body))),('X-Megalodon-Defense-Token','x'*32),('X-Megalodon-Check','1')]
    connection=HTTPConnection('127.0.0.1',server.server_port,timeout=3)
    try:
        connection.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
        for key,value in headers:
            if key not in omit:connection.putheader(key,value)
        for key,value in extra:connection.putheader(key,value)
        connection.endheaders(body)
        response=connection.getresponse();return response.status,json.loads(response.read())
    finally:connection.close()


def test_read_never_executes_and_fixed_action_queues(endpoint):
    assert request(endpoint,method='GET',body=b'')[0]==200
    assert request(endpoint,method='GET',body=b'',path='/api/operations')[0]==200
    assert endpoint[1]==[]
    assert request(endpoint)[0]==202 and endpoint[1]==[{'action':'scan_files'}]


@pytest.mark.parametrize('extra,omit,status',[
    ((),('X-Megalodon-Defense-Token',),403),
    ((('X-Megalodon-Defense-Token','y'*32),),(),403),
    ((('Origin','http://foreign.invalid'),),('Origin',),403),
    ((('Host','foreign.invalid'),),('Host',),400),
    ((('Content-Type','text/plain'),),('Content-Type',),403),
    ((('Transfer-Encoding','chunked'),),(),403),
    ((('Content-Encoding','gzip'),),(),403),
    ((('Content-Length','999999'),),('Content-Length',),400),
    ((('Content-Length','22'),),(),400),
])
def test_foreign_ambiguous_or_tokenless_request_cannot_act(endpoint,extra,omit,status):
    assert request(endpoint,extra=extra,omit=omit)[0]==status
    assert endpoint[1]==[]


@pytest.mark.parametrize('body',[b'{"action":"scan_files","action":"refresh_inventory"}',b'{"action":"scan_files","command":"id"}',b'null'])
def test_duplicate_and_arbitrary_fields_cannot_act(endpoint,body):
    assert request(endpoint,body=body)[0]==400 and endpoint[1]==[]


def test_optional_signin_query_and_local_checks(endpoint,monkeypatch):
    assert request(endpoint,path='/api/defense?x=1')[0]==405
    assert request(endpoint,method='GET',path='/api/operations?ip=1.1.1.1')[0]==400
    assert request(endpoint,method='GET',omit=('X-Megalodon-Check',))[0]==403
    endpoint[2].http_read_password='test-only'
    assert request(endpoint)[0]==401
    endpoint[2].http_read_password=None
    monkeypatch.setattr(dashboard,'_tool_management_user',lambda:False)
    assert request(endpoint)[0]==403 and endpoint[1]==[]
