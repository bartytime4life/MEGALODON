"""Report actions inherit the local HUD's Host, Origin and nonce boundary."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from threading import Lock, Thread
from types import SimpleNamespace

import pytest

from megalodon.dashboard import DashboardHandler


@pytest.fixture
def report_http(monkeypatch):
    calls=[]
    class Reports:
        token='a'*32
        def snapshot(self):return {'operator_token':self.token,'reports':[]}
        def create(self, body):calls.append(('create',body));return {'state':'running'}
        def configure(self, body):calls.append(('configure',body));return {'saved':True}
        def cancel(self):calls.append(('cancel',));return {'state':'cancelled'}
        def findings(self, identifier, **values):calls.append(('findings',identifier,values));return {'records':[]}
        def download(self, identifier, kind):calls.append(('download',identifier,kind));return 'text/html; charset=utf-8',b'<!doctype html><p>Report</p>'
    reports=Reports()
    handler=type('ReportsHandler',(DashboardHandler,),{'reports':reports,'maintenance_lock':Lock(),'http_read_password':None,'http_password_verifier':None})
    monkeypatch.setattr('megalodon.dashboard._tool_management_user',lambda:True)
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    worker=Thread(target=server.serve_forever,daemon=True);worker.start()
    def request(method,path,body=None,omit=(),extra=()):
        raw=body if isinstance(body,bytes) else json.dumps(body).encode() if body is not None else None
        host=f'127.0.0.1:{server.server_port}'
        headers=[('Host',host)]
        if method=='GET':headers.append(('X-Megalodon-Check','1'))
        else:headers.extend([('Origin',f'http://{host}'),('Content-Type','application/json'),('X-Megalodon-Reports-Token',reports.token),('Content-Length',str(len(raw or b'')))])
        conn=HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        conn.putrequest(method,path,skip_host=True)
        for key,value in headers:
            if key not in omit:conn.putheader(key,value)
        for key,value in extra:conn.putheader(key,value)
        conn.endheaders(raw)
        response=conn.getresponse();data=response.read()
        result=(response.status,dict(response.getheaders()),data)
        conn.close();return result
    yield SimpleNamespace(request=request,calls=calls,handler=handler)
    server.shutdown();server.server_close();worker.join(3)


def test_reports_discovery_and_action(report_http):
    h=report_http
    assert h.request('GET','/api/reports')[0]==200
    assert h.request('POST','/api/reports/create',{})[0]==200
    assert h.calls==[('create',{})]


@pytest.mark.parametrize('header',['Host','Origin','Content-Type','X-Megalodon-Reports-Token'])
def test_missing_or_wrong_action_headers_are_rejected(report_http,header):
    status,_,_=report_http.request('POST','/api/reports/create',{},omit=(header,))
    assert status in (400,403)
    assert report_http.calls==[]


@pytest.mark.parametrize('extra',[
    [('Origin','http://evil.test')], [('X-Megalodon-Reports-Token','a'*32)],
    [('Content-Type','application/json')], [('Content-Encoding','gzip')], [('Transfer-Encoding','chunked')],
])
def test_duplicate_and_encoded_action_headers_rejected(report_http,extra):
    status,_,_=report_http.request('POST','/api/reports/create',{},extra=extra)
    assert status==403
    assert report_http.calls==[]


@pytest.mark.parametrize('body',[b'{"start":"x","start":"y"}', b'{"x":NaN}',b'{"x":Infinity}',b'[]',b'"x"',b'\xff\xfe'])
def test_invalid_json_rejected_without_provider_call(report_http,body):
    assert report_http.request('POST','/api/reports/create',body)[0]==422
    assert report_http.calls==[]


def test_cancel_only_accepts_empty_action(report_http):
    assert report_http.request('POST','/api/reports/cancel',{'id':'anything'})[0]==422
    assert not report_http.calls
    assert report_http.request('POST','/api/reports/cancel',{})[0]==200
    assert report_http.calls==[('cancel',)]


def test_protected_download_and_server_owned_filename(report_http):
    path='/api/reports/'+'b'*32+'/html'
    assert report_http.request('GET',path,omit=('X-Megalodon-Check',))[0]==403
    status,headers,raw=report_http.request('GET',path)
    assert status==200
    assert headers['Content-Disposition']=='attachment; filename="megalodon-report-'+'b'*32+'.html"'
    assert headers['X-Content-Type-Options']=='nosniff'
    assert "script-src 'self'" in headers['Content-Security-Policy']
    assert raw.startswith(b'<!doctype html>')


@pytest.mark.parametrize('path',[
    '/api/reports/../catalog.json/html', '/api/reports/'+'b'*32+'/html?path=/tmp/x',
    '/api/reports/'+'b'*32+'/findings?limit=1&limit=2',
    '/api/reports/'+'b'*32+'/findings?offset=-1', '/api/reports?token=x',
])
def test_download_and_query_allowlists(report_http,path):
    assert report_http.request('GET',path)[0]==422
    assert not report_http.calls


def test_report_css_available_without_report_data_access(report_http):
    status,headers,raw=report_http.request('GET','/assets/report.css',omit=('X-Megalodon-Check',))
    assert status==200 and headers['Content-Type'].startswith('text/css')
    assert b'@media print' in raw
