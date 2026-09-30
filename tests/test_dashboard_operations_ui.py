"""Shipped operations UI exercised with synthetic observations and inert DOM."""
import json
from pathlib import Path
from html.parser import HTMLParser
from collections import Counter
import shutil
import subprocess
import pytest
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
from megalodon.dashboard_operations import OPERATIONS_JS, OPERATIONS_CSS


def operations_fixture():
    stamp='2026-09-30T23:00:00Z'
    local=dict(ip='192.168.1.10',scope='Private / reserved',version=4,local=True,connections=2,active_connections=2,packets=80,bytes=88000,sent_bytes=28000,received_bytes=60000,first_seen='2026-09-30T22:59:10Z',last_seen=stamp,ports=[dict(protocol='TCP',port=50484,hint=None)],names=[],location=None,flags=['ACK'],findings=[])
    peer={**local,'ip':'203.0.113.8','scope':'Public','local':False,'sent_bytes':60000,'received_bytes':28000,'ports':[dict(protocol='TCP',port=443,hint='HTTPS')],'names':[dict(name='<img src=x>',source='Observed TLS SNI',observed_at=stamp)]}
    return dict(schema='megalodon-operations-v1',observed_at=stamp,capture=dict(state='running'),background=dict(enabled=True),summary=dict(peers=2,active_connections=2,packets=80,bytes=88000,sent_bytes=28000,received_bytes=60000,unattributed_bytes=0),timeline=[dict(at='2026-09-30T22:59:55Z',sent_bytes=28000,received_bytes=60000,unattributed_bytes=0,packets=80)],protocols=[dict(name='TCP',packets=80,bytes=88000)],endpoints=[local,peer],storage=dict(status='ready',used_bytes=65536,limit_bytes=1048576,percent=6.3),coverage=dict(window_seconds=60,max_endpoints=64,unmapped=2,notes=['Synthetic test only.']))


def defense_fixture():
    return dict(schema='megalodon-defense-v1',token='b'*32,job=dict(state='idle',action=None,message='Ready for a local workflow.',started_at=None,finished_at=None,result=None),plans=[],recent=[],active=[],audit_ready=True,scope=dict(nmap_target='127.0.0.1/32',scan_folders=['Downloads']))


def test_operations_selection_fixed_defense_actions_and_visibility():
    if not shutil.which('node'):pytest.skip('Node unavailable')
    result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('operations_browser.cjs'))],input=json.dumps(dict(code=OPERATIONS_JS,fixture=operations_fixture(),defense=defense_fixture())),text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr


def test_operations_layout_ownership_and_closed_history():
    class Parse(HTMLParser):
        def __init__(self):super().__init__();self.parents=[];self.owners={};self.ids=[]
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            if 'id' in attrs:self.ids.append(attrs['id']);self.owners[attrs['id']]=list(self.parents)
            if tag not in {'input','img','meta','link','br','hr','wbr','area','base','col','embed','param','source','track'}:self.parents.append((tag,attrs))
        def handle_endtag(self,tag):
            for i in range(len(self.parents)-1,-1,-1):
                if self.parents[i][0]==tag:del self.parents[i:];break
    p=Parse();p.feed(INDEX_HTML)
    assert not [k for k,v in Counter(p.ids).items() if v>1]
    for key in ('operations-title','ops-pulse-title','live-globe','ops-endpoints-title','ops-defense-title','support-apps-start'):
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-live']
    for key in ('support-config','setup-title','live-geography-refresh','action-plane-title','app-viewer-title'):
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-setup']
    for key in ('room-traffic-grid','room-findings-visual','room-activity-table','inventory-title','clamav-title'):
        assert any(a.get('id')=='operations-history' and 'open' not in a for _,a in p.owners[key])
    assert 'id="workspace-tab-traffic"' not in INDEX_HTML
    assert "'workspace-traffic': 'live'" in DASHBOARD_JS
    assert OPERATIONS_CSS in DASHBOARD_CSS and OPERATIONS_JS in DASHBOARD_JS
    assert 'innerHTML' not in OPERATIONS_JS and 'localStorage' not in OPERATIONS_JS
    assert 'prefers-reduced-motion:reduce' in OPERATIONS_CSS
    assert '@media(max-width:900px),(pointer:coarse)' in OPERATIONS_CSS
    assert 'min-height:44px!important;font-size:.875rem!important' in OPERATIONS_CSS
