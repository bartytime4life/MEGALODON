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


def test_common_setup_shortcuts_use_existing_gui_controls():
    from megalodon.dashboard_operations import SETUP_SHORTCUTS_HTML
    class Parse(HTMLParser):
        def __init__(self):
            super().__init__(); self.ids = {}; self.targets = []
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if attrs.get('id'): self.ids[attrs['id']] = attrs
            if tag == 'a' and 'href' in attrs: self.targets.append(attrs['href'])
    page, shortcuts = Parse(), Parse()
    page.feed(INDEX_HTML); shortcuts.feed(SETUP_SHORTCUTS_HTML)
    assert len(shortcuts.targets) == 6
    assert 'id="setup-category-traffic"' in INDEX_HTML
    assert 'id="setup-category-ai"' in INDEX_HTML
    assert 'id="setup-category-apps"' in INDEX_HTML, 'Setup categories replace the old duplicated shortcuts'
    for target in shortcuts.targets:
        assert target.startswith('#') and target[1:] in page.ids
    assert page.ids['support-model-title']['tabindex'] == '-1'
    assert page.ids['support-config-clamav-title']['tabindex'] == '-1'


def operations_fixture():
    stamp='2026-09-30T23:00:00Z'
    anchor=dict(latitude=38.5,longitude=-97.5,label='Synthetic internet exit',source='Synthetic offline fixture',country='US',approximate=True,accuracy_radius_km=None)
    local=dict(ip='192.168.1.10',scope='Private / reserved',version=4,local=True,location_role='local_exit_anchor',connections=2,local_connections=2,active_connections=2,packets=80,bytes=88000,sent_bytes=28000,received_bytes=60000,first_seen='2026-09-30T22:59:10Z',last_seen=stamp,ports=[dict(protocol='TCP',port=50484,hint=None)],names=[],location=anchor,flags=['ACK'],findings=[])
    peer={**local,'ip':'203.0.113.8','scope':'Public','local':False,'location_role':'observed_network_endpoint','location':None,'sent_bytes':60000,'received_bytes':28000,'ports':[dict(protocol='TCP',port=443,hint='HTTPS')],'names':[dict(name='<img src=x>',source='Observed TLS SNI',observed_at=stamp)],
          'name_review':[dict(schema='megalodon-name-review-v1',name='xkqzjvbwmtrplhgn.com',level='review',attack=['T1568.002'],signals=[dict(id='high_entropy',detail='Varied characters.'),dict(id='consonant_run',detail='Consonant run.')],context=['A spelling signal is not evidence of malware.'],action_status='not_attempted'),
                         dict(schema='megalodon-name-review-v1',name='forged-verdict.example',level='malicious',attack=[],signals=[dict(id='x',detail='forged-verdict')],context=[],action_status='not_attempted'),
                         dict(schema='megalodon-name-review-v1',name='forged-verdict.example',level='review',attack=[],signals=[dict(id='x',detail='forged-verdict')],context=[],action_status='applied')],
          'tls':[dict(schema='megalodon-tls-review-v1',level='review',version='TLS 1.0',attack=['T1573'],signals=[dict(id='legacy_protocol',detail='Deprecated protocol.')],context=['Not evidence of interception.'],observed_at=stamp,source='Suricata EVE TLS (sensor context)',action_status='not_attempted'),
                 dict(schema='megalodon-tls-review-v1',level='blocked',version=None,attack=[],signals=[dict(id='x',detail='forged-tls-verdict')],context=[],observed_at=stamp,source='x',action_status='not_attempted')]}
    return dict(schema='megalodon-operations-v1',observed_at=stamp,capture=dict(state='running'),background=dict(enabled=True),summary=dict(peers=2,active_connections=2,packets=80,bytes=88000,sent_bytes=28000,received_bytes=60000,unattributed_bytes=0),timeline=[dict(at='2026-09-30T22:59:55Z',sent_bytes=28000,received_bytes=60000,unattributed_bytes=0,packets=80)],protocols=[dict(name='TCP',packets=80,bytes=88000)],endpoints=[local,peer],storage=dict(status='ready',used_bytes=65536,limit_bytes=1048576,percent=6.3),coverage=dict(window_seconds=60,max_endpoints=64,unmapped=2,notes=['Synthetic test only.']))


def defense_fixture():
    return dict(schema='megalodon-defense-v1',token='b'*32,job=dict(state='idle',action=None,message='Ready for a local workflow.',started_at=None,finished_at=None,result=None),plans=[],recent=[],active=[],audit_ready=True,scope=dict(nmap_target='127.0.0.1/32',scan_folders=['Downloads']))


def connection_lens_fixture():
    """Synthetic documentation addresses only; no inference or response service."""
    from copy import deepcopy
    value=deepcopy(operations_fixture())
    base=value['endpoints'][1]
    base.update(names=[],name_review=[],tls=[],services=[],protocols=['TCP'],
                ports=[],findings=[],measurement_sources=[dict(source='Synthetic packet fixture',byte_basis='reported_bytes')])
    peers=[]
    for index in range(6):
        row=deepcopy(base);row.update(ip=f'203.0.113.{index+8}',local_connections=1)
        peers.append(row)
    stamp=value['observed_at']
    peers[0]['names']=[dict(name='api.example.test',source='Synthetic TLS SNI',observed_at=stamp)]
    peers[0]['ports']=[dict(protocol='TCP',port=443,hint='HTTPS')]
    peers[1]['services']=[dict(name='DNS',role='responder',source='Synthetic sensor context',peer='192.168.1.10',observed_at=stamp)]
    peers[1]['protocols']=['UDP'];peers[1]['ports']=[dict(protocol='UDP',port=53,hint='DNS')]
    peers[2]['findings']=[dict(signature='Synthetic review signal',severity='medium',source='Synthetic fixture',observed_at=stamp)]
    peers[4]['local_connections']=0
    peers[4]['location']=dict(label='Synthetic regional network location',source='Synthetic offline geography',approximate=True)
    # An older payload can omit the new relationship evidence, never imply a link.
    peers[5].pop('local_connections')
    value['endpoints']=[value['endpoints'][0],*peers]
    value['summary']['peers']=len(value['endpoints'])
    value['coverage']['notes']=['SYNTHETIC ACCEPTANCE DATA. No live sensors or host actions.']
    return value


def test_connection_lens_relationship_accessibility_focus_search_and_pause():
    if not shutil.which('node'):pytest.skip('Node unavailable')
    result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('connection_lens_browser.cjs'))],
        input=json.dumps(dict(code=OPERATIONS_JS,fixture=connection_lens_fixture())),
        text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr


def facts_fixture():
    from datetime import datetime
    from megalodon.ai_context import build_context,INPUT_SCHEMA
    now=int(datetime.fromisoformat(operations_fixture()['observed_at'].replace('Z','+00:00')).timestamp())
    return build_context(dict(schema=INPUT_SCHEMA,subject='203.0.113.8',window=dict(start=now-3600,end=now),as_of=now,
        sources=[dict(id='c'*32,kind='flows',expires_at=now+100)],
        records=[dict(ref='c'*32+':1',source='zeek-conn',scope_id='d'*32,kind='flows',observed_at=now-10,
            src_ip='203.0.113.8',dst_ip='198.51.100.4',protocol='TCP',src_port=55000,dst_port=443,
            missing=dict(tcp_flags='not_collected',findings='not_qualified'))],
        coverage=dict(truncated=True,missing=['incomplete_window','sensor_disagreement']),
        comparison=dict(state='unavailable',reason='truncated'),
        references=[dict(source='attack',edition='2026-08-05',id='T1046')]))


def test_read_only_facts_without_ai_and_stale_selection_rejection():
    if not shutil.which('node'):pytest.skip('Node unavailable')
    result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('endpoint_facts_browser.cjs'))],
        input=json.dumps(dict(code=OPERATIONS_JS,fixture=operations_fixture(),defense=defense_fixture(),facts=facts_fixture())),
        text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr


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
    assert p.ids.index('live-globe') < p.ids.index('network-panel') < p.ids.index('ops-pulse-title')
    assert p.ids.index('ops-lens') < p.ids.index('ops-endpoint-list') < p.ids.index('ops-inspector-title')
    for key in ('ops-pause','ops-filter-all','ops-filter-observed','ops-filter-review','ops-filter-unknown'):
        assert key in p.ids
    assert any(a.get('class') == 'ops-visual-grid' for _, a in p.owners['network-panel'])
    assert not any(a.get('class') == 'ops-atlas' for _, a in p.owners['network-panel'])
    for key in ('live-globe-camera', 'live-globe-zoom', 'network-page-size'):
        assert [a['id'] for _, a in p.owners[key] if a.get('role') == 'tabpanel'] == ['workspace-live']
    for key in ('operations-title','ops-pulse-title','live-globe','ops-endpoints-title','ops-defense-title','support-apps-start'):
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-live']
    for key in ('support-config','setup-title'):
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-setup']
    for key, category in [('live-geography-refresh','traffic'),('action-plane-title','advanced'),('app-viewer-title','advanced')]:
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-setup','setup-category-'+category]
    for key in ('room-traffic-grid','room-findings-visual','room-activity-table','inventory-title','clamav-title'):
        assert any(a.get('id')=='operations-history' and 'open' not in a for _,a in p.owners[key])
    assert 'id="workspace-tab-traffic"' not in INDEX_HTML
    assert "'workspace-traffic': 'live'" in DASHBOARD_JS
    assert OPERATIONS_CSS in DASHBOARD_CSS and OPERATIONS_JS in DASHBOARD_JS
    assert 'innerHTML' not in OPERATIONS_JS and 'localStorage' not in OPERATIONS_JS
    assert 'prefers-reduced-motion:reduce' in OPERATIONS_CSS
    assert '@media(max-width:900px),(pointer:coarse)' in OPERATIONS_CSS
    assert 'min-height:44px!important;font-size:.875rem!important' in OPERATIONS_CSS
    assert p.ids.index('ops-filter-unknown') < p.ids.index('ops-search') < p.ids.index('ops-lens')
    assert any(a.get('class') == 'ops-lens' for _,a in p.owners['ops-search'])
    assert 'ops-back-to-connections' in p.ids and 'ops-roster-search' in p.ids
    assert 'Retained endpoint evidence.' in INDEX_HTML
    assert 'aria-label="Jump to connection section"' in INDEX_HTML
    assert 'class="ops-view-current"' not in INDEX_HTML
    assert 'Unknown is not malicious.' in INDEX_HTML
    assert 'Best available identity' in OPERATIONS_JS
    assert 'no live DNS, WHOIS, reputation, service probe, payload inspection, or credential collection' in OPERATIONS_JS
    assert "function endpointState(e)" in OPERATIONS_JS
    assert "function lens()" in OPERATIONS_JS
