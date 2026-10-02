"""Shipped topology UI behavior against synthetic local network observations."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from megalodon.dashboard_network import NETWORK_HTML,NETWORK_SETUP_HTML,NETWORK_CSS,NETWORK_JS


def fixture():
    stamp='2026-09-30T23:00:00Z'
    def node(id,ip,role,observed=False,discovered=False):
        return dict(id=id,ip=ip,name=ip,interface='eth0',group='eth0',role=role,mac=None,source='Synthetic test observation',first_seen=stamp,last_seen=stamp,discovered=discovered,observed=observed,sent_bytes=100 if observed else None,received_bytes=200 if observed else None,packets=3 if observed else None,ports=[],names=[],findings=[],scope='Private / reserved',local=role=='pc',active_connections=1 if observed else 0)
    return dict(schema='megalodon-network-v1',token='a'*32,observed_at=stamp,state='ready',message='Local observations',settings=dict(scopes=[],enabled=False,interval_seconds=900),available_scopes=[dict(cidr='192.168.2.0/24',interface='eth0',label='eth0 on-link IPv4')],groups=[dict(id='eth0',label='eth0',kind='lan')],nodes=[node('pc','192.168.2.10','pc',True),node('peer','192.168.2.20','device',True),node('discovered','192.168.2.30','device',False,True)],edges=[dict(id='flow',source='pc',target='peer',kind='observed',sent_bytes=100,received_bytes=200,active=True),dict(id='known',source='pc',target='discovered',kind='discovered',sent_bytes=None,received_bytes=None,active=False)],total=3,offset=0,limit=50,truncated=False,discovery=dict(state='disabled',last_run_at=None,next_run_at=None,message='Discovery disabled.'),coverage=['Synthetic test data only.'])


def test_network_behavior_validation_selection_and_explicit_configuration():
    node=shutil.which('node')
    if not node:pytest.skip('Node unavailable')
    result=subprocess.run([node,str(Path(__file__).with_name('network_browser.cjs'))],input=json.dumps(dict(code=NETWORK_JS,fixture=fixture())),capture_output=True,text=True,timeout=10)
    assert result.returncode==0,result.stderr


def test_network_component_has_text_alternative_and_no_unsafe_sinks():
    assert 'Your network, explained' in NETWORK_HTML
    assert 'id="network-directory"' in NETWORK_HTML and 'id="network-selection"' in NETWORK_HTML
    assert '<svg' not in NETWORK_HTML and "svg('" not in NETWORK_JS
    assert '<details class="network-roster" id="network-technical">' in NETWORK_HTML
    assert '<details class="network-filters" id="network-filters">' in NETWORK_HTML
    assert 'id="network-search"' in NETWORK_HTML and '<table>' in NETWORK_HTML
    assert 'id="network-setup-form"' in NETWORK_SETUP_HTML
    assert 'known individual /128 peers' in NETWORK_SETUP_HTML
    assert 'innerHTML' not in NETWORK_JS and 'localStorage' not in NETWORK_JS
    assert 'prefers-reduced-motion:reduce' in NETWORK_CSS
    assert 'window.MegalodonOperations?.selectEndpoint' in NETWORK_JS
    assert "edge.kind!=='observed'" in NETWORK_JS
    assert 'not current speeds or lifetime totals' in NETWORK_HTML
