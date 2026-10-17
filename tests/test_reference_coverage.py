"""Reference coverage is a passive, time-bounded fact, not a safety verdict."""
from datetime import timedelta
from types import SimpleNamespace
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon.host_security import HostSecurity, SOURCES, CACHE_SCHEMA, parse_feed
from megalodon.operations import Operations
from megalodon.live_connections import LiveConnections
from megalodon.config import Settings
from megalodon.dashboard_operations import OPERATIONS_JS
from test_host_security import NOW, source_body
from test_dashboard_operations_ui import operations_fixture


@pytest.mark.parametrize('ages,state,active', [((0,0,0),'ready',3),
    ((48,48,48),'stale',0), ((49,49,49),'stale',0), ((0,49,49),'partial',1)])
def test_coverage_and_matching_share_one_read_and_expiry_instant(monkeypatch, ages, state, active):
    feeds = [parse_feed(source, source_body(source, NOW-timedelta(hours=age)), NOW-timedelta(hours=age))
             for source,age in zip(SOURCES,ages)]
    calls=[]
    manager=HostSecurity(now=lambda:NOW, downloader=lambda *_:pytest.fail('Unexpected download'),
                         runner=lambda *_:pytest.fail('Unexpected process'))
    def saved(name):
        calls.append(name)
        return dict(schema=CACHE_SCHEMA, feeds=feeds)
    monkeypatch.setattr(manager,'_json',saved)
    context=manager.reference_context(['8.8.8.8','2606:4700:4700::1111'])
    assert calls == ['feeds.json']
    assert context['state']==state
    assert len(context['matches'])==active
    assert sum(row['state']=='ready' for row in context['feeds'])==active
    assert all(row['action_status']=='not_attempted' for row in context['matches'])


def test_missing_cache_is_explicit_and_read_only(monkeypatch):
    manager=HostSecurity()
    monkeypatch.setattr(manager,'_json',lambda *_:None)
    monkeypatch.setattr(manager,'_save',lambda *_:pytest.fail('Read wrote state'))
    context=manager.reference_context(['8.8.8.8'])
    assert context['state']=='missing' and context['matches']==[] and context['feeds']==[]


def test_overlapping_prefixes_preserve_later_endpoint_match_parity(monkeypatch):
    from ipaddress import ip_network
    addresses=['8.8.8.'+str(n) for n in range(1,65)]
    ranges=sorted({str(ip_network(address+'/'+str(prefix),strict=False))
        for address in addresses for prefix in range(8,33)})
    rows=[dict(cidr=cidr,sblid='SBL1') for cidr in ranges]
    rows.append(dict(type='metadata',timestamp=int(NOW.timestamp()),records=len(ranges)))
    raw=('\n'.join(json.dumps(row) for row in rows)+'\n').encode()
    feeds=[parse_feed(source,raw if source=='drop-v4' else source_body(source),NOW) for source in SOURCES]
    manager=HostSecurity(now=lambda:NOW)
    monkeypatch.setattr(manager,'_json',lambda *_:dict(schema=CACHE_SCHEMA,feeds=feeds))
    context=manager.reference_context(addresses)
    matches=[r for r in context['matches'] if r['source']=='drop-v4']
    assert len(matches)==64
    assert {r['ip'] for r in matches}==set(addresses)
    assert all(r['indicator']==r['ip']+'/32' for r in matches)
    assert len(context['matches'])<=len(addresses)*3


@pytest.mark.parametrize('failure',[None,ValueError('PRIVATE_DETAIL')])
def test_operations_exposes_unavailability_without_error_text_or_side_effects(tmp_path,failure):
    cache=LiveConnections(SimpleNamespace(snapshot=lambda:{'anchor':None},lookup=lambda _:None))
    config=SimpleNamespace(settings=Settings(db_path=tmp_path/'absent.db'),
                           live_snapshot=lambda:cache.snapshot({'state':'stopped'},{}))
    if failure:
        def unavailable(_):raise failure
        config.host_security=SimpleNamespace(reference_context=unavailable)
    value=Operations(config,context_reader=lambda:{}).snapshot()
    assert value['reference_context']['state']=='unavailable'
    assert value['reference_context']['feeds']==[]
    assert 'PRIVATE_DETAIL' not in json.dumps(value)


def test_operations_reads_same_context_for_retained_endpoints_only(tmp_path):
    from megalodon.models import PacketEvent
    from datetime import datetime,timezone
    cache=LiveConnections(SimpleNamespace(snapshot=lambda:{'anchor':None},lookup=lambda _:None))
    cache.observe(PacketEvent(datetime.now(timezone.utc),'10.0.0.2','8.8.8.8','TCP',50000,443))
    calls=[]
    def context(addresses):
        calls.append(addresses)
        return dict(schema='megalodon-reference-context-v1',state='missing',checked_at='2026-10-16T12:00:00Z',feeds=[],matches=[])
    config=SimpleNamespace(settings=Settings(db_path=tmp_path/'absent.db'),
        live_snapshot=lambda:cache.snapshot({'state':'stopped'},{}),
        host_security=SimpleNamespace(reference_context=context))
    value=Operations(config,context_reader=lambda:{}).snapshot()
    assert calls==[[row['ip'] for row in value['endpoints']]]
    assert value['reference_context']['state']=='missing'
    assert 'matches' not in value['reference_context']


def test_reference_ui_states_expiry_and_selection_are_read_only():
    if not shutil.which('node'):pytest.skip('Node unavailable')
    result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('reference_coverage_browser.cjs'))],
        input=json.dumps(dict(code=OPERATIONS_JS,fixture=operations_fixture())),text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr
