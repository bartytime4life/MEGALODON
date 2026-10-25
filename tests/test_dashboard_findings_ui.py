"""Findings selection, source binding and explicit response confirmation contracts."""
from collections import Counter
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import shutil
import subprocess
import pytest
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
from megalodon.dashboard_findings import FINDINGS_HTML, FINDINGS_JS, FINDINGS_CSS, CAUTION_JS
from megalodon.dashboard_operations import OPERATIONS_JS


def findings_fixture():
    at=datetime.now(timezone.utc)
    stamp=lambda d:d.isoformat().replace('+00:00','Z')
    a=dict(id='detector:'+'a'*32+':7',kind='detector',source='Fixed detector',source_role='Recorded fixed rule',title='Port scan threshold',severity='medium',severity_basis='Recorded fixed severity',observed_at=stamp(at-timedelta(minutes=5)),subject='1.1.1.1',summary='<script> is evidence, not markup',review_state='unreviewed',evidence_refs=['a'*32+':23'])
    b={**a,'id':'pattern:'+'b'*32,'kind':'pattern','title':'Unusual volume candidate','severity':'unknown','severity_basis':'No recorded rule severity','subject':'192.168.1.40'}
    detail=dict(finding=a,context_sha256='c'*64,facts=dict(distinct_ports=30,window_seconds=10,missing=None),evidence_refs=a['evidence_refs'],gaps=['One event is not complete window coverage.'],analysis=dict(state='not_requested',explanation=None,alternative=None,missing=None,citations=[],references=[],model=None,model_digest=None,context_sha256='c'*64,message='Ask about the exact selected facts.'),impact=dict(effect='Drop one IP on this PC.',duration_seconds=300,preview_seconds=60,caution=['Shared services may disconnect.'],unknowns=['Complete dependencies are unknown.'],targets=[dict(ip='1.1.1.1',eligible=True,reason='Current public peer passes guards.',observed_ports=[dict(protocol='TCP',port=443,hint='HTTPS')],observed_services=[],observed_peers=[])]))
    defense=dict(schema='megalodon-defense-v1',token='d'*32,audit_ready=True,job=dict(state='idle',message='Ready.',request_id=None,action=None,result=None),plans=[],recent=[],active=[],scope=dict(nmap_target='127.0.0.1/32',scan_folders=['Downloads']))
    return dict(schema='megalodon-findings-v1',generated_at=stamp(at),state='available',token='f'*32,model=dict(name='Synthetic selected model',digest='b'*64,settings_sha256='b'*64),scope=dict(start=stamp(at-timedelta(days=1)),end=stamp(at),source='all',severity='all'),items=[a,b],page=dict(limit=25,returned=2,next_cursor='next-page',candidate_count=3,truncated=True),gaps=[],selected=detail,selection_message=None,job=dict(id=None,state='idle',finding_id=None,message='Select evidence.'),defense=defense)


def run_harness(name,**values):
    node=shutil.which('node')
    if not node:pytest.skip('Node unavailable')
    result=subprocess.run([node,str(Path(__file__).with_name(name))],input=json.dumps(values),capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    return result.stdout


def test_findings_scope_queue_ai_feedback_and_bound_containment_interactions():
    run_harness('findings_browser.cjs',code=FINDINGS_JS,html=FINDINGS_HTML,fixture=findings_fixture())


def test_dense_same_time_edge_bursts_and_long_review_remain_explorable():
    run_harness('findings_browser.cjs',code=FINDINGS_JS,html=FINDINGS_HTML,fixture=findings_fixture(),stress=True)


def test_long_source_summary_and_ai_excerpts_preserve_exact_complete_text():
    run_harness('findings_browser.cjs',code=FINDINGS_JS,html=FINDINGS_HTML,fixture=findings_fixture(),longText=True)
    assert FINDINGS_HTML.index('id="fw-story"') < FINDINGS_HTML.index('id="fw-metrics"') < FINDINGS_HTML.index('id="fw-source-summary"')


def test_caution_dialog_requires_fresh_acknowledgment_and_cancel_never_confirms():
    run_harness('findings_caution_browser.cjs',code=CAUTION_JS)


def test_findings_composition_preserves_unique_handlers_and_single_active_owner():
    ids=re.findall(r'\bid="([^"]+)"',INDEX_HTML)
    assert len(ids)==len(set(ids)),Counter(ids)
    for element in ['workspace-findings','room-findings-title','room-findings-table','room-evidence-title','pattern-reviews','ki-reviews','knowledge-setup','ki-device-review','ops-apply','containment-caution']:
        assert f'id="{element}"' in INDEX_HTML
    assert 'data-findings-owned="true"' in INDEX_HTML
    assert 'body:has(#workspace-findings:not([hidden])) .room-chrome{display:none}' in FINDINGS_CSS
    assert '<div class="fw-legacy" inert>' in INDEX_HTML
    assert FINDINGS_JS in DASHBOARD_JS and CAUTION_JS in DASHBOARD_JS and FINDINGS_CSS in DASHBOARD_CSS
    assert "getAttribute?.('data-findings-owned')==='true'" in DASHBOARD_JS
    assert "getAttribute?.('data-findings-owned')!=='true'" in DASHBOARD_JS
    assert 'href="#room-findings-title">Review activity' in INDEX_HTML


def test_operations_apply_uses_same_caution_without_changing_defense_payload():
    assert "owner:'operations'" in OPERATIONS_JS
    assert 'window.MegalodonCaution.open(' in OPERATIONS_JS
    assert "if(confirmed&&valid())action('apply_containment',{plan_id:plan.id})" in OPERATIONS_JS
    assert 'acknowledge_disruption' not in OPERATIONS_JS
    assert "acknowledge_disruption:true" in FINDINGS_JS
    assert "S.planRequest.id" in FINDINGS_JS and "S.feed?.model.settings_sha256" in FINDINGS_JS
    assert 'innerHTML' not in FINDINGS_JS+CAUTION_JS
