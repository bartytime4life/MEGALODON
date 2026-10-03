"""Report interaction and navigation contracts without browser automation."""
import json
import shutil
import subprocess
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import pytest
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS
from megalodon.dashboard_reports import REPORTS_JS


def test_cached_report_workflow_behavior():
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    result = subprocess.run([shutil.which('node'), str(Path(__file__).with_name('reports_browser.cjs'))], input=json.dumps({'code': REPORTS_JS}), text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_reports_and_configuration_are_in_their_own_workspaces():
    class Parse(HTMLParser):
        def __init__(self): super().__init__(); self.stack=[]; self.parents={}; self.ids=[]
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            if 'id' in attrs: self.ids.append(attrs['id']); self.parents[attrs['id']]=list(self.stack)
            if tag not in {'input','img','meta','link','br','hr','wbr','area','base','col','embed','param','source','track'}: self.stack.append((tag,attrs))
        def handle_endtag(self,tag):
            for i in range(len(self.stack)-1,-1,-1):
                if self.stack[i][0]==tag: del self.stack[i:];break
    p=Parse();p.feed(INDEX_HTML)
    assert not [id for id,count in Counter(p.ids).items() if count>1]
    for id in ['reports-create','reports-save','reports-print','reports-document']:
        assert [a['id'] for _,a in p.parents[id] if a.get('role')=='tabpanel']==['workspace-reports']
    assert 'hud-export-title' not in p.ids
    assert 'downloadHudExport' not in DASHBOARD_JS
    for id in ['apps-connections-title','apps-setup-cards','storage-disk-title']:
        assert [a['id'] for _,a in p.parents[id] if a.get('role')=='tabpanel']==['workspace-setup']
    assert 'sandbox="allow-same-origin allow-modals"' in INDEX_HTML
    assert 'id="room-report-preview"' not in INDEX_HTML
    assert 'id="report-scope"' not in INDEX_HTML
    assert 'hud-export-prepare' not in INDEX_HTML
    assert 'Check availability in Home' not in DASHBOARD_JS
    assert "...Object.fromEntries(['core','tshark'" in DASHBOARD_JS
    assert 'innerHTML' not in REPORTS_JS
    assert 'localStorage' not in REPORTS_JS
    assert '/api/host-telemetry' not in REPORTS_JS
    assert '@media(max-width:760px)' in DASHBOARD_CSS
    assert 'reports-desk :focus-visible' in DASHBOARD_CSS


def test_setup_single_renderer_search_and_direct_configuration_anchor():
    from megalodon.dashboard_integrations import APPS_SETUP_JS, INTEGRATIONS_JS
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    script=r'''
const vm=require('node:vm'),assert=require('node:assert/strict'),fs=require('node:fs');
const code=fs.readFileSync(0,'utf8'),nodes=new Map(),listeners={},mounts=[];
class E{constructor(tag,text=''){this.tag=tag;this.textContent=text;this.children=[];this.hidden=false;this.value='';this.events={};this.open=false;}append(...children){this.children.push(...children);}addEventListener(k,v){this.events[k]=v;}querySelector(tag){return this.children.find(n=>n.tag===tag);}focus(){this.focused=true;}scrollIntoView(){this.scrolled=true;}}
const get=id=>{if(!nodes.has(id))nodes.set(id,new E('div'));return nodes.get(id);};
const context={byId:get,textNode:(tag,text)=>new E(tag,text),installControl:(id)=>new E('button',id),heartbeatLight:()=>new E('i'),heartbeatDetail:()=>new E('span'),MegalodonControls:{ids:['core','tshark','zeek','suricata','scapy','nftables','clamav','osquery','qwen','nmap'],mount:(parent,id)=>mounts.push(id)},window:{location:{hash:''},addEventListener:(name,fn)=>listeners[name]=fn}};
vm.runInNewContext(code,context);assert.equal(mounts.length,10);assert.equal(new Set(mounts).size,10);get('apps-setup-query').value='qwen';get('apps-setup-query').events.input();assert.equal(get('apps-setup-cards').children.filter(n=>!n.hidden).length,1);context.window.location.hash='#setup-app-nmap';listeners.hashchange();const nmap=get('apps-setup-cards').children.find(n=>n.id==='setup-app-nmap');assert.equal(nmap.hidden,false);assert.equal(nmap.open,true);assert.equal(nmap.children[0].focused,true);assert.equal(nmap.scrolled,true,'a card revealed by clearing a filter is scrolled into view');assert.equal(mounts.length,10,'navigation reuses the same saved-link controls');
'''
    result=subprocess.run([shutil.which('node'),'-e',script],input=APPS_SETUP_JS,text=True,capture_output=True,timeout=10)
    assert result.returncode==0,result.stderr
    card=INTEGRATIONS_JS.split('function integrationCard(item)',1)[1].split('function ',1)[0]
    assert 'MegalodonControls.mount' not in card
    assert 'installControl(' not in card
    assert "configure.href='#setup-app-'+toolId" in card
