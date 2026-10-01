"""Exercise reviewed storage transitions and navigation using the shipped script."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from megalodon.dashboard_storage import STORAGE_JS
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS


def storage_fixture():
    return dict(schema='megalodon-storage-v1',token='a'*32,enabled=False,policy=dict(profile='home',retention_days=14,cap_bytes=20*1073741824,recording_mode='packet_metadata'),profiles=[dict(id=k,label=k,retention_days=d,cap_bytes=g*1073741824,recording_mode=m) for k,d,g,m in [('home',14,20,'packet_metadata'),('lab',14,100,'packet_metadata'),('server',7,500,'connection_summaries')]],used_bytes=1073741824,free_disk_bytes=100*1073741824,percent=5,oldest_at='2026-09-28T00:00:00Z',newest_at='2026-09-30T00:00:00Z',actual_days=2,estimated_days=20,required_bytes=15*1073741824,estimate_provisional=True,growth_bytes_per_day=1073741824,categories=[dict(id='findings',label='Findings',bytes=1024,records=12,oldest_at='2026-09-28T00:00:00Z',newest_at='2026-09-30T00:00:00Z')],warnings=[],state='disabled',message='Preview a policy to enable rotation.',last_cleanup_at=None,history_count=51)


def test_storage_reviewed_transitions_and_bounded_export():
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    result=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('storage_browser.cjs'))],input=json.dumps(dict(code=STORAGE_JS,fixture=storage_fixture())),text=True,capture_output=True,timeout=15)
    assert result.returncode==0,result.stderr


def test_storage_and_expanded_workspace_composition():
    from html.parser import HTMLParser
    from collections import Counter
    class Parse(HTMLParser):
        def __init__(self):super().__init__();self.stack=[];self.owners={};self.ids=[]
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            if 'id' in attrs:self.ids.append(attrs['id']);self.owners[attrs['id']]=list(self.stack)
            if tag not in {'input','img','meta','link','br','hr','wbr','area','base','col','embed','param','source','track'}:self.stack.append((tag,attrs))
        def handle_endtag(self,tag):
            for i in range(len(self.stack)-1,-1,-1):
                if self.stack[i][0]==tag:del self.stack[i:];break
    p=Parse();p.feed(INDEX_HTML)
    assert not [k for k,v in Counter(p.ids).items() if v>1]
    for key in ['storage-history-title','storage-profile','storage-preview']:
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-setup']
    assert [a['id'] for _,a in p.owners['storage-evidence-title'] if a.get('role')=='tabpanel']==['workspace-analysis']
    for key in ['ops-download','ops-upload','pc-network-chart','ops-storage-coverage']:
        assert [a['id'] for _,a in p.owners[key] if a.get('role')=='tabpanel']==['workspace-live']
        assert not any(tag=='details' for tag,_ in p.owners[key]),'primary speeds and chart must be visible'
    assert any(tag=='details' for tag,_ in p.owners['pc-resources-title'])
    assert 'width: min(2200px, calc(100% - 32px))' in DASHBOARD_CSS
    assert 'class="hero" aria-labelledby="page-title"' not in INDEX_HTML
    assert STORAGE_JS in DASHBOARD_JS
    assert 'innerHTML' not in STORAGE_JS
