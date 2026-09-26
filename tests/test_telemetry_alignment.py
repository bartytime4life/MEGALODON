from pathlib import Path
from megalodon.telemetry_catalog import FEATURES, TOOLS, coverage_html, COVERAGE_CSS
from megalodon.dashboard_snapshot import SNAPSHOT_VALIDATOR_JS, SNAPSHOT_HOSTED_JS
from megalodon.tool_installer import RECIPES
from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS, DASHBOARD_CSS


def test_packaged_coverage_map_and_snapshot_validator():
    assert {row[0] for row in TOOLS}==set(RECIPES)
    assert len({row[0] for row in FEATURES})==len(FEATURES)
    assert coverage_html() in INDEX_HTML
    assert SNAPSHOT_VALIDATOR_JS in DASHBOARD_JS
    assert COVERAGE_CSS in DASHBOARD_CSS
    for _,_,_,_,target in FEATURES:
        assert f'id="{target}"' in INDEX_HTML
    assert 'adapter not implemented' in coverage_html()


def test_connection_observations_do_not_promote_missing_stale_or_paused_data():
    import shutil, subprocess
    import pytest
    from megalodon.dashboard_snapshot import SNAPSHOT_LOCAL_JS
    node=shutil.which('node')
    if not node:pytest.skip('Node needed for connection-state behavior')
    harness=r'''
const vm=require('node:vm'),assert=require('node:assert/strict');let code='';process.stdin.on('data',x=>code+=x);process.stdin.on('end',()=>{
 const nodes=new Map();const context={Date,document:{hidden:false},state:{paused:false},roomState:{snapshot:null,failed:false},heartbeatState:{report:null,catalog:null},heartbeatStale:()=>false,
 byId:id=>{if(!nodes.has(id))nodes.set(id,{textContent:'',addEventListener(){}});return nodes.get(id);}};
 vm.createContext(context);vm.runInContext(code,context);const paint=()=>vm.runInContext('renderTelemetryConnections()',context);
 paint();assert.equal(nodes.get('telemetry-traffic-state').textContent,'No qualified records');assert.equal(nodes.get('telemetry-tools-state').textContent,'No observation');
 context.roomState.snapshot={events:[{}],generated_at:new Date().toISOString()};context.heartbeatState.report={checked_at:new Date().toISOString()};context.heartbeatState.catalogFailed=true;
 paint();assert.equal(nodes.get('telemetry-traffic-state').textContent,'Stored metadata available');assert.equal(nodes.get('telemetry-tools-state').textContent,'Tool presence observed');assert.equal(nodes.get('telemetry-management-state').textContent,'Status unavailable');
 context.state.paused=true;paint();assert.equal(nodes.get('telemetry-traffic-state').textContent,'Refresh paused');
 context.roomState.failed=true;context.heartbeatStale=()=>true;paint();assert.equal(nodes.get('telemetry-traffic-state').textContent,'Refresh failed');assert.equal(nodes.get('telemetry-tools-state').textContent,'Stale tool observation');
 assert.match(nodes.get('telemetry-traffic-time').textContent,/sensor health unknown/);
});
'''
    subprocess.run([node,'-e',harness],input=SNAPSHOT_LOCAL_JS,text=True,check=True,timeout=10)


def test_repository_site_mirror_matches_packaged_sources():
    import pytest
    root=Path(__file__).resolve().parents[1]
    if not (root/'site/dist').is_dir():
        pytest.skip('Hosted Site mirror is separate from the Python source distribution')
    assert coverage_html(hosted=True) in (root/'site/dist/index.html').read_text()
    assert (root/'site/dist/snapshot.js').read_text()==SNAPSHOT_VALIDATOR_JS+SNAPSHOT_HOSTED_JS
    assert (root/'site/dist/telemetry.css').read_text()==COVERAGE_CSS
