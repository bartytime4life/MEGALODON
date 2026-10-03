"""Supporting-app status dots, choice chips and motion stay presentation-only."""
import re
import shutil
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_polish import APP_RAIL_TOOLS, POLISH_CSS, POLISH_JS
from megalodon.tool_heartbeat import TOOL_IDS


def test_status_dots_cover_every_heartbeat_tool_and_link_to_setup():
    assert tuple(tool for tool, _ in APP_RAIL_TOOLS) == TOOL_IDS
    topbar = INDEX_HTML[INDEX_HTML.index('<header class="topbar">'):INDEX_HTML.index('</header>')]
    assert 'id="app-rail"' in topbar and 'id="app-rail-recheck"' in topbar
    tiles = INDEX_HTML[INDEX_HTML.index('<section class="support-apps"'):]
    assert tiles.index('class="app-tiles"') < tiles.index('id="support-apps-status"')
    # Each dot navigates through the reviewed workspace router to its Setup card.
    assert "map(id=>['setup-app-'+id,'setup'])" in DASHBOARD_JS
    for tool in TOOL_IDS:
        assert f'data-app-rail="{tool}" href="#setup-app-{tool}"' in INDEX_HTML
        assert f'data-app-tile="{tool}" href="#setup-app-{tool}"' in INDEX_HTML
    assert "if (typeof renderAppStatusRail === 'function') renderAppStatusRail();" in DASHBOARD_JS


def test_polish_layer_is_last_presentation_only_and_motion_safe():
    assert DASHBOARD_CSS.endswith(POLISH_CSS)
    assert POLISH_JS in DASHBOARD_JS and DASHBOARD_JS.index(POLISH_JS) < DASHBOARD_JS.rindex('bootstrap();')
    for forbidden in ('innerHTML', 'fetch(', 'localStorage', 'clipboard', 'XMLHttpRequest', 'eval('):
        assert forbidden not in POLISH_JS
    assert '@media (prefers-reduced-motion: reduce)' in POLISH_CSS
    animated = set(re.findall(r'animation:\s*([a-z-]+)', POLISH_CSS)) - {'none'}
    defined = set(re.findall(r'@keyframes ([a-z-]+)', DASHBOARD_CSS))
    assert animated <= defined, animated - defined


def test_rail_maps_heartbeat_lights_to_dots_and_summary():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node unavailable')
    script = r'''
const vm=require('node:vm'),assert=require('node:assert/strict'),fs=require('node:fs');
const code=fs.readFileSync(0,'utf8');
const ids=['core','tshark','zeek','suricata','scapy','nftables','clamav','osquery','qwen','nmap'];
function node(attr,id){const label={textContent:''};return {attrs:{[attr]:id},dataset:{},title:'',label,
  getAttribute(k){return this.attrs[k]||null;},hasAttribute(k){return k in this.attrs;},querySelector(){return label;}};}
const rail=ids.map(id=>node('data-app-rail',id)),tiles=ids.map(id=>node('data-app-tile',id));
const byId={'app-rail':{dataset:{}},'app-rail-summary':{textContent:''}};
const t=(id,light,service,model=null)=>({id,light,service,model,running_since:service==='running'?'2026-10-03T00:00:00Z':null});
const report={tools:[t('core','green','running'),t('tshark','green','running'),t('zeek','red','none'),t('suricata','amber','stopped'),
  t('scapy','green','standalone'),t('nftables','green','standalone'),t('clamav','grey','unknown'),t('osquery','red','none'),
  t('qwen','amber','running','missing'),t('nmap','green','standalone')]};
let stale=false,refilters=0;
const context={document:{querySelectorAll:()=>[...rail,...tiles],getElementById:id=>byId[id]||null},window:{megalodonAppsRefilter:()=>refilters++},
  heartbeatState:{report,failed:false,byId:new Map(report.tools.map(x=>[x.id,x]))},heartbeatStale:()=>stale,
  heartbeatText:tool=>tool?'light '+tool.light:'unknown',heartbeatAge:()=>'2h 0m'};
vm.runInNewContext(code,context);
context.renderAppStatusRail();
assert.deepEqual(rail.map(n=>n.dataset.state),['running','running','missing','stopped','ready','ready','unknown','missing','attention','ready']);
assert.deepEqual(tiles.map(n=>n.dataset.state),rail.map(n=>n.dataset.state));
assert.equal(tiles[0].label.textContent,'Running · up 2h 0m');
assert.equal(tiles[4].label.textContent,'Installed · runs on demand');
assert.equal(tiles[8].label.textContent,'Running · model missing');
assert.equal(rail[2].title,'light red','the full heartbeat wording stays in the tooltip');
assert.equal(byId['app-rail-summary'].textContent,'2 running · 3 installed · 2 stopped · 2 missing');
assert.equal(byId['app-rail'].dataset.stale,'false');assert.equal(refilters,1);
stale=true;context.renderAppStatusRail();
assert.ok(rail.every(n=>n.dataset.state==='unknown'),'stale observations never show green');
assert.equal(byId['app-rail-summary'].textContent,'Status stale · retrying');
context.heartbeatState.report=null;context.heartbeatState.failed=true;stale=false;context.renderAppStatusRail();
assert.equal(byId['app-rail-summary'].textContent,'Status unavailable');
'''
    result = subprocess.run([node, '-e', script], input=POLISH_JS, text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr


def test_choice_chips_only_drive_existing_controls():
    # Chips change a control's value and dispatch the events its own handlers already accept.
    assert "select.value = option.value; fire(select)" in POLISH_JS
    assert "input.value = next; fire(input)" in POLISH_JS
    for control in ('reports-range', 'filter-severity', 'storage-profile', 'storage-days', 'storage-cap', 'reference-port'):
        assert f"'{control}'" in POLISH_JS and f'id="{control}"' in INDEX_HTML
    assert 'data-apps-filter="all" aria-pressed="true"' in INDEX_HTML
