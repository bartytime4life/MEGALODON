"""Supporting-app status dots, choice chips and motion stay presentation-only."""
import re
import shutil
import subprocess
from html.parser import HTMLParser

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_CSS, DASHBOARD_JS
from megalodon.dashboard_polish import APP_RAIL_TOOLS, POLISH_CSS, POLISH_JS
from megalodon.tool_heartbeat import TOOL_IDS
from megalodon.dashboard_visual_controls import VISUAL_CONTROLS_CSS


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
    assert POLISH_CSS in DASHBOARD_CSS and DASHBOARD_CSS.endswith(VISUAL_CONTROLS_CSS)
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
assert.equal(byId['app-rail-summary'].textContent,'2 running · 3 installed · 1 stopped · 1 need attention · 2 missing · 1 status unknown');
assert.equal(byId['app-rail'].dataset.stale,'false');assert.equal(refilters,1);
const qwen=context.heartbeatState.byId.get('qwen');
qwen.model='present';qwen.selected_model={state:'ready',model:'installed-model',message:'Present; verify a reply.'};
context.renderAppStatusRail();
assert.equal(rail[8].dataset.state,'attention','an available model without a recent reply stays amber');
assert.equal(tiles[8].label.textContent,'Model available · verify response','availability is not described as missing setup');
assert.match(byId['app-rail-summary'].textContent,/1 need attention/);
qwen.selected_model.state='error';context.renderAppStatusRail();
assert.equal(tiles[8].label.textContent,'AI check needs attention');
assert.equal(rail[8].dataset.state,'attention','an AI failure cannot turn the dot green');
qwen.selected_model.state='needs_setup';context.renderAppStatusRail();
assert.equal(tiles[8].label.textContent,'Local AI needs setup');
qwen.selected_model.state='collecting';qwen.light='grey';context.renderAppStatusRail();
assert.equal(tiles[8].label.textContent,'Checking local AI');
assert.equal(rail[8].dataset.state,'unknown','work in progress is not readiness');
qwen.selected_model.state='connected';qwen.light='amber';context.renderAppStatusRail();
assert.equal(rail[8].dataset.state,'attention');
assert.notEqual(tiles[8].label.textContent,'Recent AI response','a conflicting amber light cannot advertise a verified reply');
qwen.light='green';context.renderAppStatusRail();
assert.equal(rail[8].dataset.state,'running');
assert.equal(tiles[8].label.textContent,'Recent AI response');
stale=true;context.renderAppStatusRail();
assert.ok(rail.every(n=>n.dataset.state==='unknown'),'stale observations never show green');
assert.equal(tiles[8].label.textContent,'Status unknown','stale AI observations must not retain recent-response wording');
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
    for control in ('reports-range', 'filter-severity', 'storage-profile', 'reference-port'):
        assert f"'{control}'" in POLISH_JS and f'id="{control}"' in INDEX_HTML
    assert 'data-apps-filter="all" aria-pressed="true"' in INDEX_HTML


def test_status_dots_differ_by_shape_not_only_hue():
    # Red/green alone fails common colour-vision deficiencies; each state also has its own outline.
    assert re.search(r'\[data-state="stopped"\] > \.app-dot[^{]*\{[^}]*rotate\(45deg\)', POLISH_CSS)
    assert re.search(r'\[data-state="missing"\] > \.app-dot[^{]*\{[^}]*background:transparent; border:2px solid', POLISH_CSS)
    assert re.search(r'\[data-state="unknown"\] > \.app-dot \{[^}]*border:2px dashed', POLISH_CSS)
    # Installed-but-idle is half filled, so it never relies on the running pulse (absent under reduced motion).
    assert re.search(r'\[data-state="ready"\] > \.app-dot[^{]*\{[^}]*linear-gradient\(90deg,var\(--dot-ready\) 50%,transparent 50%\)', POLISH_CSS)
    forced = POLISH_CSS[POLISH_CSS.index('@media (forced-colors: active)'):]
    assert 'linear-gradient(90deg,CanvasText 50%,Canvas 50%)' in forced
    running_rule = forced[forced.index('[data-state="running"] > .app-dot'):]
    assert '[data-state="ready"]' not in running_rule[:running_rule.index('}')], 'running and installed never share a shape'
    # The legend draws the same shapes so the key matches the rail.
    for legend in ('ready', 'stopped', 'missing'):
        assert f'.app-dot[data-legend="{legend}"]' in POLISH_CSS


def test_small_screens_keep_app_names_visible_and_contained():
    narrow = POLISH_CSS[POLISH_CSS.index('@media (max-width: 900px)'):POLISH_CSS.index('@media (prefers-reduced-motion')]
    assert 'app-dot-name' not in narrow, 'app names are never hidden behind colour-only dots'
    assert 'mask-image:linear-gradient' in narrow and 'scroll-snap-type:x' in narrow
    # Visually hidden state labels are positioned inside their chip, so they cannot widen the page.
    assert '.app-dot-chip { position:relative;' in POLISH_CSS


def test_contrast_and_forced_colour_modes_are_supported():
    contrast = POLISH_CSS[POLISH_CSS.index('@media (prefers-contrast: more)'):]
    assert '--muted:' in contrast and 'body::after { display:none; }' in contrast
    forced = POLISH_CSS[POLISH_CSS.index('@media (forced-colors: active)'):]
    assert 'border:2px solid CanvasText' in forced and 'border-style:dashed' in forced


def test_unstyled_links_use_palette_without_overriding_components():
    # :where() keeps specificity at zero, so every existing component link rule still wins.
    assert ':where(.shell) :where(a:link, a:visited) { color:#8fe9e0;' in POLISH_CSS
    assert 'class="ki-strip"' in INDEX_HTML and '.ki-strip a {' in POLISH_CSS


def test_findings_keep_severity_visible_on_phones_and_tokens_whole():
    assert '.room-table :is(th,td) { overflow-wrap:normal; word-break:normal; white-space:nowrap; }' in POLISH_CSS
    phone = POLISH_CSS[POLISH_CSS.index('@media (max-width: 640px)'):POLISH_CSS.index('@media (prefers-reduced-motion')]
    assert '#room-findings-table tbody tr { display:grid;' in phone
    # Detector and severity share the first row of each card; the header stays available to assistive technology.
    assert 'td:nth-child(2) { grid-area:1 / 1;' in phone and 'td:nth-child(3) { grid-area:1 / 2;' in phone
    assert 'thead { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); }' in phone
    forced = POLISH_CSS[POLISH_CSS.index('@media (forced-colors: active)'):]
    assert '.severity::before { background:CanvasText;' in forced
    assert '<meta name="theme-color" content="#061017">' in INDEX_HTML


def test_help_names_only_workspaces_that_exist():
    help_panel = INDEX_HTML[INDEX_HTML.index('id="room-help-title"'):INDEX_HTML.index('Full status glossary')]
    for stale in ('in Home', 'In Apps', 'Apps keeps', 'Home shows'):
        assert stale not in help_panel
    assert '<a href="#integrations-title">Sensors</a>' in help_panel
    assert 'id="integrations-title"' in INDEX_HTML


class HelpStructure(HTMLParser):
    """Read composed HTML so moved copy cannot silently leave routes or hooks behind."""

    def __init__(self, html):
        super().__init__()
        self.stack = []
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        item = {"tag": tag, "attrs": dict(attrs), "ancestors": tuple(self.stack)}
        self.elements.append(item)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(item)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break


def test_help_routes_common_tasks_to_existing_gui_controls_and_keeps_commands_advanced():
    structure = HelpStructure(INDEX_HTML)
    help_elements = [item for item in structure.elements if any(
        ancestor["attrs"].get("id") == "workspace-help" for ancestor in item["ancestors"])]
    by_id = {}
    for item in structure.elements:
        if "id" in item["attrs"]:
            by_id.setdefault(item["attrs"]["id"], []).append(item)
    links = [item for item in help_elements if item["tag"] == "a"]
    hrefs = {item["attrs"].get("href") for item in links}
    assert {"#support-capture-title", "#support-model-title", "#network-setup-title", "#room-findings-title",
            "#support-config-clamav-title", "#storage-history-title", "#support-host-security"} <= hrefs
    assert "#support-apps-title" not in hrefs, "starting background tools is not capture setup"
    for href in hrefs:
        if href.startswith("#"):
            assert len(by_id[href[1:]]) == 1, f"Help route must have one real destination: {href}"
            target = by_id[href[1:]][0]
            attrs = target["attrs"]
            native_control = target["tag"] in {"button", "input", "select", "textarea", "summary"}
            native_link = target["tag"] in {"a", "area"} and "href" in attrs
            # The workspace router calls focus() after revealing the destination.
            # A fragment scrolls to a plain heading or section without focusing it.
            focusable = (attrs.get("tabindex") == "-1" or attrs.get("tabindex", "").isdigit()
                         or native_control or native_link)
            assert focusable and "disabled" not in attrs and attrs.get("type") != "hidden", (
                f"Help route must move keyboard focus to its destination: {href}")
    assert not any(item["tag"] in {"button", "form"} for item in help_elements), "Help links only navigate; they never execute a task"
    advanced = next(item for item in help_elements if item["tag"] == "details" and "help-advanced" in item["attrs"].get("class", "").split())
    assert "open" not in advanced["attrs"], "advanced terminal instructions start collapsed"
    assert all(advanced in item["ancestors"] for item in help_elements if item["tag"] == "code")
    for hook in ("room-help-title", "help-here", "help-data", "help-language", "help-terminal",
                 "help-launch-intro", "help-reopen-command", "help-source-launch", "status-glossary"):
        assert len(by_id[hook]) == 1, f"existing Help hook remains unique: {hook}"
    assert "Refreshing alone cannot grant permission" in INDEX_HTML
    assert "Setup also contains “Advanced actions, desktop apps and capability reference.”" in INDEX_HTML
    assert "Live traffic shows its own recent capture window." in INDEX_HTML
    assert "Use “Stored evidence time range” for saved metadata and Findings" in INDEX_HTML
    assert "After the first import into a previously missing store, restart the HUD." not in INDEX_HTML
    assert "refresh can read it once a valid store exists at the same location" in INDEX_HTML


def test_help_task_links_have_touch_targets_focus_and_narrow_layout():
    assert ".help-task-list a { display:flex;" in POLISH_CSS
    assert "min-height:76px" in POLISH_CSS
    assert ".help-task-list a:focus-visible { outline:3px solid #a6f4df;" in POLISH_CSS
    assert ".room-help-grid.help-guide { grid-template-columns:minmax(0,1fr);" in POLISH_CSS
    assert 'data-apps-filter="attention" aria-pressed="false">Stopped or needs attention' in INDEX_HTML
