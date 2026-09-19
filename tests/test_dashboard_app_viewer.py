"""No companion request until explicit viewing; frame lifecycle and truth labels."""
import json
import shutil
import subprocess

import pytest

from megalodon.dashboard_app_viewer import APP_VIEWER_JS
from megalodon.dashboard_tool_assets import CONTROLS_JS


def test_app_console_lifecycle_and_navigation_boundaries():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for browser logic")
    harness = r"""
const vm=require('node:vm'),assert=require('node:assert/strict');let input='';
process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>{try{
const {controls,viewer}=JSON.parse(input),nodes=new Map();
const element=tag=>({tag,children:[],attrs:{},listeners:{},textContent:'',
append(...items){this.children.push(...items)},replaceChildren(...items){this.children=items},
setAttribute(k,v){this.attrs[k]=v},removeAttribute(k){delete this[k]},
addEventListener(k,v){this.listeners[k]=v},focus(){},scrollIntoView(){}});
const byId=id=>{if(!nodes.has(id))nodes.set(id,element(id));return nodes.get(id)};
const context={URL,byId,document:{createElement:element},window:{location:{origin:'http://127.0.0.1:8787',protocol:'http:'}},
localStorage:{getItem(){return null},setItem(){}},fetch(){throw Error('No backend probes permitted')}};
vm.createContext(context);vm.runInContext(controls+viewer,context);
const run=code=>vm.runInContext(code,context),frame=()=>byId('app-viewer-frame').children[0];
assert.equal(nodes.has('app-viewer-frame'),false);
run("MegalodonControls.save('zabbix','http://127.0.0.1:8080/')");assert.equal(nodes.has('app-viewer-frame'),false);
for(const id of run('MegalodonControls.ids')) {
context.id=id;run('appConsole.view(id,id,null)');assert.equal(frame(),undefined);
assert.match(byId('app-viewer-status').textContent,/No UI connection/);
}
run("appConsole.view('zabbix','Zabbix',MegalodonControls.links().zabbix)");
assert.equal(frame().src,'http://127.0.0.1:8080/');assert.equal(frame().title,'Zabbix console');
assert.equal(frame().referrerPolicy,'no-referrer');
assert.equal(frame().attrs.sandbox,'allow-scripts allow-forms allow-same-origin');
assert.doesNotMatch(frame().attrs.sandbox,/allow-top-navigation|allow-popups|allow-downloads/);
assert.equal(frame().listeners.load,undefined,'load cannot prove successful embedding');
assert.match(byId('app-viewer-status').textContent,/cannot be verified/);
byId('app-viewer-reload').listeners.click();assert.equal(byId('app-viewer-frame').children.length,1);
run("appConsole.changed('zabbix')");assert.equal(frame(),undefined);assert.equal(byId('app-viewer-external').hidden,true);
run("appConsole.view('zabbix','Zabbix','http://127.0.0.1:8787/')");assert.equal(frame(),undefined);
assert.match(byId('app-viewer-status').textContent,/back to the HUD/);
for(const raw of ['javascript:alert(1)','https://user:pass@host/','https://host/?secret=1']) {
context.raw=raw;run("appConsole.view('zabbix','Zabbix',raw)");assert.equal(frame(),undefined);assert.equal(byId('app-viewer-external').hidden,true);
}
context.window.location.protocol='https:';context.window.location.origin='https://hud.example';
run("appConsole.view('zabbix','Zabbix','http://host/')");assert.equal(frame(),undefined);assert.equal(byId('app-viewer-external').hidden,false);
run("appConsole.view('zabbix','Zabbix','https://host/')");assert.equal(frame().src,'https://host/');
byId('app-viewer-close').listeners.click();assert.equal(frame(),undefined);assert.equal(byId('app-viewer-close').disabled,true);
console.log('app console lifecycle passed');
}catch(error){console.error(error);process.exitCode=1}});
"""
    result = subprocess.run([node, "-e", harness], input=json.dumps({"controls": CONTROLS_JS, "viewer": APP_VIEWER_JS}), text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
