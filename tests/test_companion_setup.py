"""Copy-only companion setup controls: canonical package and static mirror.

No companion binary, package manager, scanner, network or Docker daemon is used.
The DOM harness is behavior coverage, not rendered/host installation acceptance.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = runpy.run_path(str(ROOT / "megalodon/dashboard_tool_assets.py"))

HARNESS = r"""
const assert = require('node:assert/strict'), vm = require('node:vm');
class Element {
  constructor(tag) {
    this.tag=tag; this.children=[]; this.listeners={};
    this.textContent=''; this.attributes={}; this.value='';
  }
  append(...items) {this.children.push(...items);}
  replaceChildren(...items) {this.children=items;}
  setAttribute(key, value) {this.attributes[key]=value;}
  removeAttribute(key) {delete this[key];}
  addEventListener(event, fn) {this.listeners[event]=fn;}
  querySelector(tag) {return this.children.find(child=>child.tag===tag);}
  focus() {}
}
const all = element => [element, ...element.children.flatMap(all)];
function mount(id, override=null, clipboardFails=false, local=false) {
  const copied=[], writes=[], checks=[], network=[], views=[];
  const context={
    URL, document:{createElement:tag=>new Element(tag)},
    localStorage:{getItem(){return null;},setItem(...args){writes.push(args);}},
    navigator:{clipboard:{async writeText(text) {
      if(clipboardFails) throw new Error('denied'); copied.push(text);
    }}},
    fetch(...args){network.push(args); throw new Error('no network');},
    runLocalChecks(...args){checks.push(args);}, views, local
  };
  vm.createContext(context);
  const lifecycle=override === null ? lifecycleSource : lifecycleSource.replace(
    'const localPythonLifecycle = null;',
    'const localPythonLifecycle = '+JSON.stringify(override)+';');
  vm.runInContext(lifecycle,context);
  vm.runInContext(controlsSource,context);
  const parent=new Element('main');
  context.parent=parent; context.toolId=id;
  vm.runInContext('MegalodonControls.mount(parent, toolId, toolId, local ? {local:true,view(...args){views.push(args)}} : {})',context);
  const guide=all(parent).find(n=>n.className==='companion-setup');
  const find=text=>all(parent).find(n=>n.textContent===text);
  const feedback=all(parent).find(n=>n.attributes.role==='status');
  return {parent,guide,find,feedback,context,copied,writes,checks,network,views};
}
"""

CASES = [
    r"""
for(const [id,count] of [['scapy',5]]) {
  const r=mount(id);
  assert.ok(r.guide);
  assert.equal(r.guide.children[0].tag,'summary');
  assert.equal(r.guide.children[0].textContent,'Easy setup and verification');
  assert.equal(all(r.guide).filter(n=>n.tag==='strong').length,count);
  assert.ok(all(r.guide).some(n=>n.textContent.startsWith('Expected result:')));
  assert.deepEqual([r.copied,r.writes,r.checks,r.network],[[],[],[],[]]);
  assert.equal(r.feedback.textContent,'');
}
""",
    r"""
const r=mount('scapy');
const note=all(r.guide).map(n=>n.textContent).join('\n');
assert.match(note,/not required to open MEGALODON/);
assert.match(note,/standalone environment is not the HUD environment/);
assert.match(note,/No sudo pip, live capture or packet sending/);
assert.match(note,/not a pinned artifact/);
const button=r.find('Copy step 5: Check standalone package');
assert.equal(button.type,'button');
await button.listeners.click();
assert.match(r.copied[0],/^"\$HOME\/scapy\/\.venv\/bin\/python" -I -c /);
assert.match(r.copied[0],/importlib.metadata/);
assert.match(r.feedback.textContent,/not executed or verified/);
assert.deepEqual([r.writes,r.checks,r.network],[[],[],[]]);
""",
    r"""
const command="'/private/space and <tag>/python' -m pip show scapy";
const r=mount('scapy',{scapy:{verify:command}});
await r.find('Copy step 1: Check HUD Python package').listeners.click();
assert.equal(r.copied[0],command);
assert.ok(all(r.guide).some(n=>n.tag==='code' && n.textContent===command));
const hosted=mount('scapy');
await hosted.find('Copy step 1: Check HUD Python package').listeners.click();
assert.equal(hosted.copied[0],'python3 -m pip show scapy');
""",
    r"""
const r=mount('scapy',null,true);
const command=all(r.guide).find(n=>n.tag==='code').textContent;
await r.find('Copy step 1: Check HUD Python package').listeners.click();
assert.match(r.feedback.textContent,/Clipboard unavailable/);
assert.match(r.feedback.textContent,/No check was run/);
assert.deepEqual(r.copied,[]);
assert.ok(all(r.guide).some(n=>n.tag==='code' && n.textContent===command));
""",
    r"""
const r=mount('core');
assert.equal(r.guide,undefined);
const ids=vm.runInContext('MegalodonControls.ids',r.context);
assert.equal(ids.length,12);
assert.ok(!ids.includes('docker'));
assert.throws(()=>mount('__proto__'));
assert.throws(()=>mount('docker'));
""",
    r"""
assert.doesNotMatch(controlsSource,/\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|innerHTML|\beval\s*\(|new Function/);
const r=mount('scapy');
for(const n of all(r.guide).filter(n=>n.tag==='button')) {
  await n.listeners.click();
}
assert.equal(r.copied.length,5);
assert.deepEqual([r.writes,r.checks,r.network],[[],[],[]]);
assert.match(r.feedback.textContent,/not executed or verified/);
""",
]


@pytest.mark.parametrize("surface", ["canonical", "mirror"])
@pytest.mark.parametrize("case", CASES, ids=[
    "ordered-inert-steps", "scapy-environment", "serving-interpreter",
    "clipboard-failure", "closed-registry", "no-execution",
])
def test_setup_controls(surface: str, case: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node unavailable: companion UI behavior remains unverified")
    if surface == "mirror":
        directory = ROOT / "site/dist"
        if not directory.exists():
            pytest.skip("Site mirror is not part of the Python distribution")
        lifecycle = (directory / "lifecycle.js").read_text(encoding="utf-8")
        controls = (directory / "controls.js").read_text(encoding="utf-8")
    else:
        lifecycle, controls = ASSETS["LIFECYCLE_JS"], ASSETS["CONTROLS_JS"]
    source = (
        f"const lifecycleSource={json.dumps(lifecycle)};\n"
        f"const controlsSource={json.dumps(controls)};\n"
        + HARNESS
        + "\n(async()=>{\n" + case
        + "\n})().catch(error=>{console.error(error);process.exitCode=1;});\n"
    )
    result = subprocess.run(
        [node, "-"], input=source, text=True, capture_output=True, timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_setup_mirror_matches_canonical() -> None:
    directory = ROOT / "site/dist"
    if not directory.exists():
        pytest.skip("Site mirror is not part of the Python distribution")
    for key, name in [
        ("LIFECYCLE_JS", "lifecycle.js"), ("READINESS_JS", "readiness.js"),
        ("CONTROLS_JS", "controls.js"), ("CONTROLS_CSS", "controls.css"),
    ]:
        assert (directory / name).read_text(encoding="utf-8") == ASSETS[key]


def test_document_shell_examples_parse_without_execution() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash unavailable: Ubuntu command syntax remains unverified")
    document = ROOT / "docs/companion-setup.md"
    if not document.exists():
        pytest.skip("Operator documentation is not included in this distribution")
    blocks = re.findall(r"```bash\n(.*?)```", document.read_text(encoding="utf-8"), re.S)
    assert len(blocks) == 4
    for block in blocks:
        result = subprocess.run(
            [bash, "-n"], input=block, text=True, capture_output=True,
            timeout=5, check=False,
        )
        assert result.returncode == 0, result.stderr
