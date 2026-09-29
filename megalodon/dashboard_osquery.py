"""Shared automatic panel for a fixed osquery package count."""

OSQUERY_HTML = r'''
<section class="companion-panel osquery-panel" aria-labelledby="osquery-title">
  <div class="companion-head"><div><p class="companion-kicker">OSQUERY / HOST</p><h3 id="osquery-title" tabindex="-1">Package inventory</h3></div><span class="companion-kind">This PC</span></div>
  <p id="osquery-status" class="companion-state" role="status">No completed local observation shown.</p>
  <p id="osquery-automation" class="companion-collector">Collector status is available in the local HUD.</p>
  <div id="osquery-results" hidden>
    <div class="osquery-value"><strong id="osquery-count"></strong><span>DEB package rows reported</span></div>
    <p id="osquery-time" class="osquery-time"></p>
    <p class="companion-caveat">One saved count cannot show a trend. It does not establish package safety, update status or live osquery health.</p>
  </div>
  <details class="companion-advisory" id="osquery-advisory-wrap" hidden><summary>Qwen note</summary><p id="osquery-advisory"></p></details>
</section>
'''

OSQUERY_CSS = r'''
.osquery-panel{border-left-color:#658f9c}
.osquery-value{display:flex;align-items:baseline;gap:.65rem;margin:.8rem 0 .45rem;padding:.65rem .75rem;border:1px solid #304e5c;border-radius:7px;background:#0a1923}
.osquery-value strong{color:#bceeed;font-size:2rem;font-variant-numeric:tabular-nums;line-height:1}
.osquery-value span{color:#c3d9df;font-size:.78rem}
.companion-panel .osquery-time{margin:.4rem 0;color:#c2d7df;font-size:.76rem}
'''

OSQUERY_JS = r'''
function validateOsqueryCount(text,now=Date.now()) {
  const fail=()=>{throw new Error('Unsupported package count');};
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>4096)fail();
  let data;
  try {
    const keys=new Set();
    for(const token of text.match(/"(?:\\.|[^"\\])*"\s*:/g)||[]) {
      const key=JSON.parse(token.slice(0,token.lastIndexOf(':')).trim());if(keys.has(key))fail();keys.add(key);
    }
    data=JSON.parse(text);
  } catch {fail();}
  if(!data||Array.isArray(data)||Object.keys(data).length!==3||data.schema!=='megalodon-osquery-package-count-v1'||!Object.hasOwn(data,'exported_at')||!Object.hasOwn(data,'package_rows'))fail();
  if(typeof data.exported_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.exported_at))fail();
  const time=Date.parse(data.exported_at);
  if(!Number.isFinite(time)||new Date(time).toISOString().slice(0,19)+'Z'!==data.exported_at||time>now+60000)fail();
  if(!Number.isInteger(data.package_rows)||data.package_rows<0||data.package_rows>999999999)fail();
  return data;
}
if(typeof module!=='undefined')module.exports={validateOsqueryCount};
if(typeof document!=='undefined'&&document.getElementById('osquery-title')) {
  const node=id=>document.getElementById(id);
  function applyOsquery(data, source='Saved package count') {
    data=validateOsqueryCount(JSON.stringify(data));
    node('osquery-count').textContent=String(data.package_rows);
    node('osquery-time').textContent=`Observed ${data.exported_at} (UTC). Saved count.`;
    node('osquery-status').textContent=`${source} · saved observation.`;
    node('osquery-status').setAttribute('data-state','ready');
    node('osquery-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).osquery=applyOsquery;

}
'''
