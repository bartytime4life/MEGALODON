"""Shared automatic panel for a fixed osquery package count."""

OSQUERY_HTML = r'''
<section class="osquery-panel" aria-labelledby="osquery-title">
  <h3 id="osquery-title">Package inventory</h3>
  <p>Review one completed osquery package count. This is host inventory, separate from network traffic and findings.</p>
  <p id="osquery-status" role="status">Waiting for local collection.</p>
  <p id="osquery-automation">Automatic results appear in the local HUD. The hosted Console cannot read this PC. <a href="http://127.0.0.1:8787/#osquery-title" target="_blank" rel="noopener noreferrer">Open local HUD ↗</a></p>
  <div id="osquery-results" hidden><p id="osquery-count"></p><p id="osquery-time"></p>
    <p>This count does not establish package safety, update status or live osquery health.</p></div>
</section>
'''

OSQUERY_CSS = r'''
.osquery-panel{margin:1.5rem 0;padding:1.25rem;border:1px solid #495b72;border-radius:12px;background:#111d2c;color:#e6f1f6;font-size:1rem}
.osquery-panel h3{font-size:1.3rem;margin:0 0 .6rem}.osquery-panel p{line-height:1.55}
.osquery-panel :focus-visible{outline:3px solid #7be7f0;outline-offset:3px}
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
    node('osquery-count').textContent=`${data.package_rows} DEB package rows reported`;
    node('osquery-time').textContent=`Exported ${data.exported_at}. Saved observation; a configured local collector can refresh it.`;
    node('osquery-status').textContent=`${source} loaded. Not live.`;
    node('osquery-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).osquery=applyOsquery;

}
'''
