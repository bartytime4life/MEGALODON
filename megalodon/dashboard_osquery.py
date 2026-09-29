"""Shared manual saved-result panel for a fixed osquery package count."""

OSQUERY_HTML = r'''
<section class="osquery-panel" aria-labelledby="osquery-title">
  <h3 id="osquery-title">Saved package inventory</h3>
  <p>Review one completed osquery package count. This is host inventory, separate from network traffic and findings.</p>
  <label>Load package count JSON <input type="file" id="osquery-file" accept=".json,application/json"></label>
  <button type="button" id="osquery-clear" disabled>Clear package count</button>
  <p id="osquery-status" role="status">No package count loaded.</p>
  <p id="osquery-automation">Automatic collection and report watching require an explicitly configured local HUD. <a href="http://127.0.0.1:8787/#osquery-title" target="_blank" rel="noopener noreferrer">Open local HUD ↗</a></p>
  <div id="osquery-results" hidden><p id="osquery-count"></p><p id="osquery-time"></p>
    <p>Saved result. This count does not establish package safety, update status or live osquery health. Manually selected files remain in this tab.</p></div>
  <details><summary>Prepare a package count</summary><p>On a trusted Ubuntu PC with osquery already installed, run the fixed read-only query yourself. Inspect the saved result, then export and load only the counts-only JSON. Do not put package names, paths or arbitrary query output into the HUD.</p>
    <pre>umask 077
osqueryi --json 'SELECT count(*) AS package_count FROM deb_packages;' &gt; private-osquery-result.json
python -m megalodon.osquery_inventory &lt; private-osquery-result.json &gt; package-count.json</pre>
    <p>A successful command alone does not authenticate the saved file or prove complete host inventory. The exporter refuses unexpected fields and inputs over 4 KiB.</p></details>
</section>
'''

OSQUERY_CSS = r'''
.osquery-panel{margin:1.5rem 0;padding:1.25rem;border:1px solid #495b72;border-radius:12px;background:#111d2c;color:#e6f1f6;font-size:1rem}
.osquery-panel h3{font-size:1.3rem;margin:0 0 .6rem}.osquery-panel p{line-height:1.55}.osquery-panel input{max-width:100%;font:inherit}.osquery-panel button{font:inherit;padding:.55rem .8rem;margin:.5rem;border:1px solid #678399;border-radius:6px;background:#172f43;color:#e6f1f6}.osquery-panel button:disabled{opacity:.5}
.osquery-panel pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.875rem;line-height:1.6}.osquery-panel summary{cursor:pointer}.osquery-panel :focus-visible{outline:3px solid #7be7f0;outline-offset:3px}
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
if(typeof document!=='undefined'&&document.getElementById('osquery-file')) {
  const node=id=>document.getElementById(id);let generation=0;
  function applyOsquery(data, source='Saved package count') {
    data=validateOsqueryCount(JSON.stringify(data));
    node('osquery-count').textContent=`${data.package_rows} DEB package rows reported`;
    node('osquery-time').textContent=`Exported ${data.exported_at}. Saved observation; a configured local collector can refresh it.`;
    node('osquery-status').textContent=`${source} loaded. Not live.`;
    node('osquery-results').hidden=false;node('osquery-clear').disabled=false;
  }
  (globalThis.megalodonCompanionRender??={}).osquery=applyOsquery;
  node('osquery-file').addEventListener('change',async event=>{
    const current=++generation,file=event.target.files?.[0];event.target.value='';if(!file)return;
    try {
      if(file.size>4096)throw new Error('Too large');
      const buffer=await file.arrayBuffer();if(buffer.byteLength>4096)throw new Error('Too large');
      const data=validateOsqueryCount(new TextDecoder('utf-8',{fatal:true}).decode(buffer));if(current!==generation)return;
      applyOsquery(data);
    } catch {if(current===generation)node('osquery-status').textContent='Import rejected. Previous package count preserved.';}
  });
  node('osquery-clear').addEventListener('click',()=>{
    generation++;node('osquery-results').hidden=true;node('osquery-clear').disabled=true;
    node('osquery-count').textContent='';node('osquery-time').textContent='';node('osquery-status').textContent='Package count cleared from this tab.';
  });
}
'''
