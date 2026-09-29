"""Shared local and hosted completed ClamAV summary panel."""

CLAMAV_HTML = r'''
<section class="clamav-panel" aria-labelledby="clamav-title">
  <h3 id="clamav-title" tabindex="-1">Completed file scan</h3>
  <p>Review counts from a completed ClamAV clamscan report. This is separate from network traffic and its danger levels.</p>
  <label>Load scan summary JSON <input type="file" id="clamav-file" accept=".json,application/json"></label>
  <button type="button" id="clamav-clear" disabled>Clear scan summary</button>
  <p id="clamav-status" role="status">No scan summary loaded. Files stay in this tab.</p>
  <p id="clamav-automation">Automatic collection and report watching require an explicitly configured local HUD. <a href="http://127.0.0.1:8787/#clamav-title" target="_blank" rel="noopener noreferrer">Open local HUD ↗</a></p>
  <div id="clamav-results" hidden>
    <p id="clamav-range"></p>
    <div class="clamav-grid"><div id="clamav-files"></div><div id="clamav-detections"></div><div id="clamav-directories"></div></div>
    <p id="clamav-scope"></p>
    <p>Counts come from a completed report; the source is not authenticated. Zero detections do not prove complete coverage or that files are safe. Local collection requires explicit folder and schedule settings.</p>
  </div>
  <details><summary>Prepare a scan summary</summary><p>After an operator-run clamscan finishes, retain its output and exit status privately. Run this command with the matching exit status (0 for no matches, 1 for matches); exit status 2 and reported errors are refused. The report may include private paths, so only load the exported JSON into the HUD.</p><pre>umask 077
python -m megalodon.clamav_summary --exit-code 0 &lt; completed-clamscan.txt &gt; scan-summary.json</pre><p>Replace 0 with the recorded exit status when it is 1. The exporter reads at most 1 MiB; it emits only times, version and counts. Times printed by clamscan are local and have no timezone. This page holds the aggregate only until cleared or closed.</p></details>
</section>
'''

CLAMAV_CSS = r'''
.clamav-panel{margin:1.5rem 0;padding:1.25rem;border:1px solid #495b72;border-radius:12px;background:#111d2c;color:#e6f1f6;font-size:1rem}
.clamav-panel h3{font-size:1.3rem;margin:0 0 .6rem}.clamav-panel p{line-height:1.55}.clamav-panel input{max-width:100%;font:inherit}.clamav-panel button{font:inherit;padding:.55rem .8rem;margin:.5rem;border:1px solid #678399;border-radius:6px;background:#172f43;color:#e6f1f6}.clamav-panel button:disabled{opacity:.5}
.clamav-panel pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.875rem;line-height:1.6}.clamav-panel summary{cursor:pointer}.clamav-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}
.clamav-row{border:1px solid #365365;border-radius:8px;padding:.75rem;display:grid;grid-template-columns:1fr auto;gap:.4rem}.clamav-row meter{grid-column:1/-1;width:100%;height:1rem;accent-color:#56cbd0}.clamav-row.alert meter{accent-color:#ef9b70}
.clamav-panel :focus-visible{outline:3px solid #7be7f0;outline-offset:3px}@media(max-width:700px){.clamav-grid{grid-template-columns:1fr}}
'''

CLAMAV_JS = r'''
function validateClamavSummary(text, now=Date.now()) {
  const fail=()=>{throw new Error('Unsupported ClamAV summary. Export a completed report with megalodon.clamav_summary.');};
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>4096)fail();
  let data;
  try {
    const keys=new Set();
    for(const token of text.match(/"(?:\\.|[^"\\])*"\s*:/g)||[]) {
      const key=JSON.parse(token.slice(0,token.lastIndexOf(':')).trim());if(keys.has(key))fail();keys.add(key);
    }
    data=JSON.parse(text);
  } catch { fail(); }
  const keys=['schema','exported_at','scan_start_local','scan_end_local','engine_version','scanned_directories','scanned_files','infected_files','errors'];
  if(!data||Array.isArray(data)||Object.keys(data).length!==keys.length||!keys.every(k=>Object.hasOwn(data,k))||data.schema!=='megalodon-clamscan-summary-v1')fail();
  if(typeof data.exported_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.exported_at))fail();
  const time=Date.parse(data.exported_at);
  if(!Number.isFinite(time)||new Date(time).toISOString().slice(0,19)+'Z'!==data.exported_at||time>now+60000)fail();
  const stamp=value=>{
    if(typeof value!=='string'||!/^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$/.test(value))fail();
    const parsed=Date.parse(value.replace(/:/g,(match, offset)=>offset<10?'-':':').replace(' ','T')+'Z');
    if(!Number.isFinite(parsed)||new Date(parsed).toISOString().replace(/[-T]/g,(match, offset)=>offset<10?':':' ').slice(0,19)!==value)fail();
    return parsed;
  };
  if(stamp(data.scan_start_local)>stamp(data.scan_end_local))fail();
  if(typeof data.engine_version!=='string'||!/^\d+(?:\.\d+){1,3}$/.test(data.engine_version))fail();
  for(const key of ['scanned_directories','scanned_files','infected_files','errors'])if(!Number.isInteger(data[key])||data[key]<0||data[key]>999999999)fail();
  if(data.infected_files>data.scanned_files||data.errors!==0)fail();
  return data;
}
if(typeof module!=='undefined')module.exports={validateClamavSummary};
if(typeof document!=='undefined'&&document.getElementById('clamav-file')) {
  const node=id=>document.getElementById(id);let generation=0;
  function chart(id,label,value,max,alert=false) {
    const root=node(id),row=document.createElement('div'),name=document.createElement('span'),count=document.createElement('b'),bar=document.createElement('meter');
    root.replaceChildren();row.className=alert?'clamav-row alert':'clamav-row';name.textContent=label;count.textContent=String(value);
    bar.min=0;bar.max=Math.max(1,max);bar.value=value;bar.setAttribute('aria-label',`${label}: ${value}; chart maximum ${bar.max}`);
    row.append(name,count,bar);root.append(row);
  }
  function applyClamav(data, source='Saved ClamAV summary') {
    data=validateClamavSummary(JSON.stringify(data));
    chart('clamav-files','Files scanned',data.scanned_files,data.scanned_files);
    chart('clamav-detections','Files with matches',data.infected_files,data.scanned_files,true);
    chart('clamav-directories','Directories scanned',data.scanned_directories,data.scanned_directories);
    node('clamav-range').textContent=`Scan: ${data.scan_start_local} → ${data.scan_end_local} (source local time; timezone unknown). Engine ${data.engine_version}.`;
    node('clamav-scope').textContent=`Reported errors: ${data.errors}. Exported ${data.exported_at}; this is a saved result, not live scanner telemetry.`;
    node('clamav-status').textContent=`${source} · ${data.infected_files} file matches reported. Not live.`;
    node('clamav-results').hidden=false;node('clamav-clear').disabled=false;
  }
  (globalThis.megalodonCompanionRender??={}).clamav=applyClamav;
  node('clamav-file').addEventListener('change',async event=>{
    const current=++generation,file=event.target.files?.[0];event.target.value='';if(!file)return;
    try {
      if(file.size>4096)throw new Error('Choose a summary JSON under 4 KiB.');
      const buffer=await file.arrayBuffer();if(buffer.byteLength>4096)throw new Error('Summary exceeds 4 KiB.');
      const data=validateClamavSummary(new TextDecoder('utf-8',{fatal:true}).decode(buffer));if(current!==generation)return;
      applyClamav(data);
    } catch (_) {if(current===generation)node('clamav-status').textContent='Import rejected. Use a supported counts-only JSON under 4 KiB. Any previous scan summary is preserved.';}
  });
  node('clamav-clear').addEventListener('click',()=>{
    generation++;node('clamav-results').hidden=true;node('clamav-clear').disabled=true;
    for(const id of ['clamav-files','clamav-detections','clamav-directories'])node(id).replaceChildren();
    node('clamav-range').textContent='';node('clamav-scope').textContent='';node('clamav-status').textContent='Scan summary cleared from this tab.';
  });
}
'''
