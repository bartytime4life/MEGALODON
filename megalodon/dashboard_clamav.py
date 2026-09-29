"""Shared local and hosted automatic ClamAV summary panel."""

CLAMAV_HTML = r'''
<section class="clamav-panel" aria-labelledby="clamav-title">
  <h3 id="clamav-title" tabindex="-1">Completed file scan</h3>
  <p>Review counts from a completed ClamAV clamscan report. This is separate from network traffic and its danger levels.</p>
  <p id="clamav-status" role="status">Waiting for local collection.</p>
  <p id="clamav-automation">Automatic results appear in the local HUD. The hosted Console cannot read this PC. <a href="http://127.0.0.1:8787/#clamav-title" target="_blank" rel="noopener noreferrer">Open local HUD ↗</a></p>
  <div id="clamav-results" hidden>
    <p id="clamav-range"></p>
    <div class="clamav-grid"><div id="clamav-files"></div><div id="clamav-detections"></div><div id="clamav-directories"></div></div>
    <p id="clamav-scope"></p>
    <p>Counts come from a completed observation. Zero detections do not prove complete coverage or that files are safe.</p>
  </div>
</section>
'''

CLAMAV_CSS = r'''
.clamav-panel{margin:1.5rem 0;padding:1.25rem;border:1px solid #495b72;border-radius:12px;background:#111d2c;color:#e6f1f6;font-size:1rem}
.clamav-panel h3{font-size:1.3rem;margin:0 0 .6rem}.clamav-panel p{line-height:1.55}
.clamav-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}
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
if(typeof document!=='undefined'&&document.getElementById('clamav-title')) {
  const node=id=>document.getElementById(id);
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
    node('clamav-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).clamav=applyClamav;

}
'''
