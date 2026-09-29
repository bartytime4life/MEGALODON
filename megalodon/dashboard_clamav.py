"""Shared local and hosted automatic ClamAV summary panel."""

CLAMAV_HTML = r'''
<section class="companion-panel clamav-panel" aria-labelledby="clamav-title">
  <div class="companion-head"><div><p class="companion-kicker">CLAMAV / FILES</p><h3 id="clamav-title" tabindex="-1">Completed file scan</h3></div><span class="companion-kind">Files and matches</span></div>
  <p id="clamav-status" class="companion-state" role="status">No completed local observation shown.</p>
  <p id="clamav-automation" class="companion-collector">Collector status is available in the local HUD.</p>
  <div id="clamav-results" hidden>
    <div class="companion-meta"><p id="clamav-range"></p><p id="clamav-scope"></p></div>
    <div class="clamav-grid"><div id="clamav-files"></div><div id="clamav-detections"></div><div id="clamav-directories"></div></div>
    <p class="companion-caveat">Completed scan counts are separate from network traffic. Zero matches do not prove full coverage or file safety.</p>
  </div>
  <details class="companion-advisory" id="clamav-advisory-wrap" hidden><summary>Qwen note</summary><p id="clamav-advisory"></p></details>
</section>
'''

CLAMAV_CSS = r'''
.clamav-panel{border-left-color:#438f9c}
.clamav-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.5rem}
.clamav-row{min-width:0;border:1px solid #304e5c;border-radius:7px;padding:.65rem;background:#0a1923;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.3rem;font-size:.73rem}
.clamav-row b{color:#d8f7f5}.clamav-row meter{grid-column:1/-1;width:100%;height:.65rem;accent-color:#56cbd0}.clamav-row.alert meter{accent-color:#ef9b70}
@media(max-width:1150px){.clamav-grid{grid-template-columns:1fr}}
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
  function chart(id,label,value,max=null,alert=false) {
    const root=node(id),row=document.createElement('div'),name=document.createElement('span'),count=document.createElement('b');
    root.replaceChildren();row.className=alert?'clamav-row alert':'clamav-row';name.textContent=label;count.textContent=String(value);
    row.append(name,count);
    if(max!==null) {
      const bar=document.createElement('meter');bar.min=0;bar.max=Math.max(1,max);bar.value=value;
      bar.setAttribute('aria-label',`${label}: ${value} of ${max} files scanned`);row.append(bar);
    }
    root.append(row);
  }
  function applyClamav(data, source='Saved ClamAV summary') {
    data=validateClamavSummary(JSON.stringify(data));
    chart('clamav-files','Files scanned',data.scanned_files);
    chart('clamav-detections','Files with matches',data.infected_files,data.scanned_files,data.infected_files>0);
    chart('clamav-directories','Directories scanned',data.scanned_directories);
    node('clamav-range').textContent=`Scan: ${data.scan_start_local} → ${data.scan_end_local} (source local time; timezone unknown). Engine ${data.engine_version}.`;
    node('clamav-scope').textContent=`Reported errors: ${data.errors}. Exported ${data.exported_at}.`;
    node('clamav-status').textContent=`${source} · ${data.infected_files} file matches reported.`;
    node('clamav-status').setAttribute('data-state','ready');
    node('clamav-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).clamav=applyClamav;

}
'''
