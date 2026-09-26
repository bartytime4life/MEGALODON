"""Shared aggregate schema validator and explicit local export controls."""

SNAPSHOT_VALIDATOR_JS = r'''
/* Aggregate snapshots are local, unverified self-reports, never live telemetry. */
const snapshotLabels = {
  protocols:['TCP','UDP','ICMP','ICMPV6','DNS','HTTP','TLS','OTHER'],
  sources:['JSONL import','Scapy'], severities:['LOW','MEDIUM','HIGH','CRITICAL'],
  detectors:['SYN_FLOOD','PORT_SCAN','DNS_TUNNELING'], lanes:['Normal · no linked finding','Review · LOW / MEDIUM','Danger · HIGH / CRITICAL']
};
function validateHudSnapshot(text, now=Date.now()) {
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>16384)throw new Error('Choose a HUD summary smaller than 16 KiB.');
  let data; try {
    // Inspect JSON tokens before parsing so duplicate keys cannot hide another claim.
    const stack = [];
    for (let index = 0; index < text.length; index += 1) {
      const token = text[index];
      if (token === "{") stack.push(new Set());
      else if (token === "[") stack.push(null);
      else if (token === "}" || token === "]") stack.pop();
      else if (token === '"') {
        const start = index;
        index += 1;
        while (index < text.length && text[index] !== '"') { if (text[index] === "\\") index += 1; index += 1; }
        let following = index + 1;
        while (/\s/.test(text[following] || "x")) following += 1;
        if (text[following] === ":") {
          const keys = stack[stack.length - 1];
          const key = JSON.parse(text.slice(start, index + 1));
          if (!(keys instanceof Set) || keys.has(key)) throw new Error("duplicate key");
          keys.add(key);
        }
      }
      if (stack.length > 4) throw new Error("excessive nesting");
    }
    data = JSON.parse(text);
  } catch { throw new Error("Choose valid JSON without duplicate keys or excessive nesting."); }

  const keys=['schema','generated_at','start','end','events','findings','reported_bytes','lanes','timeline','protocols','sources','severities','detectors','limited','quality'];
  if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).length!==keys.length||!keys.every(k=>Object.hasOwn(data,k))||data.schema!=='megalodon-hud-snapshot-v1')throw new Error('Unsupported HUD snapshot. Export using megalodon.hud_snapshot.');
  const count=(n,max)=>Number.isInteger(n)&&n>=0&&n<=max;
  const timestamp=value=>{
    if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value))return NaN;
    const stamp=Date.parse(value); if(!Number.isFinite(stamp))return NaN;
    return new Date(stamp).toISOString().slice(0,19)===value.slice(0,19)?stamp:NaN;
  };
  const generated=timestamp(data.generated_at),start=timestamp(data.start),end=timestamp(data.end);
  if(![generated,start,end].every(Number.isFinite)||generated>now+60000||start>end||end>generated+60000)throw new Error('Invalid or future snapshot time.');
  if(!count(data.events,500)||data.events<1||!count(data.findings,200)||typeof data.reported_bytes!=='string'||!/^(0|[1-9][0-9]{0,21})$/.test(data.reported_bytes)||BigInt(data.reported_bytes)>BigInt(data.events)*9223372036854775807n||typeof data.limited!=='boolean'||!['unknown','degraded'].includes(data.quality))throw new Error('Invalid snapshot counts or quality.');
  for(const [key,length,total] of [['lanes',3,data.events],['timeline',12,data.events],['protocols',8,data.events],['sources',2,data.events],['severities',4,data.findings],['detectors',3,data.findings]]){
    if(!Array.isArray(data[key])||data[key].length!==length||!data[key].every(v=>count(v,total))||data[key].reduce((a,b)=>a+b,0)!==total)throw new Error('Inconsistent snapshot totals.');
  }
  if(data.lanes[1]>data.severities[0]+data.severities[1]||data.lanes[2]>data.severities[2]+data.severities[3]||data.findings>0&&data.lanes[1]+data.lanes[2]===0)throw new Error('Inconsistent traffic lanes.');
  return data;
}
if(typeof module!=='undefined')module.exports={validateHudSnapshot,snapshotLabels};
'''

SNAPSHOT_HOSTED_JS = r'''
if(typeof document!=='undefined'){
  const el=id=>document.getElementById(id);let generation=0;
  function chart(id,labels,values,unit='records'){
    const root=el(id);root.replaceChildren();
    if(!values){const p=document.createElement('p');p.className='snapshot-empty';p.textContent='Import a saved summary to display this chart.';root.append(p);return;}
    const peak=Math.max(1,...values);
    labels.forEach((label,i)=>{const row=document.createElement('div');row.className='snapshot-row';const name=document.createElement('span');name.textContent=label;const count=document.createElement('b');count.textContent=String(values[i]);const bar=document.createElement('meter');bar.min=0;bar.max=peak;bar.value=values[i];bar.setAttribute('aria-label',`${label}: ${values[i]} ${unit}; chart maximum ${peak}`);row.append(name,count,bar);root.append(row);});
  }
  function render(data){
    el('snapshot-events').textContent=data?String(data.events):'—';el('snapshot-findings').textContent=data?String(data.findings):'—';
    el('snapshot-bytes').textContent=data?data.reported_bytes:'—';el('snapshot-sources').textContent=data?String(data.sources.filter(n=>n>0).length):'—';
    el('snapshot-range').textContent=data?`${data.start} → ${data.end} · ${data.limited?'limited candidate window':'bounded returned set'} · quality ${data.quality}`:'No summary loaded. Charts show only imported, qualified metadata.';
    for(const name of ['protocols','sources','severities','detectors','lanes'])chart('snapshot-'+name+'-chart',snapshotLabels[name],data?.[name],['severities','detectors'].includes(name)?'findings':'records');
    const timeline=el('snapshot-timeline');timeline.replaceChildren();
    if(data){const peak=Math.max(1,...data.timeline);data.timeline.forEach((value,index)=>{const column=document.createElement('div');const bar=document.createElement('span');bar.style.height=`${value/peak*120}px`;const label=document.createElement('small');label.textContent=String(index+1);column.setAttribute('aria-label',`Interval ${index+1}: ${value} records`);column.title=`Interval ${index+1}: ${value} records`;const count=document.createElement('b');count.textContent=String(value);column.append(count,bar,label);timeline.append(column);});}
    else timeline.textContent='No saved time series loaded.';
    el('snapshot-clear').disabled=!data;
  }
  el('snapshot-file').addEventListener('change',async event=>{const current=++generation,file=event.target.files?.[0];event.target.value='';if(!file)return;
    try{if(file.size>16384)throw new Error('Choose a summary smaller than 16 KiB.');const buffer=await file.arrayBuffer();if(buffer.byteLength>16384)throw new Error('Summary is too large.');const data=validateHudSnapshot(new TextDecoder('utf-8',{fatal:true}).decode(buffer));if(current!==generation)return;render(data);el('snapshot-status').textContent=`Saved snapshot · exported ${data.generated_at}. Not live. Self-reported source authenticity is unverified.`;}
    catch(error){if(current===generation)el('snapshot-status').textContent=`Import rejected. ${error.message} Previous summary preserved.`;}
  });
  el('snapshot-clear').addEventListener('click',()=>{generation++;render(null);el('snapshot-status').textContent='Summary cleared from this page. No upload was performed.';});
  render(null);
}
'''

SNAPSHOT_LOCAL_HTML = r'''
<section class="telemetry-coverage" aria-labelledby="hud-export-title">
  <h3 id="hud-export-title">Export a hosted HUD summary</h3>
  <p>Prepare an aggregate-only summary of the newest qualified records. This export uses the latest bounded database window, independently of the displayed time filter. It contains no addresses, ports or raw records.</p>
  <button type="button" id="hud-export-prepare">Prepare summary</button>
  <button type="button" id="hud-export-download" disabled>Download summary JSON</button>
  <button type="button" id="hud-export-clear" disabled>Clear preview</button>
  <p id="hud-export-status" role="status">No summary prepared. Nothing is uploaded.</p>
  <pre id="hud-export-preview" class="room-report-preview" tabindex="0" hidden aria-label="Exact hosted summary JSON"></pre>
</section>
'''

SNAPSHOT_LOCAL_JS = r'''
const hudExportState = {text:null, busy:false};
async function prepareHudExport() {
  if(hudExportState.busy)return;
  hudExportState.busy=true;byId('hud-export-prepare').disabled=true;
  byId('hud-export-download').disabled=true;byId('hud-export-clear').disabled=true;
  byId('hud-export-status').textContent='Reading the latest bounded metadata summary…';
  try {
    const payload=await requestBoundedJSON('/api/hud-snapshot',16384);
    const summary=validateHudSnapshot(JSON.stringify(payload));
    hudExportState.text=JSON.stringify(summary,null,2)+'\n';
    byId('hud-export-preview').textContent=hudExportState.text;byId('hud-export-preview').hidden=false;
    byId('hud-export-clear').disabled=false;
    byId('hud-export-status').textContent=`Saved summary prepared: ${summary.events} records, ${summary.findings} findings. Exported ${summary.generated_at}. Review below, then download and load it into the hosted HUD.`;
  } catch(_) {
    byId('hud-export-status').textContent=hudExportState.text?'Summary refresh failed. The prior held preview is preserved; its timestamp has not changed.':'Summary unavailable. Check the local source for qualified metadata; no empty summary was invented.';
  } finally {hudExportState.busy=false;byId('hud-export-prepare').disabled=false;byId('hud-export-download').disabled=!hudExportState.text;byId('hud-export-clear').disabled=!hudExportState.text;}
}
function clearHudExport() {
  if(hudExportState.busy)return;
  hudExportState.text=null;byId('hud-export-preview').textContent='';byId('hud-export-preview').hidden=true;
  byId('hud-export-download').disabled=true;byId('hud-export-clear').disabled=true;
  byId('hud-export-status').textContent='Preview cleared. Nothing was uploaded.';
}
function downloadHudExport() {
  if(!hudExportState.text||hudExportState.busy)return;
  let url;
  try {
    url=URL.createObjectURL(new Blob([hudExportState.text],{type:'application/json'}));
    const anchor=document.createElement('a');anchor.href=url;anchor.download='megalodon-hud-summary.json';anchor.click();
    byId('hud-export-status').textContent='Summary download requested. Load this saved JSON in the hosted HUD. No upload was performed.';
  } catch(_) {byId('hud-export-status').textContent='Download unavailable. Copy the exact summary JSON from the preview.';}
  finally {if(url)setTimeout(()=>URL.revokeObjectURL(url),0);}
}
byId('hud-export-prepare').addEventListener('click',prepareHudExport);
byId('hud-export-download').addEventListener('click',downloadHudExport);
byId('hud-export-clear').addEventListener('click',clearHudExport);
function renderTelemetryConnections() {
  const traffic=typeof roomState==='undefined'?null:roomState.snapshot;
  const paused=typeof state!=='undefined'&&state.paused;
  const hidden=typeof document!=='undefined'&&document.hidden;
  const failed=typeof roomState!=='undefined'&&roomState.failed;
  const has=Boolean(traffic&&traffic.events.length);
  const fresh=traffic&&Date.now()-Date.parse(traffic.generated_at)<=300000;
  byId('telemetry-traffic-state').textContent=failed?'Refresh failed':!has?'No qualified records':!fresh?'Stale stored view':paused||hidden?'Refresh paused':'Stored metadata available';
  byId('telemetry-traffic-time').textContent=traffic?`Snapshot: ${traffic.generated_at} · sensor health unknown`:'No accepted traffic snapshot';
  const hb=typeof heartbeatState==='undefined'?null:heartbeatState;
  byId('telemetry-tools-state').textContent=!hb?.report?'No observation':heartbeatStale()?'Stale tool observation':'Tool presence observed';
  byId('telemetry-tools-time').textContent=hb?.report?`Checked: ${hb.report.checked_at} · not sensor health`:'Waiting for the local heartbeat';
  byId('telemetry-management-state').textContent=hb?.catalogFailed?'Status unavailable':hb?.catalog?hb.job?`Job: ${hb.job.state}`:'No active job':'Not checked';
  byId('telemetry-management-time').textContent=hb?.catalogFailed?'Tool observations remain independent':hb?.managementEnabled?'Management enabled for this launch':'Observation mode; management disabled';
}
'''
