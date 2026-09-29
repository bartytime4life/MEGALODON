
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
