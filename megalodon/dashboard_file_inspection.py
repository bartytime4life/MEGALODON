"""Explicit local executable inspection, separate from saved scan summaries.

Presentation only: selected bytes leave the browser only after Inspect. The
server owns admission, confinement, analyzer selection and normalized reports.
"""

FILE_INSPECTION_HTML = r'''
<section class="companion-panel fi-panel" id="file-inspection" aria-labelledby="file-inspection-title">
  <div class="companion-head"><div><p class="companion-kicker">ONE FILE / ON THIS PC</p><h3 id="file-inspection-title" tabindex="-1">Inspect a file</h3></div><span class="companion-kind">Executable clues</span></div>
  <p class="fi-intro">Understand a downloaded program before deciding what to do with it. Read its structure and compiler or packing clues without opening the program.</p>
  <ol class="fi-steps" aria-label="File inspection steps"><li data-step="choose" aria-current="step"><b>1</b><span>Choose</span></li><li data-step="inspect"><b>2</b><span>Inspect</span></li><li data-step="understand"><b>3</b><span>Understand</span></li></ol>
  <label class="fi-file-label" for="file-inspection-input">Choose one program to inspect</label>
  <input type="file" id="file-inspection-input" aria-describedby="file-inspection-limits file-inspection-selection" disabled>
  <p id="file-inspection-selection" class="fi-selection">No file selected.</p>
  <p id="file-inspection-limits" class="fi-note">ELF, Windows EXE/DLL or macOS Mach-O · up to 64 MiB · 30-second analysis limit.</p>
  <div class="fi-actions"><button type="button" id="file-inspection-run" disabled>Inspect</button><button type="button" id="file-inspection-cancel" hidden disabled>Cancel inspection</button><button type="button" id="file-inspection-check" disabled>Check inspector</button></div>
  <p id="file-inspection-status" class="fi-status" role="status" aria-live="polite" aria-atomic="true">File inspection is available in the authenticated local Linux HUD.</p>
  <p id="file-inspection-sign-in" class="fi-note fi-sign-in" hidden><a href="#setup-account-title">Open Local sign-in in Setup →</a> Prepare a protected launch there, then open and sign in to that HUD. You choose when to start the protected launch.</p>
  <div id="file-inspection-runtime" class="fi-runtime"><p id="file-inspection-runtime-note">The inspector and its isolation must be available before inspection can start.</p><button type="button" id="file-inspection-install" hidden disabled>Install file inspector</button><a id="file-inspection-authorize" href="#tool-management-controls" hidden>Authorize optional installation in Setup →</a><p id="file-inspection-install-note" hidden></p></div>
  <div id="file-inspection-result" class="fi-result" hidden>
    <header class="fi-result-head"><p id="file-inspection-report-scope"></p><button type="button" id="file-inspection-export" disabled>Export JSON</button></header>
    <ul id="file-inspection-tools" class="fi-tools" aria-label="Analyzer completion"></ul>
    <section aria-labelledby="file-inspection-what-title"><h4 id="file-inspection-what-title">What this file is</h4><p id="file-inspection-what"></p></section>
    <section class="fi-clues" aria-labelledby="file-inspection-clues-title"><h4 id="file-inspection-clues-title">Clues worth reviewing</h4><ul id="file-inspection-clues"></ul></section>
    <section class="fi-limits" aria-labelledby="file-inspection-unknown-title"><h4 id="file-inspection-unknown-title">What remains unknown</h4><ul id="file-inspection-unknowns"></ul></section>
    <section aria-labelledby="file-inspection-next-title"><h4 id="file-inspection-next-title">Suggested next step</h4><p id="file-inspection-next"></p></section>
    <details id="file-inspection-details"><summary>Technical details and coverage</summary><div id="file-inspection-technical"></div></details>
  </div>
  <p class="fi-boundary">Choosing a file does nothing until you select Inspect. Its bytes go only to this localhost HUD for inspection. The program is never run or unpacked. This is separate from the ClamAV folder summary and gives no safety verdict. Only the latest metadata report stays in this HUD session.</p>
</section>
'''

FILE_INSPECTION_CSS = r'''
.fi-panel{grid-column:1/-1;border-left-color:#87e8dc;min-width:0}
.fi-panel .fi-intro{max-width:78ch;margin:.1rem 0 .95rem;color:#c6d9e1;font-size:.88rem}
.fi-panel .fi-steps{display:flex;gap:0;list-style:none;margin:.8rem 0 1.2rem;padding:0;max-width:32rem}
.fi-steps li{display:flex;align-items:center;gap:.5rem;flex:1;position:relative;color:#b7cbd4;font-size:.82rem;font-weight:650}
.fi-steps li:not(:last-child):after{content:"";height:1px;background:#426270;flex:1;margin:0 .7rem 0 .2rem}
.fi-steps b{display:grid;place-items:center;flex:0 0 1.8rem;height:1.8rem;border:1px solid #65828e;color:#c8dce4;font-size:.78rem}
.fi-steps li[aria-current=step]{color:#a5efe0}.fi-steps li[aria-current=step] b{border-color:#87e8dc;background:#143d3a;color:#b9ffed}
.fi-panel .fi-file-label{display:block;margin:.35rem 0 .45rem;font-size:.85rem;font-weight:650}
.fi-panel input[type=file]{display:block;width:100%;max-width:36rem;min-width:0;box-sizing:border-box;padding:.5rem;border:1px solid #4b6e7b;border-radius:4px;background:#091b25;color:#d5e7ee;font:inherit;font-size:.85rem}
.fi-panel input[type=file]::file-selector-button{font:inherit;font-weight:650;color:#e6f4f7;background:#163b48;border:1px solid #5e8a96;border-radius:3px;padding:.6rem .8rem;margin-right:.7rem;cursor:pointer;min-height:40px}
.fi-panel .fi-selection{font-size:.85rem;color:#e1f2f3;margin:.65rem 0 .35rem;overflow-wrap:anywhere}
.fi-panel .fi-note,.fi-panel .fi-boundary{color:#bbced8;font-size:.78rem;line-height:1.65;margin:.35rem 0 .8rem;max-width:95ch}
.fi-panel .fi-sign-in a{display:inline-flex;align-items:center;min-height:44px;color:#a3e8e0;margin-right:.45rem}
.fi-actions{display:flex;flex-wrap:wrap;gap:.6rem;margin:.8rem 0}
.fi-panel button{font:inherit;font-size:.83rem;min-height:44px;border:1px solid #658a96;border-radius:4px;background:#143440;color:#e8f7fa;padding:.6rem .85rem;cursor:pointer;font-weight:650}
.fi-panel #file-inspection-run{background:#87e8dc;color:#07242a;border-color:#87e8dc;min-width:7rem}
.fi-panel button:hover:not(:disabled){background:#254d59}.fi-panel #file-inspection-run:hover:not(:disabled){background:#b0f3e9}
.fi-panel button:active:not(:disabled){transform:translateY(1px)}.fi-panel button:disabled,.fi-panel input:disabled{opacity:.55;cursor:default}
.fi-panel :is(button,input,a,summary):focus-visible{outline:3px solid #edc883;outline-offset:3px}
.fi-panel .fi-status{padding:.65rem .8rem;border-left:2px solid #7696a2;background:#102a35;color:#d8e8ee;font-size:.85rem;margin:.6rem 0;line-height:1.6}
.fi-panel[data-state=running] .fi-status,.fi-panel[data-state=receiving] .fi-status{border-color:#87e8dc}
.fi-panel[data-state=error] .fi-status,.fi-panel[data-state=partial] .fi-status,.fi-panel[data-state=failed] .fi-status{border-color:#edc883;color:#f3d69f}
.fi-runtime{font-size:.78rem;color:#bdd1db;margin:.65rem 0}.fi-runtime p{margin:.5rem 0}.fi-runtime a{display:inline-block;padding:.5rem 0;color:#a3e8e0;line-height:1.6}.fi-runtime button{margin:.4rem .7rem .4rem 0}
.fi-result{border-top:1px solid #426270;margin:1.2rem 0 .8rem;padding-top:1rem}.fi-result-head{display:flex;align-items:center;justify-content:space-between;gap:.75rem;flex-wrap:wrap}.fi-result-head p{font-size:.78rem;color:#bdd0db;margin:0;flex:1 1 22rem}.fi-result-head button{flex:0 0 auto}
.fi-tools{display:flex;gap:.5rem;flex-wrap:wrap;list-style:none;padding:0;margin:.8rem 0 1.2rem}.fi-tools li{padding:.35rem .55rem;border:1px solid #4b6c78;color:#d6e6ed;font-size:.75rem}.fi-tools li[data-state=completed]{border-color:#498575;color:#b8f4df}.fi-tools li[data-state=failed],.fi-tools li[data-state=timed_out],.fi-tools li[data-state=unavailable]{color:#f3d69f;border-color:#88744c}
.fi-result>section{margin:1rem 0}.fi-result h4{color:#f0f8fa;font-size:.95rem;margin:.3rem 0 .4rem}.fi-result p,.fi-result li{font-size:.83rem;line-height:1.65;overflow-wrap:anywhere}.fi-result ul:not(.fi-tools){margin:.45rem 0;padding-left:1.3rem}.fi-result li+li{margin-top:.6rem}.fi-clues,.fi-limits{padding:.4rem 0 .4rem .9rem;border-left:2px solid #6c8b97}.fi-clues{border-left-color:#edc883}.fi-limits{border-left-color:#87e8dc}.fi-result li strong{display:block;margin-bottom:.15rem;color:#e6f1f5}
.fi-result .fi-tools li+li{margin-top:0}
.fi-result details{border-top:1px solid #345463;margin-top:1rem}.fi-result summary{min-height:44px;padding:.7rem 0;font-size:.82rem;font-weight:650;line-height:1.5;cursor:pointer}.fi-result dl{display:grid;grid-template-columns:minmax(7rem,auto) minmax(0,1fr);gap:.45rem 1rem;font-size:.8rem}.fi-result dt{color:#aec6d0}.fi-result dd{margin:0;overflow-wrap:anywhere}.fi-panel .fi-boundary{border-top:1px solid #2e4c5b;margin-top:1rem;padding-top:.8rem}
@media(max-width:640px){.fi-panel{padding:1rem}.fi-panel .companion-head{flex-wrap:wrap}.fi-panel .fi-steps{width:100%}.fi-steps li{gap:.35rem;font-size:.75rem}.fi-steps li:not(:last-child):after{margin:0 .35rem 0 0}.fi-steps b{flex-basis:1.5rem;height:1.5rem}.fi-actions button{flex:1 1 8rem}.fi-result dl{grid-template-columns:1fr;gap:.25rem}.fi-result dd{margin-bottom:.5rem}.fi-result-head button{width:100%}}
@media(prefers-reduced-motion:no-preference){.fi-panel button{transition:background-color .15s ease,border-color .15s ease}}
'''

FILE_INSPECTION_JS = r'''
function validFileInspectionReport(p) {
  const keys=(v,names)=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===names.slice().sort().join();
  const text=(v,max=512)=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v);
  const count=(v,max=2147483647)=>Number.isSafeInteger(v)&&v>=0&&v<=max;
  const slice=s=>keys(s,['architecture','bits','sections','imports','writable_executable'])&&text(s.architecture,120)&&[32,64].includes(s.bits)&&count(s.sections)&&count(s.imports)&&count(s.writable_executable);
  return keys(p,['schema','inspected_at','size_bytes','state','structure','identification','tools','clues','unknowns','next_step'])
    &&p.schema==='megalodon-file-inspection-report-v1'&&typeof p.inspected_at==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(p.inspected_at)&&Number.isFinite(Date.parse(p.inspected_at))
    &&count(p.size_bytes,67108864)&&p.size_bytes>0&&['completed','partial','failed','cancelled','unsupported'].includes(p.state)
    &&(p.structure===null||(keys(p.structure,['format','slices_detected','slices'])&&['ELF','PE','Mach-O'].includes(p.structure.format)&&count(p.structure.slices_detected,2147483647)&&p.structure.slices_detected>0&&Array.isArray(p.structure.slices)&&p.structure.slices.length>0&&p.structure.slices.length<=16&&p.structure.slices.length<=p.structure.slices_detected&&p.structure.slices.every(slice)))
    &&Array.isArray(p.identification)&&p.identification.length<=32&&p.identification.every(v=>keys(v,['kind','name'])&&['compiler','packer','protector','linker'].includes(v.kind)&&text(v.name,120))
    &&Array.isArray(p.tools)&&p.tools.length===2&&p.tools.every((v,i)=>keys(v,['id','state'])&&v.id===['lief','die'][i]&&['completed','unavailable','unsupported','failed','timed_out','cancelled'].includes(v.state))
    &&Array.isArray(p.clues)&&p.clues.length<=16&&p.clues.every(v=>keys(v,['code','title','meaning'])&&typeof v.code==='string'&&/^[a-zA-Z0-9_-]{1,80}$/.test(v.code)&&text(v.title)&&text(v.meaning))
    &&Array.isArray(p.unknowns)&&p.unknowns.length<=16&&p.unknowns.every(v=>text(v))&&text(p.next_step)
    &&new TextEncoder().encode(JSON.stringify(p)).length<=65536;
}
function validFileInspectionStatus(p) {
  const keys=(v,names)=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===names.slice().sort().join();
  return keys(p,['schema','state','job_id','runtime','max_bytes','report','token'])&&p.schema==='megalodon-file-inspection-status-v1'
    &&['idle','receiving','running','completed','partial','failed','cancelled'].includes(p.state)&&(p.job_id===null||typeof p.job_id==='string'&&/^[a-f0-9]{32}$/.test(p.job_id))
    &&keys(p.runtime,['state','message'])&&['ready','unavailable','unsupported'].includes(p.runtime.state)&&typeof p.runtime.message==='string'&&p.runtime.message.length>0&&p.runtime.message.length<=512&&!/[\x00-\x1f\x7f]/.test(p.runtime.message)
    &&p.max_bytes===67108864&&(p.report===null||validFileInspectionReport(p.report))&&typeof p.token==='string'&&p.token.length===32&&/^[A-Za-z0-9_-]{32}$/.test(p.token);
}
(() => {
  const el=id=>document.getElementById('file-inspection'+(id?'-'+id:'')),panel=el('');
  if(!panel||typeof localHudLaunch==='undefined')return;
  const state={payload:null,valid:false,signInRequired:false,file:null,selection:0,ownedJob:null,ownedSelection:null,report:null,reportJob:null,uploading:false,cancelling:false,checking:false,inView:false,timer:null,upload:null,epoch:0,rendered:null};
  const names={lief:'LIEF · structure',die:'Detect It Easy · identification'},labels={completed:'Completed',partial:'Partial coverage',unavailable:'Unavailable',unsupported:'Unsupported',failed:'Failed',timed_out:'Time limit reached',cancelled:'Cancelled'};
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const active=()=>state.uploading||['receiving','running'].includes(state.payload?.state);
  const visible=()=>state.inView&&!document.hidden;
  const selected=()=>state.file&&Number.isSafeInteger(state.file.size)&&state.file.size>0&&state.file.size<=67108864;
  function message(text,kind='idle'){el('status').textContent=text;panel.dataset.state=kind;}
  function installControls(){
    const missing=state.payload&&state.payload.runtime.state!=='ready';
    const hb=typeof heartbeatState==='undefined'?null:heartbeatState,entry=hb?.catalog?.find(v=>v.id==='file-inspector');
    const allowed=Boolean(entry?.one_click&&hb.managementEnabled&&typeof toolManagementToken==='function'&&toolManagementToken()&&typeof heartbeatStale==='function'&&!heartbeatStale());
    const installing=hb?.job?.state==='running',mine=installing&&hb.job.tool==='file-inspector';
    el('install').hidden=!missing||!entry?.one_click;el('install').disabled=!allowed||!!installing||!!hb?.submitting||active();
    el('install').textContent=mine?'Installing file inspector…':'Install file inspector';el('authorize').hidden=!missing||allowed;
    el('install-note').hidden=!missing;el('install-note').textContent=mine?'Installation is running. Check inspector afterward; installation alone does not verify analysis.':installing?'Another tool action is running. Wait for it to finish.':allowed?'Optional download. Review the installation confirmation before continuing.':'Optional installation uses the existing authorized installer in Setup.';
  }
  function controls(){
    const busy=active();el('input').disabled=busy;el('run').disabled=!state.valid||!selected()||state.payload?.runtime.state!=='ready'||busy||state.cancelling;
    el('run').textContent=state.uploading?'Sending to local inspector…':state.payload?.state==='running'?'Inspecting…':'Inspect';
    el('cancel').hidden=!busy;el('cancel').disabled=!busy||state.cancelling||!state.valid;el('cancel').textContent=state.cancelling?'Cancelling…':'Cancel inspection';
    el('check').disabled=state.checking;el('export').disabled=!state.report;
    el('sign-in').hidden=!state.signInRequired;el('runtime').hidden=state.signInRequired;
    panel.setAttribute('aria-busy',busy?'true':'false');
    const step=busy?'inspect':state.report?'understand':selected()?'inspect':'choose';
    panel.querySelectorAll('[data-step]').forEach(n=>{if(n.dataset.step===step)n.setAttribute('aria-current','step');else n.removeAttribute('aria-current');});
    installControls();
  }
  function renderReport(){
    const report=state.report;el('result').hidden=!report;if(!report)return;
    const owned=state.ownedJob===state.reportJob&&state.ownedSelection===state.selection;
    el('report-scope').textContent=(owned?'Report for the file you submitted. ':'Earlier report in this HUD session; not associated with the current file selection. ')+report.inspected_at.replace('T',' ').replace('Z',' UTC')+' · '+labels[report.state];
    const key=JSON.stringify(report);if(state.rendered===key)return;state.rendered=key;
    el('tools').replaceChildren(...report.tools.map(t=>{const item=node('li',names[t.id]+': '+labels[t.state]);item.dataset.state=t.state;return item;}));
    const structure=report.structure;
    const formats={ELF:'Linux / Unix executable (ELF)',PE:'Windows executable or library (PE)','Mach-O':'macOS executable or library (Mach-O)'};
    el('what').textContent=structure?formats[structure.format]+'. '+[...new Set(structure.slices.map(s=>s.architecture+' · '+s.bits+'-bit'))].join('; ')+'.':'The available tools could not establish a supported executable structure.';
    const clues=report.clues.map(c=>{const item=node('li','');item.append(node('strong',c.title),node('span',c.meaning));return item;});
    for(const kind of ['compiler','packer','protector','linker']){
      const matches=report.identification.filter(i=>i.kind===kind);if(!matches.length)continue;
      const item=node('li','');item.append(node('strong','Reported '+kind+' clue'),node('span',matches.map(i=>i.name).join('; ')));clues.push(item);
    }
    if(report.identification.length)clues.push(node('li','Identification labels are signature matches, not a verified build history. Matches can be incomplete or mistaken.'));
    if(!clues.length)clues.push(node('li','No review clues were returned within this inspection’s coverage. This does not establish that the file is safe.'));
    if(report.identification.some(i=>['packer','protector'].includes(i.kind)))clues.push(node('li','Packing can make a program harder to inspect. Legitimate software also uses it.'));
    el('clues').replaceChildren(...clues);
    el('unknowns').replaceChildren(...(report.unknowns.length?report.unknowns:['Static metadata cannot show what a program will do when it runs.']).map(t=>node('li',t)));
    el('next').textContent=report.next_step;
    const technical=document.createElement('dl');technical.append(node('dt','Input size'),node('dd',report.size_bytes.toLocaleString()+' bytes'));
    if(structure){technical.append(node('dt','Slice coverage'),node('dd',structure.slices.length+' of '+structure.slices_detected+' reported executable slices'));
      structure.slices.forEach((s,i)=>technical.append(node('dt','Slice '+(i+1)),node('dd',s.architecture+' · '+s.bits+'-bit · '+s.sections+' sections · '+s.imports+' imports · '+s.writable_executable+' writable/executable regions')));}
    report.identification.forEach(i=>technical.append(node('dt','Reported '+i.kind+' clue'),node('dd',i.name)));
    el('technical').replaceChildren(technical);
  }
  function accept(p){
    if(!validFileInspectionStatus(p))throw Error('Invalid inspector response');state.payload=p;state.valid=true;state.signInRequired=false;
    state.report=p.report;state.reportJob=p.job_id;el('runtime-note').textContent=p.runtime.message;
    if(state.cancelling)message('Cancelling the local inspection…','receiving');
    else if(state.uploading)message('Sending the selected file to this local HUD. You can cancel while it is being received.','receiving');
    else if(p.state==='receiving')message('The local inspector is receiving a file. You can cancel this inspection.','receiving');
    else if(p.state==='running')message('Reading structure and identification clues on this PC. Analysis stops at the time limit.','running');
    else if(p.report)message(({completed:'Inspection completed. Read the clues and limits together.',partial:'Partial inspection. Some tool results or executable slices are unavailable.',failed:'Inspection could not finish. Review each tool’s status and the suggested next step.',cancelled:'Inspection cancelled. No safety conclusion is available.',unsupported:'This file is not supported by the available inspection tools.'})[p.report.state],p.report.state);
    else if(p.state==='cancelled')message('Inspection cancelled. Choose a file when you are ready.','cancelled');
    else if(p.runtime.state!=='ready')message('The file inspector is not ready. Read the availability message below.','error');
    else if(state.file&&!selected())message(state.file.size===0?'This file is empty. Choose an executable with content.':'This file is larger than 64 MiB. Choose a smaller program.','error');
    else message(selected()?'Ready. Select Inspect to send this file to the local inspector.':'Ready. Choose one file, then select Inspect.');
    renderReport();controls();
  }
  function signInError(error){
    if(!error.signInRequired)return false;
    state.signInRequired=true;state.valid=false;state.payload=null;state.report=null;state.reportJob=null;state.ownedJob=null;state.rendered=null;
    state.epoch++;state.upload?.abort();state.upload=null;state.uploading=false;state.cancelling=false;
    message('File inspection requires local HUD sign-in. Open Local sign-in in Setup to prepare a protected launch.','error');
    renderReport();controls();schedule();return true;
  }
  async function boundedBody(response){
    if(Number(response.headers.get('content-length'))>65536)throw Error('Inspector response too large');
    if(response.body?.getReader){const reader=response.body.getReader(),parts=[];let size=0;
      try{while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>65536)throw Error('Inspector response too large');parts.push(part.value);}}
      catch(error){await reader.cancel();throw error;}const bytes=new Uint8Array(size);let at=0;for(const part of parts){bytes.set(part,at);at+=part.byteLength;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
    const body=await response.text();if(new TextEncoder().encode(body).length>65536)throw Error('Inspector response too large');return JSON.parse(body);
  }
  async function request(path,options={}){
    const controller=options.signal?null:new AbortController(),timer=controller?setTimeout(()=>controller.abort(),7000):null;
    try{const response=await fetch('/api/file-inspection'+path,{cache:'no-store',credentials:'same-origin',mode:'same-origin',redirect:'error',...(controller?{signal:controller.signal}:{}),...options,headers:{'Accept':'application/json','X-Megalodon-Check':'1',...(options.headers||{})}});
      const p=await boundedBody(response);if(!response.ok){const error=Error('Inspector request failed');error.status=response.status;error.signInRequired=response.status===403&&p?.code==='file_inspection_sign_in_required';throw error;}return p;
    }finally{if(timer!==null)clearTimeout(timer);}
  }
  function stopTimer(){if(state.timer!==null)clearTimeout(state.timer);state.timer=null;}
  function schedule(){stopTimer();if(visible()||active())state.timer=setTimeout(()=>refresh(),active()?1000:15000);}
  async function refresh(){
    if(state.checking)return;state.checking=true;controls();const epoch=state.epoch,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),7000);
    try{const p=await request('',{signal:controller.signal});if(epoch===state.epoch)accept(p);}
    catch(error){if(epoch===state.epoch&&!signInError(error)){state.valid=false;message('Inspector status is unavailable. Check inspector to reconnect. Any displayed report is an earlier result.','error');}}
    finally{clearTimeout(timer);state.checking=false;controls();schedule();}
  }
  el('input').addEventListener('change',()=>{
    state.file=el('input').files?.[0]||null;state.selection++;state.report=null;state.rendered=null;el('result').hidden=true;
    el('selection').textContent=state.file?state.file.name+' · '+state.file.size.toLocaleString()+' bytes':'No file selected.';
    if(state.signInRequired)message('File inspection requires local HUD sign-in. Open Local sign-in in Setup to prepare a protected launch.','error');
    else if(state.file&&!selected())message(state.file.size===0?'This file is empty. Choose an executable with content.':'This file is larger than 64 MiB. Choose a smaller program.','error');
    else message(state.file?'Selected only. Nothing has been sent. Select Inspect when ready.':'No file selected.');controls();
  });
  el('run').addEventListener('click',async()=>{
    if(el('run').disabled)return;const epoch=++state.epoch,selection=state.selection,file=state.file,token=state.payload.token;
    state.uploading=true;state.report=null;state.rendered=null;state.ownedJob=null;state.ownedSelection=selection;el('result').hidden=true;state.upload=new AbortController();message('Sending the selected file to this local HUD. You can cancel while it is being received.','receiving');controls();schedule();
    try{const p=await request('/run',{method:'POST',signal:state.upload.signal,headers:{'Content-Type':'application/octet-stream','X-Megalodon-Config-Token':token},body:file});
      if(epoch!==state.epoch)return;if(!validFileInspectionStatus(p))throw Error('Invalid inspector response');state.ownedJob=p.job_id;state.uploading=false;accept(p);}
    catch(error){if(epoch===state.epoch&&!signInError(error)){state.uploading=false;message(error.status===409?'Another inspection is active. Check inspector to review or cancel it.':'The file could not be submitted. Check inspector before trying again.','error');}}
    finally{if(epoch===state.epoch){state.uploading=false;state.upload=null;controls();schedule();}}
  });
  el('cancel').addEventListener('click',async()=>{
    if(el('cancel').disabled)return;state.cancelling=true;controls();message('Cancelling the local inspection…','receiving');
    try{const p=await request('/cancel',{method:'POST',headers:{'Content-Type':'application/json','X-Megalodon-Config-Token':state.payload.token},body:'{}'});
      if(!validFileInspectionStatus(p))throw Error('Invalid cancellation response');state.epoch++;state.upload?.abort();state.upload=null;state.uploading=false;state.cancelling=false;accept(p);}
    catch(error){if(!signInError(error))message('Cancellation could not be confirmed. Check inspector and retry cancellation if it is still active.','error');}
    finally{state.cancelling=false;controls();schedule();}
  });
  el('check').addEventListener('click',refresh);
  el('install').addEventListener('click',async()=>{
    if(el('install').disabled)return;const entry=heartbeatState.catalog.find(v=>v.id==='file-inspector');await startInstall('file-inspector','File inspector',entry);controls();await refresh();
  });
  el('export').addEventListener('click',()=>{
    if(!state.report||!validFileInspectionReport(state.report))return;const url=URL.createObjectURL(new Blob([JSON.stringify(state.report,null,2)+'\n'],{type:'application/json'}));
    const link=document.createElement('a');link.href=url;link.download='megalodon-file-inspection.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  document.addEventListener('visibilitychange',()=>{stopTimer();if(visible()||active())refresh();});
  if(typeof IntersectionObserver==='function')new IntersectionObserver(entries=>{state.inView=entries.some(e=>e.isIntersecting);if(visible())refresh();else schedule();}).observe(panel);
  else {state.inView=true;refresh();}
  controls();
})();
'''
