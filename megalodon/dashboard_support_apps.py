"""Local HUD support-app launcher presentation; no side effects on import."""

SUPPORT_APPS_HTML = r'''
<section class="support-apps" id="support-apps" aria-labelledby="support-apps-title">
  <div class="support-apps-main">
    <div class="support-apps-copy"><p class="eyebrow">BACKGROUND WORKSPACE</p><h3 id="support-apps-title" tabindex="-1">Background tools</h3><p>Start installed services and configured collectors together. No Wireshark, Zenmap or ClamTk windows open.</p></div>
    <div class="support-apps-actions"><button type="button" id="support-apps-start" disabled>Start background tools</button><button type="button" id="support-apps-configure" aria-expanded="false" aria-controls="support-config">Configure apps</button><button type="button" id="support-apps-copy" class="button-secondary" disabled>Copy command</button><p id="support-apps-copy-status" class="support-apps-copy-status" role="status" aria-live="polite" aria-atomic="true"></p></div>
  </div>
  <div class="support-apps-feedback"><p id="support-apps-status" role="status" aria-live="polite" aria-atomic="true">Checking background controls…</p><button type="button" id="support-apps-check" class="button-secondary" hidden>Check status</button></div>
  <p class="support-apps-note">A system authorization prompt may appear when a service needs permission. <a href="#integrations-title">View tool status</a> · <a href="#live-globe-title">Background monitoring controls</a></p>
  <!-- HUD_SUPPORT_CONFIG -->
  <details id="support-apps-details"><summary id="support-apps-summary">Tool startup status</summary><ul id="support-apps-items"><li>Waiting for the local service.</li></ul><p class="support-apps-note">These are startup outcomes. Open Actions for current tool status and source updates. Collectors use their saved configuration.</p><div id="support-apps-command-wrap" hidden><label for="support-apps-command">Command for your terminal</label><input id="support-apps-command" readonly spellcheck="false"></div></details>
</section>
'''

SUPPORT_APPS_CSS = r'''
.support-apps { margin:1.25rem 0; padding:1.2rem 1.25rem; border:1px solid #456777; border-left:4px solid #75e6e1; border-radius:6px; background:#102532; color:#e5f0f6; font-size:1rem; min-width:0; }
.support-apps-main { display:flex; justify-content:space-between; align-items:center; gap:1.2rem; flex-wrap:wrap; }
.support-apps-copy { flex:1 1 24rem; } .support-apps h3 { margin:.2rem 0 .5rem; font-size:1.4rem; letter-spacing:-.025em; }
.support-apps .eyebrow { color:#75e6e1; font-size:.875rem; margin:0; } .support-apps-copy > p:last-child { color:#c7d9e3; margin:0; line-height:1.6; max-width:64ch; }
.support-apps-actions { display:flex; flex-wrap:wrap; align-items:center; gap:.65rem; }
.support-apps .support-apps-copy-status { flex-basis:100%; max-width:36ch; margin:0; color:#c7d9e3; font-size:.875rem; line-height:1.6; }
.support-apps button { font:inherit; font-weight:600; min-height:44px; padding:.65rem .9rem; border:1px solid #72939e; border-radius:4px; background:#183847; color:#eff8fb; cursor:pointer; }
.support-apps #support-apps-start { background:#75e6e1; color:#071d27; border-color:#75e6e1; }
.support-apps #support-apps-start:hover { background:#a2f1ec; } .support-apps button:hover { background:#25495a; }
.support-apps button:active { transform:translateY(1px); } .support-apps button:disabled { opacity:.55; cursor:default; transform:none; }
.support-apps :is(button,input,summary,[tabindex]):focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
.support-apps-feedback { display:flex; align-items:center; gap:.8rem; flex-wrap:wrap; margin-top:.9rem; }
.support-apps-feedback p { margin:0; line-height:1.6; color:#d6e7ee; } .support-apps[data-state="running"] #support-apps-status { color:#9bf0dc; }
.support-apps[data-state="stale"] #support-apps-status,.support-apps[data-state="failed"] #support-apps-status { color:#f2ce8b; }
.support-apps .support-apps-note { color:#b7ccd8; font-size:.875rem; line-height:1.6; margin:.4rem 0; }
.support-apps details { margin-top:.65rem; border-top:1px solid #375262; }
.support-apps summary { cursor:pointer; min-height:44px; padding:.65rem 0; font-size:.875rem; font-weight:600; line-height:1.6; }
.support-apps ul { margin:.2rem 0 .65rem; padding:0; list-style:none; }
.support-apps li { display:grid; grid-template-columns:minmax(7rem,1fr) minmax(6rem,.8fr) minmax(0,3fr); gap:.6rem; padding:.6rem 0; border-bottom:1px solid #2a4656; font-size:.875rem; line-height:1.6; overflow-wrap:anywhere; }
.support-apps li > span { color:#bfd3df; } .support-apps .support-apps-item-state { color:#c7e3eb; font-weight:600; }
.support-apps li[data-state="failed"] .support-apps-item-state,.support-apps li[data-state="needs_setup"] .support-apps-item-state,.support-apps li[data-state="missing"] .support-apps-item-state { color:#f2ce8b; }
.support-apps label { display:block; margin:.8rem 0 .4rem; font-size:.875rem; } .support-apps input { width:100%; min-width:0; color:#e3f2f5; background:#071722; padding:.7rem; border:1px solid #527081; font:inherit; font-size:.875rem; }
@media(max-width:600px) { .support-apps { padding:1rem; } .support-apps-actions { width:100%; } .support-apps-actions button { flex:1 1 10rem; } .support-apps li { grid-template-columns:minmax(0,1fr) auto; } .support-apps li > span:last-child { grid-column:1 / -1; } }
@media print { .support-apps { display:none; } }
'''

SUPPORT_APPS_JS = r'''
(() => {
  const el = id => document.getElementById(id);
  if (typeof localHudLaunch === 'undefined' || !el('support-apps')) return;
  const app = {payload:null, token:null, command:null, pending:false, starting:false, valid:false, timer:null, deadline:0};
  const labels = {idle:'Not started',checking:'Checking',running:'Running',launched:'Launch requested',queued:'Queued',missing:'Not installed',needs_setup:'Needs setup',failed:'Failed',not_needed:'Ready'};
  const text = (v,max=512) => typeof v === 'string' && v.length <= max && !/[\x00-\x1f\x7f]/.test(v);
  const timestamp = v => v === null || (text(v,40) && /Z$/.test(v) && Number.isFinite(Date.parse(v)));
  function checked(v, needToken) {
    if (!v || typeof v !== 'object' || Array.isArray(v) || v.schema !== 'megalodon-support-startup-v1'
      || !['idle','running','finished'].includes(v.state) || !timestamp(v.started_at) || !timestamp(v.finished_at)
      || !Array.isArray(v.items) || v.items.length > 16
      || !v.items.every(i => i && text(i.id,60) && text(i.name,80) && Object.hasOwn(labels,i.state) && text(i.message))
      || (needToken && !/^[A-Za-z0-9_-]{32}$/.test(v.token || ''))
      || (v.token !== undefined && !/^[A-Za-z0-9_-]{32}$/.test(v.token))
      || !text(v.command,512) || !v.command.length) throw Error('Invalid support-app response');
    return v;
  }
  function feedback(message,kind='idle') { el('support-apps-status').textContent=message;el('support-apps').dataset.state=kind; }
  function controls() {
    const busy=app.pending || (app.payload && app.payload.state === 'running');
    el('support-apps-start').disabled=!!busy || !app.valid || document.hidden;
    el('support-apps-start').textContent=(app.starting || (app.valid && app.payload && app.payload.state==='running')) ? 'Starting background tools…' : 'Start background tools';
    el('support-apps-start').setAttribute('aria-busy',app.pending ? 'true' : 'false');
    el('support-apps-copy').disabled=!app.command;
    el('support-apps-check').disabled=app.pending;
  }
  function render(v) {
    const rows=v.items.map(item=>{
      const row=document.createElement('li');row.dataset.state=item.state;
      const name=document.createElement('strong');name.textContent=item.name;
      const state=document.createElement('span');state.className='support-apps-item-state';state.textContent=labels[item.state];
      const message=document.createElement('span');message.textContent=item.message;row.append(name,state,message);return row;
    });
    el('support-apps-items').replaceChildren(...rows);
    el('support-apps-summary').textContent=`${v.state === 'finished' ? 'Last startup results' : 'Tool startup status'}${v.items.length ? ' · '+v.items.length+' tools' : ''}`;
    const count=states=>v.items.filter(item=>states.includes(item.state)).length;
    if (v.state === 'running') feedback(`Starting background tools… ${count(['running','launched','queued','not_needed'])} ready or queued.`, 'running');
    else if (v.state === 'finished') {
      const ready=count(['running','not_needed']),launched=count(['launched']),queued=count(['queued']),attention=count(['missing','needs_setup','failed']);
      const completed=v.finished_at ? ' at '+new Date(v.finished_at).toISOString().replace('T',' ').replace('.000Z',' UTC') : ' · completion time unavailable';
      feedback(`Last start completed${completed} · ${ready} were running or ready${launched ? ' · '+launched+' launch request'+(launched===1 ? '' : 's') : ''}${queued ? ' · '+queued+' queued' : ''}${attention ? ' · '+attention+' need attention — see last startup results.' : '.'}`, attention ? 'stale' : 'finished');
    } else feedback('Ready when you are. Background tools start when you press Start background tools.');
    if (document.hidden) feedback('Updates paused while this tab is hidden. Background startup continues on this PC.', 'stale');
  }
  async function responseBody(response) {
    const size=response.headers.get('content-length');
    if (size && Number(size)>32768) throw Error('Support-app response too large');
    if (response.body && response.body.getReader) {
      const reader=response.body.getReader(), chunks=[];let length=0;
      try { while (true) {const part=await reader.read();if(part.done)break;length+=part.value.byteLength;if(length>32768)throw Error('Support-app response too large');chunks.push(part.value);} }
      catch (error) {await reader.cancel();throw error;}
      const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
      return JSON.parse(new TextDecoder().decode(bytes));
    }
    const body=await response.text();if(new TextEncoder().encode(body).length>32768)throw Error('Support-app response too large');return JSON.parse(body);
  }
  function cancelPoll() {if(app.timer!==null)clearTimeout(app.timer);app.timer=null;}
  function schedule() {
    cancelPoll();
    if(document.hidden || !app.valid || !app.payload || app.payload.state!=='running')return;
    if(Date.now()>=app.deadline){app.valid=false;feedback('Startup is taking longer than expected. Check status to see the latest result.','stale');el('support-apps-check').hidden=false;controls();return;}
    app.timer=setTimeout(()=>read(false),2000);
  }
  async function request(method) {
    const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),10000);
    try {
      const options={method,cache:'no-store',credentials:'same-origin',signal:controller.signal,headers:method==='GET'?{'X-Megalodon-Check':'1'}:{'Content-Type':'application/json','X-Megalodon-Support-Token':app.token}};
      if(method==='POST')options.body=JSON.stringify({action:'start'});
      const response=await fetch('/api/support-start',options);
      if(method==='POST' && response.status===409)return null;
      if(!response.ok)throw Error('Support-app request failed');
      return checked(await responseBody(response),method==='GET');
    } finally {clearTimeout(timeout);}
  }
  function accept(v) {app.payload=v;if(v.token)app.token=v.token;app.command=v.command;app.valid=true;el('support-apps-command').value=v.command;el('support-apps-check').hidden=true;render(v);}
  function failed() {app.valid=false;app.token=null;feedback('Unable to confirm background startup status. Check status before trying again.','failed');el('support-apps-check').hidden=false;}
  async function read(reset=true) {
    if(app.pending || document.hidden)return;
    cancelPoll();if(reset)app.deadline=Date.now()+300000;app.pending=true;controls();
    try {accept(await request('GET'));}catch(_){failed();}finally{app.pending=false;controls();schedule();}
  }
  async function start() {
    if(app.pending || !app.valid || !app.token || document.hidden || app.payload.state==='running')return;
    cancelPoll();app.pending=true;app.starting=true;app.deadline=Date.now()+300000;feedback('Starting background tools… Checking what is already running.','running');controls();
    try {const v=await request('POST');if(v)accept(v);else accept(await request('GET'));}
    catch(_){failed();}
    finally{app.pending=false;app.starting=false;controls();schedule();}
  }
  el('support-apps-start').addEventListener('click',start);
  el('support-apps-check').addEventListener('click',()=>read(true));
  el('support-apps-copy').addEventListener('click',async()=>{
    if(!app.command)return;
    try {await navigator.clipboard.writeText(app.command);el('support-apps-copy-status').textContent='Start command copied.';}
    catch(_){el('support-apps-command-wrap').hidden=false;el('support-apps-details').open=true;el('support-apps-command').focus();el('support-apps-command').select();el('support-apps-copy-status').textContent='Select and copy the command shown below.';}
  });
  document.addEventListener('visibilitychange',()=>{
    cancelPoll();if(document.hidden){feedback('Updates paused while this tab is hidden. Background startup continues on this PC.','stale');controls();}
    else read(true);
  });
  read(true);
})();
'''
