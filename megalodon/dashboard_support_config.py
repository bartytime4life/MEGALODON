"""Explicit local support-tool setup and bounded capture controls."""

SUPPORT_CONFIG_HTML = r'''
<section class="support-config" id="support-config" aria-labelledby="support-config-title" hidden>
  <div class="support-config-head"><div><p class="eyebrow">CONFIGURE THIS PC</p><h4 id="support-config-title" tabindex="-1">Configure local tools</h4><p>Set up capture and collectors, or check the tools you use. Settings stay on this computer.</p></div><button type="button" id="support-config-close" class="button-secondary">Close configuration</button></div>
  <div class="support-config-feedback"><p id="support-config-status" role="status" aria-live="polite" aria-atomic="true">Checking available tools and capture settings…</p><button type="button" id="support-config-retry" hidden>Check again</button></div>
  <section class="support-capture" aria-labelledby="support-capture-title">
    <div class="support-config-section-head"><h5 id="support-capture-title">Network capture</h5><span id="support-capture-state" class="support-config-badge">Not checked</span></div>
    <div class="support-capture-steps">
      <div><label for="support-config-interface"><span class="support-step">1</span> Select your network interface</label><select id="support-config-interface" disabled><option value="">Checking interfaces…</option></select><p id="support-config-interface-note" class="support-config-note">Your active default interface is suggested when available.</p></div>
      <div><h6><span class="support-step">2</span> Allow capture for this user</h6><button type="button" id="support-config-permissions" disabled>Configure capture access</button><p class="support-config-note">An operating-system prompt grants packet-capture access to your user. Wireshark stays a normal-user app.</p></div>
    </div>
    <div class="support-capture-destinations">
      <section aria-labelledby="support-hud-capture-title"><h6 id="support-hud-capture-title"><span class="support-step">3</span> Send traffic to HUD charts</h6><p>Collect packet metadata for the HUD traffic charts.</p><div class="support-config-actions"><button type="button" id="support-config-capture-start" class="support-config-primary" disabled>Start HUD traffic</button><button type="button" id="support-config-capture-stop" disabled>Stop HUD capture</button></div><p class="support-config-note">Stops after 15 minutes or 50,000 packets. No raw packet files are retained by the HUD.</p></section>
      <details class="support-desktop-options"><summary id="support-wireshark-title">Optional desktop inspection</summary><h6>Inspect in live Wireshark</h6><p>Open the selected interface in a managed Wireshark window.</p><div class="support-config-actions"><button type="button" id="support-config-wireshark-open" disabled>Open live Wireshark</button><button type="button" id="support-config-wireshark-stop" disabled>Close managed Wireshark</button></div><p class="support-config-note">Separate from HUD collection. Its capture stops after 15 minutes or 50,000 packets. Wireshark holds its own buffer; you choose whether to save it. Save any capture you want to keep before closing. This closes only the window opened here.</p><p id="support-wireshark-result" class="support-config-note">No saved Wireshark action result. Current window state is not monitored here.</p></details>
    </div>
    <div class="support-capture-reading"><p id="support-capture-message">No capture status loaded.</p><dl><div><dt>Received packets</dt><dd id="support-capture-received">—</dd></div><div><dt>Accepted records</dt><dd id="support-capture-accepted">—</dd></div><div><dt>Skipped packets</dt><dd id="support-capture-skipped">—</dd></div></dl><p id="support-capture-time" class="support-config-note">Capture time unavailable.</p></div>
  </section>
  <details class="support-collector-settings"><summary>Inventory and file-scan settings</summary><div class="support-tool-settings">
    <section aria-labelledby="support-config-nmap-title"><h5 id="support-config-nmap-title">Nmap</h5><p>Choose a private IPv4 address or network you manage, up to 256 addresses.</p><label for="support-config-nmap-target">Inventory target</label><input id="support-config-nmap-target" type="text" value="127.0.0.1/32" maxlength="18" spellcheck="false" disabled aria-describedby="support-nmap-help"><p id="support-nmap-help" class="support-config-note">Use /24–/32, such as 192.168.1.0/24. A single address uses /32.</p><button type="button" id="support-config-nmap-save" disabled>Save and collect inventory</button></section>
    <section aria-labelledby="support-config-clamav-title"><h5 id="support-config-clamav-title">ClamAV</h5><p>Scan a folder in your home directory and update the HUD result.</p><label for="support-config-scan-folder">Folder to scan</label><select id="support-config-scan-folder" disabled><option value="Downloads">Downloads</option><option value="Documents">Documents</option></select><div class="support-config-actions"><button type="button" id="support-config-clamav-save" disabled>Save and scan folder</button><button type="button" id="support-config-signatures" disabled>Update virus signatures</button></div><p class="support-config-note">The installed signature updater may request operating-system authorization.</p></section>
    <section aria-labelledby="support-config-osquery-title"><h5 id="support-config-osquery-title">osquery</h5><p>Enable the fixed package inventory and send its count to the HUD.</p><button type="button" id="support-config-osquery" disabled>Enable package inventory</button></section>
  </div></details>
  <details class="support-service-settings"><summary>Local AI and background sensors</summary><div class="support-tool-settings">
    <section aria-labelledby="support-model-title"><h5 id="support-model-title" tabindex="-1">Local AI · Ollama</h5><p>Choose an installed model for HUD analysis and automatic collector advice.</p>
    <label for="support-model-select">Installed model</label><select id="support-model-select" disabled><option value="">Checking installed models…</option></select>
    <label for="support-model-compute">Compute</label><select id="support-model-compute" disabled><option value="cpu">CPU · keep GPU available</option><option value="auto">Ollama automatic · may use GPU</option></select>
    <div class="support-config-actions"><button type="button" id="support-model-save" disabled>Use selected model</button><button type="button" id="support-model-refresh" disabled>Refresh installed models</button></div>
    <p id="support-model-status" role="status" class="support-config-note">Checking the selected model…</p><p id="support-model-metrics" class="support-config-note"></p>
    <p class="support-config-note">Selection checks local text completion and pins the exact installed version. Large models may exceed the 15-second response limit. Models are unloaded after MEGALODON replies; another app may keep them loaded. No downloads or cloud inference occur here.</p><div class="support-config-actions"><button type="button" id="support-config-qwen-setup" disabled>Configure Ollama access</button><button type="button" id="support-config-qwen" disabled>Verify selected model</button></div><p class="support-config-note">A one-time system prompt keeps Ollama on this PC. The selected model advises; generated commands do not run.</p></section>
    <section><h5>Zeek</h5><p>Prepare the automatic background sampler and its private working folder.</p><button type="button" id="support-config-zeek" disabled>Prepare Zeek sampler</button><p class="support-config-note">Source summaries appear in Actions; they are separate from HUD packet totals and detector findings.</p></section>
    <section><h5>Suricata</h5><p>Configure the passive sensor on the selected network interface.</p><div class="support-config-actions"><button type="button" id="support-config-suricata-setup" disabled>Configure background Suricata</button><button type="button" id="support-config-suricata" disabled>Check configuration</button></div><p class="support-config-note">A one-time system prompt configures the service and access to its local logs.</p></section>
  </div></details>
  <details class="support-config-results"><summary>Latest tool results</summary><p class="support-config-note">Each result keeps its own check time. Setup and availability do not prove a tool is feeding the HUD.</p><ul id="support-config-tools"><li>No tool checks returned yet.</li></ul></details>
</section>
'''

SUPPORT_CONFIG_CSS = r'''
.support-apps #support-apps-configure { border-color:#75e6e1; box-shadow:inset 0 0 0 1px #75e6e1; }
.support-apps #support-apps-configure[aria-expanded="true"] { background:#244955; }
.support-config { border-top:1px solid #4b6b79; margin-top:1rem; padding-top:1.25rem; }
.support-config-head,.support-config-section-head,.support-config-feedback { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:.8rem; }
.support-config h4 { margin:.3rem 0 .5rem; font-size:1.3rem; } .support-config h5 { font-size:1.05rem; margin:0 0 .65rem; } .support-config h6 { font-size:1rem; margin:0 0 .8rem; line-height:1.6; }
.support-config p { margin:.5rem 0 .8rem; max-width:78ch; font-size:1rem; line-height:1.6; color:#c6d8e2; }
.support-config-feedback { margin:.75rem 0 1.25rem; align-items:center; padding:.8rem 1rem; border-left:3px solid #64858c; background:#0a1b27; }
.support-config-feedback p { margin:0; } .support-config[data-state="failed"] .support-config-feedback,.support-config[data-state="stale"] .support-config-feedback { border-color:#e9bc6b; }
.support-config[data-state="failed"] #support-config-status,.support-config[data-state="stale"] #support-config-status { color:#f2ce8b; }
.support-config select,.support-config input { box-sizing:border-box; width:100%; max-width:26rem; min-height:44px; border:1px solid #6f8b9b; border-radius:4px; padding:.6rem .75rem; color:#e3f2f5; background:#071722; font:inherit; }
.support-config :is(select,input,button):focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
.support-config select:disabled,.support-config input:disabled { opacity:.6; } .support-config label { margin:0 0 .65rem; font-size:1rem; font-weight:600; line-height:1.6; }
.support-capture { border:1px solid #3e6877; padding:1.1rem; background:#0d202c; border-radius:4px; }
.support-capture-steps,.support-capture-destinations { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1.4rem; margin-top:1.2rem; }
.support-capture-destinations { grid-template-columns:1fr; padding-top:1.2rem; border-top:1px solid #355464; }
.support-desktop-options { border-top:1px solid #355464; } .support-desktop-options > summary { color:#bfd3df; }
.support-step { display:inline-grid; place-items:center; width:1.6rem; height:1.6rem; font-size:.875rem; margin-right:.4rem; color:#b8f8ed; background:#234a54; border-radius:3px; }
.support-config .support-config-note { font-size:.875rem; line-height:1.6; color:#b7ccd8; }
.support-config-actions { display:flex; flex-wrap:wrap; gap:.65rem; margin:.8rem 0; }
.support-apps .support-config-primary { background:#75e6e1; color:#071d27; border-color:#75e6e1; } .support-apps .support-config-primary:hover { background:#a2f1ec; }
.support-config-badge { display:inline-block; color:#d7e9ef; border:1px solid #678591; border-radius:3px; padding:.3rem .55rem; font-size:.875rem; line-height:1.6; }
.support-config-badge[data-state="running"] { color:#acf2d8; border-color:#65a58d; } .support-config-badge[data-state="failed"] { color:#f2ce8b; border-color:#a3864b; }
.support-capture-reading { margin-top:1.2rem; border-top:1px solid #355464; padding-top:.75rem; }
.support-capture-reading dl { display:flex; flex-wrap:wrap; gap:1.5rem; margin:.9rem 0; } .support-capture-reading dt { color:#bdd1dd; font-size:.875rem; } .support-capture-reading dd { color:#edf7fa; font-size:1.3rem; margin:.25rem 0 0; font-variant-numeric:tabular-nums; }
.support-tool-settings { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:1.5rem; padding:.5rem 0 1rem; } .support-tool-settings section { min-width:0; } .support-tool-settings p { font-size:.875rem; }
.support-tool-settings input,.support-tool-settings select { margin-bottom:.8rem; } .support-tool-settings .support-config-actions { margin:0; }
.support-config-results li { grid-template-columns:minmax(8rem,1fr) minmax(6rem,.7fr) minmax(0,2fr); } .support-config-results time { display:block; color:#aac1d0; font-size:.875rem; }
@media(max-width:900px) { .support-tool-settings { grid-template-columns:1fr; gap:1.2rem; } .support-tool-settings section+section { border-top:1px solid #355464; padding-top:1.2rem; } }
@media(max-width:640px) { .support-capture-steps,.support-capture-destinations { grid-template-columns:1fr; gap:1rem; } .support-capture { padding:.9rem; } .support-config-actions button { flex:1 1 12rem; } .support-config select,.support-config input { max-width:none; } .support-config-results li { grid-template-columns:minmax(0,1fr) auto; } }
'''

SUPPORT_CONFIG_JS = r'''
(() => {
  const el=id=>document.getElementById(id);
  if(typeof localHudLaunch==='undefined' || !el('support-config') || !el('support-apps-configure'))return;
  // Local HUD catalog copy; the hosted/offline shelf keeps its own boundaries.
  if(typeof softwareCatalog!=='undefined'){
    const localNotes={tshark:{requirement:'Optional · saved or live packets',note:'The offline TShark adapter reads saved captures. Use Configure apps on the HUD for capture permissions, bounded live HUD traffic or a separate Wireshark window.'},clamav:{purpose:'Scan a configured home folder and review aggregate counts.',note:'The local HUD runs configured scans and watches completed reports. Configure apps selects Downloads or Documents and can start the installed signature updater. No quarantine or uploads occur.'},suricata:{note:'Start background tools starts the installed sensor service. Configure apps prepares its passive interface and local log access. Actions shows current source summaries separately from admitted findings.'}};
    for(const item of softwareCatalog)if(Object.hasOwn(localNotes,item.id))Object.assign(item,localNotes[item.id]);
  }
  const state={configVisible:false,globeVisible:false,liveAction:false,open:false,pending:false,valid:false,token:null,payload:null,timer:null,dirty:new Set(),hydrated:false,submitted:null};
  const actions={
    'support-model-save':'model_select','support-model-refresh':'model_refresh',
    'support-config-permissions':'capture_permissions','support-config-capture-start':'capture_start','support-config-capture-stop':'capture_stop',
    'support-config-wireshark-open':'wireshark_open','support-config-wireshark-stop':'wireshark_stop','support-config-nmap-save':'nmap_configure',
    'support-config-clamav-save':'clamav_configure','support-config-signatures':'signature_update','support-config-osquery':'osquery_configure',
    'support-config-qwen-setup':'qwen_configure','support-config-suricata-setup':'suricata_configure','support-config-qwen':'qwen_check','support-config-zeek':'zeek_check','support-config-suricata':'suricata_check',
    'live-background-start':'background_start','live-background-stop':'background_stop','live-geography-refresh':'geography_refresh','live-geography-disable':'geography_disable'};
  const actionNames={model_select:'Selecting and verifying local model',model_refresh:'Refreshing installed models',capture_permissions:'Configuring capture access',capture_start:'Starting HUD traffic',capture_stop:'Stopping HUD capture',wireshark_open:'Opening live Wireshark',wireshark_stop:'Closing managed Wireshark',nmap_configure:'Saving and collecting inventory',clamav_configure:'Saving and scanning folder',signature_update:'Updating virus signatures',osquery_configure:'Enabling package inventory',qwen_configure:'Configuring Ollama access',suricata_configure:'Configuring background Suricata',qwen_check:'Verifying selected model',zeek_check:'Preparing Zeek sampler',suricata_check:'Checking Suricata configuration',background_start:'Enabling background monitoring',background_stop:'Stopping background monitoring',geography_refresh:'Updating location data',geography_disable:'Disabling automatic location updates'};
  const inputIds=['support-config-interface','support-config-nmap-target','support-config-scan-folder','support-model-select','support-model-compute'];
  const interfaceActions=['capture_permissions','capture_start','wireshark_open','background_start','suricata_configure'];
  const object=v=>v && typeof v==='object' && !Array.isArray(v);
  const text=(v,max=512)=>typeof v==='string' && v.length<=max && !/[\x00-\x1f\x7f]/.test(v);
  const stamp=v=>v===null || (text(v,40) && /Z$/.test(v) && Number.isFinite(Date.parse(v)));
  const count=v=>Number.isSafeInteger(v) && v>=0;
  const time=v=>v ? new Date(v).toISOString().replace('T',' ').replace('.000Z',' UTC') : 'Time unavailable';
  function checked(v,needToken) {
    if(!object(v) || v.schema!=='megalodon-support-config-v1' || !Array.isArray(v.interfaces) || v.interfaces.length>32
      || !v.interfaces.every(i=>object(i)&&text(i.name,64)&&i.name.length>0&&typeof i.default==='boolean'&&typeof i.up==='boolean')
      || !object(v.settings) || !text(v.settings.interface,64) || !text(v.settings.nmap_target,64) || !['Downloads','Documents'].includes(v.settings.scan_folder)
      || !object(v.job) || !['idle','running','finished','failed'].includes(v.job.state) || !(v.job.action===null || Object.hasOwn(actionNames,v.job.action))
      || !text(v.job.message) || !stamp(v.job.started_at) || !stamp(v.job.finished_at)
      || !object(v.capture) || !['idle','starting','running','stopped','failed'].includes(v.capture.state) || !['received','accepted','skipped'].every(k=>count(v.capture[k]))
      || !stamp(v.capture.started_at) || !stamp(v.capture.finished_at) || !text(v.capture.message) || !(v.capture.interface===undefined || text(v.capture.interface,64))
      || !Array.isArray(v.tools) || v.tools.length>16 || !v.tools.every(t=>object(t)&&text(t.id,64)&&text(t.name,80)&&text(t.state,40)&&text(t.message)&& (t.checked_at===undefined||stamp(t.checked_at)))
      || (v.background!==undefined&&(!object(v.background)||typeof v.background.enabled!=='boolean'||!['stopped','starting','running','waiting','failed'].includes(v.background.state)||!text(v.background.message)||!count(v.background.session_count)))
      || typeof v.geography_enabled!=='boolean'
      || !text(v.command,512) || (needToken&&!/^[A-Za-z0-9_-]{32}$/.test(v.token||'')) || (v.token!==undefined&&!/^[A-Za-z0-9_-]{32}$/.test(v.token)))throw Error('Invalid configuration response');
    if(v.model!==undefined){const m=v.model;if(!object(m)||!text(m.model,96)||!text(m.message,512)||!['cpu','auto'].includes(m.compute_mode)||!Array.isArray(m.options)||m.options.length>64||!m.options.every(row=>object(row)&&text(row.name,96)&&/^[a-f0-9]{64}$/.test(row.digest)&&count(row.size_bytes))||!stamp(m.updated_at)||!stamp(m.last_response_at)||!stamp(m.last_attempt_at)||!(m.response_ms===null||count(m.response_ms))||!['loaded','memory_bytes','vram_bytes'].every(key=>key==='loaded'?(m[key]===null||typeof m[key]==='boolean'):(m[key]===null||count(m[key]))))throw Error('Invalid model telemetry');}
    return v;
  }
  const capturing=()=>state.payload && ['starting','running'].includes(state.payload.capture.state);
  const working=()=>state.payload && state.payload.job.state==='running';
  const workspace=el('workspace-live'),setupWorkspace=el('workspace-setup');
  const liveVisible=()=>!document.hidden&&!(workspace&&workspace.hidden);
  const setupVisible=()=>!!setupWorkspace&&!document.hidden&&!setupWorkspace.hidden;
  const workspaceVisible=()=>liveVisible()||setupVisible();
  const viewVisible=()=>workspaceVisible()&&(setupVisible()||typeof IntersectionObserver==='undefined'||state.globeVisible||(state.open&&state.configVisible));
  function feedback(message,kind='ready'){if(state.liveAction && el('live-action-status'))el('live-action-status').textContent=message;el('support-config-status').textContent=message;el('support-config').dataset.state=kind;}
  function controls(){
    const blocked=state.pending || !state.valid || !workspaceVisible();
    for(const [id,action] of Object.entries(actions)){
      if(!el(id))continue;el(id).disabled=blocked || (working() && !['capture_stop','background_stop'].includes(action)) || (interfaceActions.includes(action)&&!el('support-config-interface').value)
        || (action==='capture_start'&&!!capturing()) || (action==='capture_stop'&&!capturing())
        || (action==='background_start'&&!!state.payload?.background?.enabled&&state.payload.background.state!=='failed') || (action==='background_stop'&&!state.payload?.background?.enabled&&!capturing())
        || (action==='model_select'&&!el('support-model-select').value)
        || (action==='geography_disable'&&!state.payload?.geography_enabled);
    }
    for(const id of inputIds)el(id).disabled=blocked||!!working();
    el('support-config-retry').disabled=state.pending;if(el('live-action-retry'))el('live-action-retry').disabled=state.pending;
    el('support-config').setAttribute('aria-busy',state.pending?'true':'false');
  }
  function render(v){
    if(v.model){
      const model=v.model,select=el('support-model-select'),chosen=state.dirty.has('model')?select.value:model.model;
      const options=model.options.map(row=>{const option=document.createElement('option');option.value=row.name;option.textContent=row.name+' · '+(row.size_bytes/1024**3).toFixed(1)+' GiB';return option;});
      const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent=options.length?'Choose a model':['checking','model_loading'].includes(model.model_state)?'Waiting for Ollama…':'No installed models returned';select.replaceChildren(placeholder,...options);select.value=model.options.some(row=>row.name===chosen)?chosen:'';
      if(!state.dirty.has('compute_mode'))el('support-model-compute').value=model.compute_mode;
      el('support-model-status').textContent=model.message+(model.truncated?' First 64 installed artifacts shown.':'');
      const metrics=[];if(model.last_response_at)metrics.push('Last accepted response '+time(model.last_response_at));if(model.response_ms!==null)metrics.push('Last request '+(model.response_ms/1000).toFixed(2)+' s');
      if(model.loaded===false)metrics.push('Selected model is unloaded');else if(model.loaded===true)metrics.push('Loaded allocation '+(model.memory_bytes/1024**3).toFixed(1)+' GiB · GPU '+(model.vram_bytes/1024**3).toFixed(1)+' GiB');
      if(model.updated_at)metrics.push('Availability checked '+time(model.updated_at));el('support-model-metrics').textContent=metrics.join(' · ');
    }
    const selected=state.dirty.has('interface') ? el('support-config-interface').value : (v.settings.interface || (v.interfaces.find(i=>i.default&&i.up)||v.interfaces.find(i=>i.up)||{}).name || '');
    const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent=v.interfaces.length?'Select an interface':'No interfaces returned';
    const options=v.interfaces.map(i=>{const option=document.createElement('option');option.value=i.name;option.textContent=`${i.name}${i.default?' · default':''}${i.up?'':' · down'}`;return option;});
    el('support-config-interface').replaceChildren(placeholder,...options);el('support-config-interface').value=v.interfaces.some(i=>i.name===selected)?selected:'';
    if(!state.dirty.has('nmap_target'))el('support-config-nmap-target').value=v.settings.nmap_target;
    if(!state.dirty.has('scan_folder'))el('support-config-scan-folder').value=v.settings.scan_folder;
    const chosen=v.interfaces.find(i=>i.name===el('support-config-interface').value);
    if(el('live-background-start'))el('live-background-start').textContent=v.background?.state==='failed'?'Retry monitoring':'Enable background monitoring';
    if(el('live-geography-opt-in'))el('live-geography-opt-in').textContent=v.geography_enabled?'Automatic location updates enabled':'Automatic location updates off';
    if(el('live-interface-name'))el('live-interface-name').textContent='Saved interface · '+(v.settings.interface||'not selected');
    el('support-config-interface-note').textContent=chosen ? `${chosen.name}${chosen.up?' is up.':' is down; capture may fail.'} Used by HUD capture, background sensors and optional desktop inspection.` : 'Choose an available interface before configuring or starting capture.';
    const names={idle:'Not capturing',starting:'Starting',running:'HUD capture running',stopped:'Capture stopped',failed:'Capture failed'};
    el('support-capture-state').textContent=names[v.capture.state];el('support-capture-state').dataset.state=v.capture.state;
    el('support-capture-message').textContent=v.capture.message+(v.capture.state==='running'&&v.capture.accepted===0?' Awaiting usable metadata; no records have reached the HUD yet.':'');
    for(const field of ['received','accepted','skipped'])el('support-capture-'+field).textContent=String(v.capture[field]);
    el('support-capture-time').textContent=`TShark / dumpcap metadata${v.capture.interface?' · '+v.capture.interface:''}${v.capture.started_at?' · Started '+time(v.capture.started_at):''}${v.capture.finished_at?' · Finished '+time(v.capture.finished_at):''}`;
    const wireshark=v.tools.find(tool=>tool.id==='wireshark');
    el('support-wireshark-result').textContent=wireshark ? `Last Wireshark action result · ${wireshark.checked_at?time(wireshark.checked_at):'Time unavailable'}. ${wireshark.message} Current window state is not monitored here.` : 'No saved Wireshark action result. Current window state is not monitored here.';
    const rows=v.tools.map(tool=>{const row=document.createElement('li'),name=document.createElement('strong'),status=document.createElement('span'),details=document.createElement('span'),when=document.createElement('time');
      name.textContent=tool.name;status.textContent=tool.state.replace(/_/g,' ');details.textContent=tool.message;when.textContent=tool.checked_at ? 'Checked '+time(tool.checked_at) : 'Check time unavailable';if(tool.checked_at)when.setAttribute('datetime',tool.checked_at);details.append(when);row.append(name,status,details);return row;});
    if(!rows.length){const empty=document.createElement('li');empty.textContent='No tool checks returned yet.';rows.push(empty);}el('support-config-tools').replaceChildren(...rows);
    if(v.job.state==='running')feedback(`${actionNames[v.job.action]||'Working'}… ${v.job.message}`,'working');
    else if(v.job.state==='finished'||v.job.state==='failed')feedback(`Last action ${v.job.state==='failed'?'failed':'finished'}${v.job.finished_at?' at '+time(v.job.finished_at):''}. ${v.job.message}`,v.job.state==='failed'?'failed':'ready');
    else feedback('Choose an interface or tool setting. Each action runs only when you select its button.');
    if(!viewVisible())feedback('Status updates paused while this view is hidden. Local actions and capture continue.','stale');
  }
  function cancel(){if(state.timer!==null)clearTimeout(state.timer);state.timer=null;}
  function schedule(){cancel();if(!viewVisible()||!state.valid)return;const active=working()||capturing()||state.payload?.background?.enabled;if(active||state.open)state.timer=setTimeout(read,active?2000:10000);}
  async function body(response){
    if(Number(response.headers.get('content-length'))>65536)throw Error('Response too large');
    if(response.body&&response.body.getReader){const reader=response.body.getReader(),parts=[];let size=0;try{while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>65536)throw Error('Response too large');parts.push(part.value);}}catch(error){await reader.cancel();throw error;}
      const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.byteLength;}return JSON.parse(new TextDecoder().decode(bytes));}
    const value=await response.text();if(new TextEncoder().encode(value).length>65536)throw Error('Response too large');return JSON.parse(value);
  }
  async function request(payload){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
    try{const options={method:payload?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:payload?{'Content-Type':'application/json','X-Megalodon-Config-Token':state.token}:{'X-Megalodon-Check':'1'}};
      if(payload)options.body=JSON.stringify(payload);const response=await fetch('/api/support-config',options);
      if(payload&&response.status===409)return null;
      if(!response.ok){const error=Error('Request rejected');error.status=response.status;throw error;}
      return checked(await body(response),!payload);
    }finally{clearTimeout(timer);}
  }
  function accept(v){if(state.submitted && v.job.action===state.submitted.action && ['finished','failed'].includes(v.job.state)){if(v.job.state==='finished'){const action=state.submitted.action;if(interfaceActions.includes(action))state.dirty.delete('interface');if(action==='nmap_configure')state.dirty.delete('nmap_target');if(action==='clamav_configure')state.dirty.delete('scan_folder');if(action==='model_select'){state.dirty.delete('model');state.dirty.delete('compute_mode');}}state.submitted=null;}state.payload=v;if(v.token)state.token=v.token;state.valid=true;state.hydrated=true;el('support-config-retry').hidden=true;if(el('live-action-retry'))el('live-action-retry').hidden=true;render(v);}
  function fail(error){state.valid=false;state.token=null;if(!state.payload){if(el('live-interface-name'))el('live-interface-name').textContent='Saved interface unavailable';if(el('live-geography-opt-in'))el('live-geography-opt-in').textContent='Location-update setting unavailable';}el('support-capture-state').textContent='Status unavailable';el('support-capture-state').dataset.state='failed';const prefix=error.status===400?'The settings were rejected. Check the target, folder and interface.':error.status===403?'The action could not pass its local permission or session check.':'Unable to confirm configuration status.';feedback(document.hidden?'Status updates paused while this tab is hidden. The last request failed; check again when you return.':prefix+' Check again before retrying.',document.hidden?'stale':'failed');el('support-config-retry').hidden=false;if(state.liveAction&&el('live-action-retry'))el('live-action-retry').hidden=false;}
  async function read(force=false){if(state.pending||!workspaceVisible()||(!force&&!viewVisible()))return;cancel();state.pending=true;if(!state.hydrated)feedback('Checking available tools and capture settings…','checking');controls();try{accept(await request());}catch(error){fail(error);}finally{state.pending=false;controls();schedule();}}
  function payloadFor(action){
    const value={action};
    if(interfaceActions.includes(action)){value.interface=el('support-config-interface').value;if(!state.payload.interfaces.some(i=>i.name===value.interface))throw Error('Select an available capture interface.');}
    if(action==='nmap_configure'){
      let target=el('support-config-nmap-target').value.trim();if(!target.includes('/'))target+='/32';
      const match=target.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/),parts=match?match.slice(1).map(Number):[];
      if(!match||parts.slice(0,4).some(v=>v>255)||parts[4]<24||parts[4]>32||!(parts[0]===10||parts[0]===127||(parts[0]===192&&parts[1]===168)||(parts[0]===172&&parts[1]>=16&&parts[1]<=31)))throw Error('Use a private IPv4 target with /24–/32, or one local address.');
      value.nmap_target=target;
    }
    if(action==='model_select'){const row=state.payload.model?.options.find(row=>row.name===el('support-model-select').value);if(!row)throw Error('Refresh and choose an installed model.');Object.assign(value,{model:row.name,model_digest:row.digest,compute_mode:el('support-model-compute').value});}
    if(action==='clamav_configure'){value.scan_folder=el('support-config-scan-folder').value;if(!['Downloads','Documents'].includes(value.scan_folder))throw Error('Choose Downloads or Documents.');}
    return value;
  }
  async function act(action){
    const button=Object.entries(actions).find(([,value])=>value===action);
    if(!button||!el(button[0])||el(button[0]).disabled||state.pending||!state.valid||!state.token||!workspaceVisible())return;
    let payload;try{payload=payloadFor(action);}catch(error){feedback(error.message,'failed');return;}
    cancel();state.pending=true;state.liveAction=['background_start','background_stop','geography_refresh','geography_disable'].includes(action);feedback(`${actionNames[action]}…${['capture_permissions','signature_update','qwen_configure','suricata_configure'].includes(action)?' A system authorization prompt may appear.':''}`,'working');controls();
    try{const value=await request(payload);if(value){state.submitted=payload;accept(value);}else{accept(await request());feedback('Another support action is already running. Wait for it to finish, then try again.','working');}}
    catch(error){fail(error);}finally{state.pending=false;controls();schedule();}
  }
  function open(value){state.open=value;el('support-config').hidden=setupWorkspace?false:!value;el('support-apps-configure').setAttribute('aria-expanded',value?'true':'false');
    if(setupWorkspace&&typeof navigateWorkspace==='function')navigateWorkspace(value?'setup':'live');
    if(value){el('support-config-title').focus();read(true);}else{el('support-apps-configure').focus();schedule();}}
  el('support-apps-configure').addEventListener('click',()=>open(!state.open));el('support-config-close').addEventListener('click',()=>open(false));el('support-config-retry').addEventListener('click',()=>read(true));if(el('live-action-retry'))el('live-action-retry').addEventListener('click',()=>read(true));
  for(const [id,action] of Object.entries(actions))if(el(id))el(id).addEventListener('click',()=>act(action));
  for(const [id,key] of [['support-model-select','model'],['support-model-compute','compute_mode'],['support-config-interface','interface'],['support-config-nmap-target','nmap_target'],['support-config-scan-folder','scan_folder']])el(id).addEventListener('change',()=>{state.dirty.add(key);controls();});
  el('support-config-nmap-target').addEventListener('input',()=>state.dirty.add('nmap_target'));
  if(typeof window!=='undefined')window.megalodonSupportConfiguration={refresh:read,open:()=>{open(true);el('support-config-interface').focus();}};
  function syncView(){cancel();if(!viewVisible()){if(state.hydrated)feedback('Status updates paused while this view is hidden. Local actions and capture continue.','stale');controls();}else read();}
  document.addEventListener('visibilitychange',syncView);
  if(typeof MutationObserver!=='undefined')for(const panel of [workspace,setupWorkspace])if(panel)new MutationObserver(syncView).observe(panel,{attributes:true,attributeFilter:['hidden']});
  if(typeof IntersectionObserver!=='undefined'){
    const observer=new IntersectionObserver(entries=>{for(const entry of entries){if(entry.target===el('support-config'))state.configVisible=entry.isIntersecting;if(entry.target===el('live-globe'))state.globeVisible=entry.isIntersecting;}syncView();},{root:el('workspace-content'),rootMargin:'80px'});
    observer.observe(el('support-config'));if(el('live-globe'))observer.observe(el('live-globe'));
  }
})();
'''


def local_support_help(html: str) -> str:
    """Compose local operational help from the compatibility reference."""
    return html.replace(
        "Saved metadata in the shared time range. No capture starts here.",
        'Saved metadata in the shared time range. Start live collection with Configure apps in the <a href="#support-apps-title">HUD support controls</a>.',
    ).replace(
        "Installing software, starting or stopping the HUD, selecting a new data source, and importing metadata happen outside this page. Downloads open the official publisher instructions.",
        'Install software and reopen or stop the HUD using your desktop or terminal. Use <a href="#support-apps-title">Configure apps in the HUD</a> to choose a capture interface, prepare capture access, and start local traffic collection. Other saved-file imports use their adapter commands. Downloads open the official publisher instructions.',
    )


def local_support_script(script: str) -> str:
    """Compatibility hook; canonical local copy now owns administration help."""
    return script
