"""Startup overview composed into Setup; actions use the existing protected route."""

STARTUP_HTML = r'''
<section id="startup-settings" class="startup-panel" aria-labelledby="startup-title">
  <header class="startup-heading"><div><p class="eyebrow">READY WHEN YOU RETURN</p><h4 id="startup-title" tabindex="-1">After a restart</h4><p>Your model choice and configured collectors stay on this computer.</p></div><button type="button" id="startup-check" disabled>Check startup</button></header>
  <div class="startup-cards">
    <article><span class="startup-number" aria-hidden="true">01</span><h5>Start the HUD</h5><strong id="startup-login-state">Not checked</strong><p>Run quietly after you sign in to Linux. Closing the browser leaves collection running.</p><div class="support-config-actions"><button type="button" id="startup-enable" disabled>Enable at sign-in</button><button type="button" id="startup-disable" disabled>Turn off</button></div></article>
    <article><span class="startup-number" aria-hidden="true">02</span><h5>Resume monitoring</h5><strong id="startup-monitor-state">Not checked</strong><p id="startup-collectors">Checking saved collectors…</p><a href="#support-capture-title">Configure traffic and sensors →</a></article>
    <article><span class="startup-number" aria-hidden="true">03</span><h5>Keep your model choice</h5><strong id="startup-model-name">Not checked</strong><p id="startup-model-note">A saved choice is restored even when Ollama is offline.</p><a href="#support-model-title">Manage local AI →</a></article>
  </div>
  <section class="startup-services" aria-labelledby="startup-services-title"><div class="startup-heading"><div><h5 id="startup-services-title">Services at boot</h5><p>Ollama, configured passive Suricata, and the ClamAV signature updater for a configured scan folder.</p></div><button type="button" id="startup-services-enable" disabled>Enable service startup</button></div>
    <p class="support-config-note">This starts and enables eligible installed services. Linux may ask for your password. The signature updater downloads antivirus definitions.</p>
    <ul id="startup-service-list" aria-label="Service startup status"><li>Check startup to read each service.</li></ul>
  </section>
  <p id="startup-status" role="status" aria-live="polite">Check startup before changing its settings.</p>
  <details class="settings-disclosure"><summary>How the other helpers run</summary><p>TShark and Zeek resume with saved background monitoring. Configured Nmap, ClamAV scans and osquery resume on their collection schedules. Lynis and AIDE run when requested. Scapy remains an alternative capture backend; nftables is a command-line tool. No extra application windows open.</p><p>Sign-in startup does not enable a pre-login system HUD. Service activity, capture health, and AI acceptance are separate checks.</p></details>
</section>
'''

STARTUP_CSS = r'''
#workspace-setup .startup-panel { margin:28px 0; padding:24px; border:1px solid #31504e; border-radius:12px; background:linear-gradient(135deg,#102b2d,#0c1b25 70%); }
#workspace-setup .startup-heading { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px; }
#workspace-setup .startup-heading h4 { font-size:1.4rem; margin:4px 0; }
#workspace-setup .startup-heading .eyebrow { color:#91d6c8; font-size:.68rem; letter-spacing:.13em; margin:0; }
#workspace-setup .startup-cards { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; margin:22px 0; }
#workspace-setup .startup-cards article { padding:18px; border:1px solid #294751; border-radius:8px; background:#0a1b25; min-width:0; }
#workspace-setup .startup-number { color:#8cacae; font:12px ui-monospace,monospace; }
#workspace-setup .startup-cards h5 { margin:10px 0 12px; font-size:1rem; }
#workspace-setup .startup-cards strong { display:block; color:#b6edda; font-size:.9rem; overflow-wrap:anywhere; }
#workspace-setup .startup-cards p { font-size:.8rem; }
#workspace-setup .startup-cards a { color:#a1e3d4; font-size:.8rem; }
#workspace-setup .startup-services { padding-top:18px; border-top:1px solid #31505b; }
#workspace-setup #startup-service-list { padding:0; list-style:none; }
#workspace-setup #startup-service-list li { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:4px 20px; padding:12px 0; border-bottom:1px solid #253e49; }
#workspace-setup #startup-service-list small { grid-column:1/-1; color:#9db6c1; font-size:.78rem; }
#workspace-setup #startup-service-list span { color:#ecc68d; font-size:.8rem; }
#workspace-setup #startup-service-list [data-ready="true"] span { color:#b6edda; }
#workspace-setup .model-hero { padding:22px; background:linear-gradient(115deg,#163936,#102530); border:1px solid #37615c; border-radius:10px; margin-bottom:20px; }
#workspace-setup .model-hero h5 { font-size:1.2rem; }
#workspace-setup #support-model-saved { font-size:1.05rem; color:#c3f3e5; overflow-wrap:anywhere; }
#workspace-setup .model-step { padding:20px; margin:14px 0; border:1px solid #29434f; border-radius:8px; background:#0b1c27; }
#workspace-setup .settings-model button[data-next="true"] { border-color:#9be3cb; box-shadow:inset 0 0 0 1px #9be3cb; }
#workspace-setup #support-model-next { overflow-wrap:anywhere; }
#workspace-setup .model-step h6 { font-size:1rem; margin:0 0 12px; }
#workspace-setup .model-step .support-config-actions { margin-bottom:0; }
#workspace-setup .model-step #support-model-test-status { color:#c3e8df; }
#workspace-setup #support-model-authorization { border-radius:8px; margin:18px 0; }
@media(max-width:950px) { #workspace-setup .startup-cards { grid-template-columns:1fr; } }
@media(max-width:560px) { #workspace-setup .startup-panel { padding:16px; } #workspace-setup .model-step,#workspace-setup .model-hero { padding:16px; } }
'''

STARTUP_JS = r'''
  function startupChecked(v){
    if(v===undefined)return;
    if(!object(v)||!stamp(v.checked_at)||!['unchecked','enabled','disabled','unavailable'].includes(v.login)||!text(v.message)||!Array.isArray(v.services)||v.services.length>3)throw Error('Invalid startup status');
    const ids=new Set();
    for(const r of v.services){if(!object(r)||!['qwen','suricata','signatures'].includes(r.id)||ids.has(r.id)||!text(r.name,80)||!text(r.message)||!(r.unit===null||['ollama','snap.ollama.listener','suricata','clamav-freshclam'].includes(r.unit))||!['running','stopped','unknown'].includes(r.active)||!['enabled','disabled','masked','temporary','static','unknown'].includes(r.enabled))throw Error('Invalid service status');ids.add(r.id);}
  }
  function startupRender(v){
    if(!el('startup-settings'))return;
    const s=v.startup,m=v.model,restored=['saved','restored','configured'].includes(m?.selection_state);
    el('startup-login-state').textContent={enabled:'On · at user sign-in',disabled:'Off · open the app manually',unavailable:'Needs attention',unchecked:'Not checked'}[s?.login]||'Not available';
    el('startup-monitor-state').textContent=v.background?.enabled?'On · resumes with HUD':'Off · monitoring is not saved';
    const names={nmap:'Nmap',clamav:'ClamAV',osquery:'osquery'};
    const selected=(v.configured_collectors||[]).map(id=>names[id]);
    el('startup-collectors').textContent=selected.length?'Saved collectors: '+selected.join(', ')+'. Their schedules resume with the HUD.':'No collector setup saved here. Configure tools in Apps.';
    el('startup-model-name').textContent=restored?m.model:m?.selection_state==='invalid'?'Saved profile needs attention':'Choose and save a model';
    el('startup-model-note').textContent=restored?'Choice saved on this PC. Loading is separate from remembering your choice.':'Save a model in Local AI to restore its exact version and compute settings.';
    el('startup-status').textContent=(s?.message||'Startup controls are unavailable in this service version.')+(s?.checked_at?' Checked '+time(s.checked_at):'');
    const labels={enabled:'Enabled at boot',disabled:'Off at boot',masked:'Masked',temporary:'Until next reboot',static:'Managed by another unit',unknown:'Not confirmed'};
    const rows=(s?.services||[]).map(r=>{const li=document.createElement('li'),name=document.createElement('strong'),status=document.createElement('span'),detail=document.createElement('small');name.textContent=r.name;status.textContent=labels[r.enabled]+' · '+({running:'running',stopped:'stopped',unknown:'activity unknown'}[r.active]);detail.textContent=r.unit?r.unit+'.service':r.message;li.dataset.ready=String(r.enabled==='enabled'&&r.active==='running');li.append(name,status,detail);return li;});
    if(!rows.length){const li=document.createElement('li');li.textContent='Use Check startup to read the installed services.';rows.push(li);}
    el('startup-service-list').replaceChildren(...rows);
  }
  function startupControls(blocked){
    if(!el('startup-settings'))return;
    const s=state.payload?.startup,disabled=blocked||!!working()||!s;
    for(const id of ['startup-check','startup-enable','startup-disable','startup-services-enable'])el(id).disabled=disabled;
    el('startup-enable').disabled=disabled||s?.login==='enabled';
    el('startup-disable').disabled=disabled||s?.login!=='enabled';
  }
'''
