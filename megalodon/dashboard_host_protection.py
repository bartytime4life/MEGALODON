"""Host protection controls: explicit policy, expiring authority, truthful readback."""

HOST_PROTECTION_HTML = '''
<section class="host-protection" aria-labelledby="host-protection-title">
  <header><div><p class="eyebrow">PROTECT THIS PC</p><h2 id="host-protection-title" tabindex="-1">Control incoming connections</h2></div><span id="host-protection-badge">Not checked</span></header>
  <p>Automatically drop unsolicited inbound traffic. Keep outbound connections and their replies. Choose any services other devices may connect to.</p>
  <p id="host-protection-status" role="status" aria-live="polite">Reading the last recorded protection check…</p>
  <p id="host-protection-counts"></p>
  <ul id="host-protection-current-services" aria-label="Last verified inbound service policy"></ul>
  <div class="host-protection-actions"><button id="host-protection-check" type="button" disabled>Verify protection with OS authorization</button><button id="host-protection-remove" type="button" disabled>Remove this protection</button></div>
  <details id="host-protection-config"><summary>Choose allowed services and preview protection</summary>
    <p>No service exceptions are selected by default. Add one only if this PC must accept a new incoming connection, such as SSH or file sharing. Observed traffic and AI suggestions never add exceptions.</p>
    <button id="host-protection-reuse" type="button" hidden>Use last verified policy for a new preview</button>
    <div id="host-protection-services"></div>
    <button id="host-protection-add" type="button">Add an allowed service</button>
    <p id="host-protection-service-help">Up to eight exceptions. Client networks use CIDR notation: for example, 192.168.1.0/24 for a LAN, or 192.168.1.25/32 for one IPv4 client. 0.0.0.0/0 allows any IPv4 client; ::/0 allows any IPv6 client. Use the narrowest range you need.</p>
    <label class="host-protection-duration">Protection duration<select id="host-protection-duration"><option value="900">15 minutes · try first</option><option value="3600">1 hour</option><option value="28800">8 hours</option></select></label>
    <p>Protection expires in the kernel even if MEGALODON closes. Renewing requires a fresh preview and OS authorization.</p>
    <button id="host-protection-preview" type="button" disabled>Preview host protection</button>
  </details>
  <div id="host-protection-plan" hidden></div>
  <button id="host-protection-apply" type="button" hidden disabled>Confirm protection on this PC</button>
  <p id="host-protection-message" role="status" aria-live="polite"></p>
  <details><summary>What this protects and what still needs attention</summary><p>This controls traffic delivered to this Linux PC. It preserves connections already known to Linux connection tracking, loopback, essential network errors, IPv6 neighbor discovery and DHCP client replies. It does not secure other devices or traffic forwarded to containers, virtual machines or a router. Existing firewall restrictions still apply.</p><p>An allowed connection is permitted by your policy, not certified safe. Exploits inside allowed services, phishing, malicious downloads and attacks from already established sessions need other defenses. Keep software patched and use strong authentication. A blocked packet does not prove an attack or identify AI use.</p><p>Checks are explicit and may require an OS password. Displayed counts come from the last verified kernel readback and reset on renewal. Page refresh never enables protection.</p></details>
</section>
'''

HOST_PROTECTION_CSS = '''
.host-protection{margin:0 0 1.25rem;padding:1.25rem;border:1px solid #416577;border-left:4px solid #67d9ca;background:#0a1d28;border-radius:6px;color:#e7f2f5}
.host-protection header{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap}.host-protection h2{margin:.25rem 0;font-size:1.4rem}.host-protection p{line-height:1.6;max-width:95ch}.host-protection .eyebrow{margin:0;color:#8ee5d9}
#host-protection-badge{padding:.4rem .7rem;border:1px solid #587783;border-radius:4px;font-size:.85rem}.host-protection-actions{display:flex;gap:.6rem;flex-wrap:wrap}.host-protection button,.host-protection input,.host-protection select,.host-protection summary{min-height:44px}.host-protection details{margin:.85rem 0}.host-protection summary{cursor:pointer;display:flex;align-items:center;font-weight:600}.host-protection summary::before{content:'›';margin-right:.6rem}.host-protection details[open]>summary::before{content:'⌄'}.host-protection label{display:grid;gap:.35rem;font-size:.85rem}.host-protection-duration{max-width:19rem;margin:1rem 0}.host-protection-service{display:grid;grid-template-columns:6rem 6rem minmax(8rem,1fr) auto;gap:.6rem;align-items:end;margin:.8rem 0}.host-protection input,.host-protection select{width:100%;min-width:0;box-sizing:border-box;background:#102b37;color:#eefaff;border:1px solid #64818e;border-radius:3px;padding:.5rem;font:inherit}.host-protection input:focus-visible,.host-protection select:focus-visible,.host-protection button:focus-visible{outline:2px solid #8ee5d9;outline-offset:3px}#host-protection-plan{padding:1rem;border:1px solid #bba16a;background:#29291f;margin:1rem 0}#host-protection-plan h3{margin-top:0}#host-protection-apply{background:#a9eadd;color:#102127}#host-protection-message{color:#f1cf8b}.host-protection button:disabled{opacity:.55}.host-protection li{overflow-wrap:anywhere}
@media(max-width:600px){.host-protection{padding:1rem}.host-protection-service{grid-template-columns:1fr 1fr}.host-protection-service label:nth-child(3){grid-column:1/-1}.host-protection-service button{grid-column:1/-1}.host-protection-actions>*{width:100%}}
'''

HOST_PROTECTION_JS = r'''
(()=>{
  'use strict';
  if(typeof document.querySelector!=='function'||!document.querySelector('.host-protection'))return;
  const get=id=>document.getElementById('host-protection-'+id);
  if(!get('title'))return;
  const state={data:null,pending:false,loading:false,plan:null,generation:0,request:null,timer:null};
  const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
  const stamp=v=>typeof v==='string'&&v.length<=40&&Number.isFinite(Date.parse(v));
  const message=s=>{get('message').textContent=s;};
  const put=(id,text)=>{if(get(id).textContent!==text)get(id).textContent=text;};
  const make=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  function policyValid(p){return object(p)&&[900,3600,28800].includes(p.duration_seconds)&&Array.isArray(p.services)&&p.services.length<=8&&p.services.every(r=>object(r)&&['tcp','udp'].includes(r.protocol)&&Number.isInteger(r.port)&&r.port>0&&r.port<=65535&&typeof r.source==='string'&&r.source.length<=49);}
  function valid(v){
    if(!object(v)||v.schema!=='megalodon-defense-v1'||typeof v.token!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(v.token)||typeof v.audit_ready!=='boolean'||!object(v.job)||!['idle','running','finished','failed'].includes(v.job.state))throw Error('Protection controls unavailable.');
    const h=v.host_protection;
    if(!object(h)||!['unknown','needs_review','last_verified_active','last_verified_inactive','lease_elapsed'].includes(h.state)||!(h.verified_at===null||stamp(h.verified_at))||!(h.expires_at===null||stamp(h.expires_at))||!(h.policy===null||policyValid(h.policy))||!(h.counters===null||object(h.counters)&&['invalid','unsolicited','allowed_service'].every(k=>Number.isSafeInteger(h.counters[k])&&h.counters[k]>=0)))throw Error('Protection readback is unavailable.');
    if(['last_verified_active','last_verified_inactive','lease_elapsed'].includes(h.state)&&(h.verified!==true||!stamp(h.verified_at)))throw Error('Protection readback is unverified.');
    if(h.state==='last_verified_active'&&(!stamp(h.expires_at)||!policyValid(h.policy)))throw Error('Protection lease is unverified.');
    return v;
  }
  function clearPlan(){state.plan=null;get('plan').replaceChildren();get('plan').hidden=true;get('apply').hidden=true;get('apply').disabled=true;}
  function edited(){state.generation++;clearPlan();message('Policy changed. Preview these settings before applying them.');}
  function render(){
    const ready=state.data?.audit_ready===true&&!state.pending&&!state.loading&&state.data?.job.state!=='running';
    for(const id of ['preview','check','remove'])get(id).disabled=!ready;
    get('add').disabled=get('services').children.length>=8;
    if(state.plan&&Date.parse(state.plan.expires_at)<=Date.now()){clearPlan();message('Preview expired. Create a fresh preview.');}
    get('apply').disabled=!ready||!state.plan;
    const h=state.data?.host_protection;
    if(!h){put('badge','Unknown');put('status','No verified protection readback is available.');put('counts','');get('current-services').replaceChildren();get('reuse').hidden=true;return;}
    const elapsed=h.expires_at&&Date.parse(h.expires_at)<=Date.now();
    const labels={unknown:'Not checked',needs_review:'Needs verification',last_verified_active:elapsed?'Lease elapsed':'Last verified active',last_verified_inactive:'Last verified inactive',lease_elapsed:'Lease elapsed'};
    put('badge',labels[h.state]);
    let text=h.verified_at?`Last kernel check: ${new Date(h.verified_at).toLocaleString()}. `:'No kernel check has been recorded. ';
    if(h.state==='last_verified_active'&&!elapsed)text+=`Lease ends ${new Date(h.expires_at).toLocaleString()}. This is the last verified state; external firewall changes are not polled.`;
    else if(elapsed||h.state==='lease_elapsed')text+='The recorded lease has elapsed. Verify protection before relying on it.';
    else if(h.state==='needs_review')text+='An action may have been interrupted or could not be verified. Check or remove protection.';
    else text+='Use Verify protection to inspect the current managed policy.';
    put('status',text);
    put('counts',h.counters?`Last verified packet counts: ${h.counters.unsolicited} unsolicited dropped · ${h.counters.invalid} invalid dropped · ${h.counters.allowed_service} matched allowed services. Counts are not attack verdicts.`:'');
    const list=get('current-services');list.replaceChildren();get('reuse').hidden=!h.policy;
    if(h.policy){
      list.append(make('li',`Last verified policy: ${h.policy.duration_seconds/60}-minute lease; ${h.policy.services.length} inbound service exceptions.`));
      for(const rule of h.policy.services)list.append(make('li',`${rule.protocol.toUpperCase()} port ${rule.port} from ${rule.source}`));
    }
  }
  function showPlan(p,generation){
    if(generation!==state.generation)return;
    if(!object(p)||p.kind!=='host_protection'||typeof p.id!=='string'||!/^[a-f0-9]{32}$/.test(p.id)||!stamp(p.expires_at)||Date.parse(p.expires_at)<=Date.now()||!policyValid(p.policy))throw Error('The preview is invalid or expired.');
    clearPlan();state.plan=p;
    const box=get('plan');box.append(make('h3','Review incoming access'),make('p',`Protection lasts ${p.policy.duration_seconds/60} minutes. Outbound replies, tracked established connections and essential network traffic stay allowed.`));
    const list=make('ul','');
    for(const rule of p.policy.services)list.append(make('li',`${rule.protocol.toUpperCase()} port ${rule.port} from ${rule.source}`));
    if(!p.policy.services.length)list.append(make('li','No new incoming service connections allowed.'));
    box.append(list,make('p','Other unsolicited inbound traffic will be dropped automatically. Incoming remote access and sharing may stop unless listed above. Tracked established connections remain. An older untracked connection may need a service exception. This replaces the previous MEGALODON host policy for the new lease.'),make('p','An allowed service still needs patching and authentication. This preview expires in 60 seconds.'));
    box.hidden=false;get('apply').hidden=false;
  }
  async function request(payload){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
    try{
      const response=await fetch('/api/defense',{method:payload?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,headers:payload?{'Content-Type':'application/json','X-Megalodon-Defense-Token':state.data.token}:{'X-Megalodon-Check':'1'},...(payload?{body:JSON.stringify(payload)}:{})});
      if(!response.ok)throw Error(response.status===409?'Another response action is running. Retry shortly.':'Protection request failed. Refresh the page or check local sign-in.');
      const reader=response.body.getReader();let size=0,chunks=[];
      while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>262144){await reader.cancel();throw Error('Protection response exceeded its bound.');}chunks.push(value);}
      const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
      return valid(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
    }finally{clearTimeout(timer);}
  }
  function process(v){
    state.data=v;
    if(state.request&&v.job.request_id===state.request.id&&v.job.state!=='running'){
      const request=state.request;state.request=null;state.pending=false;
      message(typeof v.job.message==='string'?v.job.message:'Response finished.');
      if(v.job.state==='finished'&&request.action==='plan_host_protection')showPlan(v.job.result,request.generation);
    }else if(state.request&&v.job.request_id!==state.request.id){state.request=null;state.pending=false;clearPlan();message('Another workflow replaced the displayed action. Create a fresh preview if needed.');}
    render();
  }
  async function load(){
    if(state.loading||document.hidden)return;state.loading=true;render();
    try{process(await request());}catch(error){state.data=null;state.pending=false;state.request=null;clearPlan();message('Could not verify the response. Any applied lease still expires in the kernel. '+error.message);render();}
    finally{state.loading=false;render();clearTimeout(state.timer);if(!document.hidden)state.timer=setTimeout(load,state.request?750:10000);}
  }
  async function act(payload){
    if(state.pending||state.loading||!state.data?.audit_ready||state.data.job.state==='running')return;
    const generation=state.generation;state.pending=true;state.loading=true;clearPlan();render();message('Waiting for the fixed workflow. Any OS authorization prompt appears on this PC.');
    try{const value=await request(payload);state.request={id:value.job.request_id,action:payload.action,generation};process(value);}
    catch(error){state.data=null;state.pending=false;state.request=null;message('The action outcome is unknown. Verify protection before retrying. '+error.message);render();}
    finally{state.loading=false;render();clearTimeout(state.timer);if(!document.hidden)state.timer=setTimeout(load,500);}
  }
  function addService(value=null){
    if(get('services').children.length>=8)return;
    const row=make('div','');row.className='host-protection-service';
    const protocol=document.createElement('select');protocol.dataset.field='protocol';for(const p of ['tcp','udp']){const option=make('option',p.toUpperCase());option.value=p;protocol.append(option);}
    const port=document.createElement('input');port.type='number';port.min='1';port.max='65535';port.placeholder='22';port.dataset.field='port';
    const source=document.createElement('input');source.type='text';source.maxLength=49;source.placeholder='192.168.1.0/24';source.autocomplete='off';source.dataset.field='source';
    if(value){protocol.value=value.protocol;port.value=String(value.port);source.value=value.source;}
    for(const [title,control]of [['Protocol',protocol],['Port',port],['Allowed client network',source]]){const label=make('label',title);label.append(control);row.append(label);control.addEventListener('input',edited);control.addEventListener('change',edited);}
    const remove=make('button','Remove service');remove.type='button';remove.addEventListener('click',()=>{row.remove();edited();render();get('add').focus();});row.append(remove);get('services').append(row);edited();render();port.focus();
  }
  function selectedPolicy(){
    const services=Array.from(get('services').children).map(row=>({protocol:row.querySelector('[data-field="protocol"]').value,port:Number(row.querySelector('[data-field="port"]').value),source:row.querySelector('[data-field="source"]').value.trim()}));
    const policy={services,duration_seconds:Number(get('duration').value)};
    if(!policyValid(policy)||services.some(r=>!r.source.includes('/')))throw Error('Complete each service with TCP/UDP, a valid port and a client network in CIDR notation.');
    return policy;
  }
  get('add').addEventListener('click',()=>addService());
  get('reuse').addEventListener('click',()=>{const policy=state.data?.host_protection.policy;if(!policyValid(policy))return;get('services').replaceChildren();for(const rule of policy.services)addService(rule);get('duration').value=String(policy.duration_seconds);edited();render();message('Last verified policy copied into the form. Review it and create a new preview.');});
  get('duration').addEventListener('change',edited);
  get('preview').addEventListener('click',()=>{try{act({action:'plan_host_protection',policy:selectedPolicy()});}catch(error){clearPlan();message(error.message);}});
  get('apply').addEventListener('click',()=>{if(state.plan&&Date.parse(state.plan.expires_at)>Date.now())act({action:'apply_host_protection',plan_id:state.plan.id});else{clearPlan();message('Preview expired. Create a fresh preview.');}});
  get('check').addEventListener('click',()=>act({action:'check_host_protection'}));
  get('remove').addEventListener('click',()=>act({action:'remove_host_protection'}));
  document.addEventListener('visibilitychange',()=>{clearTimeout(state.timer);if(!document.hidden)load();});
  function tick(){if(!document.hidden)render();setTimeout(tick,1000);}
  setTimeout(tick,1000);load();
})();
'''
