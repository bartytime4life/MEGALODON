"""Explicit offline endpoint review, with no relay or person attribution."""

INVESTIGATION_HTML = r'''
<section class="ops-address-investigation" aria-labelledby="address-investigation-title">
  <h4 id="address-investigation-title">Address investigation</h4>
  <p>Review retained traffic even when the original source or location is unknown.</p>
  <button type="button" id="address-investigation-read" disabled>Investigate selected address</button>
  <button type="button" id="address-investigation-save" disabled>Save investigation note</button>
  <p id="address-investigation-status" role="status">Select an observed peer to begin. No external lookup runs automatically.</p>
  <div id="address-investigation-result" hidden></div>
</section>
'''

INVESTIGATION_JS = r'''
(() => {
  const el=id=>document.getElementById(id);
  if(!el('address-investigation-read'))return;
  const state={ip:null,serial:0,pending:false,note:null};
  const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
  const keys=(v,names)=>object(v)&&Object.keys(v).length===names.length&&names.every(k=>Object.hasOwn(v,k));
  const text=(v,max)=>typeof v==='string'&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v);
  const stamp=v=>v===null||(text(v,40)&&Number.isFinite(Date.parse(v)));
  const port=v=>object(v)&&['TCP','UDP'].includes(v.protocol)&&Number.isInteger(v.port)&&v.port>=0&&v.port<=65535;
  const count=v=>v===null||(Number.isSafeInteger(v)&&v>=0);
  const amount=v=>v===null?'unavailable':String(v);
  function checkedTraffic(t,c){
    return keys(t,['connections','active_connections','packets','bytes','sent_bytes','received_bytes','direction_basis','tcp_flags','protocols','measurement_sources'])
      &&['connections','active_connections','packets','bytes','sent_bytes','received_bytes'].every(k=>count(t[k]))
      &&t.direction_basis==='relative_to_observed_address'
      &&Array.isArray(t.tcp_flags)&&t.tcp_flags.length<=8&&t.tcp_flags.every(f=>['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'].includes(f))
      &&Array.isArray(t.protocols)&&t.protocols.length<=16&&t.protocols.every(p=>text(p,32)&&p.length>0)
      &&Array.isArray(t.measurement_sources)&&t.measurement_sources.length<=8&&t.measurement_sources.every(s=>keys(s,['source','byte_basis'])&&text(s.source,128)&&['reported_bytes','ip_bytes','payload_bytes','unknown'].includes(s.byte_basis))
      &&keys(c,['recording_mode','window_seconds','truncated','capture_gaps','notes'])
      &&['packet_metadata','connection_summaries','not_recorded'].includes(c.recording_mode)&&count(c.window_seconds)
      &&(c.truncated===null||typeof c.truncated==='boolean')&&c.capture_gaps==='unknown'
      &&Array.isArray(c.notes)&&c.notes.length<=8&&c.notes.every(n=>text(n,512));
  }
  function checked(v,ip){
    if(!keys(v,['schema','observed_address','public_address','first_seen','last_seen','source','origin_status','original_address','person_identity','relay_status','relay_clues','observed_ports','observed_names','traffic','observation_context','network_holder_status','network_holder','registry_search_url','network_access_performed','action_authority','limitations','snapshot_at','capture_state'])||v.schema!=='megalodon-address-investigation-v1'||v.observed_address!==ip||typeof v.public_address!=='boolean'
      ||v.source!=='retained_connection_metadata'||v.origin_status!=='not_established'||v.original_address!==null||v.person_identity!==null
      ||v.relay_status!=='not_established'||v.network_holder_status!=='not_recorded'||v.network_holder!==null
      ||v.network_access_performed!==false||v.action_authority!=='none'||!stamp(v.first_seen)||!stamp(v.last_seen)||!stamp(v.snapshot_at)||v.snapshot_at===null
      ||!['idle','starting','running','stopped','failed'].includes(v.capture_state)
      ||v.registry_search_url!==(v.public_address?'https://search.arin.net/rdap/':null)
      ||!Array.isArray(v.observed_ports)||v.observed_ports.length>32||!v.observed_ports.every(c=>keys(c,['protocol','port'])&&port(c))
      ||!Array.isArray(v.relay_clues)||v.relay_clues.length>32||!v.relay_clues.every(c=>keys(c,['protocol','port','label'])&&port(c)&&text(c.label,80))
      ||!Array.isArray(v.observed_names)||v.observed_names.length>5||!v.observed_names.every(n=>keys(n,['name','source','observed_at'])&&text(n.name,253)&&text(n.source,128)&&stamp(n.observed_at))
      ||!checkedTraffic(v.traffic,v.observation_context)
      ||!Array.isArray(v.limitations)||v.limitations.length!==5||!v.limitations.every(n=>text(n,256)))throw Error('Invalid investigation note');
    return v;
  }
  const node=(tag,value='')=>{const n=document.createElement(tag);n.textContent=value;return n;};
  function controls(){el('address-investigation-read').disabled=!state.ip||state.pending;el('address-investigation-save').disabled=!state.note||state.pending;}
  function render(v){
    const target=el('address-investigation-result');target.replaceChildren();target.hidden=false;
    target.append(node('h5','Observed endpoint'),node('p',v.observed_address),node('p',`First observed: ${v.first_seen||'unavailable'} · Last observed: ${v.last_seen||'unavailable'}`),node('p',`Snapshot: ${v.snapshot_at} · Capture: ${v.capture_state}. These are retained observations, not proof of a live original source.`));
    const t=v.traffic,c=v.observation_context;
    target.append(node('h5','Retained traffic evidence'),node('p',`Connections: ${amount(t.connections)} · Active in snapshot: ${amount(t.active_connections)} · Packets: ${amount(t.packets)}`),node('p',`Bytes: ${amount(t.bytes)} · Sent by this address: ${amount(t.sent_bytes)} · Received by this address: ${amount(t.received_bytes)}`),node('p','Direction is relative to the observed address. Connection counts describe retained transport tuples, not people or hidden original sources.'),node('p',`Protocols: ${t.protocols.join(', ')||'not recorded'} · TCP flags: ${t.tcp_flags.join(', ')||'not recorded'}`),node('p',v.observed_ports.length?'Ports: '+v.observed_ports.map(p=>`${p.protocol} / ${p.port}`).join(', '):'No ports were retained.'));
    const modes={packet_metadata:'Accepted packet metadata',connection_summaries:'Sensor connection summaries',not_recorded:'not recorded'};
    target.append(node('p',`Recording: ${modes[c.recording_mode]}. Sensor summary counters are reported measurements; they do not establish packet arrival times or wire speed.`));
    const bases={reported_bytes:'reported byte counts; layer not established',ip_bytes:'IP bytes',payload_bytes:'payload bytes',unknown:'byte basis unknown'};
    for(const s of t.measurement_sources)target.append(node('p',`${s.source} · ${bases[s.byte_basis]}`));
    if(!t.measurement_sources.length)target.append(node('p','Measurement source and byte basis were not recorded.'));
    if(new Set(t.measurement_sources.map(s=>s.byte_basis)).size>1)target.append(node('p','Byte bases differ across these observations; the combined total is not a single-layer traffic measurement.'));
    target.append(node('h5','Capture coverage'),node('p',`Retained window: ${c.window_seconds===null?'unavailable':c.window_seconds+' seconds'} · Projection truncated: ${c.truncated===null?'unknown':c.truncated?'yes':'no'}. Capture gaps and drops: unknown.`));
    for(const note of c.notes)target.append(node('p',note));
    target.append(node('h5','VPN and proxy clues'));
    if(!v.relay_clues.length)target.append(node('p','No relay-specific port clue was recorded. A VPN or proxy is still possible.'));
    else for(const clue of v.relay_clues)target.append(node('p',`${clue.protocol} / ${clue.port} · ${clue.label}. Port association only; software and relay use are unverified.`));
    target.append(node('h5','Original source and identity'),node('p','Original address: not established. Person or device operator: not identified.'),node('h5','Network registration'),node('p','Network holder: not recorded. Registry information identifies a network allocation, not the person behind a connection.'));
    if(v.registry_search_url){const link=node('a','Open public registry search');link.href='https://search.arin.net/rdap/';link.target='_blank';link.rel='noopener noreferrer';link.referrerPolicy='no-referrer';target.append(link,node('p','This opens another service without sending the selected address. Enter the public address there yourself if you choose.'));}
    else target.append(node('p','This address is private or reserved. Public registration cannot identify its local operator.'));
    target.append(node('h5','Names observed in the exchange'));
    for(const name of v.observed_names)target.append(node('p',`${name.name} · ${name.source} · ${name.observed_at||'time unavailable'}`));
    if(!v.observed_names.length)target.append(node('p','No hostname was retained.'));
    const limits=node('ul');for(const line of v.limitations)limits.append(node('li',line));target.append(node('h5','Evidence limits'),limits);
  }
  document.addEventListener('megalodon:endpoint-selected',event=>{
    const ip=typeof event.detail==='string'&&/^[0-9a-fA-F:.]{2,45}$/.test(event.detail)?event.detail:null;
    if(ip===state.ip)return;
    state.ip=ip;state.serial++;state.pending=false;state.note=null;el('address-investigation-result').hidden=true;
    el('address-investigation-status').textContent=ip?'Ready to read retained observations for the selected address. No external lookup runs.':'Select an observed peer to begin. No external lookup runs automatically.';controls();
  });
  el('address-investigation-read').addEventListener('click',async()=>{
    if(!state.ip||state.pending||document.hidden)return;
    const ip=state.ip,serial=++state.serial;state.pending=true;state.note=null;el('address-investigation-result').hidden=true;controls();
    el('address-investigation-status').textContent='Reading retained address evidence…';
    try{
      const value=checked(await requestBoundedJSON('/api/address-investigation?ip='+encodeURIComponent(ip),16384,{headers:{'X-Megalodon-Check':'1'}}),ip);
      if(serial!==state.serial||ip!==state.ip)return;
      state.note=value;render(value);el('address-investigation-status').textContent='Investigation note ready. Original source and identity remain unestablished. Nothing was sent to an external service.';
    }catch(_){if(serial===state.serial){el('address-investigation-result').hidden=true;el('address-investigation-status').textContent='Address evidence could not be confirmed, or the address left the retained window. Select a current peer and retry.';}}
    finally{if(serial===state.serial){state.pending=false;controls();}}
  });
  el('address-investigation-save').addEventListener('click',()=>{
    if(!state.note||state.pending)return;
    const raw=JSON.stringify(state.note,null,2)+'\n',url=URL.createObjectURL(new Blob([raw],{type:'application/json'})),link=document.createElement('a');
    link.href=url;link.download='megalodon-address-investigation.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    el('address-investigation-status').textContent='Investigation note download requested. This personal copy contains local connection metadata and is outside automatic cleanup.';
  });
})();
'''
