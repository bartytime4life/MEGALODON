"""Read-only case assembly over the already validated traffic window."""

CASE_HTML = '''
<section class="room-case finding-evidence" id="room-case" aria-labelledby="room-case-title">
  <p class="eyebrow">Automatic retained-evidence review</p>
  <h3 id="room-case-title">Address case overview</h3>
  <p id="room-case-status" role="status">Waiting for qualified retained records.</p>
  <p id="room-case-summary"></p>
  <p id="room-case-coverage"></p>
  <details><summary>Advanced · address and scope</summary>
    <label for="room-case-address">Recorded address</label>
    <select id="room-case-address" aria-describedby="room-case-scope"></select>
    <p id="room-case-scope">Uses the shared traffic time range and current returned page. An address is not a verified host identity.</p>
  </details>
  <div id="room-case-timeline" role="region" aria-label="Case event timeline" tabindex="0"></div>
  <p>Grouping means a shared recorded address, not a confirmed incident. No baseline, model conclusion, or full sensor coverage is inferred. This view does not save notes, export evidence, or authorize actions.</p>
</section>
'''
CASE_CSS = '''
#room-case-timeline { overflow:auto; max-height:420px; margin-top:16px; }
#room-case-timeline td { overflow-wrap:anywhere; }
#room-case-address { max-width:100%; min-height:44px; }
#room-case details { margin-block:16px; }
'''
CASE_JS = r'''
const roomCaseState={address:null,signature:null};
function clearRoomCase(message) {
  roomCaseState.signature=null;
  byId('room-case-status').textContent=message;
  byId('room-case-summary').textContent='';
  byId('room-case-coverage').textContent='';
  byId('room-case-timeline').replaceChildren();
  byId('room-case-address').replaceChildren();
  byId('room-case-address').disabled=true;
}
function roomCaseModel(selected,address) {
  const events=selected.events.filter(e=>e.src_ip===address||e.dst_ip===address)
    .slice().sort((a,b)=>Date.parse(a.observed_at)-Date.parse(b.observed_at)||Number(a.id)-Number(b.id));
  const ids=new Set(events.map(e=>e.id));
  return {events,findings:selected.findings.filter(f=>ids.has(f.event_id))};
}
function renderRoomCase(selected,stale) {
  const addresses=[...new Set(selected.events.flatMap(e=>[e.src_ip,e.dst_ip]))].sort();
  if(!roomCaseState.address&&addresses.length){
    const linked=selected.events.find(e=>selected.findings.some(f=>f.event_id===e.id));
    roomCaseState.address=linked?.src_ip||selected.events[0].src_ip;
  }
  if(!addresses.length){clearRoomCase('No qualified records in this returned window. Absence does not establish safety.');return;}
  const address=roomCaseState.address,model=roomCaseModel(selected,address),snapshot=roomState.snapshot;
  const signature=JSON.stringify([address,selected.start,selected.end,stale,snapshot?.truncated,snapshot?.excluded_event_candidates,selected.events,selected.findings]);
  if(signature===roomCaseState.signature)return;
  roomCaseState.signature=signature;
  const select=byId('room-case-address');select.disabled=false;select.replaceChildren();
  if(!addresses.includes(address))addresses.unshift(address);
  for(const ip of addresses){const option=textNode('option',ip);option.value=ip;select.append(option);}select.value=address;
  byId('room-case-status').textContent=(stale?'Stale retained snapshot — ':'Recorded metadata — ')+(model.events.length?'automatically assembled for '+address:'selected address is absent from this returned window; choose another under Advanced.');
  byId('room-case-summary').textContent=model.events.length+' linked metadata events and '+model.findings.length+' findings for this address in the selected returned set. '+(model.findings.length?'Review the recorded findings below; they do not establish malicious intent.':'No linked findings here; this does not establish that the address is safe.');
  byId('room-case-coverage').textContent='Scope: '+new Date(selected.start).toISOString()+' to '+new Date(selected.end).toISOString()+'. '+(snapshot?.truncated?'Candidate window truncated. ':'Completeness beyond the candidate window is unknown. ')+(snapshot?.excluded_event_candidates||0)+' excluded event candidates across the returned page. '+(model.events.length>100?'Timeline shows the first 100 of '+model.events.length+' matching events. ':'')+'Sensor liveness, drops, and missing observations are unknown.';
  const root=byId('room-case-timeline'),table=textNode('table');table.append(textNode('caption','Recorded events for '+address+' in observation-time order'));
  const head=textNode('tr');for(const label of ['Observed (UTC)','Event / run','Recorded endpoints','Related findings']){const th=textNode('th',label);th.scope='col';head.append(th);}const thead=textNode('thead');thead.append(head);table.append(thead);
  const body=textNode('tbody');
  for(const event of model.events.slice(0,100)){
    const row=textNode('tr');row.append(textNode('td',event.observed_at),textNode('td',event.id+' / '+event.run_id),textNode('td',event.src_ip+' → '+event.dst_ip));
    const cell=textNode('td'),findings=model.findings.filter(f=>f.event_id===event.id);
    for(const finding of findings){const button=textNode('button','Finding '+finding.id+' · '+finding.rule_id+' · detected '+finding.detected_at);button.type='button';button.addEventListener('click',()=>roomOpenEvidence(roomEvidenceKey(finding,event)));cell.append(button);}
    if(!findings.length)cell.append(textNode('span','No linked finding'));row.append(cell);body.append(row);
  }
  table.append(body);root.replaceChildren(table);
}
byId('room-case-address').addEventListener('change',()=>{roomCaseState.address=byId('room-case-address').value;roomCaseState.signature=null;renderRoom();});
'''
