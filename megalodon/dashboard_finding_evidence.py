"""Passive inspection of the already admitted, bounded traffic projection."""

FINDING_EVIDENCE_HTML = '''
<section class="finding-evidence" id="room-evidence-inspector" aria-labelledby="room-evidence-title">
  <div class="finding-evidence-heading"><div><p class="eyebrow">Finding → event → ingestion run</p><h3 id="room-evidence-title" tabindex="-1">Inspect the evidence</h3></div><button id="room-evidence-close" type="button" hidden>Return to finding</button></div>
  <p id="room-evidence-status" role="status">Select Inspect evidence on a qualified finding to trace its stored source.</p>
  <div id="room-evidence-content" hidden>
    <p id="room-evidence-explanation" class="finding-evidence-explanation"></p>
    <ol class="finding-evidence-lineage" aria-label="Recorded evidence links">
      <li><span>Finding</span><strong id="room-evidence-finding"></strong><small id="room-evidence-rule"></small></li>
      <li><span>Linked metadata event</span><strong id="room-evidence-event"></strong><small id="room-evidence-source"></small></li>
      <li><span>Ingestion run receipt</span><strong id="room-evidence-run"></strong><small id="room-evidence-run-state"></small></li>
    </ol>
    <dl class="finding-evidence-times"><div><dt>Event observed (UTC)</dt><dd id="room-evidence-observed"></dd></div><div><dt>Finding detected (UTC)</dt><dd id="room-evidence-detected"></dd></div><div><dt>Projection generated (UTC)</dt><dd id="room-evidence-generated"></dd></div></dl>
    <p id="room-evidence-age"></p>
    <dl class="finding-evidence-facts" aria-label="Recorded detector measurements"><div><dt>Measured value</dt><dd id="room-evidence-measured"></dd></div><div><dt>Threshold at detection</dt><dd id="room-evidence-threshold"></dd></div><div><dt>Detector evaluation window</dt><dd id="room-evidence-window"></dd></div></dl>
    <p>Recorded metadata measurements, not proof of malicious intent. Source limits and missing observations may affect counts.</p>
    <details id="room-evidence-details"><summary>Metadata, provenance and limits</summary>
      <dl class="finding-evidence-facts"><div><dt>Recorded endpoints</dt><dd id="room-evidence-endpoints"></dd></div><div><dt>Protocol / TCP flags</dt><dd id="room-evidence-protocol"></dd></div><div><dt>Reported bytes</dt><dd id="room-evidence-bytes"></dd></div><div><dt>Receipt termination reason</dt><dd id="room-evidence-termination"></dd></div><div><dt>Detector version</dt><dd id="room-evidence-version"></dd></div><div><dt>Selected display range</dt><dd id="room-evidence-range"></dd></div><div><dt>Returned candidate bounds</dt><dd id="room-evidence-bounds"></dd></div></dl>
      <p>The linked event is a source record, not the complete evidence evaluated by the detector. Only validated measurements recorded with this finding are shown; missing values are not reconstructed. Current software settings cannot establish historical detector behavior.</p>
      <p>JSONL source declarations are operator supplied. An ingestion receipt describes stored work; its running or completed state does not prove a process is active. Sensor liveness, drops, clock accuracy and complete network coverage remain unknown.</p>
      <p>Ports, protocol labels and TCP flags do not establish application identity or connection state. This view does not supply action receipts or authorize a response.</p>
    </details>
    <div class="finding-evidence-next"><strong>Continue your review</strong><p>Compare the recorded source with expected activity. These links open existing views; selecting one does not run a check or generate a report.</p><nav aria-label="Evidence follow-up"><a href="#ingestion-runs-title">Browse ingestion receipts</a><a href="#storage-evidence-title">Inspect retained evidence</a><a href="#room-reports-title">Open Reports</a></nav></div>
  </div>
</section>
'''

FINDING_EVIDENCE_CSS = r'''
.finding-evidence { margin:24px 0; padding:clamp(16px,3vw,28px); border:1px solid #426477; border-radius:10px; background:#0c202b; color:#e2f2f5; min-width:0; overflow-wrap:anywhere; }
.finding-evidence-heading { display:flex; justify-content:space-between; align-items:start; gap:16px; }
.finding-evidence-heading h3 { margin:.3rem 0; font-size:clamp(1.2rem,2.4vw,1.6rem); }
.finding-evidence p { color:#bfd0d9; line-height:1.65; }
.finding-evidence [hidden] { display:none!important; }
.finding-evidence-explanation { border-left:3px solid #a6f4df; padding:8px 14px; }
.finding-evidence-lineage { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; list-style:none; padding:0; margin:20px 0; }
.finding-evidence-lineage li { border:1px solid #355765; border-radius:7px; padding:14px; min-width:0; }
.finding-evidence-lineage span,.finding-evidence-lineage small { display:block; color:#bfd0d9; line-height:1.5; }
.finding-evidence-lineage strong { display:block; margin:6px 0; font:600 1.15rem ui-monospace,monospace; }
.finding-evidence-times { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:16px; }
.finding-evidence dt { color:#bfd0d9; font-size:.85rem; line-height:1.5; }
.finding-evidence dd { margin:5px 0 0; line-height:1.6; font-variant-numeric:tabular-nums; }
.finding-evidence-times dd { font-size:.85rem; }
.finding-evidence-facts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px 24px; }
.finding-evidence details { border-top:1px solid #355765; margin-top:16px; }
.finding-evidence summary { cursor:pointer; min-height:44px; padding:14px 0; font-weight:700; }
.finding-evidence-next { border-top:1px solid #355765; padding-top:18px; margin-top:18px; }
.finding-evidence-next nav { display:flex; flex-wrap:wrap; gap:8px 20px; }
.finding-evidence a { color:#a6f4df; min-height:44px; display:inline-flex; align-items:center; text-underline-offset:4px; }
.finding-evidence button,.room-evidence-open { min-height:44px; padding:9px 13px; border:1px solid #568392; border-radius:5px; background:#102f3b; color:#e2f2f5; font:inherit; cursor:pointer; }
.room-evidence-open[aria-expanded="true"] { border-color:#a6f4df; background:#173e46; }
.finding-evidence :focus-visible,.room-evidence-open:focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }
#room-evidence-title { scroll-margin-block:20px; }
#room-evidence-status { min-height:1.65em; }
@media(max-width:760px) { .finding-evidence-lineage,.finding-evidence-times { grid-template-columns:1fr; } .finding-evidence-heading { flex-wrap:wrap; } }
@media(max-width:640px) { #room-findings-table tbody td:nth-child(6) { grid-column:1/-1; } .finding-evidence-facts { grid-template-columns:1fr; } }
'''

FINDING_EVIDENCE_JS = r'''
const roomEvidenceState={key:null,context:null,signature:null,buttons:new Map()};
const roomEvidenceExplanations=Object.freeze({
  SYN_FLOOD:'The recorded SYN_FLOOD rule identifies SYN activity for review. Legitimate load or authorized testing can produce similar patterns.',
  PORT_SCAN:'The recorded PORT_SCAN rule identifies a port-access pattern for review. Inventory work and authorized testing can produce similar patterns.',
  DNS_TUNNELING:'The recorded DNS_TUNNELING rule identifies DNS metadata for review. A long DNS query can be legitimate; this finding does not prove tunneling.'
});
function roomEvidenceText(id,value) {const node=byId(id);if(node.textContent!==value)node.textContent=value;}
function roomEvidenceKey(f,e) {return JSON.stringify([f.id,e.id,e.run_id,e.source,e.observed_at,f.detected_at,f.rule_id,f.severity,f.detector_version,e.src_ip,e.dst_ip,e.src_port,e.dst_port,e.protocol,e.tcp_flags,e.byte_count,f.measurement??null]);}
function roomEvidenceContext() {const h=roomState.history;return JSON.stringify(h?['history',h.start,h.end,h.before]:['latest',roomState.range,roomState.custom]);}
function roomEvidenceFocused() {return byId('room-evidence-inspector').contains?.(document.activeElement);}
function clearRoomEvidence(message='Select Inspect evidence on a qualified finding to trace its stored source.') {
  const focused=roomEvidenceFocused();roomEvidenceState.key=null;
  byId('room-evidence-content').hidden=true;byId('room-evidence-close').hidden=true;
  for(const field of ['explanation','finding','event','run','rule','source','run-state','observed','detected','generated','endpoints','protocol','bytes','termination','version','range','bounds','age','measured','threshold','window'])roomEvidenceText('room-evidence-'+field,'');
  roomEvidenceText('room-evidence-title','Inspect the evidence');roomEvidenceText('room-evidence-status',message);
  for(const button of roomEvidenceState.buttons.values())button.setAttribute('aria-expanded','false');
  if(focused)byId('room-evidence-title').focus?.({preventScroll:true});
}
function renderRoomEvidence(selected,stale) {
  if(!roomEvidenceState.key)return;
  const events=new Map(selected.events.map(e=>[e.id,e]));
  const finding=selected.findings.find(f=>events.has(f.event_id)&&roomEvidenceKey(f,events.get(f.event_id))===roomEvidenceState.key);
  if(!finding){clearRoomEvidence('The selected evidence changed or is no longer in this returned page or time range. Select a finding to inspect its evidence; absence does not establish resolution.');return;}
  const event=events.get(finding.event_id),snapshot=roomState.snapshot;
  byId('room-evidence-content').hidden=false;byId('room-evidence-close').hidden=false;
  roomEvidenceText('room-evidence-title','Finding '+finding.id+' · '+finding.rule_id);
  roomEvidenceText('room-evidence-status',stale?'Stale evidence — the last valid snapshot is preserved. Refresh failed or this projection expired.':'Stored evidence — linked records in the current returned page. Sensor liveness remains unknown.');
  roomEvidenceText('room-evidence-explanation',(roomEvidenceExplanations[finding.rule_id]||'Recorded fixed-rule finding for review.')+' Recorded severity: '+finding.severity+'. A finding is not proof of malware or authority to act.');
  for(const [id,value] of Object.entries({finding:finding.id,event:event.id,run:event.run_id,rule:finding.rule_id+' · '+finding.severity,source:event.source==='jsonl'?'JSONL · operator-declared provenance':'Scapy · recorded source', 'run-state':'Recorded state: '+event.run_status,observed:event.observed_at,detected:finding.detected_at,generated:snapshot.generated_at,endpoints:roomEndpoint(event.src_ip,event.src_port)+' → '+roomEndpoint(event.dst_ip,event.dst_port),protocol:event.protocol+' / '+(event.tcp_flags.join(', ')||'no TCP flags recorded'),bytes:event.byte_count+' reported bytes',termination:event.termination_reason||'Not recorded for a running receipt',version:finding.detector_version,range:new Date(selected.start).toISOString()+' → '+new Date(selected.end).toISOString(),bounds:'At most '+snapshot.limits.events+' event candidates and '+snapshot.limits.findings+' finding candidates. '+(snapshot.truncated?'Candidate window truncated. ':'Completeness beyond the returned window is unknown. ')+snapshot.excluded_event_candidates+' excluded event candidates.'}))roomEvidenceText('room-evidence-'+id,value);
  const measurement=finding.measurement;
  roomEvidenceText('room-evidence-measured',measurement?measurement.value+' '+measurement.unit:'Not recorded');
  roomEvidenceText('room-evidence-threshold',measurement?.threshold!=null?String(measurement.threshold)+' (at least)':'Not recorded');
  roomEvidenceText('room-evidence-window',finding.rule_id==='DNS_TUNNELING'&&measurement?'Single event; no sliding window':measurement?.window_seconds!=null?measurement.window_seconds+' seconds; inclusive cutoff':'Not recorded');
  const age=Date.now()-Date.parse(event.observed_at);
  roomEvidenceText('room-evidence-age',age<0?'Observation time is ahead of this browser clock; clock agreement is unknown.':'Observation age: '+(age<60000?'less than one minute':age<3600000?Math.floor(age/60000)+' minutes':age<86400000?Math.floor(age/3600000)+' hours':Math.floor(age/86400000)+' days')+'. A refreshed projection does not make this observation new.');
  for(const [key,button] of roomEvidenceState.buttons)button.setAttribute('aria-expanded',String(key===roomEvidenceState.key));
}
function roomOpenEvidence(key) {
  if((roomState.history&&roomState.managedHistory)||!roomState.selection)return;
  roomEvidenceState.key=key;
  renderRoomEvidence(roomState.selection,Boolean(roomState.failed||(roomState.snapshot&&Date.now()-Date.parse(roomState.snapshot.generated_at)>300000)));
  byId('room-evidence-title').focus?.();
}
function renderRoomFindings(selected,stale,has) {
  const context=roomEvidenceContext();
  if(roomEvidenceState.context!==null&&context!==roomEvidenceState.context)clearRoomEvidence('The reviewed page or time range changed. Select a finding in this view to inspect its evidence.');
  roomEvidenceState.context=context;
  const events=new Map(selected.events.map(e=>[e.id,e]));
  const signature=JSON.stringify([context,has,selected.findings.map(f=>[f,events.has(f.event_id)?roomEvidenceKey(f,events.get(f.event_id)):null])]);
  if(signature!==roomEvidenceState.signature){
    const tableRoot=byId('room-findings-table'),focused=document.activeElement?.dataset?.evidenceKey,scrollTop=tableRoot.scrollTop,scrollLeft=tableRoot.scrollLeft;
    roomEvidenceState.signature=signature;roomEvidenceState.buttons=new Map();
    tableRoot.setAttribute('tabindex','0');tableRoot.setAttribute('role','region');tableRoot.setAttribute('aria-label','Scrollable qualified findings');
    const table=textNode('table');table.append(textNode('caption','Qualified findings in the shared time range'));
    const head=textNode('tr');['Time','Detector','Severity','Finding / event ID','Detector version','Evidence'].forEach(label=>{const th=textNode('th',label);th.scope='col';head.append(th);});const thead=textNode('thead');thead.append(head);table.append(thead);
    const body=textNode('tbody');
    selected.findings.forEach(f=>{const row=textNode('tr');[f.detected_at,f.rule_id,f.severity,`${f.id} / ${f.event_id}`,f.detector_version].forEach((value,index)=>{const cell=textNode('td',index===2?'':value);if(index===2){const level=['CRITICAL','HIGH','MEDIUM','LOW'].includes(value)?value:'UNKNOWN';cell.append(textNode('span',value,`severity ${level}`));}row.append(cell);});
      const cell=textNode('td'),event=events.get(f.event_id);
      if(event){const key=roomEvidenceKey(f,event),button=textNode('button','Inspect evidence','room-evidence-open');button.type='button';button.setAttribute('data-evidence-key',key);button.setAttribute('aria-controls','room-evidence-inspector');button.setAttribute('aria-expanded',String(key===roomEvidenceState.key));button.setAttribute('aria-label','Inspect evidence for finding '+f.id);button.addEventListener('click',()=>roomOpenEvidence(key));roomEvidenceState.buttons.set(key,button);cell.append(button);}else cell.append(textNode('span','Linked evidence unavailable'));
      row.append(cell);body.append(row);
    });table.append(body);tableRoot.replaceChildren(table);if(!selected.findings.length)tableRoot.append(textNode('p',has?'No linked findings in this bounded set. This does not prove no threat.':'No qualified data available.','room-empty'));
    if(focused){const button=roomEvidenceState.buttons.get(focused);if(button)button.focus?.({preventScroll:true});else byId('room-findings-title').focus?.({preventScroll:true});}
    tableRoot.scrollTop=scrollTop;tableRoot.scrollLeft=scrollLeft;
  }
  renderRoomEvidence(selected,stale);
}
byId('room-evidence-close').addEventListener('click',()=>{const button=roomEvidenceState.buttons.get(roomEvidenceState.key);clearRoomEvidence();if(button)button.focus?.();else byId('room-findings-title').focus?.();});
'''
