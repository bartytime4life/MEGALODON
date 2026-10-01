"""Retained, paginated history charts. No synthetic traffic or implicit writes."""
HISTORY_JS = r'''
function validateManagedHistory(value,request) {
  if(!value || value.schema!=='megalodon-traffic-history-v2' || !Array.isArray(value.records) || value.records.length>128
    || !Array.isArray(value.gaps) || !value.gaps.every(x=>typeof x==='string'&&x.length<512)
    || !Array.isArray(value.source_segments) || value.source_segments.length>32
    || !Number.isInteger(value.candidate_count) || value.candidate_count<0 || value.candidate_count>4096
    || Date.parse(value.range?.start)!==request.start || Date.parse(value.range?.end)!==request.end
    || !(value.next_cursor===null||/^[a-f0-9]{32}:[0-9]{1,19}$/.test(value.next_cursor))
    || !value.records.every(r=>r&&/^[a-f0-9]{32}:[0-9]+$/.test(r.id)&&roomStamp(r.observed_at)
      && ['packets','packet_rollups','flows','findings'].includes(r.category)&&typeof r.source==='string'&&r.source.length<256&&r.data&&typeof r.data==='object')) throw Error('Invalid retained history');
  return value;
}
function renderManagedHistory() {
  const page=roomState.managedHistory, h=roomState.history;
  const packets=page.records.filter(r=>r.category==='packets'||(r.category==='packet_rollups'&&r.data.kind==='conversation_v1'));
  const counts=new Map(), peers=new Map(), bins=new Map(), sensors=new Map(), findings=[];
  let count=0, bytes=0;
  const amount=x=>Number.isSafeInteger(x)&&x>=0?x:0;
  const add=(map,key,n)=>map.set(String(key).slice(0,256),(map.get(String(key).slice(0,256))||0)+n);
  packets.forEach(r=>{const d=r.data,n=amount(d.packet_count);count+=n;bytes+=amount(d.byte_count);
    add(counts,d.protocol||'Unknown',n);for(const key of ['src_ip','dst_ip'])if(d[key])add(peers,d[key],n);
    add(bins,r.observed_at.slice(0,16)+' UTC',n);
    for(const f of d.findings||[])findings.push({id:r.id+':finding:'+f.id,source:'MEGALODON',title:f.rule_id,severity:f.severity});
  });
  page.records.forEach(r=>{
    if(r.category==='flows')add(sensors,r.source,1);
    if(r.category==='findings'||r.data.kind==='finding_v1')findings.push({id:r.id,source:r.source,title:r.data.rule_id||r.data.signature||'Recorded finding',severity:r.data.severity||'Unknown'});
  });
  const selection={start:h.start,end:h.end,events:packets,findings};
  roomState.selection=selection;
  const note='Retained history across source segments. This page contains packet detail or verified conversation summaries, never both for one source. Use Reports for complete interval aggregation.';
  byId('room-overall').textContent=roomState.failed?'Stale history':'Retained history';
  byId('room-connection').textContent=roomState.failed?'Unavailable · preserved view':'Local history connected';
  byId('room-coverage').textContent=page.truncated?'Partial page':'End of retained range';
  byId('room-sources').textContent=[...new Set(page.records.map(r=>r.source))].join(', ')||'No retained source';
  byId('room-count').textContent=String(findings.length)+' findings in this page';
  byId('room-notice').textContent=note+' '+page.gaps.join(' ');
  byId('room-home-summary').textContent=note;
  byId('hud-records').textContent=String(count);byId('hud-findings').textContent=String(findings.length);
  byId('hud-bytes').textContent=String(bytes);byId('hud-source-count').textContent=String(new Set(page.records.map(r=>r.source)).size);
  const grid=byId('room-traffic-grid');grid.replaceChildren();
  const ranked=map=>[...map].sort((a,b)=>b[1]-a[1]).slice(0,12);
  for(const [title,map,unit] of [['Traffic by observation time',bins,'represented packet records'],['Protocol mix',counts,'represented packet records'],['Observed endpoints',peers,'endpoint appearances'],['Separate sensor observations',sensors,'flow updates']]){
    const panel=roomVisual(grid,title,selection,'Retained page',page.records.length?'data':'unavailable');roomBars(panel,map===bins?[...map].sort((a,b)=>a[0].localeCompare(b[0])).slice(0,12):ranked(map),unit);
    if(map===bins)panel.append(textNode('p','Conversation fragments are placed at their first observation. Packet arrival timing is unavailable after compaction.','room-meta'));
    if(map===sensors)panel.append(textNode('p','Flow updates are not added to packet counts or treated as unique connections.','room-meta'));
  }
  const activity=textNode('table');activity.append(textNode('caption','Source evidence references for this page'));
  const head=textNode('thead'), headings=textNode('tr');['Time','Source','Evidence type','Reference'].forEach(v=>{const cell=textNode('th',v);cell.scope='col';headings.append(cell);});head.append(headings);activity.append(head);
  const body=textNode('tbody');page.records.forEach(r=>{const row=textNode('tr');[r.observed_at,r.source,r.category,r.id].forEach(v=>row.append(textNode('td',String(v))));body.append(row);});activity.append(body);
  byId('room-activity-table').replaceChildren(activity);
  const root=byId('room-findings-visual');root.replaceChildren();const panel=roomVisual(root,'Retained findings',selection,findings.length+' on this page',findings.length?'data':'unavailable');
  roomBars(panel,roomCounts(findings.map(f=>f.source+' / '+f.severity)),'findings');
  const details=textNode('table');details.append(textNode('caption','Retained findings on this page'));const fh=textNode('thead'),fr=textNode('tr');['Source','Rule','Severity','Evidence reference'].forEach(v=>{const c=textNode('th',v);c.scope='col';fr.append(c);});fh.append(fr);details.append(fh);const fb=textNode('tbody');findings.forEach(f=>{const row=textNode('tr');[f.source,f.title,f.severity,f.id].forEach(v=>row.append(textNode('td',String(v))));fb.append(row);});details.append(fb);byId('room-findings-table').replaceChildren(details);
  renderRoomControls();
  byId('room-feed-status').textContent='History is held for review. Interface speeds and the globe continue to use their live observations.';
  byId('room-history-status').textContent=`Page ${h.previous.length+1} · ${page.candidate_count} source rows checked · ${page.source_segments.length} segments visited. ${page.next_cursor?'More retained history available.':'End of this range.'}`;
  byId('room-older').textContent='Next history page';byId('room-newer').textContent='Previous history page';
}
'''
