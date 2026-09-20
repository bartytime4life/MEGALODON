"""Anchored control-room presentation; all traffic comes from the local reader."""

STATUS_HTML = """
<section class="room-status" aria-label="Control room status">
  <div><span>Overall Status</span><strong id="room-overall">Unknown</strong></div>
  <div><span>Local Service</span><strong id="room-connection">Not checked</strong></div>
  <div><span>Data Coverage</span><strong id="room-coverage">Unavailable</strong></div>
  <div><span>Last Updated</span><strong id="room-updated">Not fetched</strong></div>
  <div><span>Active Sources</span><strong id="room-sources">Unknown</strong></div>
  <div><span>Findings</span><strong id="room-count">Unavailable</strong></div>
</section>
<p id="room-notice" class="room-notice" role="status" aria-live="polite">No qualified data available until the local metadata check succeeds.</p>
<div class="room-range" aria-label="Shared time range">
  <label>When?<select id="room-range"><option value="recorded">Recorded window</option><option value="now">Now (last 5 minutes)</option><option value="hour">Last hour</option><option value="today">Today (UTC)</option><option value="custom">Custom UTC</option></select></label>
  <label id="room-start-label" hidden>Start (UTC)<input id="room-start" type="datetime-local" step="1"></label>
  <label id="room-end-label" hidden>End (UTC)<input id="room-end" type="datetime-local" step="1"></label>
  <button type="button" id="room-apply">Apply time range</button><button type="button" id="room-refresh">Refresh metadata</button>
  <p id="room-range-description">Time range unavailable</p>
</div>
"""

HOME_HTML = """
<section class="room-home panel" aria-labelledby="room-home-title">
  <p class="eyebrow">Your control room</p><h2 id="room-home-title" tabindex="-1">What can I see?</h2>
  <p id="room-home-summary">No qualified data available. Your saved audit data and optional tools are checked separately.</p>
  <div class="room-actions"><a href="#room-traffic-title">See traffic</a><a href="#room-findings-title">Review findings</a><a href="#integrations-title">Open Apps</a><a href="#room-reports-title">Make a report</a></div>
  <details><summary>How do we know?</summary><p>Only validated, bounded metadata linked to a non-sample ingestion run appears in Traffic and Findings. Imported JSONL provenance is unverified. Open Evidence for separate saved reports and audit history.</p></details>
</section>
"""

TRAFFIC_HTML = """
<section class="workspace-view" id="workspace-traffic" role="tabpanel" aria-labelledby="workspace-tab-traffic" hidden>
  <h2 id="room-traffic-title" tabindex="-1">Traffic</h2><p>Saved metadata in the shared time range. No capture starts here.</p>
  <div id="room-traffic-grid" class="room-grid"></div>
</section>
<section class="workspace-view" id="workspace-findings" role="tabpanel" aria-labelledby="workspace-tab-findings" hidden>
  <h2 id="room-findings-title" tabindex="-1">Findings</h2><p>Fixed detector results linked to the qualified event set. A finding is a reason to review, not proof of malware.</p>
  <div id="room-findings-visual" class="room-grid"></div><div id="room-findings-table" class="room-table"></div>
</section>
<section class="workspace-view" id="workspace-reports" role="tabpanel" aria-labelledby="workspace-tab-reports" hidden>
  <h2 id="room-reports-title" tabindex="-1">Make a local report</h2>
  <p>Preview the exact metadata-only JSON before downloading it. Nothing is uploaded, sent, or written by the server.</p>
  <div id="room-report-flow" class="room-report-flow">
    <ol class="room-report-steps">
      <li><strong>1. Confirm range</strong><span>The shared UTC range above controls this report.</span></li>
      <li><strong>2. Preview locally</strong><span>Review the complete bounded JSON in this browser tab.</span></li>
      <li><strong>3. Download explicitly</strong><span>Save only after the preview is ready.</span></li>
    </ol>
    <div class="room-report-actions">
      <button type="button" id="room-report-create">Preview local report</button>
      <button type="button" id="room-report-download" disabled>Download JSON report</button>
    </div>
    <p id="room-report-status" class="room-meta" role="status" aria-live="polite">No preview is ready.</p>
    <pre id="room-report-preview" class="room-report-preview" tabindex="0" hidden aria-label="Exact local report preview"></pre>
  </div>
</section>
<section class="workspace-view" id="workspace-help" role="tabpanel" aria-labelledby="workspace-tab-help" hidden>
  <h2 id="room-help-title" tabindex="-1">Help</h2>
  <section class="panel"><h3>No qualified data available?</h3><p>Open the HUD from your installed MEGALODON environment with <code>python -m megalodon hud</code>. It never creates sample data or starts a sensor.</p>
  <p>To learn how to import an authorized metadata file, run <code>python -m megalodon run --help</code>. Choose an existing completed report under Home for the next launch. Evidence shows those separate offline snapshots.</p>
  <p>Refresh only reads the selected store. After the first import into a previously missing store, restart this HUD. If the store is unsafe or incompatible, inspect the terminal refusal; never weaken file permissions to force it open.</p>
  <h3>What do the words mean?</h3><p>Unavailable: there is no usable evidence. Unknown: evidence cannot answer that question. Degraded: some evidence is limited or incomplete. Stale: a saved view is older than five minutes or a refresh failed. None means that the network is safe.</p>
  <h3>What stays on this computer?</h3><p>Traffic, findings, tool checks and reports stay local. MEGALODON does not send them to the hosted reference console. Qwen is optional and cannot create findings, commands or reports.</p></section>
</section>
"""


def compose_control_room(html: str) -> str:
    start = html.index('  <nav class="section-nav"')
    end = html.index('  <div class="workspace-scroll"', start)
    tabs = (("live", "Home"), ("traffic", "Traffic"), ("findings", "Findings"), ("interfaces", "Apps"),
            ("reports", "Reports"), ("analysis", "Evidence"), ("help", "Help"))
    nav = '<nav class="section-nav" aria-label="Command center workspaces" role="tablist">'
    for key, name in tabs:
        nav += f'<button id="workspace-tab-{key}" type="button" role="tab" aria-controls="workspace-{key}" aria-selected="{"true" if key == "live" else "false"}" tabindex="{0 if key == "live" else -1}">{name}</button>'
    nav += '</nav><a class="room-back" href="#page-title">← Back to Main HUD</a>'
    html = html[:start] + '<div class="room-chrome">' + STATUS_HTML + '</div>' + nav + html[end:]
    # Preserve the older audit inspector and its IDs in the Evidence workspace.
    start = html.index('  <section class="trust-strip')
    end = html.index('  <section class="workspace-view" id="workspace-analysis"', start)
    legacy = html[start:end]
    legacy = legacy[:legacy.rfind('  </section>')]
    html = html[:start] + HOME_HTML + '</section>\n' + html[end:]
    marker = '<section class="workspace-view" id="workspace-analysis" role="tabpanel" aria-labelledby="workspace-tab-analysis" hidden>'
    html = html.replace(marker, marker + '<details class="room-audit-history"><summary>Audit history — may include sample and unlinked rows</summary>' + legacy + '</details>')
    html = html.replace('  <noscript>', TRAFFIC_HTML + '  <noscript>')
    html = html.replace('>Network activity</h1>', '>Main HUD</h1>')
    return html


ROOM_CSS = r"""
.shell { display:flex; flex-direction:column; }
.shell > .topbar,.shell > .section-nav,.room-back { flex-shrink:0; }
.room-chrome { max-height:45vh; overflow:auto; flex-shrink:1; }
.workspace-scroll { flex:1; min-height:80px; }
.section-nav { grid-template-columns:repeat(7,minmax(0,1fr)); margin:0; }
.room-status { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:.6rem; margin:.7rem 0; }
.room-status > div { background:#102632; border:1px solid #325061; border-radius:10px; padding:.75rem; min-width:0; }
.room-status span { display:block; font-size:.8rem; color:#b7cbd4; margin-bottom:.4rem; }
.room-status strong { display:block; font-size:.96rem; overflow-wrap:anywhere; color:#f2f7f9; }
.room-notice { color:#e2d298; font-size:.88rem; margin:.35rem 0 .7rem; }
.room-range { display:flex; flex-wrap:wrap; gap:.6rem; align-items:end; }
.room-range label { display:grid; gap:.25rem; font-size:.85rem; }
.room-range select,.room-range input,.room-range button,.room-back,.room-actions a { min-height:44px; font:inherit; border:1px solid #426173; border-radius:7px; padding:.65rem .8rem; color:#e9f5f9; background:#112b38; }
.room-range p { flex-basis:100%; font-size:.78rem; color:#b7cbd4; margin:.1rem 0 .6rem; overflow-wrap:anywhere; }
.room-range button { cursor:pointer; }
.room-back { display:inline-flex; align-items:center; text-decoration:none; align-self:start; margin:.35rem 0; }
.section-nav { flex-wrap:wrap; }
.room-actions { display:flex; gap:.6rem; flex-wrap:wrap; }
.room-actions a { text-decoration:none; }
.room-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1rem; margin:1rem 0; }
.room-visual { min-width:0; background:#0e2330; border:1px solid #335064; border-radius:12px; padding:1rem; }
.room-visual h3 { font-size:1.05rem; margin:0 0 .5rem; color:#f2f7f9; }
.room-meta,.room-empty { font-size:.85rem; color:#bfd0d9; line-height:1.6; overflow-wrap:anywhere; }
.room-bars { list-style:none; padding:0; margin:.7rem 0; }
.room-bars li { display:grid; grid-template-columns:minmax(0,1fr) 5rem; gap:.2rem .5rem; margin:.6rem 0; font-size:.85rem; overflow-wrap:anywhere; }
.room-bars meter { grid-column:1/-1; width:100%; height:12px; }
.room-bars strong { text-align:right; }
.room-table { overflow:auto; max-height:50vh; }
.room-table table { min-width:580px; }
.room-table caption { text-align:left; color:#e6f3f8; padding:.6rem; }
.room-flow { display:grid; gap:.5rem; }
.room-flow p { border-left:3px solid #62d6c6; padding:.6rem; margin:0; font-family:ui-monospace,monospace; font-size:.8rem; overflow-wrap:anywhere; }
.room-visual svg { width:100%; height:140px; }
.room-visual svg rect { fill:#67dfcc; }
.room-visual svg text { fill:#c3d2da; font-size:10px; }
.room-audit-history > summary { min-height:44px; padding:1rem; color:#d9e8ef; cursor:pointer; }
.room-home p,.workspace-view > p { color:#bfd0d9; line-height:1.6; }
.room-home summary { min-height:44px; padding:.8rem 0; cursor:pointer; }
.room-report-flow { display:grid; gap:1rem; max-width:900px; }
.room-report-steps { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.75rem; margin:0; padding:0; list-style:none; counter-reset:none; }
.room-report-steps li { display:grid; gap:.4rem; border:1px solid #335064; border-radius:10px; padding:.85rem; background:#0e2330; }
.room-report-steps span { color:#bfd0d9; font-size:.82rem; line-height:1.5; }
.room-report-actions { display:flex; flex-wrap:wrap; gap:.6rem; }
.room-report-actions button { min-height:44px; font:inherit; border:1px solid #426173; border-radius:7px; padding:.65rem .8rem; color:#e9f5f9; background:#112b38; cursor:pointer; }
.room-report-actions button:disabled { cursor:not-allowed; opacity:.58; }
.room-report-preview { max-height:48vh; overflow:auto; margin:0; padding:1rem; border:1px solid #335064; border-radius:10px; background:#071923; color:#dcebf0; white-space:pre-wrap; overflow-wrap:anywhere; font-size:.78rem; line-height:1.5; }
:is(.room-range,.room-actions,.room-visual,.room-table,.room-report-actions) :focus-visible,.room-report-preview:focus-visible,.room-back:focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }
@media(max-width:760px) { .section-nav { grid-template-columns:repeat(4,minmax(0,1fr)); } .room-report-steps { grid-template-columns:1fr; } .room-grid { grid-template-columns:1fr; } .room-status { grid-template-columns:repeat(2,minmax(0,1fr)); } .room-range label { flex:1 1 140px; } .room-range select,.room-range input { max-width:100%; min-width:0; } }
@media(max-height:500px) { .shell { padding-top:4px; } .topbar { display:none; } .room-chrome { max-height:25vh; } .workspace-scroll { min-height:44px; } }
@media(prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none!important; transition:none!important; scroll-behavior:auto!important; } }
"""

ROOM_JS = r"""
const roomState = {snapshot:null, failed:false, connected:null, busy:false, range:'recorded', custom:null, selection:null, report:null};
const roomProtocols = ['TCP','UDP','ICMP','ICMPV6','DNS','HTTP','TLS','OTHER'];
const roomRules = ['SYN_FLOOD','PORT_SCAN','DNS_TUNNELING'];
const roomFlags = ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR'];
const roomId = value => typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value) && Number.isSafeInteger(Number(value));
function roomStamp(value) {
  if(typeof value!=='string') return false;
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(value);
  if(!match) return false;
  const [year,month,day,hour,minute,second]=match.slice(1,7).map(Number);
  if(year<1 || month<1 || month>12 || hour>23 || minute>59 || second>59) return false;
  const instant=new Date(0);
  instant.setUTCFullYear(year,month-1,day);
  instant.setUTCHours(hour,minute,second,Number((match[7]||'').padEnd(3,'0').slice(0,3)));
  return Number.isFinite(instant.valueOf())
    && instant.getUTCFullYear()===year && instant.getUTCMonth()===month-1 && instant.getUTCDate()===day
    && instant.getUTCHours()===hour && instant.getUTCMinutes()===minute && instant.getUTCSeconds()===second;
}
function validateTraffic(value) {
  if (!referenceExactKeys(value, ['schema','status','reason','generated_at','unit','vantage','quality','window','limits','truncated','excluded_event_candidates','events','findings','limitations','build'])
    || value.schema !== 'dashboard-traffic-v1' || !['available','unavailable'].includes(value.status)
    || !roomStamp(value.generated_at) || Date.parse(value.generated_at)>Date.now()+60000
    || !['unknown','degraded'].includes(value.quality) || typeof value.truncated !== 'boolean'
    || !Number.isInteger(value.excluded_event_candidates) || value.excluded_event_candidates<0 || value.excluded_event_candidates>500
    || !Array.isArray(value.events) || value.events.length>500 || !Array.isArray(value.findings) || value.findings.length>200
    || !referenceExactKeys(value.limits,['events','findings','bytes']) || value.limits.events!==500 || value.limits.findings!==200 || value.limits.bytes!==262144
    || !referenceExactKeys(value.window,['start','end']) || !referenceExactKeys(value.build,['package_version','base_commit','projection_sha256','commit'])
    || !/^[0-9a-f]{64}$/.test(value.build.projection_sha256) || !/^[0-9a-f]{40}$/.test(value.build.base_commit)
    || !Array.isArray(value.limitations) || value.limitations.length!==7
    || ![value.reason,value.unit,value.vantage,...value.limitations,...Object.values(value.build)].every(x=>typeof x==='string' && x.length<=256 && !/[\x00-\x1f\x7f]/.test(x))) throw new Error('Invalid traffic envelope');
  const ids = new Set();
  value.events.forEach(e=>{
    if(!referenceExactKeys(e,['id','observed_at','src_ip','dst_ip','protocol','src_port','dst_port','tcp_flags','byte_count','run_id','source','run_status','termination_reason'])
      || !roomId(e.id) || ids.has(e.id) || !roomId(e.run_id) || !roomStamp(e.observed_at)
      || ![e.src_ip,e.dst_ip].every(ip=>typeof ip==='string' && ip.length<=45 && /^[0-9a-f:.]+$/i.test(ip))
      || !roomProtocols.includes(e.protocol) || !['jsonl','scapy'].includes(e.source)
      || !['running','completed','incomplete','failed'].includes(e.run_status)
      || ![null,'source_exhausted','event_limit_reached','failed','interrupted'].includes(e.termination_reason)
      || ![e.src_port,e.dst_port].every(p=>p===null || (Number.isInteger(p)&&p>=0&&p<=65535))
      || !Array.isArray(e.tcp_flags) || e.tcp_flags.length>8 || new Set(e.tcp_flags).size!==e.tcp_flags.length || !e.tcp_flags.every(f=>roomFlags.includes(f))
      || typeof e.byte_count!=='string' || !/^(0|[1-9][0-9]{0,18})$/.test(e.byte_count) || BigInt(e.byte_count)>9223372036854775807n) throw new Error('Invalid event');
    ids.add(e.id);
  });
  const findings = new Set();
  value.findings.forEach(f=>{
    if(!referenceExactKeys(f,['id','event_id','detected_at','rule_id','severity','detector_version']) || !roomId(f.id) || findings.has(f.id) || !ids.has(f.event_id)
      || !roomStamp(f.detected_at) || !roomRules.includes(f.rule_id) || !knownSeverities.has(f.severity)
      || f.detector_version!=='unknown; not stored on historical finding') throw new Error('Invalid finding');
    findings.add(f.id);
  });
  const times=value.events.map(e=>e.observed_at).sort();
  if(value.window.start!==(times[0]||null) || value.window.end!==(times.at(-1)||null) || (value.status==='available')!==(value.events.length>0)) throw new Error('Invalid coverage');
  return value;
}
function roomSelection(snapshot, range, custom, now=Date.now()) {
  let start,end;
  if(range==='recorded') { end=snapshot?.window.end ? Date.parse(snapshot.window.end) : now; start=Math.max(end-31*86400000,snapshot?.window.start ? Date.parse(snapshot.window.start) : end); }
  else if(range==='now') {end=now;start=end-300000;}
  else if(range==='hour') {end=now;start=end-3600000;}
  else if(range==='today') {end=now;start=Date.parse(new Date(now).toISOString().slice(0,10)+'T00:00:00Z');}
  else if(range==='custom' && custom) {start=custom.start;end=custom.end;}
  else throw new Error('Choose a valid time range.');
  if(!Number.isFinite(start)||!Number.isFinite(end)||start>end||end-start>31*86400000||(range!=='recorded' && end>now+60000)) throw new Error('Choose an ordered UTC range of at most 31 days, ending no later than now.');
  const events=(snapshot?.events||[]).filter(e=>Date.parse(e.observed_at)>=start&&Date.parse(e.observed_at)<=end);
  const ids=new Set(events.map(e=>e.id));
  const findings=(snapshot?.findings||[]).filter(f=>ids.has(f.event_id)&&Date.parse(f.detected_at)>=start&&Date.parse(f.detected_at)<=end);
  return {start,end,events,findings};
}
function roomCounts(values) {const counts=new Map();values.forEach(v=>counts.set(v,(counts.get(v)||0)+1));return [...counts].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0])).slice(0,10);}
function roomEndpoint(address,port) {return port===null?address:`${address.includes(':')?`[${address}]`:address}:${port}`;}
function roomMeta(selection) {
  const value=roomState.snapshot;
  return `${new Date(selection.start).toISOString()} → ${new Date(selection.end).toISOString()} · source: ${[...new Set(selection.events.map(e=>e.source))].join(', ')||'unavailable'} · vantage: unknown · last update: ${value?.generated_at||'unavailable'} · unit: metadata events / reported bytes · quality: ${roomState.failed?'stale':value?.quality||'unavailable'} · bounded candidate window (top lists omit lower-ranked rows)`;
}
function roomVisual(parent,title,selection) {
  const article=textNode('article','','room-visual'); article.append(textNode('h3',title),textNode('p',roomMeta(selection),'room-meta')); parent.append(article);return article;
}
function roomBars(parent,rows,unit='events') {
  if(!rows.length) {parent.append(textNode('p','No qualified data available in this time range. Use Help to select or import authorized metadata.','room-empty'));return;}
  const list=textNode('ul','','room-bars'),max=Math.max(...rows.map(r=>r[1]));
  rows.forEach(([label,count])=>{const item=textNode('li'),meter=document.createElement('meter');meter.min=0;meter.max=max;meter.value=count;meter.setAttribute('aria-label',`${label}: ${count} ${unit}`);item.append(textNode('span',label),textNode('strong',`${count}`),meter);list.append(item);});parent.append(list);
}
function roomTimeline(parent,selection,rows,stamp) {
  if(!rows.length){roomBars(parent,[]);return;}
  const bins=Array.from({length:12},()=>0),span=Math.max(1,selection.end-selection.start);
  rows.forEach(row=>bins[Math.min(11,Math.floor((Date.parse(row[stamp])-selection.start)/span*12))]++);
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 480 140');svg.setAttribute('role','img');svg.setAttribute('aria-label',`12 equal time bins, metadata record counts: ${bins.join(', ')}. Gaps do not prove no traffic.`);
  const max=Math.max(1,...bins);
  bins.forEach((count,i)=>{const bar=document.createElementNS(svg.namespaceURI,'rect');bar.setAttribute('x',String(i*40+4));bar.setAttribute('y',String(115-count/max*105));bar.setAttribute('width','30');bar.setAttribute('height',String(count/max*105));svg.append(bar);const label=document.createElementNS(svg.namespaceURI,'text');label.setAttribute('x',String(i*40+8));label.setAttribute('y','134');label.textContent=String(count);svg.append(label);});parent.append(svg);
  parent.append(textNode('p','12 equal time bins, left to right. An empty bin means no returned records; sensor gaps and drops are unknown.','room-meta'));
}
const roomReportFields = ['schema','generated_at','title','range','sources','vantage','quality','freshness','unit','counts','findings','limitations','build'];
const roomReportLimitations = [
  'Saved metadata only; no packet bodies, raw logs, messages, model output, addresses, ports, IDs, or commands.',
  'Source authenticity, sensor health, installed-tool qualification, drops, and whole-network completeness remain unknown.',
  'Direction, local-subnet scope, connection state, and observed service identities are unavailable.',
  'Counts cover only the validated events in the selected bounded range.',
  'A missing finding or empty range does not prove safety or absence of traffic.',
  'Imported source labels are provenance, not independent authentication.',
  'This report was created locally in the browser and was not uploaded by MEGALODON.'
];
function roomReportDocument(now=Date.now()) {
  const snapshot=roomState.snapshot,selection=roomState.selection;
  if(!snapshot || !selection || !selection.events.length) throw new Error('No qualified data is available in the selected range. No report was created.');
  const findings=new Map();
  selection.findings.forEach(item=>{
    const key=item.rule_id+'\n'+item.severity;
    findings.set(key,(findings.get(key)||0)+1);
  });
  const document={
    schema:'megalodon-local-report-v1',
    generated_at:new Date(now).toISOString(),
    title:'MEGALODON local metadata report',
    range:{start:new Date(selection.start).toISOString(),end:new Date(selection.end).toISOString()},
    sources:[...new Set(selection.events.map(item=>item.source))].sort(),
    vantage:'unknown',
    quality:snapshot.quality,
    freshness:roomState.failed || now-Date.parse(snapshot.generated_at)>300000 ? 'stale' : 'current_by_five_minute_ui_threshold',
    unit:'metadata events / linked findings / reported bytes',
    counts:{
      events:selection.events.length,
      findings:selection.findings.length,
      reported_bytes:selection.events.reduce((sum,item)=>sum+BigInt(item.byte_count),0n).toString()
    },
    findings:[...findings].sort((a,b)=>a[0].localeCompare(b[0])).map(([key,count])=>{
      const [rule_id,severity]=key.split('\n');return {rule_id,severity,count};
    }),
    limitations:[...roomReportLimitations],
    build:{
      package_version:snapshot.build.package_version,
      base_commit:snapshot.build.base_commit,
      projection_sha256:snapshot.build.projection_sha256,
      commit:snapshot.build.commit
    }
  };
  if(!referenceExactKeys(document,roomReportFields)
      || !referenceExactKeys(document.range,['start','end'])
      || !referenceExactKeys(document.counts,['events','findings','reported_bytes'])
      || !referenceExactKeys(document.build,['package_version','base_commit','projection_sha256','commit'])
      || document.findings.some(item=>!referenceExactKeys(item,['rule_id','severity','count']))) throw new Error('The local report contract could not be satisfied.');
  const json=JSON.stringify(document,null,2)+'\n';
  if(new TextEncoder().encode(json).byteLength>65536) throw new Error('The local report exceeded its 64 KiB limit. No report was created.');
  return {document,json};
}
function invalidateRoomReport() {
  roomState.report=null;
  byId('room-report-download').disabled=true;
  const preview=byId('room-report-preview');preview.replaceChildren();preview.hidden=true;
  byId('room-report-status').textContent=roomState.selection && roomState.selection.events.length
    ? 'No preview is ready. Preview the current selected range before downloading.'
    : 'No qualified data is available in the selected range. No report can be created.';
}
function previewRoomReport() {
  try {
    const report=roomReportDocument();roomState.report=report;
    const preview=byId('room-report-preview');preview.replaceChildren(textNode('code',report.json));preview.hidden=false;
    byId('room-report-download').disabled=false;
    byId('room-report-status').textContent='Preview ready in this browser. Review it, then download explicitly.';
    return true;
  } catch(_) {
    roomState.report=null;byId('room-report-download').disabled=true;
    const preview=byId('room-report-preview');preview.replaceChildren();preview.hidden=true;
    byId('room-report-status').textContent='No qualified data is available in the selected range. No report was created.';
    return false;
  }
}
function downloadRoomReport() {
  if(!roomState.report) {byId('room-report-status').textContent='Preview the current selected range before downloading.';return false;}
  const url=URL.createObjectURL(new Blob([roomState.report.json],{type:'application/json'}));
  const link=document.createElement('a');
  link.href=url;link.download='megalodon-local-report-'+roomState.report.document.generated_at.replace(/[:.]/g,'-')+'.json';
  link.click();setTimeout(()=>URL.revokeObjectURL(url),0);
  byId('room-report-status').textContent='Local JSON download requested. MEGALODON did not upload it.';
  return true;
}
function renderRoom() {
  let selected;
  try {selected=roomSelection(roomState.snapshot,roomState.range,roomState.custom);} catch(error) {byId('room-notice').textContent=error.message;return;}
  roomState.selection=selected;
  const snapshot=roomState.snapshot,has=selected.events.length>0;
  const stale=roomState.failed || (snapshot && Date.now()-Date.parse(snapshot.generated_at)>300000);
  const old=has && Date.now()-Math.max(...selected.events.map(e=>Date.parse(e.observed_at)))>300000;
  const future=has && selected.events.some(e=>Date.parse(e.observed_at)>Date.now()+60000);
  const needs=stale||old||future||snapshot?.quality==='degraded'||selected.findings.length>0;
  byId('room-overall').textContent=!snapshot||snapshot.status==='unavailable'?'Not Ready':needs?'Needs Attention':'Unknown';
  byId('room-connection').textContent=roomState.connected===true?'Connected · read-only':roomState.connected===false?(snapshot?'Unavailable · preserved view':'Unavailable'):'Not checked';
  byId('room-coverage').textContent=stale?'Stale':future?'Clock uncertain':has?'Partial · quality unknown':'Unavailable';
  byId('room-updated').textContent=snapshot?.generated_at||'Not fetched';
  byId('room-sources').textContent=has?'Unknown · '+new Set(selected.events.map(e=>e.source)).size+' stored source types':'Unknown';
  byId('room-count').textContent=has?`${selected.findings.length} in returned set`:'Unavailable';
  const note=stale?(snapshot?'Refresh failed or snapshot expired. Preserved metadata is stale.':'No qualified data available. The metadata check failed; use Help for the safe next step.'):!has?'No qualified data available in this time range.':future?'Clock uncertainty: future timestamps are present.':old?'Historical metadata only. Current sensor activity is unknown.':'Showing saved metadata. Sensor health and full coverage are unknown.';
  byId('room-notice').textContent=note;
  byId('room-home-summary').textContent=has?`${selected.events.length} stored metadata events and ${selected.findings.length} linked findings are available. ${note}`:note+' Open Help for the safe next command.';
  byId('room-range-description').textContent=roomMeta(selected);
  const grid=byId('room-traffic-grid');grid.replaceChildren();
  let panel=roomVisual(grid,'Traffic volume over time',selected);roomTimeline(panel,selected,selected.events,'observed_at');
  if(has) panel.append(textNode('p',`${selected.events.reduce((sum,e)=>sum+BigInt(e.byte_count),0n)} reported bytes in this returned set. No packets-per-second or link-speed claim.`,'room-meta'));
  panel=roomVisual(grid,'Protocol mix',selected);roomBars(panel,roomCounts(selected.events.map(e=>e.protocol)));panel.append(textNode('p','Recorded labels only. A port number does not prove DNS, HTTP or TLS.','room-meta'));
  panel=roomVisual(grid,'Inbound, outbound and internal',selected);panel.append(textNode('p','Unavailable — no qualified local-subnet or sensor-vantage contract. Private addresses alone do not establish direction.','room-empty'));
  panel=roomVisual(grid,'Top observed endpoints',selected);roomBars(panel,roomCounts(selected.events.flatMap(e=>[e.src_ip,e.dst_ip])),'endpoint appearances');panel.append(textNode('p','Which endpoints are local is unknown. Each event contributes both endpoint appearances.','room-meta'));
  panel=roomVisual(grid,'Top conversations',selected);roomBars(panel,roomCounts(selected.events.map(e=>`${roomEndpoint(e.src_ip,e.src_port)} → ${roomEndpoint(e.dst_ip,e.dst_port)} · ${e.protocol}`)));
  panel=roomVisual(grid,'Ports and connection indicators',selected);roomBars(panel,roomCounts(selected.events.map(e=>`${e.protocol} / source ${e.src_port===null?'not recorded':e.src_port}`)));roomBars(panel,roomCounts(selected.events.map(e=>`${e.protocol} / destination ${e.dst_port===null?'not recorded':e.dst_port}`)));roomBars(panel,roomCounts(selected.events.filter(e=>e.protocol==='TCP').map(e=>'Flags: '+(e.tcp_flags.join(', ')||'none recorded'))));panel.append(textNode('p','TCP flags are indicators; connection state and actual service identity are unavailable.','room-meta'));
  panel=roomVisual(grid,'Source → destination → protocol / port',selected);const flow=textNode('div','','room-flow');roomCounts(selected.events.map(e=>`${roomEndpoint(e.src_ip,e.src_port)} → ${roomEndpoint(e.dst_ip,e.dst_port)} → ${e.protocol}`)).slice(0,8).forEach(([label,count])=>flow.append(textNode('p',`${label} · ${count} events`)));panel.append(flow);if(!has)roomBars(panel,[]);
  panel=roomVisual(grid,'Coverage and gaps',selected);panel.append(textNode('p',`Candidate window limited: ${snapshot?.truncated?'Yes':'Unknown beyond returned window'}. Excluded sample/unlinked/legacy/held event candidates: ${snapshot?snapshot.excluded_event_candidates:'Unknown'}. Drops: Unknown. Rejected records: Unknown. Missing intervals: Unknown. Clock accuracy: Unknown.`,'room-meta'));
  const findings=byId('room-findings-visual');findings.replaceChildren();panel=roomVisual(findings,'Findings over time',selected);roomTimeline(panel,selected,selected.findings,'detected_at');panel=roomVisual(findings,'Detector and severity',selected);roomBars(panel,roomCounts(selected.findings.map(f=>`${f.rule_id} · ${f.severity}`)),'findings');
  const tableRoot=byId('room-findings-table');tableRoot.replaceChildren();tableRoot.setAttribute('tabindex','0');tableRoot.setAttribute('role','region');tableRoot.setAttribute('aria-label','Scrollable qualified findings');
  const table=textNode('table'),caption=textNode('caption','Qualified findings in the shared time range');table.append(caption);const head=textNode('tr');['Time','Detector','Severity','Finding / event ID','Detector version'].forEach(label=>{const th=textNode('th',label);th.scope='col';head.append(th);});const thead=textNode('thead');thead.append(head);table.append(thead);const body=textNode('tbody');selected.findings.forEach(f=>{const row=textNode('tr');[f.detected_at,f.rule_id,f.severity,`${f.id} / ${f.event_id}`,f.detector_version].forEach(value=>row.append(textNode('td',value)));body.append(row);});table.append(body);tableRoot.append(table);if(!selected.findings.length)tableRoot.append(textNode('p',has?'No linked findings in this bounded set. This does not prove no threat.':'No qualified data available.','room-empty'));
  if(typeof invalidateRoomReport==='function')invalidateRoomReport();
}
async function refreshRoom() {
  if(roomState.busy)return;roomState.busy=true;byId('room-refresh').disabled=true;
  try {
    const response=await fetch('/api/traffic',{method:'GET',cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(3000)});
    const reader=response.body?.getReader();if(!reader)throw new Error('Unavailable');let bytes=0,chunks=[];
    while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>262144){await reader.cancel();throw new Error('Oversized');}chunks.push(value);}
    const merged=new Uint8Array(bytes);let offset=0;chunks.forEach(chunk=>{merged.set(chunk,offset);offset+=chunk.length;});
    const snapshot=validateTraffic(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(merged)));
    if(!response.ok && !(response.status===503 && snapshot.status==='unavailable')) throw new Error('Unavailable');
    roomState.snapshot=snapshot;roomState.failed=false;roomState.connected=true;
  } catch(_) {roomState.failed=true;roomState.connected=false;} finally {roomState.busy=false;byId('room-refresh').disabled=false;renderRoom();}
}
byId('room-range').addEventListener('change',()=>{const custom=byId('room-range').value==='custom';byId('room-start-label').hidden=!custom;byId('room-end-label').hidden=!custom;});
byId('room-apply').addEventListener('click',()=>{try{const range=byId('room-range').value;const custom=range==='custom'?{start:Date.parse(byId('room-start').value+'Z'),end:Date.parse(byId('room-end').value+'Z')}:null;roomSelection(roomState.snapshot,range,custom);roomState.range=range;roomState.custom=custom;renderRoom();}catch(error){byId('room-notice').textContent=error.message;}});
byId('room-refresh').addEventListener('click',refreshRoom);
byId('room-report-create').addEventListener('click',previewRoomReport);
byId('room-report-download').addEventListener('click',downloadRoomReport);
"""
