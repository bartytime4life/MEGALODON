"""Presentation for the read-only local PC sampler. Hosted markup is inert."""

HOST_TELEMETRY_HTML = r'''
<section class="pc-live" id="pc-live" aria-labelledby="pc-live-title">
  <header class="pc-live-head"><div><p class="eyebrow">THIS PC / LIVE RESOURCES</p><h3 id="pc-live-title" tabindex="-1">Live PC resources</h3><p>MEGALODON and companion activity, alongside this computer’s network use.</p></div>
    <div class="pc-live-controls"><span class="pc-status" id="pc-status" data-state="waiting" role="status">Connecting</span><button type="button" id="pc-pause" aria-pressed="false">Pause live view</button></div>
  </header>
  <p class="pc-caption" id="pc-freshness">Waiting for the first local observation.</p>
  <div class="pc-main-grid">
    <section class="pc-resources" aria-labelledby="pc-resources-title"><h4 id="pc-resources-title">MEGALODON + companions</h4>
      <div class="pc-gauges">
        <div class="pc-gauge"><svg viewBox="0 0 120 120" aria-hidden="true"><circle class="pc-gauge-track" cx="60" cy="60" r="50"/><circle id="pc-cpu-arc" class="pc-gauge-value" cx="60" cy="60" r="50" pathLength="100" stroke-dasharray="0 100"/></svg><div class="pc-gauge-label"><strong id="pc-suite-cpu">—</strong><span>CPU capacity</span></div></div>
        <div class="pc-gauge pc-gauge-memory"><svg viewBox="0 0 120 120" aria-hidden="true"><circle class="pc-gauge-track" cx="60" cy="60" r="50"/><circle id="pc-memory-arc" class="pc-gauge-value" cx="60" cy="60" r="50" pathLength="100" stroke-dasharray="0 100"/></svg><div class="pc-gauge-label"><strong id="pc-suite-memory">—</strong><span>RAM capacity</span></div></div>
      </div>
      <p class="pc-resource-total" id="pc-suite-detail">Resource readings unavailable.</p>
      <div class="pc-machine"><span>Whole PC CPU</span><strong id="pc-system-cpu">—</strong><span>Whole PC RAM</span><strong id="pc-system-memory">—</strong></div>
      <div class="pc-cpu-trend-head"><h5>CPU over time</h5><p><span class="pc-legend-rx">MEGALODON + companions</span> · <span class="pc-legend-tx">Whole PC</span></p></div><div id="pc-cpu-chart" class="pc-chart pc-chart-compact"><p class="pc-empty">Waiting for two CPU observations.</p></div>
    </section>
    <section class="pc-network" aria-labelledby="pc-network-title"><div class="pc-section-head"><h4 id="pc-network-title">Network activity</h4><label for="pc-interface">Interface <select id="pc-interface" disabled><option value="">Waiting</option></select></label></div>
      <div class="pc-network-rates"><div><span class="pc-legend-rx">↓ Receive</span><strong id="pc-rx">—</strong></div><div><span class="pc-legend-tx">↑ Send</span><strong id="pc-tx">—</strong></div></div>
      <div id="pc-network-chart" class="pc-chart"><p class="pc-empty">Waiting for two rate observations to draw a trend.</p></div>
      <p class="pc-caption" id="pc-network-detail">Rates are measured for one interface at a time.</p>
    </section>
  </div>
  <div class="pc-secondary-grid">
    <section class="pc-apps" aria-labelledby="pc-apps-title"><h4 id="pc-apps-title">What is using resources?</h4><div class="pc-table-scroll" tabindex="0" role="region" aria-label="Per-app CPU, memory and disk activity"><table><thead><tr><th scope="col">App</th><th scope="col">Processes</th><th scope="col">CPU</th><th scope="col">RAM</th><th scope="col">Disk read / s</th><th scope="col">Disk write / s</th></tr></thead><tbody id="pc-apps-body"><tr><td colspan="6">Waiting for process observations.</td></tr></tbody></table></div><p class="pc-caption" id="pc-process-coverage">Process visibility is being checked.</p></section>
    <section class="pc-sockets" aria-labelledby="pc-sockets-title"><h4 id="pc-sockets-title">Connections on this PC</h4><div class="pc-socket-totals"><div><strong id="pc-tcp">—</strong><span>TCP sockets</span></div><div><strong id="pc-udp">—</strong><span>UDP sockets</span></div></div><dl class="pc-state-list"><div><dt>Established TCP</dt><dd id="pc-established">—</dd></div><div><dt>Listening TCP</dt><dd id="pc-listening">—</dd></div><div><dt>TCP time wait</dt><dd id="pc-time-wait">—</dd></div></dl><details><summary>Most connected remote addresses</summary><ol id="pc-peers"><li>No observation yet.</li></ol></details></section>
  </div>
  <details class="pc-scope"><summary>What these readings tell you</summary><p>Read-only Linux measurements every 2 seconds, with up to 10 minutes of history held in memory. CPU percentages use whole-PC capacity. RAM is resident memory; shared pages can appear in multiple processes. Companion rows include all recognized instances on this PC.</p><p>Receive and send rates belong to the selected interface. Bridges and VPNs can count the same traffic again. Socket counts describe connections, not the protocol share of captured bytes. Comparing resource and network activity can help investigate load; it does not prove traffic caused it. GPU use and network bytes per app are not measured.</p><p>Pause stops this view’s refresh. Local collection continues while the HUD runs. Traffic metadata and detection charts below use their own saved evidence and selected time range.</p><ul id="pc-notes"></ul></details>
</section>
'''

HOST_TELEMETRY_HOSTED_HTML = r'''
<section class="pc-hosted" aria-labelledby="pc-hosted-title"><p class="panel-kicker">AUTOMATIC ON YOUR LINUX PC</p><h2 id="pc-hosted-title">Live resources. Clearer network activity.</h2><p>The local HUD shows MEGALODON and companion CPU / RAM gauges, per-app disk activity, receive / send trends and connection counts. Its local collector needs no account, API key or uploaded report.</p><p>Open the local HUD using the launch link above. Measurements stay on your computer; this hosted view has no live PC connection.</p></section>
'''

HOST_TELEMETRY_CSS = r'''
.pc-live { --pc-cyan:#75e6e1; --pc-amber:#e9bc6b; margin:1.5rem 0 2rem; border:1px solid #3b5b6a; border-top:3px solid var(--pc-cyan); background:#0c1a25; color:#e5f0f6; padding:1.25rem; border-radius:8px; min-width:0; }
.pc-live h3,.pc-live h4 { margin:0; } .pc-live h3 { font-size:1.4rem; letter-spacing:-.025em; } .pc-live h4 { font-size:1rem; }
.pc-live-head,.pc-section-head { display:flex; align-items:flex-start; justify-content:space-between; gap:1rem; flex-wrap:wrap; }
.pc-live-head p { margin:.5rem 0; max-width:64ch; color:#bdceda; } .pc-live-head .eyebrow { color:var(--pc-cyan); }
.pc-live-controls { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; } .pc-status { font-size:.875rem; font-weight:700; padding:.4rem .6rem; border:1px solid #647888; color:#cfdae3; }
.pc-status[data-state="live"] { border-color:#427c71; color:#a6f4d7; } .pc-status[data-state="stale"],.pc-status[data-state="unavailable"] { border-color:#90743f; color:#f2ce8b; }
.pc-live button,.pc-live select { background:#162c3b; color:#edf6fb; border:1px solid #527081; border-radius:4px; padding:.6rem .8rem; font:inherit; min-height:44px; max-width:100%; }
.pc-live button { cursor:pointer; } .pc-live button:hover { background:#213f51; } .pc-live button:active { background:#2a5263; }
.pc-live :is(button,select,summary,[tabindex]):focus-visible { outline:3px solid var(--pc-cyan); outline-offset:3px; }
.pc-live select:disabled { opacity:.65; } .pc-live summary { cursor:pointer; padding:.7rem 0; min-height:44px; line-height:1.5; }
.pc-caption { font-size:.875rem; line-height:1.6; color:#b4c8d5; overflow-wrap:anywhere; } .pc-live > .pc-caption { margin:.5rem 0 1.25rem; }
.pc-main-grid { display:grid; grid-template-columns:minmax(250px,.8fr) minmax(0,1.4fr); gap:1.5rem; }
.pc-resources { padding-right:1.5rem; border-right:1px solid #2c4555; } .pc-gauges { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,8.5rem),1fr)); gap:1rem; max-width:370px; margin:1.2rem auto .5rem; }
.pc-gauge { position:relative; width:100%; aspect-ratio:1; } .pc-gauge svg { width:100%; height:100%; overflow:visible; transform:rotate(-90deg); }
.pc-gauge circle { fill:none; stroke-width:5; } .pc-gauge-track { stroke:#293f4e; } .pc-gauge-value { stroke:var(--pc-cyan); stroke-linecap:round; transition:stroke-dasharray .5s ease; } .pc-gauge-memory .pc-gauge-value { stroke:var(--pc-amber); }
.pc-gauge-label { position:absolute; inset:0; display:flex; flex-direction:column; justify-content:center; align-items:center; padding:1rem; gap:.2rem; }
.pc-gauge-label strong { font-size:clamp(1.4rem,2.4vw,2rem); font-variant-numeric:tabular-nums; letter-spacing:-.05em; }
.pc-gauge-label span { font-size:.875rem; color:#bfd0dc; text-align:center; } .pc-resource-total { text-align:center; font-size:.875rem; color:#c3d8e3; }
.pc-machine { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.2fr); font-size:.875rem; border-top:1px solid #2c4555; padding-top:.9rem; gap:.65rem; } .pc-machine span { color:#b8cbd7; } .pc-machine strong { text-align:right; overflow-wrap:anywhere; }
.pc-section-head label { display:flex; align-items:center; gap:.5rem; font-size:.875rem; flex-wrap:wrap; }
.pc-network-rates { display:flex; gap:2rem; margin:1rem 0; flex-wrap:wrap; } .pc-network-rates div { display:flex; flex-direction:column; gap:.3rem; }
.pc-network-rates strong { font-size:1.6rem; font-variant-numeric:tabular-nums; } .pc-network-rates span { font-size:.875rem; font-weight:600; }
.pc-legend-rx { color:var(--pc-cyan); } .pc-legend-tx { color:var(--pc-amber); } .pc-chart { min-height:160px; } .pc-chart svg { width:100%; height:160px; display:block; overflow:visible; }
.pc-chart-grid { stroke:#2c4555; stroke-width:1; } .pc-chart-rx,.pc-chart-tx { fill:none; stroke:var(--pc-cyan); stroke-width:2; vector-effect:non-scaling-stroke; } .pc-chart-tx { stroke:var(--pc-amber); stroke-dasharray:5 3; }
.pc-cpu-trend-head { margin-top:1.2rem; } .pc-cpu-trend-head h5 { font-size:.875rem; margin:0 0 .4rem; } .pc-cpu-trend-head p { font-size:.875rem; margin:.3rem 0; line-height:1.5; } .pc-chart-compact { min-height:100px; } .pc-chart-compact svg { height:100px; } .pc-chart-scale { font-size:.875rem; color:#bfd0dc; margin:.4rem 0; }
.pc-chart text { fill:#bfd0dc; font:12px sans-serif; } .pc-chart-axis { display:flex; justify-content:space-between; color:#bdceda; font-size:.875rem; gap:1rem; }
.pc-empty { border:1px dashed #486271; padding:2rem 1rem; color:#c0d2df; margin:.5rem 0; font-size:.875rem; line-height:1.6; }
.pc-secondary-grid { display:grid; grid-template-columns:minmax(0,1.7fr) minmax(220px,.7fr); border-top:1px solid #2c4555; margin-top:1.5rem; padding-top:1.5rem; gap:1.5rem; }
.pc-table-scroll { max-width:100%; overflow:auto; margin-top:.75rem; } .pc-live table { width:100%; border-collapse:collapse; font-size:.875rem; }
.pc-live td,.pc-live th { text-align:right; padding:.7rem .6rem; border-bottom:1px solid #2c4555; white-space:nowrap; font-variant-numeric:tabular-nums; } .pc-live th { color:#bed2df; font-weight:500; }
.pc-live td:first-child,.pc-live th:first-child { text-align:left; } .pc-live tbody th { color:#edf5f8; font-weight:600; }
.pc-socket-totals { display:flex; gap:2rem; margin:1rem 0; } .pc-socket-totals div { display:flex; flex-direction:column; gap:.3rem; } .pc-socket-totals strong { font-size:1.7rem; font-variant-numeric:tabular-nums; } .pc-socket-totals span { font-size:.875rem; color:#bcd0de; }
.pc-state-list { margin:0; font-size:.875rem; } .pc-state-list div { display:flex; justify-content:space-between; gap:1rem; padding:.5rem 0; border-bottom:1px solid #2c4555; } .pc-state-list dd { margin:0; font-variant-numeric:tabular-nums; }
.pc-sockets summary { font-size:.875rem; } .pc-sockets ol { margin:0; padding-left:1.5rem; font-size:.875rem; overflow-wrap:anywhere; } .pc-sockets li { padding:.35rem 0; }
.pc-scope { margin-top:1rem; border-top:1px solid #2c4555; } .pc-scope p,.pc-scope li { max-width:105ch; color:#baceDB; font-size:.875rem; line-height:1.6; }
.pc-hosted { border-left:3px solid #75e6e1; padding:1rem 1.5rem; margin:1.5rem 0; background:#102633; color:#e5f0f6; } .pc-hosted p { max-width:95ch; line-height:1.6; } .pc-hosted h2 { margin:.4rem 0; }
@media(max-width:980px) { .pc-main-grid,.pc-secondary-grid { grid-template-columns:1fr; } .pc-resources { border-right:0; border-bottom:1px solid #2c4555; padding:0 0 1rem; } .pc-machine { max-width:370px; margin:0 auto; } }
@media(max-width:480px) { .pc-live { padding:.9rem; } .pc-gauges { gap:.5rem; } .pc-gauge-label { padding:.5rem; } .pc-gauge-label span { font-size:.875rem; } .pc-live-controls { width:100%; } .pc-section-head label { width:100%; } .pc-section-head select { min-width:0; flex:1; } }
@media(prefers-reduced-motion:reduce) { .pc-gauge-value { transition:none; } }
'''

HOST_TELEMETRY_JS = r'''
(() => {
  if (typeof localHudLaunch === 'undefined' || !document.getElementById('pc-live')) return;
  const el = id => document.getElementById(id);
  const state = {paused:false, pending:false, payload:null, selected:'', timer:null, controller:null, revision:0, failed:false};
  const number = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
  const metric = value => value === null || number(value);
  const text = value => typeof value === 'string' && value.length <= 512 && !/[\x00-\x1f\x7f]/.test(value);
  const timestamp = value => typeof value === 'string' && value.length <= 40 && /Z$/.test(value) && Number.isFinite(Date.parse(value));
  const object = value => value && typeof value === 'object' && !Array.isArray(value);
  function checked(value) {
    if (!object(value) || value.schema !== 'megalodon-host-telemetry-v1' || !['ready','warming','partial','unavailable'].includes(value.status)
      || !(value.observed_at === null || timestamp(value.observed_at)) || value.interval_seconds !== 2 || value.history_seconds !== 600
      || !object(value.system) || !object(value.suite) || !object(value.network) || !['ready','partial','unavailable'].includes(value.network.status)
      || !object(value.sockets) || !['ready','unavailable'].includes(value.sockets.status) || !object(value.coverage)
      || !Array.isArray(value.apps) || value.apps.length > 10 || !Array.isArray(value.network.interfaces) || value.network.interfaces.length > 64
      || !Array.isArray(value.history) || value.history.length > 300 || !Array.isArray(value.sockets.remote_peers) || value.sockets.remote_peers.length > 10
      || !Array.isArray(value.notes) || value.notes.length > 30 || !value.notes.every(text)) throw Error('Invalid local reading');
    const fields = (item, names) => names.every(name => metric(item[name]));
    const percent = v => metric(v) && (v === null || v <= 100);
    if (!fields(value.system,['cpu_percent','memory_total_bytes','memory_used_bytes','memory_percent'])
      || !fields(value.suite,['cpu_percent','rss_bytes','memory_percent','process_count'])
      || !percent(value.system.cpu_percent) || !percent(value.system.memory_percent) || !percent(value.suite.cpu_percent)) throw Error('Invalid resource reading');
    const interfaces = items => Array.isArray(items) && items.length <= 64 && new Set(items.map(item=>item?.name)).size === items.length
      && items.every(item=>object(item) && text(item.name) && fields(item,['rx_bps','tx_bps']));
    if (!interfaces(value.network.interfaces) || !value.network.interfaces.every(item=>fields(item,['rx_pps','tx_pps','rx_errors','tx_errors','rx_drops','tx_drops']))
      || !value.apps.every(item=>object(item) && text(item.id) && text(item.name) && text(item.io_status) && fields(item,['process_count','cpu_percent','rss_bytes','read_bps','write_bps']) && percent(item.cpu_percent))
      || !fields(value.sockets,['tcp','udp','established','listening','time_wait'])
      || !value.sockets.remote_peers.every(item=>object(item) && text(item.address) && number(item.connections))
      || !value.history.every(item=>object(item) && timestamp(item.observed_at) && fields(item,['system_cpu_percent','suite_cpu_percent','suite_rss_bytes']) && interfaces(item.interfaces))) throw Error('Invalid local detail');
    let previous = -Infinity;
    for (const item of value.history) { const time = Date.parse(item.observed_at); if (time <= previous || (value.observed_at && time > Date.parse(value.observed_at))) throw Error('Invalid observation order'); previous = time; }
    return value;
  }
  const fmt = value => number(value) ? value.toLocaleString(undefined,{maximumFractionDigits:0}) : '—';
  const pct = value => number(value) ? value.toLocaleString(undefined,{maximumFractionDigits:1})+'%' : '—';
  function bytes(value, rate=false) {
    if (!number(value)) return '—';
    const units = ['B','KiB','MiB','GiB','TiB']; let index = 0;
    while (value >= 1024 && index < units.length-1) { value /= 1024; index++; }
    return value.toLocaleString(undefined,{maximumFractionDigits:index ? 1 : 0})+' '+units[index]+(rate?'/s':'');
  }
  const time = value => new Date(value).toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  function node(tag, content, className='') { const item=document.createElement(tag); item.textContent=content; if(className)item.className=className; return item; }
  function status(label, kind) { el('pc-status').textContent=label; el('pc-status').setAttribute('data-state',kind); }
  function gauge(id, value) { el(id).setAttribute('stroke-dasharray',`${number(value)?Math.min(value,100):0} 100`); }
  function clearCurrent() {
    for(const id of ['suite-cpu','suite-memory','system-cpu','system-memory','rx','tx','tcp','udp','established','listening','time-wait']) el('pc-'+id).textContent='—';
    gauge('pc-cpu-arc',null); gauge('pc-memory-arc',null);
    el('pc-suite-detail').textContent='Current resource readings unavailable.';
    el('pc-process-coverage').textContent='Current process coverage unavailable.';
    el('pc-apps-body').replaceChildren(); const row=node('tr',''), cell=node('td','Current app readings unavailable.'); cell.setAttribute('colspan','6'); row.append(cell); el('pc-apps-body').append(row);
    el('pc-peers').replaceChildren(node('li','Current socket readings unavailable.'));
    el('pc-network-detail').textContent='Current interface readings unavailable.';
  }
  function emptyChart(message) { el('pc-network-chart').replaceChildren(node('p',message,'pc-empty')); }
  function plot(payload) {
    const samples=payload.history.map(sample=>({at:Date.parse(sample.observed_at),reading:sample.interfaces.find(item=>item.name===state.selected)}));
    const qualified=samples.filter(item=>number(item.reading?.rx_bps)||number(item.reading?.tx_bps));
    if(qualified.length<2) { emptyChart('Collecting rate observations. The trend appears after two measured intervals.'); return; }
    const start=samples[0].at, end=samples.at(-1).at, max=Math.max(1,...samples.flatMap(item=>[item.reading?.rx_bps,item.reading?.tx_bps]).filter(number));
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'); svg.setAttribute('viewBox','0 0 600 150'); svg.setAttribute('preserveAspectRatio','none'); svg.setAttribute('role','img');
    svg.setAttribute('aria-label',`${state.selected} receive and send rates in bytes per second, ${time(start)} to ${time(end)}. Scale 0 to ${bytes(max,true)}. Gaps indicate unavailable measurements.`);
    const shape=(tag,attrs)=>{ const item=document.createElementNS('http://www.w3.org/2000/svg',tag); for(const [key,value] of Object.entries(attrs))item.setAttribute(key,String(value)); svg.append(item); return item; };
    for(const y of [20,80,140]) shape('line',{x1:5,y1:y,x2:595,y2:y,class:'pc-chart-grid'});
    let isolated=0;
    for(const [key,kind] of [['rx_bps','rx'],['tx_bps','tx']]) {
      let path='', previous=null;
      for(const [index,sample] of samples.entries()) { const value=sample.reading?.[key]; if(!number(value)){previous=null;continue;}
        const x=5+(sample.at-start)/Math.max(1,end-start)*590, y=140-value/max*120;
        const connected=previous!==null && sample.at-previous<=6000,next=samples[index+1];
        if(!connected && !(next && number(next.reading?.[key]) && next.at-sample.at<=6000)){shape('circle',{cx:x,cy:y,r:3,class:'pc-chart-'+kind});isolated++;}
        path+=(connected?'L':'M')+x.toFixed(2)+' '+y.toFixed(2)+' '; previous=sample.at;
      }
      if(path)shape('path',{d:path,class:'pc-chart-'+kind});
    }
    const axis=node('div','','pc-chart-axis'); axis.append(node('span',time(start)),node('span',time(end)));
    el('pc-network-chart').replaceChildren(node('p',`Scale: 0–${bytes(max,true)}${isolated?' · Dots are isolated readings; gaps stay blank.':''}`,'pc-chart-scale'),svg,axis);
  }
  function cpuPlot(payload) {
    const samples=payload.history, valid=samples.filter(sample=>number(sample.system_cpu_percent)||number(sample.suite_cpu_percent));
    const target=el('pc-cpu-chart');
    if(valid.length<2){target.replaceChildren(node('p','Collecting CPU observations. The trend appears after two measured intervals.','pc-empty'));return;}
    const start=Date.parse(samples[0].observed_at),end=Date.parse(samples.at(-1).observed_at);
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 360 100');svg.setAttribute('preserveAspectRatio','none');svg.setAttribute('role','img');
    svg.setAttribute('aria-label',`CPU use from ${time(start)} to ${time(end)}. Cyan: MEGALODON and companions. Dashed amber: whole PC. Scale 0 to 100 percent of whole-PC capacity. Gaps are unavailable.`);
    const shape=(tag,attrs)=>{const item=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value] of Object.entries(attrs))item.setAttribute(key,String(value));svg.append(item);return item;};
    for(const y of [15,50,85])shape('line',{x1:5,y1:y,x2:355,y2:y,class:'pc-chart-grid'});
    let isolated=0;
    for(const [key,kind] of [['system_cpu_percent','tx'],['suite_cpu_percent','rx']]){
      let path='',previous=null;
      for(const [index,sample] of samples.entries()){const value=sample[key],at=Date.parse(sample.observed_at);if(!number(value)){previous=null;continue;}
        const x=5+(at-start)/Math.max(1,end-start)*350,y=85-Math.min(100,value)/100*70;
        const connected=previous!==null&&at-previous<=6000,next=samples[index+1];
        if(!connected && !(next && number(next[key]) && Date.parse(next.observed_at)-at<=6000)){shape('circle',{cx:x,cy:y,r:3,class:'pc-chart-'+kind});isolated++;}
        path+=(connected?'L':'M')+x.toFixed(2)+' '+y.toFixed(2)+' ';previous=at;}
      if(path)shape('path',{d:path,class:'pc-chart-'+kind});
    }
    const axis=node('div','','pc-chart-axis');axis.append(node('span',time(start)),node('span',time(end)));target.replaceChildren(node('p','Scale: 0–100% of PC capacity'+(isolated?' · Dots are isolated readings; gaps stay blank.':''),'pc-chart-scale'),svg,axis);
  }
  function interfaces(payload) {
    const options=payload.network.interfaces;
    if(!options.some(item=>item.name===state.selected)) state.selected=(options.find(item=>item.name!=='lo')||options[0])?.name||'';
    const select=el('pc-interface');
    const names=options.map(item=>item.name).join('\n');
    if(select.dataset.interfaces!==names) { select.replaceChildren(...options.map(item=>{const option=node('option',item.name);option.value=item.name;return option;})); select.dataset.interfaces=names; }
    select.value=state.selected;select.disabled=!options.length;
    const current=options.find(item=>item.name===state.selected);
    el('pc-rx').textContent=bytes(current?.rx_bps,true);el('pc-tx').textContent=bytes(current?.tx_bps,true);
    el('pc-network-detail').textContent=current?`${state.selected} · ${fmt(current.rx_pps)} receive / ${fmt(current.tx_pps)} send packets/s · since the previous observation: ${fmt(current.rx_errors)} receive / ${fmt(current.tx_errors)} send errors; ${fmt(current.rx_drops)} receive / ${fmt(current.tx_drops)} send drops.`:'No interface readings available.';
    plot(payload);
  }
  function render(payload) {
    el('pc-suite-cpu').textContent=pct(payload.suite.cpu_percent);el('pc-suite-memory').textContent=pct(payload.suite.memory_percent);
    gauge('pc-cpu-arc',payload.suite.cpu_percent);gauge('pc-memory-arc',payload.suite.memory_percent);
    el('pc-suite-detail').textContent=`${bytes(payload.suite.rss_bytes)} resident memory · ${fmt(payload.suite.process_count)} recognized processes`;
    el('pc-system-cpu').textContent=pct(payload.system.cpu_percent);el('pc-system-memory').textContent=`${pct(payload.system.memory_percent)} · ${bytes(payload.system.memory_used_bytes)} / ${bytes(payload.system.memory_total_bytes)}`;
    const rows=payload.apps.map(app=>{const row=node('tr',''); const name=node('th',app.name); name.setAttribute('scope','row'); row.append(name,...[fmt(app.process_count),pct(app.cpu_percent),bytes(app.rss_bytes),bytes(app.read_bps,true),bytes(app.write_bps,true)].map(value=>node('td',value)));return row;});
    if(!rows.length) {const row=node('tr',''),cell=node('td','No recognized app processes observed.');cell.setAttribute('colspan','6');row.append(cell);rows.push(row);}
    el('pc-apps-body').replaceChildren(...rows);
    el('pc-process-coverage').textContent=(payload.coverage.processes==='complete'?'Visible process counters read.':'Partial process visibility; inaccessible or changing processes may be missing.')+' A dash means unavailable. Disk counters are not network traffic.';
    for(const [id,key] of [['tcp','tcp'],['udp','udp'],['established','established'],['listening','listening'],['time-wait','time_wait']]) el('pc-'+id).textContent=fmt(payload.sockets[key]);
    el('pc-peers').replaceChildren(...(payload.sockets.remote_peers.length?payload.sockets.remote_peers.map(peer=>node('li',`${peer.address} · ${fmt(peer.connections)} connections`)):[node('li',payload.sockets.status==='ready'?'No remote peer addresses observed.':'Remote peer addresses unavailable.')]));
    el('pc-notes').replaceChildren(...payload.notes.map(note=>node('li',note)));
    interfaces(payload);cpuPlot(payload);
  }
  function age(payload) { return payload.observed_at===null?Infinity:Date.now()-Date.parse(payload.observed_at); }
  function freshness(payload) {
    if(state.failed || payload.status==='unavailable') {status('Unavailable','unavailable');clearCurrent();el('pc-freshness').textContent='Local readings are unavailable. Any trend is retained history; retrying automatically.';return;}
    if (age(payload)>10000 || age(payload)<-5000) { status('Stale','stale'); clearCurrent(); el('pc-freshness').textContent='Latest observation is outside the live window. Any trend is retained history.'; return; }
    const warming=payload.status==='warming';
    status(warming?'Warming up':payload.status==='ready'?'Live':'Partial readings',warming?'waiting':payload.status==='ready'?'live':'waiting');
    el('pc-freshness').textContent=`Observed ${time(payload.observed_at)} · refreshes every 2 seconds · trend holds up to 10 minutes${warming?' · rate measurements need another sample':''}.`;
  }
  function schedule() { clearTimeout(state.timer); if(!state.paused && !document.hidden)state.timer=setTimeout(refresh,2000); }
  async function readBounded(response) {
    if(Number(response.headers?.get('content-length'))>2097152)throw Error('Reading too large');
    if(response.body?.getReader) {const reader=response.body.getReader(), decoder=new TextDecoder();let size=0,body='';
      try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2097152)throw Error('Reading too large');body+=decoder.decode(value,{stream:true});}body+=decoder.decode();return JSON.parse(body);}
      finally {await reader.cancel().catch(()=>{});}
    }
    const body=await response.text(); if(new TextEncoder().encode(body).byteLength>2097152)throw Error('Reading too large');return JSON.parse(body);
  }
  async function refresh() {
    if(state.paused || document.hidden || state.pending)return;
    state.pending=true;const revision=state.revision;state.controller=new AbortController();const timeout=setTimeout(()=>state.controller?.abort(),5000);
    try {
      const response=await fetch('/api/host-telemetry',{cache:'no-store',headers:{'X-Megalodon-Check':'1'},signal:state.controller.signal});
      if(!response.ok)throw Error('Local reading unavailable');
      const payload=checked(await readBounded(response));
      if(revision!==state.revision || state.paused || document.hidden)return;
      state.failed=false;state.payload=payload;render(payload);freshness(payload);
    } catch(_) {
      if(revision!==state.revision || state.paused || document.hidden)return;
      state.failed=true;status('Unavailable','unavailable');clearCurrent();el('pc-freshness').textContent='Local readings could not refresh. Any trend is retained history; retrying automatically.';
      if(!state.payload)emptyChart('The local resource collector is unavailable. The HUD must run with local tool inspection enabled.');
    } finally { clearTimeout(timeout);state.pending=false;state.controller=null;schedule(); }
  }
  el('pc-pause').addEventListener('click',()=>{
    state.paused=!state.paused;state.revision++;clearTimeout(state.timer);state.controller?.abort();
    el('pc-pause').textContent=state.paused?'Resume live view':'Pause live view';el('pc-pause').setAttribute('aria-pressed',String(state.paused));
    if(state.paused){status('Paused','paused');el('pc-freshness').textContent='View paused. Displayed values are retained observations; collection continues locally.';}
    else {status('Connecting','waiting');clearCurrent();refresh();}
  });
  el('pc-interface').addEventListener('change',()=>{state.selected=el('pc-interface').value;if(state.payload){interfaces(state.payload);if(!state.paused)freshness(state.payload);else if(state.failed)clearCurrent();}});
  document.addEventListener('visibilitychange',()=>{
    state.revision++;clearTimeout(state.timer);state.controller?.abort();
    if(document.hidden) {status(state.paused?'Paused':'Hidden tab','paused');el('pc-freshness').textContent='Refresh suspended while this tab is hidden. Displayed values are retained observations.';}
    else if(!state.paused) {status('Connecting','waiting');clearCurrent();refresh();}
  });
  refresh();
})();
'''
