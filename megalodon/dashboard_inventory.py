"""Shared local/hosted inventory view for automatic local aggregates."""

INVENTORY_HTML = r'''
<section class="inventory-panel" aria-labelledby="inventory-title">
  <h3 id="inventory-title" tabindex="-1">Network inventory</h3>
  <p>Review a completed Nmap report as host and port-state counts. These observations are separate from traffic and detection severity; an open port is not a confirmed threat.</p>
  <p id="inventory-status" role="status">Waiting for local collection.</p>
  <p id="inventory-automation">Automatic results appear in the local HUD. The hosted Console cannot read this PC. <a href="http://127.0.0.1:8787/#inventory-title" target="_blank" rel="noopener noreferrer">Open local HUD ↗</a></p>
  <div id="inventory-results" hidden>
    <p id="inventory-range"></p><p id="inventory-coverage"></p>
    <div class="inventory-grid">
      <section><h4>Hosts reported by Nmap</h4><div id="inventory-hosts"></div></section>
      <section><h4>Protocols · individually listed ports</h4><div id="inventory-protocols"></div></section>
      <section><h4>Individually listed port states</h4><div id="inventory-explicit"></div></section>
      <section><h4>Grouped port states</h4><div id="inventory-grouped"></div></section>
    </div>
    <p>Counts describe a completed observation, not current reachability or complete network coverage. Grouped ports have no protocol breakdown. Source authenticity is unverified.</p>
  </div>
</section>
'''

INVENTORY_CSS = r'''
.inventory-panel{margin:1.5rem 0;padding:1.25rem;border:1px solid #355266;border-radius:12px;background:#0c1925;color:#e6f1f6;font-size:1rem}
.inventory-panel h3{font-size:1.3rem;margin:0 0 .6rem}.inventory-panel h4{font-size:1rem;margin:.5rem 0}
.inventory-panel p{line-height:1.55}
.inventory-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1.25rem}
.inventory-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.25rem .5rem;margin:.8rem 0;font-size:.875rem}.inventory-row meter{grid-column:1/-1;width:100%;height:1rem;accent-color:#40c9d6}
.inventory-panel :focus-visible{outline:3px solid #7be7f0;outline-offset:3px}@media(max-width:700px){.inventory-grid{grid-template-columns:1fr}}
'''

INVENTORY_JS = r'''
function validateInventorySummary(text, now=Date.now()) {
  const fail=()=>{throw new Error('Unsupported inventory summary. Export a completed report with megalodon.nmap_inventory.');};
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>4096)fail();
  let data;
  try {
    const keys=new Set();
    for(const token of text.match(/"(?:\\.|[^"\\])*"\s*:/g)||[]) {
      const key=JSON.parse(token.slice(0,token.lastIndexOf(':')).trim());if(keys.has(key))fail();keys.add(key);
    }
    data=JSON.parse(text);
  } catch { fail(); }
  const keys=['schema','started_at','finished_at','hosts','represented_hosts','explicit_states','grouped_states','protocols'];
  if(!data||Array.isArray(data)||Object.keys(data).length!==keys.length||!keys.every(k=>Object.hasOwn(data,k))||data.schema!=='megalodon-nmap-inventory-v1')fail();
  const stamp=value=>{
    if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value))fail();
    const n=Date.parse(value);if(!Number.isFinite(n)||new Date(n).toISOString().slice(0,19)+'Z'!==value||n>now+60000)fail();return n;
  };
  if(stamp(data.started_at)>stamp(data.finished_at))fail();
  const sum=values=>values.reduce((a,b)=>a+b,0);
  for(const [key,length] of [['hosts',2],['represented_hosts',2],['explicit_states',6],['grouped_states',6],['protocols',3]]) {
    if(!Array.isArray(data[key])||data[key].length!==length||!data[key].every(n=>Number.isInteger(n)&&n>=0&&n<=1000000)||sum(data[key])>1000000)fail();
  }
  if(sum(data.represented_hosts)>4096||data.represented_hosts.some((n,i)=>n>data.hosts[i])||sum(data.explicit_states)!==sum(data.protocols)||sum(data.explicit_states)+sum(data.grouped_states)>1000000||sum(data.represented_hosts)===0&&(sum(data.protocols)+sum(data.grouped_states)>0))fail();
  return data;
}
if(typeof module!=='undefined')module.exports={validateInventorySummary};
if(typeof document!=='undefined'&&document.getElementById('inventory-title')) {
  const node=id=>document.getElementById(id);
  const states=['Open','Closed','Filtered','Unfiltered','Open or filtered','Closed or filtered'];
  function chart(id,labels,values) {
    const root=node(id);root.replaceChildren();const peak=Math.max(1,...values);
    labels.forEach((label,i)=>{const row=document.createElement('div');row.className='inventory-row';const name=document.createElement('span');name.textContent=label;const count=document.createElement('b');count.textContent=String(values[i]);const bar=document.createElement('meter');bar.min=0;bar.max=peak;bar.value=values[i];bar.setAttribute('aria-label',`${label}: ${values[i]}; chart maximum ${peak}`);row.append(name,count,bar);root.append(row);});
  }
  function applyInventory(data, source='Saved inventory') {
    data=validateInventorySummary(JSON.stringify(data));
    chart('inventory-hosts',['Up','Down'],data.hosts);chart('inventory-protocols',['TCP','UDP','SCTP'],data.protocols);
    chart('inventory-explicit',states,data.explicit_states);chart('inventory-grouped',states,data.grouped_states);
    node('inventory-range').textContent=`Report interval: ${data.started_at} → ${data.finished_at}`;
    node('inventory-coverage').textContent=`Host detail present: ${data.represented_hosts[0]} up / ${data.represented_hosts[1]} down. Report totals can include hosts whose detail was omitted.`;
    node('inventory-status').textContent=`${source} · completed ${data.finished_at}. Not live.`;
    node('inventory-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).nmap=applyInventory;

}
'''
