"""Shared local/hosted inventory view for automatic local aggregates."""

INVENTORY_HTML = r'''
<section class="companion-panel inventory-panel" aria-labelledby="inventory-title">
  <div class="companion-head"><div><p class="companion-kicker">NMAP / NETWORK</p><h3 id="inventory-title" tabindex="-1">Network inventory</h3></div><span class="companion-kind">Hosts and ports</span></div>
  <p id="inventory-status" class="companion-state" role="status">No completed local observation shown.</p>
  <p id="inventory-automation" class="companion-collector">Collector status is available in the local HUD.</p>
  <div id="inventory-results" hidden>
    <div class="companion-meta"><p id="inventory-range"></p><p id="inventory-coverage"></p></div>
    <div class="inventory-grid">
      <section><h4>Host state</h4><div id="inventory-hosts"></div></section>
      <section><h4>Listed ports by protocol</h4><div id="inventory-protocols"></div></section>
      <section><h4>Listed port states</h4><div id="inventory-explicit"></div></section>
      <section><h4>Grouped port states</h4><div id="inventory-grouped"></div></section>
    </div>
    <p class="companion-caveat">A completed Nmap count is not current reachability or full network coverage. Open ports are not confirmed threats. Grouped ports have no protocol breakdown; report origin is unverified.</p>
  </div>
  <details class="companion-advisory" id="inventory-advisory-wrap" hidden><summary>Local AI note</summary><p id="inventory-advisory"></p></details>
</section>
'''

INVENTORY_CSS = r'''
.companion-section{margin:2rem 0 1.5rem;color:#e6f1f6}
.companion-section-head{display:flex;align-items:end;justify-content:space-between;gap:1rem;margin-bottom:1rem;padding:0 .15rem}
.companion-section-head h2,.companion-section-head h3{margin:.15rem 0 .35rem;font-size:1.3rem;line-height:1.2;color:#f2f7f9}
.companion-section .companion-section-head p{margin:.25rem 0;max-width:62rem;color:#b7cbd4;font-size:.88rem;line-height:1.5}
.companion-section .companion-section-head .eyebrow{color:#73d7da;font-size:.7rem;font-weight:750;letter-spacing:.12em}
.companion-local-link{display:inline-flex;align-items:center;min-height:44px;padding:.55rem .85rem;border:1px solid #4e8390;border-radius:7px;color:#c1f3ef;white-space:nowrap;text-decoration:none;font-size:.82rem;font-weight:700}
.companion-local-link:hover,.companion-local-link:focus-visible{background:#143541;border-color:#89dbdc}
.companion-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
.companion-panel{min-width:0;padding:1.15rem 1.2rem;border:1px solid #345262;border-left:3px solid #3e9daa;border-radius:10px;background:#0c1c28;box-shadow:0 10px 28px rgba(0,0,0,.12);color:#e6f1f6}
.companion-panel p{line-height:1.5;overflow-wrap:anywhere}
.companion-head{display:flex;align-items:start;justify-content:space-between;gap:.75rem}
.companion-head h3{margin:.1rem 0 .7rem;font-size:1.12rem;line-height:1.25;color:#f2f7f9}
.companion-panel .companion-kicker{margin:0;color:#70ced5;font-size:.67rem;font-weight:750;letter-spacing:.12em}
.companion-kind{border:1px solid #365564;border-radius:4px;padding:.2rem .4rem;color:#acc8d1;font-size:.68rem;line-height:1.25;white-space:nowrap}
.companion-panel .companion-state{display:inline-block;max-width:100%;margin:.25rem 0 .4rem;padding:.38rem .58rem;border:1px solid #665d3e;border-radius:5px;background:#2b281b;color:#ead99e;font-size:.8rem;font-weight:700}
.companion-state[data-state="ready"]{border-color:#387f7f;background:#12383b;color:#bbf0ef}
.companion-state[data-state="checking"]{border-color:#416879;background:#152f3b;color:#c6e7ed}
.companion-panel .companion-collector{margin:.1rem 0 .65rem;color:#bfd0d9;font-size:.79rem}
.companion-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem;margin:.7rem 0}
.companion-panel .companion-meta p{margin:0;padding:.55rem .65rem;border:1px solid #2f4b58;border-radius:6px;background:#0a1922;color:#c5d8de;font-size:.75rem}
.companion-panel .companion-caveat{margin:.75rem 0 0;color:#aebfc8;font-size:.73rem}
.companion-advisory{margin-top:.7rem;border-top:1px solid #304a59;color:#bfd0d9;font-size:.75rem}
.companion-advisory summary{padding:.6rem 0;cursor:pointer}.companion-advisory p{margin:0 0 .4rem}
.companion-section :focus-visible{outline:3px solid #7be7f0;outline-offset:3px}
.inventory-panel{grid-column:1/-1}
.inventory-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.6rem}
.inventory-grid>section{min-width:0;padding:.7rem;border:1px solid #304e5c;border-radius:7px;background:#0a1923}
.inventory-panel h4{margin:0 0 .45rem;color:#cee4e9;font-size:.77rem;line-height:1.3}
.inventory-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.15rem .4rem;margin:.38rem 0;font-size:.72rem}.inventory-row b{color:#d8f7f5}.inventory-row meter{grid-column:1/-1;width:100%;height:.6rem;accent-color:#47c9d4}
@media(max-width:1000px){.inventory-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:700px){.companion-section-head{align-items:start;flex-direction:column}.companion-grid,.companion-meta,.inventory-grid{grid-template-columns:1fr}.companion-local-link{white-space:normal}.companion-panel{padding:1rem}}
@media(prefers-reduced-motion:no-preference){.companion-panel{transition:border-color .2s ease,background-color .2s ease}.companion-panel:hover{border-color:#568493;background:#102330}.inventory-row meter{transition:opacity .2s ease}}
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
    node('inventory-status').textContent=`${source} · saved observation.`;
    node('inventory-status').setAttribute('data-state','ready');
    node('inventory-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).nmap=applyInventory;

}
'''
