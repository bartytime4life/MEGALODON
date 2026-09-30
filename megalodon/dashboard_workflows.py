"""Local-only background workflow presentation over bounded observed status."""
import re

from .dashboard_action_plane import ACTION_HTML
from .dashboard_integrations import INTEGRATIONS_HTML


def local_workflow_script(script: str) -> str:
    """Resolve the current local renderer when shared filter handlers run."""
    return script.replace(
        "addEventListener('input', renderIntegrationMap)",
        "addEventListener('input', () => renderIntegrationMap())",
    ).replace(
        "addEventListener('change', renderIntegrationMap)",
        "addEventListener('change', () => renderIntegrationMap())",
    )


def compose_workflows(html: str) -> str:
    """Keep the shared hosted map unchanged; compose local live rows in its place."""
    source = INTEGRATIONS_HTML
    before, advanced = source.split(ACTION_HTML, 1)
    advanced = ACTION_HTML + advanced
    cards = '<div class="integration-cards" id="integrations-cards" aria-busy="false"></div>'
    advanced = advanced.replace(cards, '')
    moved = []
    for control in ('integrations-query', 'integrations-status-filter'):
        pattern = r'<label class="field" for="' + control + r'">.*?</label>'
        match = re.search(pattern, advanced, re.S)
        if not match:
            raise AssertionError('workflow filter missing')
        moved.append(match.group())
        advanced = advanced.replace(match.group(), '')
    clear = '<button id="integrations-clear" type="button" class="button-secondary">Clear map filters</button>'
    advanced = advanced.replace(clear, '')
    filters = moved[0] + '''<label class="field" for="integrations-status-filter"><span>Workflow status</span><select id="integrations-status-filter"><option value="ALL">All tools</option><option value="connected">Data connected</option><option value="saved_result">Saved result available</option><option value="collecting">Collecting</option><option value="ready">Ready</option><option value="stopped">Configured · stopped</option><option value="standby">Standby alternative</option><option value="needs_setup">Needs setup</option><option value="unavailable">Unavailable</option><option value="error">Error</option></select></label>''' + clear.replace('Clear map filters', 'Clear filters')
    advanced = advanced.replace('id="integrations-status"', 'id="workflow-reference-status"')
    advanced = advanced.replace('<h3 id="support-app-launch-title">Open desktop support apps</h3>', '<h3 id="support-app-launch-title">Optional desktop apps</h3>')
    before = before.replace('Actions &amp; apps', 'Background tools').replace('No profile loaded', 'Local status · not checked')
    before = re.sub(r'(<h2 id="integrations-title".*?</h2>)<p>.*?</p>', r'\1<p>See what each local tool is doing and which data has reached MEGALODON.</p>', before, count=1, flags=re.S)
    local = before + '''
    <nav class="workflow-actions" aria-label="Background tool controls"><a class="companion-button" href="#support-apps-title">Start background tools</a><a href="#support-config-title" id="workflows-configure">Configure apps</a><a href="#live-globe-title">Monitoring start / stop</a><button type="button" id="workflows-refresh">Refresh status</button></nav>
    <p class="workflow-explainer">Normal startup uses background commands. No Wireshark, Zenmap or ClamTk windows open.</p>
    <div class="integration-controls workflow-filters">''' + filters + '''</div>
    <p class="reference-status workflow-status" id="integrations-status" role="status" aria-live="polite" aria-atomic="true">Checking local workflow status…</p>
    ''' + cards + '''
    <p class="workflow-explainer">Sensor counts are bounded source summaries. They are separate from HUD packet totals and admitted detector findings.</p>
    <details class="workflow-advanced"><summary>Advanced actions, desktop apps and capability reference</summary>''' + advanced.rsplit('</section>', 1)[0] + '</details></section>'
    result = html.replace(INTEGRATIONS_HTML, local)
    result = result.replace('Start installed support apps and configured collectors', 'Start installed background tools and configured collectors').replace('Support apps control in the HUD', 'Background tools control in the HUD').replace('Apps keeps its startup observations until you reopen the HUD.', 'Actions refreshes local workflow status while its view is open; capability references keep their own startup observations.')
    return result


WORKFLOWS_CSS = r'''
.workflow-actions { display:flex; flex-wrap:wrap; gap:.8rem 1.2rem; align-items:center; padding:.4rem 22px 0; }
.workflow-actions a { color:#a9ece5; font-size:.9rem; text-underline-offset:3px; }
.workflow-actions button { margin-left:auto; min-height:44px; }
.workflow-explainer { padding:0 22px; color:#bdd0db; font-size:.875rem; line-height:1.6; }
.workflow-status { min-height:1.6em; }
.workflow-card { border-radius:5px; border-color:#355361; background:#0b1e29; }
.workflow-card > summary { grid-template-columns:minmax(10rem,1fr) auto; padding:1rem; min-height:84px; }
.workflow-card .integration-title { font-size:1rem; font-weight:650; }
.workflow-card .integration-zone { color:#9bb7c5; font-size:.75rem; font-weight:500; letter-spacing:0; text-transform:none; }
.workflow-state { justify-self:end; border:1px solid #607b89; border-radius:3px; padding:.3rem .55rem; color:#c9d9e2; font-size:.85rem; }
.workflow-card[data-state="connected"] .workflow-state { color:#a2efda; border-color:#559b85; }
.workflow-card[data-state="collecting"] .workflow-state { color:#a5def1; border-color:#52879d; }
.workflow-card[data-state="needs_setup"] .workflow-state,.workflow-card[data-state="error"] .workflow-state { color:#f0cc8c; border-color:#a38750; }
.workflow-metrics { display:flex; flex-wrap:wrap; gap:.4rem 1.4rem; grid-column:1 / -1; margin:.2rem 0 0; font-size:.875rem; color:#b5cbd7; }
.workflow-metrics strong { color:#e1f1f6; font-weight:600; font-variant-numeric:tabular-nums; }
.workflow-message { margin:0 0 .5rem; color:#cee0e8; line-height:1.6; font-size:.925rem; }
.workflow-time { display:block; margin:.5rem 0 .8rem; color:#a9becb; font-size:.825rem; }
.workflow-reference { border-top:1px solid #355361; padding-top:.3rem; }
.workflow-reference > summary { cursor:pointer; min-height:44px; padding:.7rem 0; color:#9fc4d2; font-size:.875rem; }
.workflow-card .integration-card-body { padding:1rem; }
.workflow-advanced { margin:1rem 22px; border-top:1px solid #375361; }
.workflow-advanced > summary { padding:1rem 0; cursor:pointer; color:#b6d1dc; font-size:.925rem; min-height:44px; }
.workflow-actions :is(a,button):focus-visible,.workflow-card summary:focus-visible,.workflow-advanced > summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
@media(max-width:600px) { .workflow-actions { padding:0 14px; gap:.65rem 1rem; } .workflow-actions button { margin-left:0; } .workflow-explainer { padding:0 14px; } .workflow-advanced { margin:1rem 14px; } .workflow-card > summary { grid-template-columns:1fr; gap:.65rem; } .workflow-state { justify-self:start; } }
'''

WORKFLOWS_JS = r'''
(() => {
  if(typeof localHudLaunch==='undefined'||!byId('workflows-refresh'))return;
  const ids=['core','tshark','zeek','suricata','scapy','nftables','clamav','osquery','qwen','nmap'];
  const names={core:'MEGALODON',tshark:'TShark',zeek:'Zeek',suricata:'Suricata',scapy:'Scapy',nftables:'nftables',clamav:'ClamAV',osquery:'osquery',qwen:'Qwen',nmap:'Nmap'};
  const labels={connected:'Data connected',saved_result:'Saved result available',collecting:'Collecting',ready:'Ready',stopped:'Configured · stopped',standby:'Standby alternative',needs_setup:'Needs setup',unavailable:'Unavailable',error:'Error'};
  const view={payload:null,failed:false,pending:false,visible:false,timer:null,lastAt:0,open:new Set(),reference:new Set()};
  const workspace=byId('workspace-interfaces');
  const visible=()=>!document.hidden&&!(workspace&&workspace.hidden)&&(typeof IntersectionObserver==='undefined'||view.visible);
  const fresh=()=>view.payload&&!view.failed&&Date.now()-view.lastAt<15000&&Date.now()-Date.parse(view.payload.observed_at)<30000;
  const text=(value,max)=>typeof value==='string'&&value.length<=max&&!/[\x00-\x1f\x7f]/.test(value);
  const stamp=value=>text(value,40)&&/Z$/.test(value)&&Number.isFinite(Date.parse(value));
  const time=value=>new Date(value).toISOString().replace('T',' ').replace('.000Z',' UTC');
  function checked(value){
    if(!value||value.schema!=='megalodon-support-workflows-v1'||value.mode!=='background'||!stamp(value.observed_at)||Date.parse(value.observed_at)>Date.now()+5000||!Array.isArray(value.tools)||value.tools.length>10)throw Error('Invalid workflow status');
    const seen=new Set();for(const row of value.tools){if(!row||!ids.includes(row.id)||seen.has(row.id)||!text(row.name,80)||!row.name.length||(!Object.hasOwn(labels,row.state)||row.state==='saved_result')||!text(row.message,512)||(row.updated_at!==null&&!stamp(row.updated_at))||!Array.isArray(row.metrics)||row.metrics.length>6||!row.metrics.every(metric=>metric&&text(metric.label,64)&&metric.label.length>0&&Number.isFinite(metric.value)&&text(metric.unit,32)))throw Error('Invalid workflow row');seen.add(row.id);}
    return value;
  }
  const periodic=new Set(['clamav','osquery','nmap']);
  const displayState=row=>!fresh()?'unavailable':periodic.has(row.id)&&row.state==='connected'?'saved_result':row.state;
  const displayLabel=row=>fresh()?labels[displayState(row)]:'Status unavailable';
  const timeLabel=row=>row.id==='tshark'?'Capture started':row.id==='clamav'?'Result saved':periodic.has(row.id)?'Result completed':'Source updated';
  const originalCard=integrationCard;
  function card(row){
    const item=document.createElement('details');item.className='integration-card workflow-card';item.dataset.state=displayState(row);item.open=view.open.has(row.id);
    item.addEventListener('toggle',()=>{if(item.open)view.open.add(row.id);else view.open.delete(row.id);});
    const summary=document.createElement('summary'),identity=textNode('span','','integration-identity');
    identity.append(textNode('span',names[row.id],'integration-title'),textNode('span',row.updated_at?timeLabel(row)+' '+time(row.updated_at):timeLabel(row)+' · time unavailable','integration-zone'));
    summary.append(identity,textNode('span',displayLabel(row),'workflow-state'));
    if(fresh()&&row.metrics.length){const metrics=textNode('span','','workflow-metrics');if(periodic.has(row.id))metrics.append(textNode('span','Saved result'));for(const metric of row.metrics){const part=textNode('span',metric.label+' ');part.append(textNode('strong',new Intl.NumberFormat(undefined,{maximumFractionDigits:2}).format(metric.value)+(metric.unit?' '+metric.unit:'')));metrics.append(part);}summary.append(metrics);}
    const body=textNode('div','','integration-card-body');body.append(textNode('p',(fresh()?'':'Last observation: ')+row.message,'workflow-message'));
    const when=textNode('time','View checked '+time(view.payload.observed_at)+(fresh()?'':' · refresh needed'),'workflow-time');when.setAttribute('datetime',view.payload.observed_at);body.append(when);
    const index=ids.indexOf(row.id),reference=integrationState.snapshot?.workflows.find(entry=>entry.id===integrationIds[index]);
    if(reference){const detail=originalCard(reference);detail.className='workflow-reference';detail.open=view.reference.has(row.id);detail.firstElementChild.replaceChildren(textNode('span','Capability reference · '+integrationStatuses[reference.selected_status]));detail.addEventListener('toggle',()=>{if(detail.open)view.reference.add(row.id);else view.reference.delete(row.id);});body.append(detail);}
    item.append(summary,body);return item;
  }
  renderIntegrationMap=function(){
    const payload=view.payload,query=byId('integrations-query').value.slice(0,160).trim().toLowerCase(),filter=byId('integrations-status-filter').value;
    const rows=payload?payload.tools.filter(row=>(filter==='ALL'||displayState(row)===filter)&&(!query||[names[row.id],row.name,row.message,displayLabel(row),...row.metrics.map(metric=>metric.label)].some(value=>value.toLowerCase().includes(query)))):[];
    const children=rows.map(card);if(!children.length)children.push(textNode('p',payload?(payload.tools.length?'No tools match these filters.':'No tool observations were returned.'):(view.failed?'Local workflow status is unavailable. Refresh to try again.':'Checking local workflow status…'),'integration-empty'));
    byId('integrations-cards').replaceChildren(...children);byId('integrations-cards').setAttribute('aria-busy',view.pending?'true':'false');
    byId('integrations-profile').textContent=payload?'Local background view':'Local status · not checked';
    byId('integrations-status').textContent=payload?(fresh()?`${rows.length} of ${payload.tools.length} tools · checked ${time(payload.observed_at)}`:`Status unavailable · last view ${time(payload.observed_at)}. Refresh before relying on these observations.`):(view.failed?'Unable to read local workflow status.':'Checking local workflow status…');
    if(!visible()&&payload)byId('integrations-status').textContent='View updates paused. Background tools continue on this PC. Last check '+time(payload.observed_at)+'.';
    if(byId('workflow-reference-status'))byId('workflow-reference-status').textContent=integrationViewStatus(integrationState.snapshot?.workflows.length||0);
    byId('workflows-refresh').disabled=view.pending;
  };
  function cancel(){if(view.timer!==null)clearTimeout(view.timer);view.timer=null;}
  function schedule(){cancel();if(visible())view.timer=setTimeout(read,5000);}
  async function body(response){if(Number(response.headers.get('content-length'))>65536)throw Error('Response too large');if(response.body&&response.body.getReader){const reader=response.body.getReader(),parts=[];let length=0;try{while(true){const part=await reader.read();if(part.done)break;length+=part.value.byteLength;if(length>65536)throw Error('Response too large');parts.push(part.value);}}catch(error){await reader.cancel();throw error;}const bytes=new Uint8Array(length);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.byteLength;}return JSON.parse(new TextDecoder().decode(bytes));}const content=await response.text();if(new TextEncoder().encode(content).length>65536)throw Error('Response too large');return JSON.parse(content);}
  async function read(){if(view.pending||!visible())return;cancel();view.pending=true;renderIntegrationMap();const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),8000);try{const response=await fetch('/api/support-workflows',{method:'GET',credentials:'same-origin',cache:'no-store',headers:{'X-Megalodon-Check':'1'},signal:controller.signal});if(!response.ok)throw Error('Unavailable');view.payload=checked(await body(response));view.failed=false;view.lastAt=Date.now();}catch(_){view.failed=true;}finally{clearTimeout(timeout);view.pending=false;renderIntegrationMap();schedule();}}
  function sync(){cancel();if(visible())read();else renderIntegrationMap();}
  byId('workflows-refresh').addEventListener('click',read);
  byId('workflows-configure').addEventListener('click',()=>{if(window.megalodonSupportConfiguration)window.megalodonSupportConfiguration.open();});
  document.addEventListener('visibilitychange',sync);
  if(typeof MutationObserver!=='undefined'&&workspace)new MutationObserver(sync).observe(workspace,{attributes:true,attributeFilter:['hidden']});
  if(typeof IntersectionObserver!=='undefined')new IntersectionObserver(entries=>{view.visible=entries.some(entry=>entry.isIntersecting);sync();},{root:byId('workspace-content'),rootMargin:'80px'}).observe(byId('integrations-cards'));
  renderIntegrationMap();if(typeof IntersectionObserver==='undefined')read();
})();
'''
