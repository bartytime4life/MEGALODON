"""Review-only presentation for the persistence location review."""
import json

from .persistence_review import (LOCATIONS, MAX_FINDINGS, MAX_GAPS, MAX_ITEMS, SUMMARY_FINDINGS, SUMMARY_GAPS,
                                 SUMMARY_SCHEMA, TRUST)

PERSISTENCE_HTML = r'''
    <h6 id="persistence-title">Persistence locations</h6>
    <p class="support-config-note">Read-only review of fixed autostart, systemd, cron, shell-startup, session, SSH and loader locations, compared with a baseline you record. Nothing is run, edited or removed. A change is a reason to look, not proof of compromise; package updates and your own edits change these files too.</p>
    <div id="persistence-review" aria-labelledby="persistence-title"><p>Persistence locations have not been reviewed.</p></div>
    <div class="support-config-actions"><button type="button" id="persistence-baseline" disabled>Record initial persistence baseline</button></div>
    <p class="support-config-note">The baseline records what is present now; it is not a known-clean state. The HUD records only an initial baseline. Replacing one is a command-line step after you review its changes: <code>python -m megalodon.persistence_review baseline</code>.</p>
'''

PERSISTENCE_CSS = r'''
#persistence-review { min-width:0; overflow-wrap:anywhere; }
#persistence-review > details { border-top:1px solid #3e6877; padding:.8rem 0; }
#persistence-review summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#persistence-review summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#persistence-review dl { margin:.4rem 0; }
#persistence-review dt { font-weight:700; margin-top:.4rem; }
#persistence-review dd { margin:0; line-height:1.6; }
#persistence-review li { margin:.4rem 0; line-height:1.6; }
'''

PERSISTENCE_JS = r'''
function validPersistence(p) {
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s));
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  const keys=(o,names)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join()===[...names].sort().join();
  const rules=['PRELOAD_PRESENT','WORLD_WRITABLE','UNEXPECTED_OWNER','ADDED','CHANGED','REMOVED'];
  const finding=f=>keys(f,['rule','path','category','attack','detail','action_status'])&&rules.includes(f.rule)&&text(f.path,256)
    &&Object.hasOwn(__TECHNIQUES__,f.category)&&__TECHNIQUES__[f.category]===f.attack&&text(f.detail,256)&&f.action_status==='not_attempted';
  return keys(p,['schema','reviewed_at','baseline_at','trust','items','findings','findings_total','gaps','gaps_total','inventory_truncated','incomplete_locations','action_authority'])
    &&p.schema===__SCHEMA__&&p.action_authority==='none'&&p.trust===__TRUST__&&stamp(p.reviewed_at)&&(p.baseline_at===null||stamp(p.baseline_at))
    &&count(p.items)&&p.items<=__MAX_ITEMS__&&Array.isArray(p.findings)&&p.findings.length<=__FINDINGS__&&p.findings.every(finding)
    &&count(p.findings_total)&&p.findings_total>=p.findings.length&&(p.findings.length===Math.min(p.findings_total,__FINDINGS__))
    &&Array.isArray(p.gaps)&&p.gaps.length<=__GAPS__&&p.gaps.every(g=>text(g,256))&&count(p.gaps_total)&&p.gaps_total>=p.gaps.length
    &&typeof p.inventory_truncated==='boolean'&&count(p.incomplete_locations);
}
// The HUD may record only a first baseline; it never replaces one.
function persistenceAllowsBaseline(p){return validPersistence(p)&&p.baseline_at===null;}
function renderPersistence(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const time=s=>s.replace('T',' ').replace('Z',' UTC');
  if(!payload||payload.schema!==__SCHEMA__||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Persistence review is unavailable.'));return;
  }
  if(!validPersistence(payload)){
    panel.replaceChildren(node('p','Persistence locations could not be read on this PC.'));return;
  }
  const labels={PRELOAD_PRESENT:'Loader preload in use',WORLD_WRITABLE:'Writable by any account',UNEXPECTED_OWNER:'Unexpected owner',ADDED:'Added since baseline',CHANGED:'Changed since baseline',REMOVED:'Removed since baseline'};
  const children=[node('p',`${payload.items} startup items reviewed · `+(payload.baseline_at?'baseline '+time(payload.baseline_at):'no baseline recorded')+' · checked '+time(payload.reviewed_at))];
  if(!payload.findings_total)children.push(node('p',payload.baseline_at?'No review items.':'No review items. Record an initial baseline to see later additions, changes and removals.'));
  for(const f of payload.findings){
    const item=document.createElement('details');item.dataset.rule=f.rule;
    item.append(node('summary',`${labels[f.rule]} · ${f.path}`));
    const facts=document.createElement('dl');
    for(const [label,value] of [['Detail',f.detail],['Location type',f.category],['ATT&CK technique',f.attack]])facts.append(node('dt',label),node('dd',value));
    item.append(facts);children.push(item);
  }
  if(payload.findings_total>payload.findings.length)children.push(node('p',`Showing the first ${payload.findings.length} of ${payload.findings_total} review items. python -m megalodon.persistence_review review lists up to the first ${__CLI_FINDINGS__}.`));
  if(payload.gaps.length){
    const item=document.createElement('details');item.append(node('summary',`Coverage gaps (${payload.gaps_total})`));
    const list=document.createElement('ul');for(const gap of payload.gaps)list.append(node('li',gap));
    if(payload.gaps_total>payload.gaps.length)list.append(node('li',`${payload.gaps_total-payload.gaps.length} more gaps; the command-line review lists up to ${__CLI_GAPS__}.`));
    item.append(list);children.push(item);
  }
  panel.replaceChildren(...children);
}
'''
# Each location category carries one ATT&CK technique; a finding must name its category's.
TECHNIQUES = {category: technique for category, technique, _location, _kind in LOCATIONS}
for _name, _value in (('__TECHNIQUES__', TECHNIQUES), ('__SCHEMA__', SUMMARY_SCHEMA), ('__TRUST__', TRUST),
                      ('__MAX_ITEMS__', MAX_ITEMS), ('__FINDINGS__', SUMMARY_FINDINGS), ('__GAPS__', SUMMARY_GAPS),
                      ('__CLI_FINDINGS__', MAX_FINDINGS), ('__CLI_GAPS__', MAX_GAPS)):
    PERSISTENCE_JS = PERSISTENCE_JS.replace(_name, json.dumps(_value))
