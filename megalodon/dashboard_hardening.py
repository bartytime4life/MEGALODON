"""Review-only presentation for the live hardening posture checks."""
import json

from .hardening_review import CHECK_IDS

HARDENING_HTML = r'''
    <h6 id="hardening-title">Hardening posture</h6>
    <p class="support-config-note">Read-only checks of live kernel, SSH, update and listener settings. Nothing is changed; each remediation is advice for you to apply. A pass does not establish that this PC is secure, and a fail does not establish compromise.</p>
    <div id="hardening-review" aria-labelledby="hardening-title"><p>Hardening posture has not been checked.</p></div>
'''

HARDENING_CSS = r'''
#hardening-review { min-width:0; overflow-wrap:anywhere; }
#hardening-review > details { border-top:1px solid #3e6877; padding:.8rem 0; }
#hardening-review summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#hardening-review summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#hardening-review dl { margin:.4rem 0; }
#hardening-review dt { font-weight:700; margin-top:.4rem; }
#hardening-review dd { margin:0; line-height:1.6; }
#hardening-review li { margin:.4rem 0; line-height:1.6; }
'''

HARDENING_JS = r'''
function renderHardening(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s));
  // The complete check set; a missing or repeated check could hide a failure.
  const ids=__CHECK_IDS__;
  const states={fail:'Fail',review:'Review',unknown:'Unknown',pass:'Pass',not_applicable:'Not applicable'};
  const valid=c=>c&&typeof c==='object'&&!Array.isArray(c)&&text(c.id,40)&&text(c.title,160)&&Object.hasOwn(states,c.state)
    &&text(c.observed,200)&&text(c.expected,64)&&/^M\d{4}$/.test(c.mitigation)&&text(c.remediation,256)&&c.action_status==='not_attempted'
    &&(c.note===undefined||text(c.note,1024));
  if(!payload||payload.schema!=='megalodon-hardening-review-v1'||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Hardening posture is unavailable.'));return;
  }
  if(payload.state!==undefined||!stamp(payload.reviewed_at)||!Array.isArray(payload.checks)||payload.checks.length!==ids.length||!payload.checks.every(valid)
    ||new Set(payload.checks.map(c=>c.id)).size!==ids.length||!payload.checks.every(c=>ids.includes(c.id))){
    panel.replaceChildren(node('p','Hardening posture could not be read on this PC.'));return;
  }
  const order=['fail','review','unknown','pass','not_applicable'];
  const counts=order.map(s=>[s,payload.checks.filter(c=>c.state===s).length]).filter(([,n])=>n);
  const children=[node('p',counts.map(([s,n])=>`${n} ${states[s].toLowerCase()}`).join(' · ')+' · checked '+payload.reviewed_at.replace('T',' ').replace('Z',' UTC'))];
  for(const c of payload.checks.filter(c=>['fail','review','unknown'].includes(c.state)).sort((a,b)=>order.indexOf(a.state)-order.indexOf(b.state))){
    const item=document.createElement('details');item.dataset.state=c.state;
    item.append(node('summary',`${states[c.state]} · ${c.title}`));
    const facts=document.createElement('dl');
    for(const [label,value] of [['Observed',c.observed],['Expected',c.expected],['ATT&CK mitigation',c.mitigation],['Suggested remediation',c.remediation]].concat(c.note?[['Note',c.note]]:[]))facts.append(node('dt',label),node('dd',value));
    item.append(facts);children.push(item);
  }
  const rest=payload.checks.filter(c=>['pass','not_applicable'].includes(c.state));
  if(rest.length){
    const item=document.createElement('details');item.append(node('summary',`Passing and not-applicable checks (${rest.length})`));
    const list=document.createElement('ul');for(const c of rest)list.append(node('li',`${states[c.state]} · ${c.title} · ${c.observed}`));
    item.append(list);children.push(item);
  }
  panel.replaceChildren(...children);
}
'''
HARDENING_JS = HARDENING_JS.replace('__CHECK_IDS__', json.dumps(list(CHECK_IDS)))
