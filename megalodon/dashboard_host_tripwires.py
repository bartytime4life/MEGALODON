"""Review-only Setup panel for canary files and login review."""
import json

from .auth_review import ATTACK as AUTH_ATTACK, SEVERITY as AUTH_SEVERITY
from .host_tripwires import MAX_FINDINGS, MAX_SOURCES, SCHEMA

CANARY_SEVERITY = {"CANARY_REMOVED": "CRITICAL", "CANARY_MODIFIED": "CRITICAL", "CANARY_READ": "HIGH"}

HOST_TRIPWIRES_HTML = r'''
    <h6 id="host-tripwires-title">Tripwires and login review</h6>
    <p class="support-config-note">Canary files report when bait is read, changed or deleted; the login review reads this computer's auth log for password guessing, spraying and suspicious successes. Read-only: planting, rearming and any response stay explicit commands. A trip is a strong reason to investigate, not proof of who or why.</p>
    <div id="host-tripwires-review" aria-labelledby="host-tripwires-title"><p>Tripwires have not been checked.</p></div>
'''

HOST_TRIPWIRES_CSS = r'''
#host-tripwires-review { min-width:0; overflow-wrap:anywhere; }
#host-tripwires-review h6 { margin:.9rem 0 .3rem; font-size:.95rem; }
#host-tripwires-review > details, #host-tripwires-review section > details { border-top:1px solid #3e6877; padding:.6rem 0; }
#host-tripwires-review summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#host-tripwires-review summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#host-tripwires-review dl { margin:.4rem 0; }
#host-tripwires-review dt { font-weight:700; margin-top:.4rem; }
#host-tripwires-review dd { margin:0; line-height:1.6; }
#host-tripwires-review code { overflow-wrap:anywhere; }
#host-tripwires-review [data-severity="CRITICAL"] > summary, #host-tripwires-review [data-severity="HIGH"] > summary { color:#ffb3a7; font-weight:700; }
'''

HOST_TRIPWIRES_JS = r'''
function hostTripwiresPending(p) {
  return !!p&&typeof p==='object'&&!Array.isArray(p)&&Object.keys(p).sort().join()==='action_authority,schema,state'
    &&p.schema===__SCHEMA__&&p.state==='pending'&&p.action_authority==='none';
}
function validHostTripwires(p) {
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s));
  const iso=s=>typeof s==='string'&&s.length<=40&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(s)&&Number.isFinite(Date.parse(s));
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  const keys=(o,names)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join()===[...names].sort().join();
  const canaryRules=__CANARY__, authRules=__AUTH__, attack=__ATTACK__, max=__MAX__;
  const list=(a,ok)=>Array.isArray(a)&&a.length<=max&&a.every(ok);
  const canaryFinding=f=>keys(f,['rule_id','severity','name','detail'])&&Object.hasOwn(canaryRules,f.rule_id)
    &&f.severity===canaryRules[f.rule_id]&&text(f.name,255)&&text(f.detail,512);
  const canary=c=>{
    if(!c||typeof c!=='object')return false;
    if(c.state==='not_configured')return keys(c,['state','setup'])&&text(c.setup,256);
    if(c.state==='unavailable')return keys(c,['state','reason'])&&text(c.reason,256);
    return ['clear','tripped'].includes(c.state)&&keys(c,['state','canaries','read_detection','findings','findings_total'])
      &&count(c.canaries)&&c.canaries>=1&&c.canaries<=16&&typeof c.read_detection==='boolean'
      &&list(c.findings,canaryFinding)&&count(c.findings_total)&&c.findings_total>=c.findings.length&&c.findings_total<=c.canaries
      &&(c.state==='tripped')===(c.findings_total>0);
  };
  const authFinding=f=>keys(f,['rule_id','severity','observed_at','subject','message','attack'])&&Object.hasOwn(authRules,f.rule_id)
    &&f.severity===authRules[f.rule_id]&&iso(f.observed_at)&&text(f.subject,128)&&text(f.message,512)
    &&Array.isArray(f.attack)&&JSON.stringify(f.attack)===JSON.stringify(attack[f.rule_id]);
  const observedKeys=['failed_logins','successful_logins','sudo_failures','sudo_denied','accounts_created','privilege_grants'];
  const severities=['CRITICAL','HIGH','MEDIUM','LOW'];
  const source=s=>keys(s,['source','failures'])&&typeof s.source==='string'&&/^[0-9a-f:.]{2,45}$/i.test(s.source)&&count(s.failures)&&s.failures>0;
  const auth=a=>{
    if(!a||typeof a!=='object')return false;
    if(a.state==='not_found')return keys(a,['state','checked'])&&Array.isArray(a.checked)&&a.checked.length>=1&&a.checked.length<=4&&a.checked.every(x=>text(x,64));
    if(a.state==='unreadable')return keys(a,['state','reason'])&&text(a.reason,256);
    const total=a.severity_counts&&severities.reduce((n,k)=>n+(count(a.severity_counts[k])?a.severity_counts[k]:NaN),0);
    return a.state==='ready'&&keys(a,['state','source','window','observed','severity_counts','top_failing_sources','findings','findings_total','truncated'])
      &&text(a.source,64)&&keys(a.window,['start','end'])&&(a.window.start===null||iso(a.window.start))&&(a.window.end===null||iso(a.window.end))
      &&keys(a.observed,observedKeys)&&observedKeys.every(k=>count(a.observed[k]))
      &&keys(a.severity_counts,severities)&&Number.isSafeInteger(total)&&total===a.findings_total
      &&Array.isArray(a.top_failing_sources)&&a.top_failing_sources.length<=__SOURCES__&&a.top_failing_sources.every(source)
      &&list(a.findings,authFinding)&&count(a.findings_total)&&a.findings_total>=a.findings.length&&typeof a.truncated==='boolean';
  };
  return keys(p,['schema','reviewed_at','canary','auth','action_authority'])&&p.schema===__SCHEMA__
    &&p.action_authority==='none'&&stamp(p.reviewed_at)&&canary(p.canary)&&auth(p.auth);
}
function renderHostTripwires(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const time=s=>s.replace('T',' ').replace(/(\.\d+)?(Z|[+-]\d{2}:\d{2})$/,m=>m.endsWith('Z')?' UTC':' '+m.replace(/^\.\d+/,''));
  if(hostTripwiresPending(payload)){panel.replaceChildren(node('p','Reviewing tripwires and login records…'));return;}
  if(!payload||payload.schema!==__SCHEMA__||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Tripwire and login review is unavailable.'));return;
  }
  if(!validHostTripwires(payload)){
    panel.replaceChildren(node('p','Tripwire and login review could not be read on this PC.'));return;
  }
  const finding=(severity,title,facts,key)=>{
    const item=document.createElement('details');item.dataset.severity=severity;item.dataset.refreshKey=key;
    item.append(node('summary',`${severity} · ${title}`));
    const list=document.createElement('dl');for(const [label,value] of facts)list.append(node('dt',label),node('dd',value));
    item.append(list);return item;
  };
  const children=[node('p',`Checked ${time(payload.reviewed_at)}.`)];
  const c=payload.canary,cs=document.createElement('section');cs.append(node('h6','Canary files'));
  const canaryLabels={CANARY_REMOVED:'Canary removed or replaced',CANARY_MODIFIED:'Canary modified',CANARY_READ:'Canary read'};
  if(c.state==='not_configured'){
    cs.append(node('p','No canary files are planted yet. Plant bait files with:'),node('code',c.setup));
  }else if(c.state==='unavailable'){
    cs.append(node('p',`The canary manifest could not be checked: ${c.reason}`));
  }else{
    const reads=c.read_detection?'reads are detectable':'reads are not detectable on this filesystem (noatime)';
    cs.append(node('p',c.state==='clear'?`All ${c.canaries} canary files are intact · ${reads}.`
      :`${c.findings_total} of ${c.canaries} canary files tripped · ${reads}. Investigate before running canary rearm.`));
    for(const f of c.findings)cs.append(finding(f.severity,`${canaryLabels[f.rule_id]} · ${f.name}`,[['Detail',f.detail]],JSON.stringify(['canary',f.rule_id,f.name])));
  }
  children.push(cs);
  const a=payload.auth,as=document.createElement('section');as.append(node('h6','Login review'));
  const authLabels={AUTH_SUCCESS_AFTER_FAILURES:'Login succeeded after failures',AUTH_FAILURE_BURST:'Failed login burst',
    PASSWORD_SPRAY:'Password spraying',SUDO_DENIED:'Sudo by a non-sudoer',PRIVILEGE_GRANT:'Privileged group granted',
    SUDO_FAILURES:'Repeated wrong sudo passwords',ACCOUNT_CREATED:'New local account'};
  if(a.state==='not_found'){
    as.append(node('p',`No system auth log was found (checked ${a.checked.join(', ')}). Use megalodon auth-review with journalctl output instead.`));
  }else if(a.state==='unreadable'){
    as.append(node('p',`The auth log could not be read: ${a.reason}`));
  }else{
    const span=a.window.start?`${time(a.window.start)} → ${time(a.window.end)}`:'no recognized entries';
    const o=a.observed;
    as.append(node('p',`${a.source} · ${span} · ${o.failed_logins} failed and ${o.successful_logins} successful SSH logins · ${o.sudo_failures} wrong sudo passwords · ${a.findings_total} findings${a.truncated?' (truncated)':''}.`));
    if(!a.findings_total)as.append(node('p','No login findings in this log.'));
    for(const f of a.findings)as.append(finding(f.severity,`${authLabels[f.rule_id]} · ${f.subject}`,
      [['Detail',f.message],['Observed',time(f.observed_at)],['ATT&CK technique',f.attack.join(', ')]],JSON.stringify(['auth',f.rule_id,f.subject,f.observed_at])));
    if(a.findings_total>a.findings.length)as.append(node('p',`${a.findings_total-a.findings.length} more findings: run megalodon auth-review for the full report.`));
    if(a.top_failing_sources.length){
      const item=document.createElement('details');item.dataset.refreshKey='sources';
      item.append(node('summary',`Most failed logins by source (${a.top_failing_sources.length})`));
      const list=document.createElement('ul');for(const s of a.top_failing_sources)list.append(node('li',`${s.source} · ${s.failures} failures`));
      item.append(list);as.append(item);
    }
  }
  children.push(as);
  panel.replaceChildren(...children);
}
'''
for _name, _value in (('__SCHEMA__', SCHEMA), ('__CANARY__', CANARY_SEVERITY), ('__AUTH__', AUTH_SEVERITY),
                      ('__ATTACK__', AUTH_ATTACK), ('__MAX__', MAX_FINDINGS), ('__SOURCES__', MAX_SOURCES)):
    HOST_TRIPWIRES_JS = HOST_TRIPWIRES_JS.replace(_name, json.dumps(_value))
