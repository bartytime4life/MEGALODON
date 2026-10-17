"""Review-only presentation for saved local host observations."""

HOST_FINDINGS_HTML = r'''
    <h6 id="host-findings-title">Host findings to review</h6>
    <p class="support-config-note">Configuration warnings and file changes need operator review. Reputation matches appear in the network inspector. None of these observations verifies a security incident or authorizes containment.</p>
    <div id="host-findings" aria-labelledby="host-findings-title"><p>Host findings have not been checked.</p></div>
'''

HOST_FINDINGS_CSS = r'''
#host-findings > details { border-top:1px solid #3e6877; padding:.8rem 0; }
#host-findings summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#host-findings summary:focus-visible,#host-findings a:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#host-findings li { margin:.75rem 0; line-height:1.6; overflow-wrap:anywhere; }
#host-findings code { overflow-wrap:anywhere; white-space:normal; font-size:.85rem; }
#host-findings a { color:#a9ece5; display:inline-block; min-height:44px; line-height:44px; }
'''

HOST_FINDINGS_JS = r'''
function renderHostFindings(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&new TextEncoder().encode(s).length<=max&&!/[\p{C}\p{Zl}\p{Zp}]/u.test(s);
  const date=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s.replace('Z','.000Z');
  const digest=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
  const count=(n,max)=>Number.isInteger(n)&&n>=0&&n<=max;
  const keys=(o,expected)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===[...expected].sort().join(',');
  const when=s=>s.replace('T',' ').replace('Z',' UTC');
  const sources=[['audit','Lynis','lynis-report.dat','host-security-audit','Review audit controls'],['integrity','AIDE','aide-report.txt','host-security-check','Review comparison controls']];
  if(!payload||payload.schema!=='megalodon-host-security-v1'||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Host findings unavailable. Check configuration status again.'));return;
  }
  const opened=new Set(Array.from(panel.children||[]).filter(n=>n.open).map(n=>n.dataset.source));
  const cards=[];
  for(const [key,name,report,control,label] of sources){
    const card=document.createElement('details'),summary=node('summary',name+' · observations unavailable');card.dataset.source=key;card.open=opened.has(key);card.append(summary);
    try{
      const state=payload[key+'_state'],saved=payload[key];
      if(!['missing','unavailable','legacy','available'].includes(state))throw Error();
      if(state==='missing'||state==='unavailable'){
        if(saved!==null)throw Error();
        summary.textContent=name+(state==='missing'?' · no saved observation':' · evidence unavailable');
        card.append(node('p',state==='missing'?'No completed observation is available. Run an explicit local check when ready.':'Saved evidence could not be validated. Review the private files or rerun the fixed check; no result is inferred.'));
      }else{
        const fields=['checked_at','message','metrics'];if(state==='available')fields.push('review');
        if(!keys(saved,fields)||!date(saved.checked_at)||Date.parse(saved.checked_at)>Date.now()+300000||!text(saved.message,512))throw Error();
        const m=saved.metrics,metricKeys=key==='audit'?['warnings','suggestions']:['added_detected','removed_detected','changed_detected'];
        if(!keys(m,metricKeys)||!Object.values(m).every(n=>count(n,key==='audit'?10000:1))||(key==='audit'&&m.warnings+m.suggestions>10000))throw Error();
        const r=saved.review;
        if(state==='available'){
          const extra=key==='audit'?['items','omitted']:['baseline_created_at','baseline_sha256','exit_code'];
          if(!keys(r,['schema','operation','report_sha256',...extra])||r.schema!=='megalodon-host-review-v1'||!digest(r.report_sha256))throw Error();
          if(key==='audit'){
            if(r.operation!=='audit'||!Array.isArray(r.items)||r.items.length!==Math.min(16,m.warnings+m.suggestions)||!count(r.omitted,10000)||r.items.length+r.omitted!==m.warnings+m.suggestions)throw Error();
            const lines=new Set(),totals={configuration_warning:0,configuration_suggestion:0};
            for(const item of r.items){
              if(!keys(item,['kind','rule','text','line'])||!Object.hasOwn(totals,item.kind)||typeof item.rule!=='string'||!/^[A-Z][A-Z0-9-]{0,31}$/.test(item.rule)||!text(item.text,240)||!count(item.line,12582912)||item.line<1||lines.has(item.line))throw Error();
              lines.add(item.line);totals[item.kind]++;
            }
            if(totals.configuration_warning>m.warnings||totals.configuration_suggestion>m.suggestions)throw Error();
          }else if(!count(r.exit_code,7)||Object.entries({added_detected:1,removed_detected:2,changed_detected:4}).some(([k,bit])=>m[k]!==Number(Boolean(r.exit_code&bit)))||!['baseline','check'].includes(r.operation)||!date(r.baseline_created_at)||Date.parse(r.baseline_created_at)>Date.parse(saved.checked_at)||!digest(r.baseline_sha256)||(r.operation==='baseline'&&Object.values(m).some(Boolean)))throw Error();
        }
        const old=Date.now()-Date.parse(saved.checked_at)>7*86400000;
        summary.textContent=name+' · '+(state==='legacy'?'legacy aggregate only':key==='audit'?m.warnings+' configuration warnings · '+m.suggestions+' hardening suggestions':r.operation==='baseline'?'initial baseline recorded':Object.values(m).some(Boolean)?'file changes reported':'no differences reported')+(old?' · older than 7 days':'');
        card.append(node('p','Observed '+when(saved.checked_at)+' · saved result, not continuous monitoring.'),node('p',saved.message));
        if(old)card.append(node('p','This observation is older than 7 days. Recheck before relying on it; a newer observation also does not prove safety.'));
        if(state==='legacy')card.append(node('p','This earlier summary has no bound report identity or rule detail. It cannot distinguish AIDE baseline creation from a comparison. Run a new explicit check for reviewable findings.'));
        else{
          if(key==='audit'){
            const list=document.createElement('ul');
            for(const item of r.items){const li=document.createElement('li');li.append(node('strong',(item.kind==='configuration_warning'?'Configuration warning':'Hardening suggestion')+' · '+item.rule),node('p',item.text),node('p','Evidence: '+report+' line '+item.line+'. Significance: '+(item.kind==='configuration_warning'?'review recommended':'advisory improvement')+'; incident severity is unassigned.'));list.append(li);}
            if(!r.items.length)list.append(node('li','No warnings or suggestions were reported in this unprivileged audit. Coverage remains limited.'));
            card.append(list,node('p',r.omitted?r.omitted+' additional observations remain in the private report; the view shows at most 16, warnings first.':'All reported warning and suggestion entries are shown.'));
            card.append(node('p','Follow-up: inspect the named rule in the private report and compare the current configuration with your intended policy. Review any remediation separately; tool recommendations never run here.'));
          }else{
            if(r.operation==='check'){
              const changes=Object.entries(m).filter(([,v])=>v===1).map(([k])=>k.replace('_detected',''));
              card.append(node('p',changes.length?'AIDE exit status '+r.exit_code+' · change categories: '+changes.join(', ')+'. These are exit-status flags, not file counts.':'No change category was reported. This does not establish that the host is clean.'));
            }
            card.append(node('p','Scope: readable /usr/bin, /usr/sbin, /etc/ssh and /etc/systemd/system only. Package upgrades and authorized changes can explain differences. The initial baseline is not known clean.'),node('p','Baseline observed '+when(r.baseline_created_at)),node('code','Baseline SHA-256: '+r.baseline_sha256),node('p','Follow-up: inspect changed paths in the private report and compare with expected package or administrator changes. Preserve the baseline until separately reviewed; this view cannot accept, restore, delete or quarantine files.'));
          }
          card.append(node('p','Private evidence: ~/.local/share/megalodon/support/host-security/'+report),node('code','Report SHA-256: '+r.report_sha256));
        }
      }
      const link=node('a',label);link.setAttribute('href','#'+control);card.append(link,node('p','Actions: not attempted by this view. Use the explicit control to run a fixed check. Host modifications require separate operator authorization.'));
    }catch(_){card.replaceChildren(node('summary',name+' · evidence unavailable'),node('p','Malformed or contradictory observation. Check configuration status again; no finding is inferred.'));}
    cards.push(card);
  }
  panel.replaceChildren(...cards);
}
'''
