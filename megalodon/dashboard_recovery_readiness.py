"""Read-only recovery limits, derived from the existing saved AIDE observation."""
import json

from .host_security import AIDE_SCOPE
from .backup_evidence import DETAILS

RECOVERY_READINESS_HTML = r'''
    <h6 id="recovery-readiness-title">Recovery readiness</h6>
    <p class="support-config-note">Check what the saved file-integrity observation can support before considering recovery. Expected software installs and your edits need review; an IP match or AI explanation cannot identify which files to undo.</p>
    <div id="recovery-readiness" aria-labelledby="recovery-readiness-title"><p>Recovery readiness has not been checked.</p></div>
'''

RECOVERY_READINESS_CSS = r'''
#recovery-readiness { min-width:0; overflow-wrap:anywhere; }
#recovery-readiness dl { margin:.6rem 0; }
#recovery-readiness dt { font-weight:700; margin-top:.6rem; }
#recovery-readiness dd { margin:0; line-height:1.6; }
#recovery-readiness summary { cursor:pointer; min-height:44px; line-height:1.6; }
#recovery-readiness summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#recovery-readiness code { white-space:normal; overflow-wrap:anywhere; }
'''

RECOVERY_READINESS_JS = r'''
function renderRecoveryReadiness(panel, payload, backupEvidence) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const keys=['schema','state','action_authority','action_status','restore_eligible','baseline_state','integrity_state','integrity_operation','checked_at','change_categories','scope','backup_state','causality_state','conflict_state'];
  const scope=__AIDE_SCOPE__, categories=['added','removed','changed'];
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s.replace('Z','.000Z')&&Date.parse(s)<=Date.now()+300000;
  const unavailable=()=>panel.replaceChildren(node('p','Recovery readiness is unavailable. Check configuration status again; no restore eligibility is inferred.'));
  if(!payload||typeof payload!=='object'||Array.isArray(payload)||Object.keys(payload).sort().join(',')!==[...keys].sort().join(',')
      ||payload.schema!=='megalodon-recovery-readiness-v1'||payload.state!=='unavailable'||payload.action_authority!=='none'
      ||payload.action_status!=='not_attempted'||payload.restore_eligible!==false||payload.backup_state!=='not_integrated'
      ||payload.causality_state!=='unavailable'||payload.conflict_state!=='not_assessed'
      ||!['present','missing','unknown'].includes(payload.baseline_state)||!['available','legacy','missing','unavailable'].includes(payload.integrity_state)
      ||!Array.isArray(payload.scope)||payload.scope.length!==scope.length||!payload.scope.every((s,i)=>s===scope[i])){unavailable();return;}
  if(payload.integrity_state==='available'){
    if(!stamp(payload.checked_at)||!['baseline','check'].includes(payload.integrity_operation)||!Array.isArray(payload.change_categories)
        ||payload.change_categories.length>categories.length||!payload.change_categories.every((s,i,a)=>categories.includes(s)&&(i===0||categories.indexOf(a[i-1])<categories.indexOf(s)))
        ||(payload.integrity_operation==='baseline'&&payload.change_categories.length)){unavailable();return;}
  }else if(payload.change_categories!==null||payload.integrity_operation!==null
      ||(payload.integrity_state==='legacy'?!stamp(payload.checked_at):payload.checked_at!==null)){unavailable();return;}
  const baseline={present:'Present · observed state, not a clean-system certificate',missing:'No validated baseline observed',unknown:'Could not validate baseline availability'};
  let observation={missing:'No saved AIDE observation',unavailable:'Saved AIDE observation could not be validated',legacy:'Legacy aggregate · operation and report identity unavailable'}[payload.integrity_state];
  if(payload.integrity_state==='available')observation=payload.integrity_operation==='baseline'?'Initial baseline recorded · no comparison':payload.change_categories.length?'Comparison reports these change categories: '+payload.change_categories.join(', '):'Comparison reports no differences within its limited scope';
  const facts=document.createElement('dl');
  for(const [label,value] of [['AIDE baseline',baseline[payload.baseline_state]],['Saved file-integrity observation',observation],['Known-good host backup','Not integrated · no recoverable earlier version verified'],['Process-to-file attribution','Unavailable · network observations do not establish file causality'],['Conflicts with your work','Not assessed · legitimate installs and edits must be preserved']])facts.append(node('dt',label),node('dd',value));
  const children=[node('p','Host file restoration unavailable'),facts];
  if(payload.checked_at){
    children.push(node('p','Recorded '+payload.checked_at.replace('T',' ').replace('Z',' UTC')+' · saved result, not continuous monitoring.'));
    if(Date.now()-Date.parse(payload.checked_at)>7*86400000)children.push(node('p','This observation is older than 7 days. A newer check also cannot establish a known-good backup or safe restoration.'));
  }
  const backupOpen=Array.from(panel.children||[]).some(n=>n.id==='recovery-backup-details'&&n.open);
  const detail=document.createElement('details');detail.id='recovery-integrity-details';detail.open=Array.from(panel.children||[]).some(n=>n.id===detail.id&&n.open);
  detail.append(node('summary','File-integrity scope and recovery limits'));
  const list=document.createElement('ul');for(const path of scope){const item=document.createElement('li');item.append(node('code',path));list.append(item);}detail.append(list,node('p','Readable files in this fixed AIDE scope only. Reported changes are review items, not malware verdicts or file counts. Compare them with software updates and work you expected. This view runs no scans, restores, deletions or containment.'));
  children.push(detail);panel.replaceChildren(...children);
  renderBackupEvidence(panel,backupEvidence,backupOpen);
}

function renderBackupEvidence(panel, value, open=false) {
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const unavailable=()=>panel.append(node('p','External backup evidence unavailable · no backup availability or restore-test result verified.'));
  const fields=__BACKUP_DETAILS__, keys=['schema','state','reason',...fields];
  const object=v=>v&&typeof v==='object'&&!Array.isArray(v);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s.replace('Z','.000Z');
  const id=s=>typeof s==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(s);
  const digest=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
  if(!object(value)||Object.keys(value).sort().join(',')!==[...keys].sort().join(',')||value.schema!=='megalodon-backup-evidence-v1'){unavailable();return;}
  if(value.state==='unavailable'){
    if(!['missing','malformed','untrusted','conflicting','incomplete','expired','unreadable'].includes(value.reason)||!fields.every(k=>value[k]===null)){unavailable();return;}
    panel.append(node('p','External backup evidence unavailable · '+value.reason+'. No restoration eligibility is inferred.'));return;
  }
  if(value.state!=='verified_external_evidence'||value.reason!=='verified'
      ||!['backup_id','source_id','test_id','verifier_id'].every(k=>id(value[k]))
      ||!['artifact_sha256','source_snapshot_sha256'].every(k=>digest(value[k]))
      ||!['backup_created_at','backup_verified_at','test_completed_at','approved_at','expires_at'].every(k=>stamp(value[k]))
      ||!['not_assessed','reported_legitimate_changes'].includes(value.conflicts)){unavailable();return;}
  const created=Date.parse(value.backup_created_at),verified=Date.parse(value.backup_verified_at),tested=Date.parse(value.test_completed_at),approved=Date.parse(value.approved_at),expires=Date.parse(value.expires_at),now=Date.now();
  if(!(created<=verified&&verified<=tested&&tested<=approved&&approved<=now&&now<expires&&expires<=verified+7*86400000)){unavailable();return;}
  const detail=document.createElement('details');detail.id='recovery-backup-details';detail.open=open;
  detail.append(node('summary','Pinned external backup and restore-test evidence'));
  const facts=document.createElement('dl');
  for(const [label,text] of [['Backup / source',value.backup_id+' / '+value.source_id],['Backup recorded',value.backup_created_at],['Availability observed externally',value.backup_verified_at],['Isolated full-snapshot test',value.test_id+' · '+value.test_completed_at],['Independent verifier (operator-pinned)',value.verifier_id],['Approval / expiry',value.approved_at+' / '+value.expires_at],['Artifact SHA-256',value.artifact_sha256],['Source snapshot SHA-256',value.source_snapshot_sha256]])facts.append(node('dt',label),node('dd',text));
  detail.append(facts,node('p',value.conflicts==='reported_legitimate_changes'?'External evidence reports legitimate source changes. Preserve current work; restoration remains unavailable.':'Conflicts with current work are not assessed. Restoration remains unavailable.'),node('p','Receipt bytes match separately approved pins. MEGALODON did not inspect this backup or run this restore test. These records do not certify a clean backup, current availability, malicious activity or a safe restoration.'));
  panel.append(detail);
}
'''
RECOVERY_READINESS_JS = RECOVERY_READINESS_JS.replace('__AIDE_SCOPE__', json.dumps(list(AIDE_SCOPE)))
RECOVERY_READINESS_JS = RECOVERY_READINESS_JS.replace('__BACKUP_DETAILS__', json.dumps(list(DETAILS)))
