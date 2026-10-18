"""Review-only presentation for this account's programs that hold network sockets."""
import json

from .process_network import HASH_STATUSES, MAX_GAPS, MAX_HASH_FILE, MAX_PROGRAMS, MAX_REMOTES, RULES, SCHEMA

PROCESS_NETWORK_HTML = r'''
    <h6 id="process-network-title">Programs on the network</h6>
    <p class="support-config-note">Read-only map of this account's TCP and UDP sockets to the programs holding them, by executable path and process name. Command lines are never read, and nothing is stopped or changed. Processes of other accounts and of root are not visible, and loopback-only sockets are left out. A flag is a reason to look: updates replace running programs, and installers and developer tools also run from temporary folders.</p>
    <div id="process-network-review" aria-labelledby="process-network-title"><p>Programs on the network have not been checked.</p></div>
'''

PROCESS_NETWORK_CSS = r'''
#process-network-review { min-width:0; overflow-wrap:anywhere; }
#process-network-review > details { border-top:1px solid #3e6877; padding:.8rem 0; }
#process-network-review summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#process-network-review summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#process-network-review dl { margin:.4rem 0; }
#process-network-review dt { font-weight:700; margin-top:.4rem; }
#process-network-review dd { margin:0; line-height:1.6; }
#process-network-review li { margin:.4rem 0; line-height:1.6; }
'''

PROCESS_NETWORK_JS = r'''
function processPending(p){return !!p&&typeof p==='object'&&!Array.isArray(p)&&Object.keys(p).sort().join()==='action_authority,schema,state'
  &&p.schema===__SCHEMA__&&p.state==='pending'&&p.action_authority==='none';}
function validProcessNetwork(p) {
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s));
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  const keys=(o,names)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join()===[...names].sort().join();
  const endpoint=s=>typeof s==='string'&&s.length<=64&&/^((\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:.]+\]):\d{1,5}$/.test(s);
  const rules=__RULES__;
  const program=r=>keys(r,['program','executable','parent','processes','established','listening','other','remotes','remotes_total','flags','sha256','hash_status'])
    &&__HASH_STATUSES__.includes(r.hash_status)&&(r.hash_status==='hashed'?/^[0-9a-f]{64}$/.test(r.sha256):r.sha256===null)
    &&text(r.program,256)&&text(r.executable,256)&&text(r.parent,256)&&count(r.processes)&&r.processes>0
    &&count(r.established)&&count(r.listening)&&count(r.other)&&r.established+r.listening+r.other>0
    &&Array.isArray(r.remotes)&&r.remotes.length<=__REMOTES__&&r.remotes.every(endpoint)&&new Set(r.remotes).size===r.remotes.length
    &&count(r.remotes_total)&&r.remotes_total>=r.remotes.length
    &&Array.isArray(r.flags)&&r.flags.length<=2&&r.flags.every(f=>Object.hasOwn(rules,f))&&new Set(r.flags).size===r.flags.length;
  return keys(p,['schema','reviewed_at','programs','programs_total','flagged_total','processes_reviewed','tables_complete','scan_complete','gaps','action_status','action_authority'])
    &&p.schema===__SCHEMA__&&p.action_authority==='none'&&p.action_status==='not_attempted'&&stamp(p.reviewed_at)
    &&Array.isArray(p.programs)&&p.programs.length<=__PROGRAMS__&&p.programs.every(program)
    &&count(p.programs_total)&&p.programs_total>=p.programs.length&&count(p.flagged_total)&&p.flagged_total<=p.programs_total
    &&p.flagged_total>=p.programs.filter(r=>r.flags.length).length&&count(p.processes_reviewed)
    &&typeof p.tables_complete==='boolean'&&typeof p.scan_complete==='boolean'
    &&Array.isArray(p.gaps)&&p.gaps.length<=__GAPS__&&p.gaps.every(g=>text(g,256));
}
function renderProcessNetwork(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const time=s=>s.replace('T',' ').replace('Z',' UTC');
  if(!payload||payload.schema!==__SCHEMA__||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Programs on the network are unavailable.'));return;
  }
  if(processPending(payload)){
    panel.replaceChildren(node('p','Reviewing programs on the network. Results appear at the next status check.'));return;
  }
  if(!validProcessNetwork(payload)){
    panel.replaceChildren(node('p','Programs on the network could not be read on this PC.'));return;
  }
  const rules=__RULES__,labels={EXECUTABLE_DELETED:'Program file deleted',EXECUTABLE_IN_MEMORY:'Program runs from memory',EXECUTABLE_IN_TEMPORARY:'Program in a temporary folder'};
  const children=[node('p',`${payload.programs_total} programs hold network sockets · ${payload.flagged_total} need review · ${payload.processes_reviewed} of this account's processes reviewed · checked ${time(payload.reviewed_at)}`)];
  if(!payload.programs.length)children.push(node('p','No program of this account holds a non-loopback network socket.'));
  for(const r of payload.programs){
    const item=document.createElement('details');if(r.flags.length)item.dataset.review='true';
    item.append(node('summary',(r.flags.length?'Review · ':'')+`${r.program} · ${r.executable}`));
    const facts=document.createElement('dl');
    const remotes=r.remotes.length?r.remotes.join(', ')+(r.remotes_total>r.remotes.length?` and ${r.remotes_total-r.remotes.length} more`:''):'none';
    const hashes={hashed:r.sha256,too_large:'not hashed: larger than __HASH_MIB__ MiB',unreadable:'not hashed: the file could not be read',deferred:'not hashed yet: this review reached its read or time limit',changed:'not hashed: the file changed while it was read'};
    for(const [label,value] of [['Executable',r.executable],['SHA-256',hashes[r.hash_status]],['Parent process',r.parent],['Processes',String(r.processes)],
      ['Sockets',`${r.established} connected · ${r.listening} listening · ${r.other} other`],['Remote peers',remotes]])facts.append(node('dt',label),node('dd',value));
    for(const flag of r.flags)facts.append(node('dt',`${labels[flag]} · ATT&CK ${rules[flag][0]}`),node('dd',rules[flag][1]));
    item.append(facts);children.push(item);
  }
  if(payload.programs_total>payload.programs.length)children.push(node('p',`Showing the first ${payload.programs.length} of ${payload.programs_total} programs, those needing review first. python -m megalodon.process_network lists the same first ${__PROGRAMS__}.`));
  if(payload.gaps.length){
    const item=document.createElement('details');item.append(node('summary',`Coverage gaps (${payload.gaps.length})`));
    const list=document.createElement('ul');for(const gap of payload.gaps)list.append(node('li',gap));
    item.append(list);children.push(item);
  }
  panel.replaceChildren(...children);
}
'''
for _name, _value in (('__GAPS__', MAX_GAPS), ('__HASH_MIB__', MAX_HASH_FILE // 1048576), ('__HASH_STATUSES__', list(HASH_STATUSES)), ('__RULES__', RULES), ('__SCHEMA__', SCHEMA), ('__PROGRAMS__', MAX_PROGRAMS), ('__REMOTES__', MAX_REMOTES)):
    PROCESS_NETWORK_JS = PROCESS_NETWORK_JS.replace(_name, json.dumps(_value))
