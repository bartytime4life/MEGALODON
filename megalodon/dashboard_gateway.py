"""Review-only presentation for the passive local gateway review."""
import json

from .gateway_review import ATTACK, MAX_GROUP_ADDRESSES, MAX_GROUPS, RULES, SCHEMA, TRUST

GATEWAY_HTML = r'''
    <h6 id="gateway-title">Local gateway</h6>
    <p class="support-config-note">Passive check of the IPv4 default gateway and the ARP cache this computer already holds. Nothing is sent, probed or changed. A changed or shared MAC address is a reason to look, not proof of ARP spoofing; a replaced router, failover, proxy ARP and virtual machines cause the same signals. Record an expected gateway with <code>python -m megalodon.gateway_review baseline</code>; until then the HUD compares with the first MAC it sees for each gateway in this session.</p>
    <div id="gateway-review" aria-labelledby="gateway-title"><p>The local gateway has not been checked.</p></div>
'''

GATEWAY_CSS = r'''
#gateway-review { min-width:0; overflow-wrap:anywhere; }
#gateway-review > details { border-top:1px solid #3e6877; padding:.8rem 0; }
#gateway-review summary { cursor:pointer; min-height:44px; line-height:1.6; color:#edf7fa; }
#gateway-review summary:focus-visible { outline:3px solid #e9bc6b; outline-offset:3px; }
#gateway-review dl { margin:.4rem 0; }
#gateway-review dt { font-weight:700; margin-top:.4rem; }
#gateway-review dd { margin:0; line-height:1.6; }
#gateway-review li { margin:.4rem 0; line-height:1.6; }
'''

GATEWAY_JS = r'''
function validGateway(p) {
  const text=(s,max)=>typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s);
  const stamp=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)&&Number.isFinite(Date.parse(s));
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  const keys=(o,names)=>!!o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join()===[...names].sort().join();
  const ip=s=>typeof s==='string'&&/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s);
  const mac=s=>typeof s==='string'&&/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(s);
  const iface=s=>typeof s==='string'&&/^[A-Za-z0-9_.:@-]{1,15}$/.test(s);
  const rules=__RULES__;
  const gateway=g=>g===null||(keys(g,['ip','interface','mac','entry'])&&ip(g.ip)&&iface(g.interface)
    &&(['complete','permanent'].includes(g.entry)?mac(g.mac):(['incomplete','absent'].includes(g.entry)&&g.mac===null)));
  const compared=c=>c===null||(keys(c,['source','interface','ip','mac','at'])&&['baseline','session'].includes(c.source)&&iface(c.interface)&&ip(c.ip)&&mac(c.mac)&&stamp(c.at));
  const group=g=>keys(g,['interface','mac','addresses','count'])&&iface(g.interface)&&mac(g.mac)&&Array.isArray(g.addresses)
    &&g.addresses.length>=2&&g.addresses.length<=__ADDRESSES__&&g.addresses.every(ip)&&new Set(g.addresses).size===g.addresses.length&&count(g.count)&&g.count>=g.addresses.length;
  const finding=f=>Object.hasOwn(rules,f?.rule)&&keys(f,['rule','level','attack','detail','action_status'].concat(['GATEWAY_MAC_SHARED','SHARED_MAC'].includes(f.rule)?['mac']:[]))
    &&f.level===rules[f.rule]&&f.attack===__ATTACK__&&text(f.detail,512)&&f.action_status==='not_attempted'&&(f.mac===undefined||mac(f.mac));
  return keys(p,['schema','reviewed_at','gateway','other_default_routes','neighbors','shared','shared_total','tables_complete','compared_with','findings','gaps','trust','action_authority'])
    &&p.schema===__SCHEMA__&&p.action_authority==='none'&&p.trust===__TRUST__&&stamp(p.reviewed_at)&&gateway(p.gateway)&&compared(p.compared_with)
    &&count(p.other_default_routes)&&count(p.neighbors)&&typeof p.tables_complete==='boolean'
    &&Array.isArray(p.shared)&&p.shared.length<=__GROUPS__&&p.shared.every(group)&&count(p.shared_total)&&p.shared_total>=p.shared.length
    &&Array.isArray(p.findings)&&p.findings.length<=__GROUPS__+1&&p.findings.every(finding)
    &&Array.isArray(p.gaps)&&p.gaps.length<=8&&p.gaps.every(g=>text(g,256));
}
function renderGateway(panel, payload) {
  if(!panel)return;
  const node=(tag,text)=>{const n=document.createElement(tag);n.textContent=text;return n;};
  const time=s=>s.replace('T',' ').replace('Z',' UTC');
  if(!payload||payload.schema!==__SCHEMA__||payload.action_authority!=='none'){
    panel.replaceChildren(node('p','Local gateway review is unavailable.'));return;
  }
  if(!validGateway(payload)){
    panel.replaceChildren(node('p','The local gateway could not be read on this PC.'));return;
  }
  const g=payload.gateway,entries={complete:'ARP entry learned',permanent:'static ARP entry',incomplete:'ARP entry unresolved',absent:'no ARP entry yet'};
  const head=g?`Gateway ${g.ip} on ${g.interface} · `+(g.mac?`MAC ${g.mac} · `:'')+entries[g.entry]:'No IPv4 default gateway is visible';
  const children=[node('p',`${head} · ${payload.neighbors} resolved neighbors · checked ${time(payload.reviewed_at)}`)];
  const c=payload.compared_with;
  children.push(node('p',c?(c.source==='baseline'?`Compared with the recorded baseline from ${time(c.at)} (MAC ${c.mac}).`:`Compared with the first MAC this session saw for this gateway, at ${time(c.at)} (MAC ${c.mac}).`)
    :'No earlier observation of this gateway to compare with yet.'));
  if(!payload.findings.length)children.push(node('p','No review items.'));
  const labels={GATEWAY_MAC_CHANGED:'Gateway MAC address changed',GATEWAY_MAC_SHARED:'Gateway MAC address shared',GATEWAY_CHANGED:'Default gateway changed',SHARED_MAC:'Shared MAC address'};
  for(const f of payload.findings){
    const item=document.createElement('details');item.dataset.rule=f.rule;
    item.append(node('summary',`${f.level==='review'?'Review':'Note'} · ${labels[f.rule]}`));
    const facts=document.createElement('dl');
    for(const [label,value] of [['Detail',f.detail],['ATT&CK technique',f.attack]])facts.append(node('dt',label),node('dd',value));
    item.append(facts);children.push(item);
  }
  if(payload.shared.length){
    const item=document.createElement('details');item.append(node('summary',`Shared MAC addresses (${payload.shared_total})`));
    const list=document.createElement('ul');
    for(const s of payload.shared)list.append(node('li',`${s.mac} on ${s.interface} · ${s.addresses.join(', ')}${s.count>s.addresses.length?` and ${s.count-s.addresses.length} more`:''}`));
    item.append(list);children.push(item);
  }
  if(payload.gaps.length){
    const item=document.createElement('details');item.append(node('summary',`Coverage gaps (${payload.gaps.length})`));
    const list=document.createElement('ul');for(const gap of payload.gaps)list.append(node('li',gap));
    item.append(list);children.push(item);
  }
  panel.replaceChildren(...children);
}
'''
for _name, _value in (('__RULES__', RULES), ('__ATTACK__', ATTACK), ('__SCHEMA__', SCHEMA), ('__TRUST__', TRUST),
                      ('__GROUPS__', MAX_GROUPS), ('__ADDRESSES__', MAX_GROUP_ADDRESSES)):
    GATEWAY_JS = GATEWAY_JS.replace(_name, json.dumps(_value))
