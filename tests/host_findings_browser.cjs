const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',()=>{
  const {code,fixture}=JSON.parse(input);
  function element(tag){return {tag,textContent:'',dataset:{},children:[],attrs:{},open:false,
    append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},
    setAttribute(key,value){this.attrs[key]=value;}};}
  const panel=element('div'),flatten=n=>[n.textContent,...n.children.map(flatten)].join(' ');
  const nodes=n=>[n,...n.children.flatMap(nodes)];
  let effects=0;
  const noEffect=()=>{effects++;throw Error('Unexpected effect');};
  class Clock extends Date {static now(){return Date.parse('2026-10-17T12:00:00Z');}}
  const context={document:{createElement:element},Date:Clock,TextEncoder,fetch:noEffect,localStorage:{setItem:noEffect},setTimeout:noEffect};
  vm.runInNewContext(code,context);
  const render=value=>{context.renderHostFindings(panel,value);return flatten(panel);};
  let shown=render(fixture);
  assert.match(shown,/1 configuration warnings · 1 hardening suggestions/);
  assert.match(shown,/SSH-7408/);assert.match(shown,/line 5/);assert.match(shown,/Observed 2026-10-17 12:00:00 UTC/);
  assert.match(shown,/file changes reported/);assert.match(shown,/AIDE exit status 5 · change categories: added, changed/);
  assert.match(shown,/not file counts/);assert.match(shown,/initial baseline is not known clean/);
  assert.match(shown,/Report SHA-256/);assert.match(shown,/Baseline SHA-256/);
  assert.match(shown,/not attempted by this view/);assert.doesNotMatch(shown,/private-detail|never run me|invalid\.test|private-host/);
  assert.deepEqual(nodes(panel).filter(n=>n.tag==='a').map(n=>n.attrs.href),['#host-security-audit','#host-security-check']);
  panel.children[0].open=true;render(fixture);assert.equal(panel.children[0].open,true,'polling preserves expanded evidence');
  let copy=structuredClone(fixture);copy.audit.checked_at='2026-10-01T12:00:00Z';shown=render(copy);assert.match(shown,/older than 7 days/);assert.match(shown,/Recheck before relying/);
  copy=structuredClone(fixture);copy.integrity.review.operation='baseline';copy.integrity.review.exit_code=0;Object.keys(copy.integrity.metrics).forEach(k=>copy.integrity.metrics[k]=0);
  shown=render(copy);assert.match(shown,/initial baseline recorded/);assert.doesNotMatch(shown,/no differences reported/);
  copy=structuredClone(fixture);copy.audit_state='legacy';delete copy.audit.review;shown=render(copy);assert.match(shown,/legacy aggregate only/);assert.match(shown,/no bound report identity/);
  for(const state of ['missing','unavailable']){copy=structuredClone(fixture);copy.audit_state=state;copy.audit=null;shown=render(copy);assert.match(shown,state==='missing'?/no saved observation/:/evidence unavailable/);assert.doesNotMatch(shown,/SSH-7408/);}
  const mutations=[
    f=>f.audit.review.items[0].kind='verified_incident',f=>f.audit.review.items[0].text='bad\u202etext',
    f=>f.audit.review.items[0].line=0,f=>f.audit.metrics.warnings=true,
    f=>f.audit.review.items.push(...f.audit.review.items),f=>f.audit.checked_at='2026-02-30T12:00:00Z',
    f=>f.audit.checked_at='2026-10-17T12:06:00Z',f=>f.audit.review.omitted=99,
    f=>f.audit.review.report_sha256='oops',f=>f.audit_state='current',
    f=>f.integrity.review.exit_code=0,
  ];
  for(const mutate of mutations){copy=structuredClone(fixture);mutate(copy);shown=render(copy);assert.match(shown,/Malformed or contradictory/);}
  copy=structuredClone(fixture);copy.audit.review.items[0].text='<img src=x onerror=alert(1)>';
  shown=render(copy);assert.match(shown,/<img src=x/);assert.equal(nodes(panel).filter(n=>n.tag==='img').length,0);
  shown=render(null);assert.match(shown,/findings unavailable/);assert.doesNotMatch(shown,/SSH-7408|file changes reported/);
  assert.equal(effects,0,'rendering has no host, storage, network, timer or action effects');
  console.log('host findings review projection passed');
});
