const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
  const {code,payloads}=JSON.parse(input);
  function element(tag='div'){
    const n={tagName:tag.toUpperCase(),textContent:'',children:[],open:false,
      append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};
    Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink');}});return n;
  }
  const context={document:{createElement:element},fetch(){throw Error('panel performed I/O');}};
  vm.runInNewContext(code,context);
  const panel=element(),text=n=>n.textContent+' '+n.children.map(text).join(' ');
  function render(payload){context.renderRecoveryReadiness(panel,payload);return text(panel);}
  for(const payload of Object.values(payloads)){
    const body=render(payload);
    assert.match(body,/Host file restoration unavailable/);
    assert.match(body,/no recoverable earlier version verified/);
    assert.match(body,/legitimate installs and edits must be preserved/);
    assert.doesNotMatch(body,/Synthetic private report/);
    assert.equal(panel.children.filter(n=>n.tagName==='DETAILS').length,1);
  }
  assert.match(render(payloads.baseline),/Initial baseline recorded · no comparison/);
  assert.doesNotMatch(render(payloads.baseline),/Comparison reports no differences/);
  assert.match(render(payloads.comparison),/change categories: added, removed, changed/);
  assert.match(render(payloads.no_differences),/no differences within its limited scope/);
  assert.match(render(payloads.legacy),/Legacy aggregate/);
  assert.match(render(payloads.old),/older than 7 days/);
  assert.match(render(payloads.missing),/No validated baseline observed/);
  const clone=()=>JSON.parse(JSON.stringify(payloads.comparison));
  const patch=(key,value)=>Object.assign(clone(),{[key]:value});
  const bad=[null,[],{},patch('schema','unknown'),patch('state','ready'),patch('restore_eligible',true),
    patch('action_authority','restore'),patch('action_status','applied'),patch('backup_state','ready'),
    patch('causality_state','proven'),patch('conflict_state','resolved'),patch('baseline_state','clean'),
    patch('scope',['/']),patch('checked_at',null),patch('checked_at','2026-02-30T12:00:00Z'),
    patch('checked_at','9999-01-01T00:00:00Z'),patch('change_categories',['changed','added']),
    patch('change_categories',['added','added']),patch('change_categories',['<img src=x onerror=alert(1)>']),
    patch('change_categories',null),patch('integrity_operation','restore'),patch('integrity_operation','baseline'),
    patch('integrity_state','legacy'),patch('integrity_state','missing'),{...clone(),command:'restore /private'}];
  const missing=clone();delete missing.conflict_state;bad.push(missing);
  for(const payload of bad){
    render(payloads.comparison);const body=render(payload);
    assert.match(body,/Recovery readiness is unavailable/);
    assert.doesNotMatch(body,/change categories:|Known-good host backup|<img/);
    assert.equal(panel.children.length,1,'failed read must clear earlier details');
  }
  render(payloads.comparison);panel.children.find(n=>n.tagName==='DETAILS').open=true;
  render(payloads.comparison);assert.equal(panel.children.find(n=>n.tagName==='DETAILS').open,true);
  console.log('recovery readiness panel passed');
});
