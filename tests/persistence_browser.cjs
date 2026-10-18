const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
 const {code,fresh,changed}=JSON.parse(input);
 function element(tag=''){const n={tag,textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const document={createElement:element};const context={document};vm.runInNewContext(code,context);
 const text=n=>n.textContent+' '+n.children.map(text).join(' ');
 const render=value=>{const panel=element('div');context.renderPersistence(panel,value);return panel;};
 // Before a baseline: findings that need none, an invitation to record one, and the only state that allows it.
 let body=text(render(fresh));
 assert.match(body,/startup items reviewed · no baseline recorded · checked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
 assert.match(body,/Writable by any account/);assert.match(body,/Record an initial baseline|Coverage gaps/);
 assert.equal(context.persistenceAllowsBaseline(fresh),true);
 // After a baseline: change findings with their ATT&CK technique, and no further HUD baseline.
 const panel=render(changed);body=text(panel);
 assert.match(body,/baseline \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);assert.match(body,/Added since baseline/);assert.match(body,/Changed since baseline/);
 assert.match(body,/ATT&CK technique\s+T\d{4}/);assert.ok(panel.children.some(c=>c.dataset.rule==='ADDED'));
 assert.equal(context.persistenceAllowsBaseline(changed),false);
 // A truncated list says so.
 const full={...changed,findings:Array(16).fill(changed.findings[0]),findings_total:56};
 assert.match(text(render(full)),/Showing the first 16 of 56 review items/);
 // Hostile text renders as text, never markup.
 const hostile=JSON.parse(JSON.stringify(changed));hostile.findings[0].path='<img src=x onerror=alert(1)>';
 assert.match(text(render(hostile)),/<img src=x/);
 // Forged authority, unknown states, extra fields and inconsistent findings never render or allow a baseline.
 const first=patch=>({...changed,findings:[{...changed.findings[0],...patch},...changed.findings.slice(1)]});
 for(const bad of [null,{...fresh,action_authority:'remove'},{...fresh,schema:'x'},{...fresh,state:'unavailable'},{...fresh,command:'rm'},
   first({rule:'DELETED'}),first({action_status:'removed'}),first({attack:'T1059'}),first({category:'kernel'}),first({extra:1}),
   {...changed,findings_total:0},{...changed,findings:changed.findings.slice(1)},{...fresh,items:513},{...fresh,baseline_at:'yesterday'},
   {...fresh,trust:'known_clean'},{...fresh,gaps:Array(9).fill('gap')},{...fresh,inventory_truncated:'no'}]){
   const out=text(render(bad));assert.match(out,/unavailable|could not be read/);assert.doesNotMatch(out,/since baseline|any account/);
   assert.equal(context.persistenceAllowsBaseline(bad),false);
 }
 console.log('persistence panel passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
