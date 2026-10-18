const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
 const {code,payload}=JSON.parse(input);
 function element(tag=''){const n={tag,textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const document={createElement:element};const context={document};vm.runInNewContext(code,context);
 const text=n=>n.textContent+' '+n.children.map(text).join(' ');
 const render=value=>{const panel=element('div');context.renderHardening(panel,value);return panel;};
 // A real review: failures first, with remediation; passes collapsed.
 let panel=render(payload);const body=text(panel);
 assert.match(panel.children[0].textContent,/\d+ fail · .* · checked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
 assert.equal(panel.children[1].tag,'details');assert.equal(panel.children[1].dataset.state,'fail');
 assert.match(body,/Suggested remediation/);assert.match(body,/ATT&CK mitigation\s+M\d{4}/);assert.match(body,/Passing and not-applicable checks/);
 const states=panel.children.slice(1).map(c=>c.dataset.state).filter(Boolean);
 assert.deepEqual(states,[...states].sort((a,b)=>['fail','review','unknown'].indexOf(a)-['fail','review','unknown'].indexOf(b)),'fail, then review, then unknown');
 // Hostile text renders as text, never markup.
 const hostile=JSON.parse(JSON.stringify(payload));hostile.checks[0].observed='<img src=x onerror=alert(1)>';
 assert.match(text(render(hostile)),/<img src=x/);
 // Forged authority, unknown states, bad shapes and unavailable reviews never render checks.
 for(const bad of [null,{...payload,action_authority:'apply'},{...payload,schema:'x'},{...payload,state:'unavailable'},{...payload,state:'running'},
   {...payload,checks:[{...payload.checks[0],state:'fixed'}]},{...payload,checks:[{...payload.checks[0],action_status:'applied'}]},
   {...payload,checks:[{...payload.checks[0],mitigation:'T1059'}]},{...payload,checks:Array(33).fill(payload.checks[0])},{...payload,reviewed_at:'yesterday'}]){
   const out=text(render(bad));assert.match(out,/unavailable|could not be read/);assert.doesNotMatch(out,/Suggested remediation/);
 }
 console.log('hardening panel passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
