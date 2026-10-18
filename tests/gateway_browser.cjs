const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
 const {code,first,changed,baseline,offline}=JSON.parse(input);
 function element(tag=''){const n={tag,textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const document={createElement:element};const context={document};vm.runInNewContext(code,context);
 const text=n=>n.textContent+' '+n.children.map(text).join(' ');
 const render=value=>{const panel=element('div');context.renderGateway(panel,value);return panel;};
 for(const value of [first,changed,baseline,offline])assert.equal(context.validGateway(value),true);
 assert.match(text(render(first)),/Gateway 192\.168\.1\.1 on eth0 · MAC aa:bb:cc:00:00:01 · ARP entry learned · \d+ resolved neighbors · checked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
 assert.match(text(render(first)),/No earlier observation of this gateway[\s\S]*No review items/);
 const panel=render(changed),body=text(panel);
 assert.match(body,/first MAC this session saw for this gateway/);assert.match(body,/Review · Gateway MAC address changed/);
 assert.match(body,/Review · Gateway MAC address shared/);assert.match(body,/ATT&CK technique\s+T1557\.002/);assert.match(body,/Shared MAC addresses \(1\)/);
 assert.ok(panel.children.some(c=>c.dataset.rule==='GATEWAY_MAC_CHANGED'));
 assert.match(text(render(baseline)),/Compared with the recorded baseline from \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
 assert.match(text(render(offline)),/No IPv4 default gateway is visible[\s\S]*Coverage gaps/);
 // Forged authority, shapes and identifiers never render or claim a check.
 const first0=patch=>({...changed,findings:[{...changed.findings[0],...patch},...changed.findings.slice(1)]});
 for(const bad of [null,{...first,action_authority:'block'},{...first,schema:'x'},{...first,state:'unavailable'},{...first,extra:1},
   {...first,gateway:{...first.gateway,ip:'192.168.001.1'}},{...first,gateway:{...first.gateway,mac:'AA:BB:CC:00:00:01'}},
   {...first,gateway:{...first.gateway,entry:'absent'}},{...first,gateway:{...first.gateway,interface:'<img src=x>'}},
   first0({level:'note'}),first0({rule:'BLOCKED'}),first0({action_status:'blocked'}),first0({attack:'T1059'}),first0({extra:1}),
   {...changed,shared:[{...changed.shared[0],addresses:['192.168.1.1']}]},{...changed,shared_total:0},
   {...first,compared_with:{source:'guess',interface:'eth0',ip:'192.168.1.1',mac:'aa:bb:cc:00:00:01',at:first.reviewed_at}},
   {...first,trust:'known_clean'},{...first,tables_complete:'yes'},{...first,gaps:Array(9).fill('gap')}]){
   const out=text(render(bad));assert.match(out,/unavailable|could not be read/);assert.doesNotMatch(out,/Gateway \d|Review ·/);
 }
 console.log('gateway panel passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
