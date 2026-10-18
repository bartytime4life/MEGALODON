const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
 const {code,result,empty,pending,wide}=JSON.parse(input);
 function element(tag=''){const n={tag,textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const document={createElement:element};const context={document};vm.runInNewContext(code,context);
 const text=n=>n.textContent+' '+n.children.map(text).join(' ');
 const render=value=>{const panel=element('div');context.renderProcessNetwork(panel,value);return panel;};
 for(const value of [result,empty,wide])assert.equal(context.validProcessNetwork(value),true);
 const panel=render(result),body=text(panel);
 assert.match(body,/4 programs hold network sockets · 3 need review · \d+ of this account's processes reviewed · checked \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
 assert.match(body,/Review · x · \/home\/u\/\.cache\/x/);assert.match(body,/Program file deleted · ATT&CK T1070\.004/);
 assert.match(body,/Program runs from memory · ATT&CK T1620/);assert.match(body,/Program in a temporary folder · ATT&CK T1105/);
 assert.match(body,/curl · \/usr\/bin\/curl[\s\S]*Remote peers\s+203\.0\.113\.10:443, 203\.0\.113\.9:443/);
 assert.equal(panel.children.filter(c=>c.dataset.review==='true').length,3);
 assert.match(text(render(empty)),/No program of this account holds a non-loopback network socket/);
 assert.match(text(render(pending)),/Reviewing programs on the network/);assert.equal(context.processPending(pending),true);
 assert.match(text(render(wide)),/\u{1F600}+\.\.\./u);
 const hostile=JSON.parse(JSON.stringify(result));hostile.programs[0].executable='<img src=x onerror=alert(1)>';assert.match(text(render(hostile)),/<img src=x/);
 // Forged authority, shapes and flags never render a program.
 const first=patch=>({...result,programs:[{...result.programs[0],...patch},...result.programs.slice(1)]});
 for(const bad of [null,{...result,action_authority:'kill'},{...result,action_status:'stopped'},{...result,schema:'x'},{...result,extra:1},
   {...pending,extra:1},first({flags:['KILLED']}),first({flags:['EXECUTABLE_DELETED','EXECUTABLE_DELETED']}),first({pid:42}),first({processes:0}),
   first({established:0,listening:0,other:0}),first({hash_status:'hashed',sha256:null}),first({hash_status:'hashed',sha256:'A'.repeat(64)}),first({hash_status:'skipped'}),first({hash_status:'too_large',sha256:'a'.repeat(64)}),first({remotes:['example.com:443']}),first({remotes_total:0}),first({executable:''}),
   {...result,programs_total:1},{...result,flagged_total:0},{...result,programs:Array(17).fill(result.programs[3])},{...result,scan_complete:'yes'},
   {...result,gaps:Array(7).fill('gap')},{...result,reviewed_at:'yesterday'}]){
   const out=text(render(bad));assert.match(out,/unavailable|could not be read/);assert.doesNotMatch(out,/Review ·|Remote peers/);
   assert.equal(context.processPending(bad),false);
 }
 console.log('process network panel passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
