const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
 const {code,fixture,unbound_model,model_test}=JSON.parse(input),nodes=new Map(),timers=new Map(),requests=[];
 let payload={...fixture,model:{...unbound_model,connection_state:'reachable',response_test:model_test}},seq=0;
 function element(){return {textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){}};}
 const get=id=>{if(id==='workspace-setup')return null;if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const context={localHudLaunch:{},document:{hidden:false,getElementById:get,createElement:element,addEventListener(){}},TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(path,opts)=>{requests.push({path,opts});return {status:200,ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
 const settle=()=>new Promise(resolve=>setImmediate(resolve)),click=id=>get(id).events.click(),posts=()=>requests.filter(x=>x.opts.method==='POST');
 const poll=async delay=>{const entry=[...timers.entries()].find(([,t])=>t.ms===delay);assert.ok(entry);timers.delete(entry[0]);await entry[1].fn();await settle();};
 vm.runInNewContext(code,context);await settle();assert.equal(requests.length,0);
 await click('support-apps-configure');await settle();assert.equal(posts().length,0);
 assert.match(get('support-ollama-connection').textContent,/Ollama connected/);
 assert.equal(get('support-model-test').disabled,false);assert.equal(get('support-model-load').disabled,true);
 get('support-model-compute').value='cpu';get('support-model-compute').events.change();assert.equal(get('support-model-test').disabled,true,'save changed preferences before testing');
 payload={...payload,job:{...fixture.job,state:'finished',action:'model_select'}};
 // Reopening starts a fresh controller, with the already saved server choice.
 const clean={...fixture,model:{...payload.model,compute_mode:'cpu'}};payload=clean;
 // Exercise the actual test action in a new controller without a dirty field.
 nodes.clear();timers.clear();requests.length=0;vm.runInNewContext(code,context);await click('support-apps-configure');await settle();
 await click('support-model-test');assert.equal(posts().length,1);
 assert.deepEqual(JSON.parse(posts()[0].opts.body),{action:'model_test'});
 assert.equal(posts()[0].opts.headers['X-Megalodon-Config-Token'],fixture.token);
 assert.ok(!JSON.stringify([...nodes.values()]).includes(fixture.token));
 payload={...clean,job:{...fixture.job,state:'running',action:'model_test'},model:{...clean.model,response_test:{...model_test,state:'running',started_at:'2026-11-03T04:00:00Z'}}};
 await poll(10000);assert.equal(get('support-model-test').disabled,true);assert.equal(get('support-model-test-cancel').disabled,false);
 await click('support-model-test-cancel');assert.deepEqual(JSON.parse(posts().at(-1).opts.body),{action:'model_test_cancel'});
 payload={...clean,job:{...fixture.job,state:'finished',action:'model_test'},model:{...clean.model,response_test:{...model_test,state:'passed',message:'Local response test passed.',finished_at:'2026-11-03T04:00:02Z',duration_ms:2000}}};
 await poll(2000);assert.match(get('support-model-test-status').textContent,/Local response test passed/);assert.equal(get('support-model-load').disabled,true,'fixed probe never enables operational loading');
 const total=posts().length;await poll(10000);assert.equal(posts().length,total,'polling does not rerun a model test');
 console.log('fixed Ollama model test UI behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
