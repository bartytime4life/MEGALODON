const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',s=>input+=s);
process.stdin.on('end',async()=>{
 const {code,fixture,unbound_model,model_test}=JSON.parse(input),nodes=new Map(),timers=new Map(),requests=[],issues=[];let seq=0;
 let payload;
 function element(){return {textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){}};}
 const get=id=>{if(id==='workspace-setup')return null;if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const context={localHudLaunch:{},document:{hidden:false,getElementById:get,createElement:element,addEventListener(){}},TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(path,opts)=>{requests.push({path,opts});return {status:200,ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
 const settle=()=>new Promise(resolve=>setImmediate(resolve)),click=id=>get(id).events.click(),posts=()=>requests.filter(x=>x.opts.method==='POST');
 const poll=async()=>{const entry=[...timers.entries()].find(([,t])=>t.ms===10000);assert.ok(entry);timers.delete(entry[0]);await entry[1].fn();await settle();};
 const model={...unbound_model,selection_state:'restored',connection_state:'reachable',options:[{name:unbound_model.model,digest:'b'.repeat(64),size_bytes:2**30}],compute_mode:'cpu',response_test:{...model_test,selection_saved:true,state:'passed',model:unbound_model.model,message:'Local response test passed.',finished_at:'2026-11-03T04:00:02Z'}};
 payload={...fixture,model};vm.runInNewContext(code,context);await click('support-apps-configure');await settle();
 assert.match(get('support-model-test-status').textContent,/Local response test passed/);
 get('support-model-compute').value='auto';get('support-model-compute').events.change();
 if(!/Unsaved/.test(get('support-model-test-status').textContent))issues.push('Editing compute leaves the earlier test pass visible as current');
 assert.equal(get('support-model-test').disabled,true);await poll();
 if(!/Unsaved/.test(get('support-model-test-status').textContent))issues.push('Polling restores a stale pass over the unsaved choice');
 assert.equal(posts().length,0,'draft editing and polling never save or run a test');
 // Exact installed-version adoption is selection, not runtime inference.
 nodes.clear();timers.clear();requests.length=0;
 payload={...fixture,model:{...model,selected_digest:'a'.repeat(64),installed_digest:'b'.repeat(64),drift:'digest_changed',response_test:{...model.response_test,state:'idle'}}};
 vm.runInNewContext(code,context);await click('support-apps-configure');await settle();
 assert.equal(get('support-model-adopt').hidden,false);
 if(get('support-model-adopt').disabled)issues.push('UNBOUND incorrectly disables the explicit installed-version selection shortcut');
 else{
  await click('support-model-adopt');await settle();assert.equal(posts().length,1);
  assert.deepEqual(JSON.parse(posts()[0].opts.body),{action:'model_select',model:unbound_model.model,model_digest:'b'.repeat(64),compute_mode:'cpu',timeout_seconds:300});
  assert.equal(get('support-model-load').disabled,true,'selection cannot lift runtime hold');
 }
 assert.deepEqual(issues,[]);console.log('Local AI stale-draft results and installed-version adoption passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
