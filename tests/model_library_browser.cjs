const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
 const {code,fixture,unbound_model,library}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map(),requests=[],opens=[];
 let seq=0,payload={...fixture,model:unbound_model,model_library:library},failure=false,denyNext=false;
 function element(tag=''){return {tag,textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',checked:false,hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){this.focused=true;}};}
 const get=id=>{if(id==='workspace-setup')return null;if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const document={hidden:false,getElementById:get,createElement:element,addEventListener:(k,v)=>listeners[k]=v};
 const context={localHudLaunch:{},document,TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(path,opts)=>{requests.push({path,opts});if(failure)throw Error('offline');if(denyNext&&opts.method==='POST'){denyNext=false;return {status:403,ok:false,headers:{get:()=>null},text:async()=>JSON.stringify({})};}return {status:200,ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
 context.window={open:(...args)=>{opens.push(args);return null;}};
 const settle=()=>new Promise(resolve=>setImmediate(resolve)),click=id=>get(id).events.click({isTrusted:true});
 const posts=()=>requests.filter(x=>x.opts.method==='POST');
 const poll=async delay=>{const next=[...timers.entries()].find(([,v])=>v.ms===delay);assert.ok(next);timers.delete(next[0]);await next[1].fn();await settle();};
 vm.runInNewContext(code,context);await settle();assert.equal(requests.length,0);
 await click('support-apps-configure');await settle();assert.equal(posts().length,0);
 get('model-library-select').value=library.catalog[0].id;get('model-library-select').events.change();
 assert.equal(opens.length,0,'initial rendering must not open a publisher page');
 const beforeReview=requests.length;
 await get('model-library-review-source').events.click({isTrusted:false});
 assert.equal(opens.length,0,'a synthetic event is not an operator review action');
 await click('model-library-review-source');await click('model-library-review-license');
 const base='https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/'+library.catalog[0].revision+'/';
 assert.deepEqual(opens,[[base+library.catalog[0].filename,'_blank','noopener,noreferrer'],[base+'LICENSE','_blank','noopener,noreferrer']]);
 assert.equal(requests.length,beforeReview,'review opens no backend request');
 assert.equal(get('model-library-online').checked,false,'reviewing is not download consent');
 document.hidden=true;await click('model-library-review-source');document.hidden=false;
 assert.equal(opens.length,2,'a hidden page cannot open publisher review');
 assert.equal(get('model-library-download').disabled,true);
 await click('model-library-download');assert.equal(posts().length,0,'no download without explicit consent');
 get('model-library-online').checked=true;get('model-library-online').events.change();
 assert.equal(get('model-library-download').disabled,false,'UNBOUND does allow staging');
 assert.equal(get('support-model-load').disabled,true,'staging does not lift runtime acceptance');
 await click('model-library-download');await settle();assert.equal(posts().length,1);
 const sent=posts()[0];assert.equal(sent.path,'/api/support-config');
 assert.deepEqual(JSON.parse(sent.opts.body),{action:'model_stage_download',catalog_id:library.catalog[0].id});
 assert.equal(sent.opts.headers['X-Megalodon-Config-Token'],fixture.token);
 assert.ok(!JSON.stringify([...nodes.values()]).includes(fixture.token));
 payload={...payload,job:{...fixture.job,state:'running',action:'model_stage_download'},model_library:{...library,state:'downloading',message:'Downloading…',active:{job_id:'a'.repeat(32),catalog_id:library.catalog[0].id,state:'downloading',bytes_received:42,error_code:null}}};
 await poll(10000);assert.equal(posts().length,1,'polling never resumes or starts a transfer');
 assert.equal(get('model-library-download').disabled,true);assert.equal(get('model-library-cancel').disabled,false);
 assert.equal(get('model-library-progress').value,42);
 await click('model-library-cancel');assert.deepEqual(JSON.parse(posts().at(-1).opts.body),{action:'model_stage_cancel'});
 payload={...fixture,model:unbound_model,model_library:{...library,state:'checked',models:[{catalog_id:library.catalog[0].id,state:'staged_verified',checked_at:1}]}};
 await poll(2000);assert.match(get('model-library-models').children[0].textContent,/Verified at last check/);
 assert.equal(get('support-model-load').disabled,true);
 const prior=posts().length;await poll(10000);assert.equal(posts().length,prior);
 failure=true;await poll(10000);assert.equal(get('model-library-download').disabled,true);assert.equal(get('model-library-cancel').disabled,true);
 await click('model-library-review-source');assert.equal(opens.length,2,'failed status disables stale review controls');
 failure=false;payload={...payload,model_library:{...library,free_bytes:-1}};await click('support-config-retry');await settle();
 assert.equal(get('model-library-download').disabled,true,'malformed status fails closed');assert.equal(posts().length,prior);
 // Existing-file verification remains an explicit action under UNBOUND.
 const local={store_id:'user',model:unbound_model.model,manifest_sha256:unbound_model.selected_digest,provider_sha256:'c'.repeat(64),verified_bytes:123,profile:'standard',state:'files_verified',error_code:null,checked_at:1};
 payload={...fixture,model:unbound_model,model_library:{...library,local_models:[local]}};
 await click('support-config-retry');await settle();
 get('model-library-profile').value='standard';
 assert.equal(get('model-library-reuse').disabled,false);
 assert.match(get('model-library-local').children[0].textContent,/Files verified at last check/);
 await click('model-library-reuse');await settle();
 assert.deepEqual(JSON.parse(posts().at(-1).opts.body),{action:'model_library_reuse',store_id:'user',model:unbound_model.model,model_digest:unbound_model.selected_digest,verification_profile:'standard'});
 assert.equal(get('support-model-load').disabled,true);
 const count=posts().length;await poll(10000);assert.equal(posts().length,count,'polling never starts an offline check');
 payload={...payload,model:{...unbound_model,selected_digest:'d'.repeat(64)}};
 await poll(10000);assert.match(get('model-library-local').children[0].textContent,/Previous selection/);
 get('model-library-online').checked=true;get('model-library-online').events.change();
 payload={...payload,model_library:{...payload.model_library,catalog:library.catalog.map(x=>({...x,sha256:'e'.repeat(64)}))}};
 await poll(10000);assert.equal(get('model-library-online').checked,false,'changed file pins invalidate download consent');
 assert.equal(posts().length,count);
 get('model-library-online').checked=true;get('model-library-online').events.change();denyNext=true;
 await click('model-library-download');await settle();
 assert.equal(posts().length,count+1,'expired permission never automatically retries a download');
 assert.equal(get('model-library-online').checked,false);
 assert.equal(get('model-library-download').disabled,true);
 assert.match(get('support-config-status').textContent,/confirm the download again/);
 // Existing catalog fields may only derive a fixed HTTPS publisher-page URL.
 for(const change of [
  {source:'javascript:alert(1)'},{source:'Hugging Face / ../repo'},
  {source:'Hugging Face / Qwen/repo/extra'},{source:'Hugging Face / Qwen/repo?token=x'},
  {source:'Hugging Face / Qwen/repo#fragment'},{source:'Hugging Face / Qwen\\repo'},
  {filename:'../weights.gguf'},{filename:'%2e%2e.gguf'},
  {filename:'weights.gguf?token=x'},{filename:'weights.gguf#fragment'},
  {filename:'weights\\file.gguf'},{filename:'weights.gguf\n'},
  {source:'Hugging Face / Qwen/repo\n'},{revision:'main'}]){
  payload={...fixture,model:unbound_model,model_library:{...library,catalog:library.catalog.map(x=>({...x,...change}))}};
  const beforePosts=posts().length;
  await click('support-config-retry');await settle();
  assert.equal(get('model-library-review-source').disabled,true,JSON.stringify(change));
  assert.equal(get('model-library-review-license').disabled,true,JSON.stringify(change));
  get('model-library-online').checked=true;get('model-library-online').events.change();
  assert.equal(get('model-library-download').disabled,true,'unreviewable catalog cannot gain download consent');
  await click('model-library-review-source');await click('model-library-review-license');
  assert.equal(opens.length,2,'malformed metadata never opens a page');
  assert.equal(posts().length,beforePosts,'review/polling never downloads');
 }
 payload={...fixture,model:unbound_model,model_library:library};
 await click('support-config-retry');await settle();
 get('model-library-online').checked=true;get('model-library-online').events.change();
 const changed='f'.repeat(40);
 payload={...payload,model_library:{...library,catalog:library.catalog.map(x=>({...x,revision:changed}))}};
 const beforePinPosts=posts().length;
 await poll(10000);
 assert.equal(get('model-library-online').checked,false,'revision changes revoke prior download consent');
 await click('model-library-review-source');
 assert.equal(opens.at(-1)[0],'https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/blob/'+changed+'/'+library.catalog[0].filename);
 assert.equal(posts().length,beforePinPosts,'review of a new pin is still separate from transfer');
 console.log('explicit publisher review and model staging UI behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
