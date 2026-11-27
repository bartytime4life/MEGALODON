/* Inert DOM and deferred HTTP: no browser, model, service or network. */
const assert = require('node:assert/strict'), vm = require('node:vm'), fs = require('node:fs');
const {webcrypto} = require('node:crypto');
const code = fs.readFileSync(0, 'utf8');
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(r => setImmediate(r)); };
function environment() {
  const nodes = new Map(), timers = new Map(), requests = []; let serial = 0;
  function node() {
    const classes = new Set();
    return {textContent:'',value:'',type:'password',hidden:false,disabled:false,children:[],events:{},attributes:{},dataset:{},
      classList:{add:v=>classes.add(v),remove:v=>classes.delete(v)},
      setAttribute(k,v){this.attributes[k]=v;},removeAttribute(k){delete this.attributes[k];},
      addEventListener(k,fn){this.events[k]=fn;},dispatchEvent(e){this.events[e.type]?.(e);},
      replaceChildren(...v){this.children=v;},querySelectorAll(){return this.children;},focus(){}};
  }
  const get = id => {if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
  get('ai-token').value = 'a'.repeat(32); get('ai-question').value='seeing';
  get('ai-question').options=[{value:'seeing',textContent:'What is MEGALODON seeing?'}];
  get('ai-ask').disabled=true;get('ai-cancel').hidden=true;get('ai-result').hidden=true;
  const context = {document:{getElementById:get,createElement:node},crypto:webcrypto,Event,TextDecoder,Uint8Array,AbortController,
    setTimeout(fn,ms){timers.set(++serial,{fn,ms});return serial;},clearTimeout:id=>timers.delete(id),
    fetch(path,options){return new Promise((resolve,reject)=>{
      const entry={path,options,resolve,reject};requests.push(entry);
      options.signal?.addEventListener('abort',()=>{const e=new Error('Aborted');e.name='AbortError';reject(e);});
    });}};
  vm.runInNewContext(code, context);
  function response(value, status=200, opts={}) {
    const bytes=Buffer.from(JSON.stringify(value));let sent=false;
    return {ok:status>=200&&status<300,status,headers:{get:()=>opts.declared??null},body:{cancel:async()=>{},getReader(){return {
      read:async()=>sent?{done:true}:(sent=true,{done:false,value:bytes}),cancel:async()=>{},releaseLock(){}};}}};
  }
  const click=id=>get(id).events.click();
  const main=()=>requests.filter(r=>r.path!=='/api/ai/cancel');
  const cancels=()=>requests.filter(r=>r.path==='/api/ai/cancel');
  const reply=(request,value,status=200,opts={})=>request.resolve(response(value,status,opts));
  async function verify(){const task=click('ai-check');await settle();reply(main().at(-1),{schema:'megalodon-ai-status-v1',state:'model_ready',inference_verified:true,model:'synthetic',timeout_seconds:30});await task;assert.equal(get('ai-ask').disabled,false);}
  async function timeout(ms){const entry=[...timers].find(([,t])=>t.ms===ms);assert.ok(entry,'timer '+ms);timers.delete(entry[0]);entry[1].fn();await settle();}
  return {get,click,requests,main,cancels,reply,verify,timeout,timers};
}
(async()=>{
  // A cancel is immediate locally, immutable, scoped, single-flight and bounded.
  const e=environment();await e.verify();const task=e.click('ai-ask');await settle();
  const first=e.main().at(-1), id=first.options.headers['X-Megalodon-AI-Request'];
  assert.match(id,/^[a-f0-9]{32}$/);assert.notEqual(id,e.main()[0].options.headers['X-Megalodon-AI-Request']);
  e.get('ai-token').value='b'.repeat(32);e.click('ai-cancel');await settle();
  const cancel=e.cancels()[0];assert.ok(first.options.signal.aborted,'Cancel stops its original browser wait immediately');
  assert.deepEqual(JSON.parse(cancel.options.body),{request_id:id});
  assert.equal(cancel.options.headers['X-Megalodon-AI-Token'],'a'.repeat(32),'Cancellation uses the original admitted token');
  assert.equal(e.get('ai-check').disabled,true);assert.equal(e.get('ai-ask').disabled,true);
  e.click('ai-cancel');await e.click('ai-check');assert.equal(e.cancels().length,1);assert.equal(e.main().length,2,'pending cancellation admits no new operation');
  await e.timeout(3000);await task;assert.ok(cancel.options.signal.aborted,'Cancel POST has its own bounded wait');
  assert.match(e.get('ai-state').textContent,/not confirmed/);assert.doesNotMatch(e.get('ai-state').textContent,/canceled by operator|termination is verified/);
  assert.equal(e.get('ai-result').hidden,true);assert.equal(e.get('ai-ask').disabled,false);
  const next=e.click('ai-ask');await settle();const second=e.main().at(-1);
  assert.notEqual(second.options.headers['X-Megalodon-AI-Request'],id);assert.equal(second.options.signal.aborted,false);
  e.reply(cancel,{schema:'megalodon-ai-cancel-v1',request_id:id,cancelled:true});await settle();
  assert.equal(second.options.signal.aborted,false,'A late cancel reply cannot abort the newer controller');
  e.reply(second,{schema:'megalodon-ai-answer-v1',observed:{events:2},inferred:'Synthetic completed answer',tool:'megalodon.status',authority_level:0,execution_state:'observed',receipt_id:'synthetic'});await next;
  assert.equal(e.get('ai-badge').textContent,'Answered');assert.equal(e.get('ai-inferred').textContent,'Synthetic completed answer');
  assert.equal(e.timers.size,0,'Completion clears request, cancellation and elapsed timers');

  for(const outcome of ['accepted','inactive','denied','mismatch','malformed','oversize','network']){
    const v=environment(),check=v.click('ai-check');await settle();const request=v.main()[0];v.click('ai-cancel');await settle();const c=v.cancels()[0],requestId=request.options.headers['X-Megalodon-AI-Request'];
    if(outcome==='network')c.reject(new Error('Synthetic lost reply'));
    else v.reply(c,{schema:outcome==='malformed'?'wrong':'megalodon-ai-cancel-v1',request_id:outcome==='mismatch'?'f'.repeat(32):requestId,cancelled:outcome==='accepted'},outcome==='denied'?403:200,outcome==='oversize'?{declared:'513'}:{});
    await check;assert.equal(v.get('ai-result').hidden,true);assert.equal(v.get('ai-ask').disabled,true,'A cancelled Verify does not establish readiness');
    assert.match(v.get('ai-state').textContent,outcome==='accepted'?/accepted cancellation.*termination is not verified/:outcome==='inactive'?/no active matching request/:/not confirmed/);
    assert.equal(v.timers.size,0,outcome+' clears timers');
  }
  // A browser deadline sends cancellation only for the request that expired.
  const t=environment();await t.verify();const expired=t.click('ai-ask');await settle();const request=t.main().at(-1);
  await t.timeout(630000);assert.ok(request.options.signal.aborted);const c=t.cancels()[0];
  const requestId=request.options.headers['X-Megalodon-AI-Request'];assert.deepEqual(JSON.parse(c.options.body),{request_id:requestId});
  t.reply(c,{schema:'megalodon-ai-cancel-v1',request_id:requestId,cancelled:true});await expired;
  assert.match(t.get('ai-state').textContent,/browser deadline.*accepted cancellation/);assert.equal(t.timers.size,0);
  assert.ok([...e.cancels(),...t.cancels()].every(r=>r.options.body!=='{}'),'New browser code never invokes broad legacy cancellation');
  console.log('Scoped cancellation: original controller/token, immediate abort, bounded acknowledgement, late replies, invalid replies, no false readiness/output and exact deadline cancellation passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
