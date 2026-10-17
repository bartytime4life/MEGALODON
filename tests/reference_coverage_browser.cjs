const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',async()=>{
  const {code,fixture}=JSON.parse(input),nodes=new Map(),timers=new Map(),requests=[];
  let payload=structuredClone(fixture),current=Date.parse(fixture.observed_at),serial=0,failure=false;
  function element(tag=''){
    const n={tag,textContent:'',children:[],dataset:{},attributes:{},style:{},events:{},hidden:false,disabled:false,value:'',
      setAttribute(k,v){this.attributes[k]=String(v);},append(...x){this.children.push(...x);},
      replaceChildren(...x){this.children=x;this.textContent='';},addEventListener(k,fn){this.events[k]=fn;},focus(){document.activeElement=this;}};
    Object.defineProperty(n,'innerHTML',{set(){throw Error('Unsafe HTML sink');}});return n;
  }
  const get=id=>{if(!nodes.has(id)){const n=element();n.id=id;nodes.set(id,n);}return nodes.get(id);};
  const document={hidden:false,activeElement:null,getElementById:get,createElement:element,createElementNS:(_,tag)=>element(tag),addEventListener(){}};
  class Clock extends Date{static now(){return current;}}
  const context={localHudLaunch:{},window:{},document,Date:Clock,TextEncoder,TextDecoder,Uint8Array,AbortController,
    MutationObserver:class{observe(){}},setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),
    fetch:async(path,opts)=>{requests.push({path,opts});if(failure)throw Error('PRIVATE_ERROR');return {ok:path==='/api/operations',status:503,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
  const settle=()=>new Promise(r=>setImmediate(r));
  async function poll(){const item=[...timers].find(([,v])=>v.ms===2000);assert.ok(item);timers.delete(item[0]);await item[1].fn();await settle();}
  const text=n=>n.textContent+' '+n.children.map(text).join(' '),details=()=>text(get('ops-endpoint-detail'));
  const stamp=ms=>new Date(ms).toISOString();
  vm.runInNewContext(code,context);await settle();await settle();
  get('ops-endpoint-list').children[1].events.click();await settle();assert.match(details(),/Reference coverage unavailable/);
  payload.reference_context={schema:'megalodon-reference-context-v1',checked_at:stamp(current),state:'missing',feeds:[]};
  await poll();assert.match(details(),/References not loaded/);assert.match(details(),/no reference comparison/i);
  const feeds=['drop-v4','drop-v6','ipsum'].map(source=>({source,state:'ready',indicators:1,publisher_at:stamp(current-3600000),expires_at:stamp(current+1000)}));
  payload.reference_context={...payload.reference_context,state:'ready',feeds};
  payload.endpoints[1].threat_context=[{ip:payload.endpoints[1].ip,source:'drop-v4',indicator:'203.0.113.0/24',publisher_at:feeds[0].publisher_at,expires_at:feeds[0].expires_at,status:'context_match',action_status:'not_attempted'}];
  await poll();assert.match(details(),/Current cached references/);assert.match(details(),/drop-v4 match/);assert.match(details(),/No live reputation lookup/);
  current+=1000;await poll();assert.match(details(),/References expired/);assert.doesNotMatch(details(),/drop-v4 match/,'expiry removes a formerly shown match');
  payload.reference_context.checked_at=stamp(current);
  payload.reference_context.feeds[0].expires_at=stamp(current+5000);
  payload.reference_context.feeds[1].state=payload.reference_context.feeds[2].state='stale';
  payload.reference_context.state='partial';payload.endpoints[1].threat_context=[];
  await poll();assert.match(details(),/Partial reference coverage/);assert.match(details(),/Coverage is incomplete/);
  payload.reference_context.state='ready';await poll();assert.match(details(),/Reference coverage unavailable/,'contradictory source summary fails closed');
  payload.reference_context.feeds=[feeds[0],feeds[0],feeds[0]];await poll();assert.match(details(),/Reference coverage unavailable/);assert.equal(get('ops-peers').textContent,'2','optional context failure preserves telemetry');
  payload.reference_context={...payload.reference_context,state:'ready',feeds:feeds.map(f=>({...f,state:'ready',expires_at:stamp(current+5000)}))};
  payload.endpoints[1].threat_context=[{ip:payload.endpoints[0].ip,source:'drop-v4',indicator:'wrong-selection',publisher_at:feeds[0].publisher_at,expires_at:stamp(current+5000),status:'context_match',action_status:'not_attempted'}];
  await poll();assert.doesNotMatch(details(),/wrong-selection/);assert.match(details(),/No match in current cached references/);
  failure=true;await poll();assert.match(details(),/Reference coverage unavailable/);assert.doesNotMatch(details(),/Current cached references/);
  assert.equal(requests.filter(r=>r.opts.method==='POST').length,0,'coverage reads and selection never execute an action');
  console.log('reference coverage states, expiry, selection and read-only behavior passed');
});process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
