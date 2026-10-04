// Shipped operations code, synthetic context and inert DOM; no model or host action.
const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',async()=>{
  const {code,fixture,defense,facts}=JSON.parse(input),nodes=new Map(),timers=new Map(),listeners={},requests=[];
  let serial=0,current=Date.parse(fixture.observed_at),packet=structuredClone(facts),held=null,fail=false,defenseFail=true;
  function element(tag=''){
    const n={tag,textContent:'',children:[],attributes:{},dataset:{},style:{},events:{},hidden:false,disabled:false,value:'',
      setAttribute(k,v){this.attributes[k]=String(v);},append(...x){this.children.push(...x);},
      replaceChildren(...x){this.children=x;this.textContent='';},addEventListener(k,fn){this.events[k]=fn;},focus(){document.activeElement=this;}};
    Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink');}});return n;
  }
  const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
  const document={hidden:false,activeElement:null,getElementById:get,createElement:element,createElementNS:(_ns,t)=>element(t),addEventListener:(k,fn)=>listeners[k]=fn};
  class Clock extends Date{static now(){return current;}}
  const window={},context={localHudLaunch:{},document,window,Date:Clock,TextEncoder,TextDecoder,Uint8Array,AbortController,
    MutationObserver:class{observe(){}},setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),
    fetch:async(path,opts)=>{
      requests.push({path,opts});
      if(path.startsWith('/api/intelligence/context')){const value=structuredClone(packet);if(held)await held;
        return {ok:!fail,headers:{get:()=>null},text:async()=>JSON.stringify(value)};}
      if(path==='/api/defense'&&defenseFail)throw Error('PRIVATE_PROVIDER_FAILURE');
      return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(path==='/api/operations'?fixture:defense)};
    }};
  const settle=async()=>{await new Promise(r=>setImmediate(r));await new Promise(r=>setImmediate(r));};
  const click=async id=>{get(id).events.click();await settle();};
  const poll=async name=>{const entry=[...timers].find(([,t])=>t.fn.name===name);assert.ok(entry,'missing timer '+name);timers.delete(entry[0]);await entry[1].fn();await settle();};
  const text=n=>n.textContent+' '+n.children.map(text).join(' ');
  const resetPacket=()=>{packet=structuredClone(facts);packet.as_of=Math.floor(current/1000);packet.window={start:packet.as_of-3600,end:packet.as_of};packet.dependencies[0].expires_at=packet.as_of+100;};
  vm.runInNewContext(code,context);await settle();
  assert.equal(get('ops-facts-read').disabled,true);
  window.MegalodonOperations.selectEndpoint(fixture.endpoints[1].ip);
  assert.equal(get('ops-facts-read').disabled,false,'facts do not require response controls');
  const before=requests.length;await click('ops-facts-read');
  assert.equal(requests.length,before+1);assert.equal(requests.at(-1).opts.method,'GET');
  assert.equal(requests.at(-1).opts.headers['X-Megalodon-Check'],'1');
  assert.equal(requests.at(-1).opts.cache,'no-store');
  assert.equal(get('ops-facts').hidden,false);
  assert.match(text(get('ops-facts')),/updates, not unique connections/);
  assert.match(text(get('ops-facts')),/TCP\/443: 1 records/);
  assert.match(text(get('ops-facts')),/Selection was truncated/);
  assert.match(text(get('ops-facts')),/Sensors disagree/);
  assert.match(text(get('ops-facts')),/Comparison unavailable: the observation selection was truncated/);
  assert.match(text(get('ops-facts')),/attack@2026-08-05:T1046/);
  assert.match(text(get('ops-facts')),/10 seconds before this check/);
  assert.match(get('ops-facts-status').textContent,/No AI request was made/);
  assert.equal(requests.filter(r=>r.opts.method==='POST').length,0);

  // A -> B -> A clears the old view and rejects even an ignored abort's late response.
  let release;held=new Promise(r=>release=r);get('ops-facts-read').events.click();await settle();
  window.MegalodonOperations.selectEndpoint(fixture.endpoints[0].ip);
  window.MegalodonOperations.selectEndpoint(fixture.endpoints[1].ip);
  assert.equal(get('ops-facts').hidden,true);release();held=null;await settle();
  assert.equal(get('ops-facts').hidden,true);assert.equal(get('ops-facts-read').disabled,false);
  assert.equal([...timers.values()].some(t=>t.fn.name==='readFacts'),false,'stale requests cannot resume polling');

  // Current source checks can invalidate a still-unexpired snapshot.
  await click('ops-facts-read');fail=true;await poll('readFacts');
  assert.equal(get('ops-facts').hidden,true);assert.match(get('ops-facts-status').textContent,/unavailable/);
  fail=false;await click('ops-facts-read');
  packet.dependencies[0].expires_at=current/1000;await poll('readFacts');
  assert.equal(get('ops-facts').hidden,true,'expired dependencies fail before rendering');
  resetPacket();await click('ops-facts-read');current+=100000;await poll('watchFacts');
  assert.equal(get('ops-facts').hidden,true,'expiry is checked without waiting for network refresh');

  // Inactive views drop host-sensitive facts and stop their polling.
  resetPacket();await click('ops-facts-read');document.hidden=true;listeners.visibilitychange();
  assert.equal(get('ops-facts').hidden,true);assert.equal([...timers.values()].some(t=>['readFacts','watchFacts'].includes(t.fn.name)),false);
  document.hidden=false;listeners.visibilitychange();await settle();assert.equal(get('ops-facts').hidden,true);

  // Missing evidence is visibly different from zero detections or safety.
  resetPacket();packet.groups=[];packet.dependencies=[];packet.coverage={truncated:false,missing:['incomplete_window','no_qualified_records']};
  packet.comparison={state:'unavailable',reason:'no_baseline'};packet.reference_ids=[];await click('ops-facts-read');
  assert.equal(get('ops-facts').hidden,false);assert.match(text(get('ops-facts')),/No qualified retained observations/);
  assert.match(text(get('ops-facts')),/no qualified baseline/);
  resetPacket();packet.reference_ids=['<script>literal only</script>'];await click('ops-facts-read');
  assert.match(text(get('ops-facts')),/<script>literal only/,'reference text stays in a text node');
  packet={...packet,subject:'192.0.2.99'};await click('ops-facts-read');assert.equal(get('ops-facts').hidden,true,'wrong subject cannot render');
  resetPacket();packet.reference_ids=['x'.repeat(4000)];await click('ops-facts-read');assert.equal(get('ops-facts').hidden,true,'oversized context rejected');
  assert.equal(requests.filter(r=>r.opts.method==='POST').length,0,'facts never infer, write a review or request a response action');
  console.log('read-only endpoint facts and stale-selection behavior passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
