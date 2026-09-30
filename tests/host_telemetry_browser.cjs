const assert = require('node:assert/strict');
const vm = require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
  const {code, fixture}=JSON.parse(input), nodes=new Map(), listeners={}, timers=new Map();let seq=0, requests=[], payload=fixture, failure=false, oversized=false, hold=null;
  function element(tag='') {return {tag,textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,
    setAttribute(k,v){this.attributes[k]=v;},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},
    addEventListener(name,fn){this.events[name]=fn;}};}
  const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
  const document={hidden:false,getElementById:get,createElement:element,createElementNS:(_ns,tag)=>element(tag),addEventListener:(name,fn)=>listeners[name]=fn};
  const current=new Date('2026-09-30T18:04:19.460Z').getTime();
  class Clock extends Date {static now(){return current;}}
  const context={localHudLaunch:{},document,Date:Clock,TextEncoder,TextDecoder,AbortController,
    setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(path,opts)=>{requests.push({path,opts});if(hold)await hold;if(failure)throw Error('offline');return {ok:true,headers:{get:()=>oversized?'3000000':null},text:async()=>JSON.stringify(payload)};}};
  const settled=()=>new Promise(resolve=>setImmediate(resolve));
  const poll=async()=>{const next=[...timers.entries()].find(([,v])=>v.ms===2000);assert.ok(next,'poll scheduled');timers.delete(next[0]);await next[1].fn();await settled();};
  const status=()=>get('pc-status').textContent;
  vm.runInNewContext(code,context);await settled();
  assert.equal(status(),'Live');assert.equal(requests[0].path,'/api/host-telemetry');assert.equal(requests[0].opts.headers['X-Megalodon-Check'],'1');
  assert.match(get('pc-network-detail').textContent,/since the previous observation:/);
  assert.doesNotMatch(get('pc-network-detail').textContent,/cumulative/);
  assert.equal(get('pc-interface').value,'enp11s0','first non-loopback selected');assert.equal(get('pc-suite-cpu').textContent,'0%','measured zero remains zero');
  assert.match(get('pc-network-chart').children[0].textContent,/Collecting/,'only one valid rate does not fabricate a trend');
  assert.match(get('pc-process-coverage').textContent,/Visible process counters read/);
  assert.doesNotMatch(get('pc-process-coverage').textContent,/observation complete/);
  assert.equal(get('pc-apps-body').children.length,9);assert.equal(get('pc-apps-body').children[0].children[0].textContent,'MEGALODON');
  // A second measured interval yields distinct receive/send paths and a unit-bearing accessible label.
  payload=JSON.parse(JSON.stringify(fixture));payload.history[0].interfaces=payload.history[1].interfaces;await poll();
  const chart=get('pc-network-chart').children.find(n=>n.tag==='svg');assert.equal(chart.tag,'svg');assert.match(chart.attributes['aria-label'],/bytes per second/);assert.equal(chart.children.filter(n=>n.tag==='path').length,2);
  assert.match(get('pc-cpu-chart').children.find(n=>n.tag==='svg').attributes['aria-label'],/100 percent/);
  assert.equal(get('pc-cpu-chart').children.find(n=>n.tag==='svg').children.filter(n=>n.tag==='path').length,2);
  payload.history[0].observed_at='2026-09-30T18:03:49.460Z';await poll();
  for(const id of ['pc-network-chart','pc-cpu-chart']) {
    const sparse=get(id).children.find(n=>n.tag==='svg');
    assert.equal(sparse.children.filter(n=>n.tag==='circle').length,4,'isolated readings remain visible');
    assert.ok(sparse.children.filter(n=>n.tag==='path').every(n=>!n.attributes.d.includes('L')),'coverage gaps remain unconnected');
    assert.match(get(id).children[0].textContent,/Dots are isolated readings/);
  }
  get('pc-interface').value='lo';get('pc-interface').events.change();assert.match(get('pc-network-chart').children.find(n=>n.tag==='svg').attributes['aria-label'],/^lo receive/);
  // Pausing prevents polls and labels retained values, then resumes without a second poll chain.
  get('pc-pause').events.click();assert.equal(status(),'Paused');assert.equal(get('pc-pause').attributes['aria-pressed'],'true');assert.equal([...timers.values()].filter(t=>t.ms===2000).length,0);
  get('pc-pause').events.click();await settled();assert.equal(status(),'Live');assert.equal([...timers.values()].filter(t=>t.ms===2000).length,1);
  document.hidden=true;listeners.visibilitychange();assert.equal(status(),'Hidden tab');assert.equal([...timers.values()].filter(t=>t.ms===2000).length,0);
  document.hidden=false;listeners.visibilitychange();await settled();assert.equal(status(),'Live');
  failure=true;await poll();assert.equal(status(),'Unavailable');assert.equal(get('pc-suite-cpu').textContent,'—');assert.equal(get('pc-cpu-arc').attributes['stroke-dasharray'],'0 100');
  get('pc-interface').value='enp11s0';get('pc-interface').events.change();assert.equal(status(),'Unavailable','changing interface cannot revive failed readings');assert.equal(get('pc-rx').textContent,'—');
  failure=false;oversized=true;await poll();assert.equal(status(),'Unavailable');oversized=false;
  payload={...payload,status:'partial',coverage:{processes:'partial'}};await poll();assert.equal(status(),'Partial readings');assert.match(get('pc-process-coverage').textContent,/Partial process visibility/);
  payload={...payload,status:'warming',suite:{...payload.suite,cpu_percent:null},network:{...payload.network,interfaces:payload.network.interfaces.map(i=>({...i,rx_bps:null,tx_bps:null}))}};await poll();assert.equal(status(),'Warming up');assert.equal(get('pc-suite-cpu').textContent,'—');assert.equal(get('pc-rx').textContent,'—');
  payload={...payload,status:'ready',observed_at:'2026-09-30T18:03:19.460Z',history:[]};await poll();assert.equal(status(),'Stale');assert.equal(get('pc-suite-memory').textContent,'—');
  payload={...payload,status:'unavailable',observed_at:null};await poll();assert.equal(status(),'Unavailable');
  payload={...fixture,system:{...fixture.system,cpu_percent:'oops'}};await poll();assert.equal(status(),'Unavailable','invalid value rejected');
  // A pending response cannot overwrite pause or hidden-tab status.
  payload=fixture;let release;hold=new Promise(resolve=>release=resolve);const next=[...timers.entries()].find(([,v])=>v.ms===2000);timers.delete(next[0]);const pending=next[1].fn();get('pc-pause').events.click();release();await pending;await settled();assert.equal(status(),'Paused');
  console.log('host telemetry UI behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
