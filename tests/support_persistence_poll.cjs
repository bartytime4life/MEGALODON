const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',c=>input+=c);process.stdin.on('end',async()=>{
 // Setup opened directly by its tab: no Configure-apps click, so state.open stays false.
 const {code,fixture,pending,ready,malformed}=JSON.parse(input),nodes=new Map(),timers=new Map(),callbacks=new Map(),requests=[],queue=[pending,ready];let serial=0;
 const get=id=>{if(!nodes.has(id))nodes.set(id,{id,hidden:id==='workspace-live',open:false,value:'',textContent:'',children:[],dataset:{},events:{},setAttribute(){},replaceChildren(...c){this.children=c;},append(...c){this.children.push(...c);},addEventListener(k,fn){this.events[k]=fn;},focus(){}});return nodes.get(id);};
 const context={localHudLaunch:{},document:{hidden:false,getElementById:get,createElement:tag=>{const n=get('created'+serial++);n.tag=tag;return n;},addEventListener(){}},window:{},TextEncoder,TextDecoder,Uint8Array,AbortController,
   MutationObserver:class{constructor(fn){this.fn=fn;}observe(n){callbacks.set(n.id,this.fn);}},IntersectionObserver:class{observe(){}},
   setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),
   fetch:async(path,opts)=>{requests.push({path,opts});const persistence=queue.length>1?queue.shift():queue[0];return{ok:true,status:200,headers:{get:()=>null},text:async()=>JSON.stringify({...fixture,persistence})};}};
 const settle=()=>new Promise(r=>setImmediate(r));vm.runInNewContext(code,context);
 callbacks.get('workspace-setup')();await settle();
 assert.equal(requests.length,1);
 if(malformed){ // a rejected summary stays unreadable and uses normal Setup polling
   assert.match(get('persistence-review').children[0].textContent,/unavailable|could not be read/);assert.equal(timers.size,1);assert.equal([...timers.values()][0].ms,10000);
   console.log('malformed pending summary is not polled');return;
 }
 assert.match(get('persistence-review').children[0].textContent,/Reviewing persistence locations/);
 assert.equal(get('persistence-baseline').disabled,true);
 const polls=[...timers.values()];assert.equal(polls.length,1,'a pending summary schedules another read');assert.equal(polls[0].ms,2000);
 timers.clear();polls[0].fn();await settle();
 assert.equal(requests.length,2);assert.match(get('persistence-review').children[0].textContent,/startup items reviewed · no baseline recorded/);
 assert.equal(get('persistence-baseline').disabled,false,'the initial baseline becomes available without navigation');
 assert.equal(timers.size,1,'Setup keeps one status refresh scheduled');assert.equal([...timers.values()][0].ms,10000,'a completed summary leaves the fast pending cadence');
 assert.ok(requests.every(r=>r.opts.method==='GET'),'polling never records a baseline');
 console.log('pending persistence summary is polled');
}).on('error',e=>{console.error(e);process.exitCode=1;});process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
