const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',async()=>{
 const {code,fixture}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map(),requests=[];let serial=0,mutation,payload=fixture,failure=false,held=null,current=Date.parse(fixture.observed_at);
 function element(tag=''){const n={tag,textContent:'',children:[],attributes:{},dataset:{},style:{},events:{},hidden:false,disabled:false,value:'',setAttribute(k,v){this.attributes[k]=String(v);},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;this.textContent='';},addEventListener(k,fn){this.events[k]=fn;},focus(){document.activeElement=this;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const get=id=>{if(!nodes.has(id)){const n=element();n.id=id;nodes.set(id,n);}return nodes.get(id);};
 const document={hidden:false,activeElement:null,getElementById:get,createElement:element,createElementNS:(_ns,t)=>element(t),addEventListener:(k,fn)=>listeners[k]=fn};class Clock extends Date{static now(){return current;}}
 const window={};const context={localHudLaunch:{},window,document,Date:Clock,TextEncoder,TextDecoder,Uint8Array,AbortController,MutationObserver:class{constructor(fn){mutation=fn;}observe(){}},setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),fetch:async(path,opts)=>{requests.push({path,opts});if(held)await held;if(failure)throw Error('PRIVATE_ERROR');if(path==='/api/defense')return {ok:false,status:503};return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(path==='/api/operations'?payload:response)};}};
 const settle=()=>new Promise(r=>setImmediate(r)),click=async id=>{get(id).events.click();await settle();await settle();},poll=async ms=>{const entry=[...timers].find(([,x])=>x.ms===ms);assert.ok(entry,`timer ${ms}`);timers.delete(entry[0]);await entry[1].fn();await settle();},text=n=>n.textContent+' '+n.children.map(text).join(' ');

 vm.runInNewContext(code,context);await settle();await settle();
 const svg=()=>get('ops-lens').children[0],lensNodes=()=>svg().children.filter(n=>n.attributes.role==='button'),links=()=>svg().children.filter(n=>n.attributes.class==='ops-lens-link');
 assert.equal(svg().attributes.role,'group');assert.equal(svg().attributes['aria-hidden'],undefined);
 assert.equal(lensNodes().length,6);assert.equal(links().length,4,'unattributed endpoints never gain a device link');
 // The compact graph preserves readable viewBox units, 44px targets, and a
 // bounded first six without dropping the searchable full roster.
 get('ops-lens').clientWidth=310;await poll(2000);assert.equal(svg().dataset.layout,'compact');
 assert.ok(lensNodes().every(n=>Number(n.children.find(c=>c.tag==='circle').attributes.r)>=22));
 assert.ok(lensNodes().every(n=>text(n).includes(n.dataset.ip)),'each compact node visibly identifies its address');
 get('ops-lens').clientWidth=0;await poll(2000);assert.equal(svg().dataset.layout,'radial');
 for(const n of lensNodes()){assert.match(n.attributes['aria-label'],new RegExp(n.dataset.ip));assert.equal(n.attributes['aria-controls'],'ops-endpoint-detail');}
 assert.match(lensNodes().at(-1).attributes['aria-label'],/Local relationship not established/);
 const chosen=lensNodes()[0];chosen.events.keydown({key:'Enter',preventDefault(){}});
 assert.equal(get('ops-inspector-title').textContent,'203.0.113.8');assert.equal(document.activeElement,get('ops-inspector-title'));
 await click('ops-back-to-connections');assert.equal(document.activeElement,get('ops-search'));assert.equal(get('ops-inspector-title').textContent,'203.0.113.8');
 await click('ops-roster-search');assert.equal(document.activeElement,get('ops-search'));
 assert.match(text(get('ops-endpoint-detail')),/Synthetic TLS SNI/);
 lensNodes()[1].events.keydown({key:' ',preventDefault(){}});assert.equal(get('ops-inspector-title').textContent,'203.0.113.9');
 lensNodes()[2].focus();await poll(2000);assert.equal(document.activeElement.dataset.lensIp,'203.0.113.10');assert.ok(lensNodes().includes(document.activeElement),'poll preserves focus on a connected node');
 get('ops-endpoint-list').children[2].focus();await poll(2000);assert.equal(document.activeElement.dataset.rosterIp,'203.0.113.9');
 for(const [filter,size] of [['observed',3],['review',1],['unknown',2],['all',6]]){await click('ops-filter-'+filter);assert.equal(lensNodes().length,size);assert.equal(get('ops-filter-'+filter).attributes['aria-pressed'],'true');}
 const search=async value=>{get('ops-search').value=value;get('ops-search').events.input();await settle();};
 for(const value of ['api.example.test','443','UDP','Synthetic review','regional','offline geography']){await search(value);assert.equal(get('ops-endpoint-list').children.length,1,value);}
 await search('regional');get('ops-endpoint-list').children[0].events.click();assert.match(text(get('ops-endpoint-detail')),/Identity not observed/,'a geographic label is not a host identity');
 await search('no-such-evidence');assert.match(text(get('ops-lens')),/No retained endpoints match/);await search('');
 // Discard a request that was already in flight at the moment Pause was pressed.
 let release;held=new Promise(r=>release=r);get('ops-refresh').events.click();await settle();
 await click('ops-pause');payload={...fixture,endpoints:[]};release();held=null;await settle();await settle();
 assert.equal(lensNodes().length,6);assert.equal(get('ops-pause').textContent,'Resume view');
 const reads=requests.length;await click('ops-refresh');assert.equal(requests.length,reads,'manual refresh respects Pause');
 assert.equal([...timers.values()].filter(t=>t.ms===2000).length,0);
 await click('ops-pause');assert.match(text(get('ops-lens')),/No external endpoint/);
 payload=fixture;await poll(2000);failure=true;await poll(2000);assert.match(get('ops-lens-summary').textContent,/refresh unavailable/);
 failure=false;payload=structuredClone(fixture);payload.endpoints[1].local_connections=3;await poll(2000);assert.match(get('ops-status').textContent,/unavailable/,'contradictory relationship counts fail validation');
 assert.equal(requests.filter(r=>r.opts.method==='POST').length,0,'acceptance interactions never perform host actions');
 console.log('connection lens evidence, accessibility, focus, filtering, search, and pause passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
