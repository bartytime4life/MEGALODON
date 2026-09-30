const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',async()=>{
 const {code,fixture}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map();let serial=0,intersection=null,reads=0,historyReads=0,historyDraws=0,originalStart=0,locations=0,held=null;
 function element(){return {hidden:false,open:false,textContent:'',children:[],dataset:{},events:{},setAttribute(){},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;},addEventListener(k,v){this.events[k]=v;},getContext:()=>null};}
 const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const context={localHudLaunch:{},document:{hidden:false,getElementById:get,createElement:element,addEventListener:(k,v)=>listeners[k]=v},TextEncoder,TextDecoder,Uint8Array,AbortController,
 state:{paused:false,config:{refresh_seconds:5}},globeState:{frame:null,hour:{started:false,timer:null}},refreshGlobeHour:async()=>{historyReads++;if(held)await held;},startGlobeHour:()=>originalStart++,startGlobeSpin:()=>{},stopGlobeSpin:()=>{},stopGlobeFocusTimer:()=>{},renderGlobeView:()=>historyDraws++,drawGlobe:()=>historyDraws++,refreshGlobeLocations:()=>locations++,initializeGlobe:()=>{},
 IntersectionObserver:class{constructor(fn){intersection=fn;}observe(){}},window:{setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),cancelAnimationFrame(){},matchMedia:()=>({matches:true}),addEventListener(){},location:{hash:''}},
 fetch:async()=>{reads++;return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(fixture)};}};
 vm.runInNewContext(code,context);await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,0,'offscreen globe does not request live snapshots');
 context.startGlobeHour();await context.refreshGlobeHour(true);context.renderGlobeView();context.drawGlobe();context.refreshGlobeLocations({});assert.equal(historyReads,0);assert.equal(historyDraws,0);assert.equal(locations,0);assert.equal(originalStart,0);
 intersection([{isIntersecting:true}]);await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,1);assert.ok([...timers.values()].some(v=>v.ms===2000));
 intersection([{isIntersecting:false}]);assert.ok(![...timers.values()].some(v=>v.ms===2000));
 get('live-globe-history').open=true;get('live-globe-history').events.toggle();await new Promise(resolve=>setImmediate(resolve));assert.equal(historyReads,1);assert.ok(historyDraws>0);assert.ok([...timers.values()].some(v=>v.ms===5000));
 // Closing during a history request cannot restart the stopped history timer chain.
 let release;held=new Promise(resolve=>release=resolve);const tick=[...timers].find(([,v])=>v.ms===5000);timers.delete(tick[0]);const pending=tick[1].fn();get('live-globe-history').open=false;get('live-globe-history').events.toggle();release();await pending;assert.ok(![...timers.values()].some(v=>v.ms===5000));assert.equal(context.globeState.hour.started,false);
 console.log('offscreen live reads and collapsed history stop independently');
}).on('error',e=>{console.error(e);process.exitCode=1;});process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
