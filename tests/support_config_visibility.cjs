const assert=require('node:assert/strict');const vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
 const {code,fixture}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map(),requests=[];let seq=0,intersection,mutation;
 function element(){return {textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){}};}
 const get=id=>{if(id==='workspace-setup')return null; /* legacy embedding contract */ if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const document={hidden:false,getElementById:get,createElement:element,addEventListener:(k,v)=>listeners[k]=v};
 const payload={...fixture,background:{enabled:true,state:'running',message:'Monitoring continues.',session_count:1},capture:{...fixture.capture,state:'running'}};
 const context={localHudLaunch:{},document,window:{},TextEncoder,TextDecoder,Uint8Array,AbortController,
  IntersectionObserver:class{constructor(callback){intersection=callback;}observe(){}},MutationObserver:class{constructor(callback){mutation=callback;}observe(){}},
  setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
  fetch:async(path,opts)=>{requests.push({path,opts});return {status:200,ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
 const settle=()=>new Promise(resolve=>setImmediate(resolve));
 const polls=()=>[...timers.values()].filter(timer=>[2000,10000].includes(timer.ms));
 const visible=async(id,value)=>{intersection([{target:get(id),isIntersecting:value}]);await settle();};
 vm.runInNewContext(code,context);await settle();
 await context.window.megalodonSupportConfiguration.refresh();assert.equal(requests.length,0,'offscreen live view does not fetch');
 await visible('live-globe',true);assert.equal(requests.length,1);assert.equal(polls().length,1);assert.equal(polls()[0].ms,2000,'visible background state refreshes');
 get('workspace-live').hidden=true;mutation();assert.equal(polls().length,0,'leaving live workspace cancels background-status polling');
 const hiddenCount=requests.length;await context.window.megalodonSupportConfiguration.refresh();assert.equal(requests.length,hiddenCount,'hidden workspace cannot be refreshed by another HUD component');
 get('workspace-live').hidden=false;mutation();await settle();assert.equal(requests.length,hiddenCount+1,'returning refreshes once');assert.equal(polls().length,1);
 await visible('live-globe',false);assert.equal(polls().length,0,'scrolling past closed controls pauses polling');
 get('support-apps-configure').events.click();await settle();assert.equal(requests.length,hiddenCount+2,'opening settings deliberately refreshes');assert.equal(polls().length,0,'opening does not poll before the panel is visible');
 await visible('support-config',true);assert.equal(polls().length,1,'visible settings can monitor the running capture');
 get('support-config-close').events.click();assert.equal(polls().length,0,'closing the only visible controls pauses polling');
 await visible('live-globe',true);assert.equal(polls().length,1);
 document.hidden=true;listeners.visibilitychange();assert.equal(polls().length,0,'hidden browser tab pauses polling');
 document.hidden=false;listeners.visibilitychange();await settle();assert.equal(polls().length,1);
 assert.ok(requests.every(request=>request.path==='/api/support-config'&&request.opts.method==='GET'),'view changes never start or stop background services');
 console.log('support configuration visibility behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
