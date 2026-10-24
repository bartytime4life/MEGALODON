const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',async()=>{
 const {code,fixture}=JSON.parse(input),nodes=new Map(),timers=new Map(),listeners={},requests=[];let sequence=0,payload=fixture,held=null;
 function element(){return {textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){document.activeElement=this;}};}
 const get=id=>{if(id==='workspace-setup')return null;if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const document={hidden:false,activeElement:null,getElementById:get,createElement:element,addEventListener:(k,v)=>listeners[k]=v};
 const context={localHudLaunch:{},document,window:{},TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout(fn,ms){const id=++sequence;timers.set(id,{fn,ms});return id;},clearTimeout:id=>timers.delete(id),fetch:async(path,options)=>{requests.push({path,options});if(held)await held;return {ok:true,status:200,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};}};
 vm.runInNewContext(code,context);const settle=()=>new Promise(resolve=>setImmediate(resolve));
 const click=id=>get(id).events.click(),posts=()=>requests.filter(r=>r.options.method==='POST').length;
 async function poll(){const tick=[...timers].find(([,v])=>v.ms===10000);assert.ok(tick);timers.delete(tick[0]);await tick[1].fn();}
 await click('support-apps-configure');await settle();
 const option=get('support-config-interface').children[1];let release;held=new Promise(resolve=>release=resolve);const reading=poll();await settle();
 assert.equal(get('support-config-interface').disabled,false);assert.equal(get('support-config-qwen').disabled,false);assert.equal(get('support-config').attributes['aria-busy'],'false');
 get('support-config-interface').value='wlan0';get('support-config-interface').events.change();const waiting=click('support-config-qwen');await settle();assert.equal(posts(),0);
 release();held=null;await reading;await waiting;
 assert.equal(posts(),1);assert.ok(get('support-config-interface').children[1]===option,'unchanged native options stay in place');assert.equal(get('support-config-interface').value,'wlan0');
 held=new Promise(resolve=>release=resolve);const invalidRead=poll();await settle();const rejected=click('support-config-qwen');payload={...fixture,token:'invalid'};release();held=null;await invalidRead;await rejected;assert.equal(posts(),1,'invalid status cancels the waiting action');
 payload=fixture;await click('support-config-retry');held=new Promise(resolve=>release=resolve);const hiddenRead=poll();await settle();const hiddenAction=click('support-config-qwen');document.hidden=true;listeners.visibilitychange();release();held=null;await hiddenRead;await hiddenAction;assert.equal(posts(),1,'a hidden view cannot finish a queued action');
 console.log('routine reads preserve controls and option nodes; deliberate actions revalidate after reads');
});process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
