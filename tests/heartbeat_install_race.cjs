// A /api/install answer from before an install POST must not erase the
// running job that the POST returned.
const assert=require('node:assert/strict'),vm=require('node:vm');let input='';
process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',async()=>{
 const {code}=JSON.parse(input),nodes=new Map(),timers=new Map();let tid=0;
 function element(tag=''){return{tag,children:[],textContent:'',attrs:{},className:'',value:'',append(...i){this.children.push(...i)},replaceChildren(...i){this.children=i;this.textContent=''},setAttribute(k,v){this.attrs[k]=v},addEventListener(){}};}
 const byId=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 byId('tool-management-token').value='A'.repeat(32);
 const ctx={Date,Map,AbortController,Promise,workflowToolIds:['suricata'],byId,formatRefreshTime:d=>d.toISOString(),
  textNode:(t,x='',c='')=>Object.assign(element(t),{textContent:x,className:c}),
  document:{visibilityState:'visible',createElement:element,addEventListener(){},querySelectorAll:()=>[]},
  window:{setTimeout(fn,d){const id=++tid;timers.set(id,{fn,d});return id},clearTimeout(id){timers.delete(id)},confirm:()=>true}};
 let serverJob={state:'idle'},release,hold=false;const gate=new Promise(r=>release=r);
 const report=()=>({schema:'megalodon-tool-heartbeat-v1',checked_at:new Date().toISOString(),tools:[{id:'suricata',light:'red',installed:'no',expects_service:true,service:'none'}]});
 ctx.fetch=async(path,opts)=>{
  if(path==='/api/install'&&opts.method==='POST'){serverJob={tool:'suricata',action:'install',state:'running',output:[]};return{ok:true,status:202,json:async()=>serverJob};}
  if(path==='/api/install'){const snap=JSON.parse(JSON.stringify(serverJob));if(hold){hold=false;await gate;}
   return{ok:true,status:200,json:async()=>({tools:[{id:'suricata',one_click:true,method:'apt',summary:'x'}],job:snap,management:{enabled:true}})};}
  if(path==='/api/heartbeat')return{ok:true,status:200,json:async()=>report()};
  return{ok:true,status:200,json:async()=>({schema:'megalodon-support-apps-v1',apps:[]})};
 };
 vm.createContext(ctx);vm.runInContext(code,ctx);const run=s=>vm.runInContext(s,ctx);
 await run('pollHeartbeat()');hold=true;
 const inflight=run('pollHeartbeat()');await new Promise(r=>setImmediate(r));
 await run("startInstall('suricata','Suricata',{summary:'x'})");
 release();await inflight;
 assert.equal(run('heartbeatState.job&&heartbeatState.job.state'),'running','the stale poll kept the running job');
 assert.equal(Math.max(...[...timers.values()].map(t=>t.d)),2000,'polling stays at the install cadence');
 console.log('install job survives a stale poll');
}).on('error',e=>{console.error(e);process.exitCode=1;});process.on('unhandledRejection',e=>{console.error(e);process.exitCode=1;});
