const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',async()=>{
 const {code}=JSON.parse(input),nodes=new Map(),controls=[],requests=[],timers=[];
 let token='t'.repeat(32),mode='ready',confirmations=0,confirmed=true;
 const node=(tag='')=>({tag,children:[],value:'',textContent:'',events:{},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},setAttribute(){},addEventListener(key,fn){this.events[key]=fn;}});
 const byId=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
 const tool={id:'lynis',installed:'no',light:'red',service:'none'},recipe={id:'lynis',method:'apt',one_click:true,terminal:'sudo apt-get install lynis',summary:'Fixed test recipe'};
 const context={Date,Map,AbortController,workflowToolIds:['lynis'],byId,textNode:(tag,text='',className='')=>Object.assign(node(tag),{textContent:text,className}),formatRefreshTime:date=>date.toISOString(),
  document:{visibilityState:'visible',createElement:node,addEventListener(){},querySelectorAll:selector=>selector==='[data-heartbeat-install]'?controls:[]},
  window:{setTimeout(fn,ms){timers.push({fn,ms});return timers.length;},clearTimeout(){},confirm(){confirmations++;return confirmed;}},
  localStorage:new Proxy({},{get(){throw Error('Session token must stay in page memory');}}),
  fetch:async(path,options)=>{requests.push({path,options});
   if(options.method==='POST'){
    if(mode==='network'){mode='ready';throw Error('Connection interrupted');}
    if(mode==='expired'){mode='ready';token='u'.repeat(32);return{ok:false,status:403,json:async()=>({error:'expired session'})};}
    if(mode==='forbidden')return{ok:false,status:403,json:async()=>({error:'denied'})};
    assert.equal(options.headers['X-Megalodon-Install-Token'],token);return{ok:true,status:202,json:async()=>({tool:'lynis',action:'install',state:'succeeded',output:[]})};
   }
   const value=path==='/api/heartbeat'?{schema:'megalodon-tool-heartbeat-v1',checked_at:new Date().toISOString(),tools:[tool]}:path==='/api/install/token'?{schema:'megalodon-tool-session-v1',enabled:true,token}:path==='/api/install'?{tools:[recipe],management:{enabled:true},job:{state:'idle'}}:{schema:'megalodon-support-apps-v1',apps:[['wireshark','Wireshark'],['zenmap','Zenmap'],['clamtk','ClamTk']].map(([id,name])=>({id,name,available:false,reason:'not_found'}))};
   return{ok:true,status:200,json:async()=>value};
  }};
 vm.createContext(context);vm.runInContext(code,context);
 const run=script=>vm.runInContext(script,context),settle=()=>new Promise(resolve=>setImmediate(resolve)),posts=()=>requests.filter(request=>request.options.method==='POST');
 await run('pollHeartbeat()');
 const wrap=run('installControl("lynis","Lynis")');controls.push(wrap);
 assert.equal(byId('tool-management-token').value,'','installed launch requires no pasted token');
 assert.equal(wrap.children[0].disabled,false,'fresh local session enables Install');
 const original=wrap.children[0];await run('pollHeartbeat()');assert.equal(wrap.children[0],original,'unchanged polls retain the focused control node');
 confirmed=false;await run('startInstall("lynis","Lynis",heartbeatState.catalog[0])');assert.equal(posts().length,0);
 confirmed=true;mode='expired';const beforeExpired=posts().length,beforeConfirm=confirmations;
 await run('startInstall("lynis","Lynis",heartbeatState.catalog[0])');await settle();
 assert.equal(posts().length,beforeExpired+2,'known 403 refreshes once and retries once');assert.equal(confirmations,beforeConfirm+1,'one explicit action has one confirmation');
 assert.equal(posts().at(-1).options.headers['X-Megalodon-Install-Token'],token);
 mode='network';const beforeNetwork=posts().length;await run('startInstall("lynis","Lynis",heartbeatState.catalog[0])');await settle();assert.equal(posts().length,beforeNetwork+1,'an unknown network outcome never resubmits installation');
 mode='forbidden';const beforeDenied=posts().length;await run('startInstall("lynis","Lynis",heartbeatState.catalog[0])');await settle();assert.equal(posts().length,beforeDenied+2,'repeated 403 is bounded at two explicit submissions');
 assert.ok(requests.filter(request=>request.options.method!=='POST').every(request=>!request.path.includes(token)&&!request.options.headers['X-Megalodon-Install-Token']));
 console.log('Local installation session, bounded retry and stable controls passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
