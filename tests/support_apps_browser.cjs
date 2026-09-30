const assert=require('node:assert/strict');
const vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
  const {code,fixture}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map(),requests=[];
  let seq=0,payload=fixture,responseStatus=200,failure=false,hold=null,oversized=false,clock=Date.now(),clipboard='',clipboardFailure=false;
  function element(tag='') {return {tag,textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,
    setAttribute(k,v){this.attributes[k]=v;},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},
    addEventListener(name,fn){this.events[name]=fn;},focus(){this.focused=true;},select(){this.selected=true;}};}
  const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
  const document={hidden:false,getElementById:get,createElement:element,addEventListener:(name,fn)=>listeners[name]=fn};
  class Clock extends Date {static now(){return clock;}}
  const context={localHudLaunch:{},document,Date:Clock,TextEncoder,TextDecoder,Uint8Array,AbortController,
    navigator:{clipboard:{writeText:async value=>{if(clipboardFailure)throw Error('blocked');clipboard=value;}}},
    setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(path,opts)=>{requests.push({path,opts});if(hold)await hold;if(failure)throw Error('offline');const status=responseStatus;responseStatus=200;return {ok:status>=200&&status<300,status,headers:{get:()=>oversized?'32769':null},text:async()=>JSON.stringify(payload)};}};
  const settled=()=>new Promise(resolve=>setImmediate(resolve));
  const status=()=>get('support-apps-status').textContent;
  const polls=()=>[...timers.values()].filter(v=>v.ms===2000);
  const poll=async()=>{const next=[...timers.entries()].find(([,v])=>v.ms===2000);assert.ok(next,'poll scheduled');timers.delete(next[0]);await next[1].fn();await settled();};
  const click=id=>get(id).events.click();
  vm.runInNewContext(code,context);await settled();
  assert.equal(requests.length,1);assert.equal(requests[0].path,'/api/support-start');assert.equal(requests[0].opts.method,'GET');assert.equal(requests[0].opts.headers['X-Megalodon-Check'],'1');
  assert.equal(polls().length,0,'idle read does not start a poll chain');assert.equal(get('support-apps-start').disabled,false);assert.match(status(),/Ready when you are/);
  await click('support-apps-copy');assert.equal(clipboard,fixture.command);assert.ok(!clipboard.includes(fixture.token));
  assert.ok(!JSON.stringify([...nodes.values()]).includes(fixture.token),'action token never enters the DOM');
  // An explicit start uses only the action nonce and fixed action; duplicate clicks are ignored.
  payload={...fixture,state:'running',started_at:'2026-09-30T20:00:00Z',token:undefined,items:[{id:'wireshark',name:'Wireshark',state:'checking',message:'Checking desktop session.'}]};
  let release;hold=new Promise(resolve=>release=resolve);const starting=click('support-apps-start');await settled();
  assert.match(status(),/Starting support apps/);assert.equal(get('support-apps-start').disabled,true);await click('support-apps-start');
  assert.equal(requests.filter(r=>r.opts.method==='POST').length,1);
  const post=requests.at(-1);assert.equal(post.opts.headers['X-Megalodon-Support-Token'],fixture.token);assert.equal(post.opts.headers['Content-Type'],'application/json');assert.equal(post.opts.body,'{"action":"start"}');
  release();hold=null;await starting;assert.equal(polls().length,1);assert.equal(get('support-apps-start').disabled,true);
  const progress=status(),progressState=get('support-apps').dataset.state;await click('support-apps-copy');
  assert.equal(status(),progress,'copy confirmation preserves startup progress');assert.equal(get('support-apps').dataset.state,progressState);assert.equal(get('support-apps-copy-status').textContent,'Start command copied.');
  payload={...payload,token:fixture.token,items:[{id:'wireshark',name:'<b>Wireshark</b>',state:'launched',message:'<img src=x onerror=alert(1)>'}]};await poll();
  assert.equal(get('support-apps-items').children[0].children[0].textContent,'<b>Wireshark</b>');assert.equal(get('support-apps-items').children[0].children[2].textContent,'<img src=x onerror=alert(1)>');
  document.hidden=true;listeners.visibilitychange();assert.equal(polls().length,0);assert.match(status(),/paused/);const before=requests.length;await click('support-apps-start');assert.equal(requests.length,before);
  document.hidden=false;listeners.visibilitychange();await settled();assert.equal(polls().length,1);
  payload={...payload,state:'finished',finished_at:'2026-09-30T20:00:04Z',items:[{id:'wireshark',name:'Wireshark',state:'launched',message:'Desktop launch requested.'},{id:'zeek',name:'Zeek',state:'needs_setup',message:'Choose a capture interface.'},{id:'nmap',name:'Nmap',state:'queued',message:'Collection requested.'}]};await poll();
  assert.match(status(),/Last start completed at 2026-09-30 20:00:04 UTC/);assert.match(status(),/0 were running or ready · 1 launch request · 1 queued · 1 need attention/);assert.equal(get('support-apps-summary').textContent,'Last startup results · 3 tools');assert.equal(get('support-apps-items').children[0].children[1].textContent,'Launch requested');assert.equal(polls().length,0);assert.equal(get('support-apps-start').disabled,false);
  // Busy response is reconciled by GET without resending the action.
  const postCount=requests.filter(r=>r.opts.method==='POST').length;responseStatus=409;await click('support-apps-start');
  assert.equal(requests.filter(r=>r.opts.method==='POST').length,postCount+1);assert.equal(requests.at(-1).opts.method,'GET');assert.equal(get('support-apps-start').disabled,false);
  failure=true;await click('support-apps-start');assert.equal(get('support-apps-start').disabled,true);assert.equal(get('support-apps-check').hidden,false);assert.match(status(),/Unable to confirm/);
  const failedPosts=requests.filter(r=>r.opts.method==='POST').length;await click('support-apps-start');assert.equal(requests.filter(r=>r.opts.method==='POST').length,failedPosts);
  failure=false;await click('support-apps-check');assert.equal(get('support-apps-start').disabled,false);assert.equal(requests.at(-1).opts.method,'GET');
  oversized=true;await click('support-apps-check');assert.match(status(),/Unable to confirm/);assert.equal(get('support-apps-start').disabled,true);oversized=false;
  payload={...fixture,items:[...Array(17)].map((_,i)=>({id:String(i),name:'App',state:'idle',message:''}))};await click('support-apps-check');assert.equal(get('support-apps-start').disabled,true);
  payload={...fixture,token:'invalid'};await click('support-apps-check');assert.equal(get('support-apps-start').disabled,true);
  payload=fixture;await click('support-apps-check');clipboardFailure=true;await click('support-apps-copy');assert.equal(get('support-apps-details').open,true);assert.equal(get('support-apps-command-wrap').hidden,false);assert.equal(get('support-apps-command').selected,true);assert.equal(get('support-apps-copy-status').textContent,'Select and copy the command shown below.');
  payload={...fixture,state:'running',started_at:'2026-09-30T20:00:00Z'};await click('support-apps-check');clock+=300001;await poll();assert.equal(polls().length,0);assert.match(status(),/taking longer/);assert.equal(get('support-apps-start').disabled,true);assert.equal(get('support-apps-check').hidden,false);
  // Responses which arrive after hiding the tab cannot replace the stale label or schedule a poll.
  payload={...fixture,state:'running',started_at:'2026-09-30T20:00:00Z'};hold=new Promise(resolve=>release=resolve);const pending=click('support-apps-check');document.hidden=true;listeners.visibilitychange();release();hold=null;await pending;
  assert.match(status(),/paused/);assert.equal(polls().length,0);assert.equal(get('support-apps-start').disabled,true);
  console.log('support apps UI behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
