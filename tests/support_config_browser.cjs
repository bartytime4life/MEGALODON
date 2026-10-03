const assert=require('node:assert/strict');const vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);
process.stdin.on('end',async()=>{
 const {code,fixture}=JSON.parse(input),nodes=new Map(),listeners={},timers=new Map(),requests=[];let seq=0,payload=fixture,responseStatus=200,failure=false,oversized=false,hold=null;
 function element(tag=''){return {tag,textContent:'',children:[],attributes:{},dataset:{},events:{},value:'',hidden:false,disabled:false,setAttribute(k,v){this.attributes[k]=v;},append(...v){this.children.push(...v);},replaceChildren(...v){this.children=v;},addEventListener(k,v){this.events[k]=v;},focus(){this.focused=true;}};}
 const get=id=>{if(id==='workspace-setup')return null; /* legacy embedding contract */ if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const document={hidden:false,getElementById:get,createElement:element,addEventListener:(k,v)=>listeners[k]=v};
 const context={localHudLaunch:{},softwareCatalog:[{id:'tshark',note:'The HUD never starts capture.'},{id:'clamav',note:'It does not update signatures.'}],document,TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout(fn,ms){const id=++seq;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(path,opts)=>{requests.push({path,opts});if(hold)await hold;if(failure)throw Error('offline');const status=responseStatus;responseStatus=200;return {status,ok:status>=200&&status<300,headers:{get:()=>oversized?'65537':null},text:async()=>JSON.stringify(payload)};}};
 const settle=()=>new Promise(resolve=>setImmediate(resolve));const click=id=>get(id).events.click();const status=()=>get('support-config-status').textContent;
 const postCount=()=>requests.filter(r=>r.opts.method==='POST').length;
 const poll=async delay=>{const next=[...timers.entries()].find(([,v])=>v.ms===delay);assert.ok(next,`poll at ${delay}`);timers.delete(next[0]);await next[1].fn();await settle();};
 const change=(id,value)=>{get(id).value=value;get(id).events.change();};
 vm.runInNewContext(code,context);await settle();assert.equal(requests.length,0,'closed pane does not fetch or start work');assert.match(context.softwareCatalog[0].note,/offline TShark adapter/);assert.match(context.softwareCatalog[0].note,/Configure apps/);assert.doesNotMatch(context.softwareCatalog[1].note,/does not update signatures/);
 await click('support-config-capture-start');assert.equal(postCount(),0,'action guard holds before configuration GET');
 failure=true;await click('support-apps-configure');await settle();assert.match(get('live-interface-name').textContent,/unavailable/);assert.match(get('live-geography-opt-in').textContent,/unavailable/);failure=false;await click('support-config-retry');await settle();assert.equal(requests.length,2);assert.equal(requests[0].opts.method,'GET');assert.equal(requests[0].opts.headers['X-Megalodon-Check'],'1');assert.equal(get('support-apps-configure').attributes['aria-expanded'],'true');assert.equal(get('support-config').hidden,false);
 assert.equal(get('support-config-interface').value,'eth0');assert.equal(get('support-config-nmap-target').value,'127.0.0.1/32');assert.equal(get('support-config-capture-stop').disabled,true);assert.equal(get('support-config-capture-start').disabled,false);
 assert.ok(!JSON.stringify([...nodes.values()]).includes(fixture.token),'configuration nonce never enters DOM');
 // Polling refreshes backend state without losing settings typed by the user.
 change('support-config-interface','wlan0');change('support-config-nmap-target','192.168.1.0/24');change('support-config-scan-folder','Documents');await poll(10000);
 assert.equal(get('support-config-interface').value,'wlan0');assert.equal(get('support-config-nmap-target').value,'192.168.1.0/24');assert.equal(get('support-config-scan-folder').value,'Documents');assert.equal(postCount(),0);

 // A selected install directory stays a bounded, fixed-tool setup action.
 change('support-config-tool-directory','/home/operator/apps/zeek/bin');
 await click('support-config-tool-directory-save');
 assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'tool_directory_set',tool_id:'zeek',directory:'/home/operator/apps/zeek/bin'});
 payload={...fixture,tool_directories:{zeek:'/home/operator/apps/zeek/bin'}};await poll(10000);
 assert.equal(get('support-config-tool-directory').value,'/home/operator/apps/zeek/bin');
 change('support-config-tool-directory','');await click('support-config-tool-directory-save');
 assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'tool_directory_set',tool_id:'zeek',directory:''});
 payload=fixture;
 // Model selection shares the protected setup request and retains unsaved choices.
 const model={model:'qwen3.6:latest',message:'Configured model available.',compute_mode:'cpu',options:[{name:'qwen3.6:latest',digest:'a'.repeat(64),size_bytes:2**30},{name:'llama3.2:3b',digest:'b'.repeat(64),size_bytes:2**30}],updated_at:null,last_response_at:null,last_attempt_at:null,response_ms:null,inference_verified:false,loaded:false,memory_bytes:null,vram_bytes:null};
 payload={...fixture,model};await poll(10000);
 assert.equal(get('support-model-select').value,'qwen3.6:latest');
 assert.match(get('support-model-metrics').textContent,/No accepted response recorded for this model/);
 payload={...fixture,model:{...model,last_response_at:'2026-09-30T20:09:30Z',last_attempt_at:'2026-09-30T20:10:00Z',response_ms:1200}};await poll(10000);
 assert.match(get('support-model-metrics').textContent,/Last accepted response 2026-09-30 20:09:30 UTC · reverify for current readiness/);
 assert.match(get('support-model-metrics').textContent,/Last attempt 2026-09-30 20:10:00 UTC · Last attempt duration 1.20 s/);
 payload={...fixture,model:{...model,inference_verified:true,last_response_at:'2026-09-30T20:10:00Z'}};await poll(10000);
 assert.match(get('support-model-metrics').textContent,/Last accepted response 2026-09-30 20:10:00 UTC · recent/);
 change('support-model-select','llama3.2:3b');change('support-model-compute','auto');await poll(10000);
 assert.equal(get('support-model-select').value,'llama3.2:3b');assert.equal(get('support-model-compute').value,'auto');
 await click('support-model-save');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'model_select',model:'llama3.2:3b',model_digest:'b'.repeat(64),compute_mode:'auto',timeout_seconds:300});
 assert.equal(requests.at(-1).opts.headers['X-Megalodon-Config-Token'],fixture.token);
 await click('support-model-refresh');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'model_refresh'});
 change('support-model-select','');const modelPosts=postCount();await click('support-model-save');assert.equal(postCount(),modelPosts);
 payload=fixture;
 // Every fixed action sends exactly its declared fields and the separate nonce.
 const scenarios=[['support-config-permissions',{action:'capture_permissions',interface:'wlan0'}],['support-config-capture-start',{action:'capture_start',interface:'wlan0'}],['support-config-wireshark-open',{action:'wireshark_open',interface:'wlan0'}],['support-config-wireshark-stop',{action:'wireshark_stop'}],['support-config-nmap-save',{action:'nmap_configure',nmap_target:'192.168.1.0/24'}],['support-config-clamav-save',{action:'clamav_configure',scan_folder:'Documents'}],['support-config-signatures',{action:'signature_update'}],['support-config-osquery',{action:'osquery_configure'}],['support-config-qwen-setup',{action:'qwen_configure'}],['support-config-suricata-setup',{action:'suricata_configure',interface:'wlan0'}],['support-config-qwen',{action:'qwen_check'}],['support-config-zeek',{action:'zeek_check'}],['support-config-suricata',{action:'suricata_check'}]];
 for(const [id,expected] of scenarios){await click(id);const request=requests.at(-1);assert.equal(request.path,'/api/support-config');assert.equal(request.opts.method,'POST');assert.equal(request.opts.headers['X-Megalodon-Config-Token'],fixture.token);assert.deepEqual(JSON.parse(request.opts.body),expected);assert.equal(request.opts.headers['Content-Type'],'application/json');}
 change('support-config-nmap-target','8.8.8.8/32');let before=postCount();await click('support-config-nmap-save');assert.equal(postCount(),before);assert.match(status(),/private IPv4/);
 change('support-config-nmap-target','10.0.0.1');await click('support-config-nmap-save');assert.equal(JSON.parse(requests.at(-1).opts.body).nmap_target,'10.0.0.1/32');
 // An asynchronous save retains the submitted draft until the matching worker finishes.
 change('support-config-nmap-target','192.168.2.5/24');
 payload={...fixture,job:{...fixture.job,state:'running',action:'nmap_configure',started_at:'2026-09-30T20:09:00Z'}};
 await click('support-config-nmap-save');assert.equal(get('support-config-nmap-target').value,'192.168.2.5/24');
 payload={...fixture,settings:{...fixture.settings,nmap_target:'192.168.2.0/24'},job:{...payload.job,state:'finished',finished_at:'2026-09-30T20:09:01Z'}};
 await poll(2000);assert.equal(get('support-config-nmap-target').value,'192.168.2.0/24','successful save adopts canonical backend setting');
 // A failed worker preserves the user draft for correction or retry.
 change('support-config-nmap-target','192.168.3.0/24');payload={...payload,job:{...payload.job,state:'running',finished_at:null}};await click('support-config-nmap-save');
 payload={...payload,job:{...payload.job,state:'failed',finished_at:'2026-09-30T20:09:02Z'}};await poll(2000);assert.equal(get('support-config-nmap-target').value,'192.168.3.0/24');
 payload=fixture;
 // Duplicate clicks do not resend, permission progress appears immediately.
 let release;hold=new Promise(resolve=>release=resolve);const action=click('support-config-permissions');await settle();before=postCount();assert.match(status(),/Configuring capture access/);await click('support-config-permissions');assert.equal(postCount(),before);release();hold=null;await action;
 payload={...fixture,capture:{...fixture.capture,state:'running',interface:'eth0',started_at:'2026-09-30T20:10:00Z',message:'Capturing metadata.'}};await poll(10000);
 assert.match(get('support-capture-message').textContent,/Awaiting usable metadata/);assert.equal(get('support-config-capture-start').disabled,true);assert.equal(get('live-background-start').disabled,false,'manual capture may transition to saved background mode');assert.equal(get('support-config-capture-stop').disabled,false);assert.match(get('support-capture-time').textContent,/TShark \/ dumpcap metadata · eth0 · Started 2026-09-30 20:10:00 UTC/);
 await click('live-background-start');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'background_start',interface:'wlan0'});
 payload={...payload,background:{enabled:true,state:'running',message:'Monitoring.',session_count:1}};await poll(2000);assert.equal(get('live-background-start').disabled,true);assert.equal(get('live-background-stop').disabled,false);
 payload={...payload,background:{...payload.background,state:'failed'}};await poll(2000);assert.equal(get('live-background-start').disabled,false,'saved failed monitoring needs explicit retry');assert.equal(get('live-background-start').textContent,'Retry monitoring');payload={...payload,background:{...payload.background,state:'running'}};await poll(2000);
 payload={...payload,job:{...fixture.job,state:'running',action:'geography_refresh',started_at:'2026-09-30T20:10:00Z'}};await poll(2000);assert.equal(get('live-background-stop').disabled,false,'stop remains available during another setup action');payload={...payload,job:fixture.job};
 await click('live-background-stop');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'background_stop'});
 await click('live-geography-refresh');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'geography_refresh'});
 payload={...payload,geography_enabled:true};await poll(2000);assert.equal(get('live-geography-disable').disabled,false);assert.match(get('live-geography-opt-in').textContent,/enabled/);
 await click('live-geography-disable');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'geography_disable'});
 payload={...payload,geography_enabled:false};await poll(2000);assert.equal(get('live-geography-disable').disabled,true);assert.match(get('live-geography-opt-in').textContent,/off/);
 responseStatus=403;await click('live-geography-refresh');assert.equal(get('live-action-retry').hidden,false);const retryPosts=postCount();await click('live-action-retry');assert.equal(postCount(),retryPosts,'retry only refreshes controls');assert.equal(get('live-action-retry').hidden,true);
 await click('support-config-capture-stop');assert.deepEqual(JSON.parse(requests.at(-1).opts.body),{action:'capture_stop'});
 payload={...payload,capture:{...payload.capture,received:12,accepted:9,skipped:3},tools:[{id:'tshark',name:'<b>TShark</b>',state:'ready',message:'<img src=x>',checked_at:'2026-09-30T20:11:00Z'},{id:'wireshark',name:'Wireshark / capture access',state:'ready',message:'Live Wireshark launch requested for eth0.',checked_at:'2026-09-30T20:09:50Z'}]};await poll(2000);
 assert.match(get('support-wireshark-result').textContent,/Last Wireshark action result · 2026-09-30 20:09:50 UTC/);assert.match(get('support-wireshark-result').textContent,/launch requested/);assert.match(get('support-wireshark-result').textContent,/Current window state is not monitored/);assert.equal(get('support-capture-accepted').textContent,'9');assert.doesNotMatch(get('support-capture-message').textContent,/Awaiting usable/);assert.equal(get('support-config-tools').children[0].children[0].textContent,'<b>TShark</b>');assert.equal(get('support-config-tools').children[0].children[2].children[0].textContent,'Checked 2026-09-30 20:11:00 UTC');
 // Closing preserves active-capture polling; hiding pauses it. Reopening never starts capture.
 await click('support-config-close');assert.equal(get('support-config').hidden,true);await poll(2000);document.hidden=true;listeners.visibilitychange();assert.equal([...timers.values()].filter(v=>[2000,10000].includes(v.ms)).length,0);assert.match(status(),/paused/);
 document.hidden=false;listeners.visibilitychange();await settle();assert.equal(get('support-config-capture-stop').disabled,false);
 payload={...fixture,job:{state:'finished',action:'qwen_check',message:'Local service checked.',started_at:'2026-09-30T20:10:00Z',finished_at:'2026-09-30T20:11:00Z'}};await poll(2000);assert.match(status(),/Last action finished at 2026-09-30 20:11:00 UTC/);assert.equal([...timers.values()].filter(v=>[2000,10000].includes(v.ms)).length,0,'collapsed idle panel stops polling');
 await click('support-apps-configure');await settle();responseStatus=409;before=postCount();await click('support-config-qwen');assert.equal(postCount(),before+1);assert.equal(requests.at(-1).opts.method,'GET');assert.match(status(),/already running/);
 responseStatus=403;await click('support-config-qwen');assert.match(status(),/permission or session check/);assert.equal(get('support-config-retry').hidden,false);assert.equal(get('support-config-qwen').disabled,true);assert.equal(get('support-capture-state').textContent,'Status unavailable');
 await click('support-config-retry');assert.equal(get('support-config-qwen').disabled,false);responseStatus=400;await click('support-config-qwen');assert.match(status(),/settings were rejected/);await click('support-config-retry');
 failure=true;await poll(10000);assert.match(status(),/Unable to confirm/);failure=false;oversized=true;await click('support-config-retry');assert.equal(get('support-config-qwen').disabled,true);oversized=false;
 payload={...fixture,interfaces:Array.from({length:33},()=>fixture.interfaces[0])};await click('support-config-retry');assert.equal(get('support-config-qwen').disabled,true);
 payload={...fixture,token:'wrong'};await click('support-config-retry');assert.equal(get('support-config-qwen').disabled,true);
 payload=fixture;await click('support-config-retry');hold=new Promise(resolve=>release=resolve);const pending=click('support-config-qwen');document.hidden=true;listeners.visibilitychange();release();hold=null;await pending;assert.match(status(),/paused/);assert.equal([...timers.values()].filter(v=>[2000,10000].includes(v.ms)).length,0);
 console.log('support configuration UI behavior passed');
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
