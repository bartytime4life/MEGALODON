/* Shipped file-inspection code with an inert DOM; no analyzer or sample run. */
const assert = require('node:assert/strict'), vm = require('node:vm');
let input = '';
process.stdin.on('data', part => input += part);
process.stdin.on('end', async () => {
  const {code, report} = JSON.parse(input), elements = new Map(), requests = [], timers = new Map(), downloads = [], exports = [];
  let observer, timerId = 0, installed = 0;
  function element(tag = 'div') {
    const value = {tag, textContent:'', hidden:false, disabled:false, dataset:{}, children:[], attributes:{}, listeners:{}, files:[],
      append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
      setAttribute(key, text) { this.attributes[key] = text; }, removeAttribute(key) { delete this.attributes[key]; },
      addEventListener(name, callback) { (this.listeners[name] ??= []).push(callback); },
      async emit(name) { for (const listener of this.listeners[name] || []) await listener({target:this}); },
      click() { downloads.push(this); }, remove() {}, querySelectorAll() { return []; }};
    Object.defineProperty(value, 'innerHTML', {set() { throw Error('unsafe HTML sink'); }});
    return value;
  }
  const el = id => { if(!elements.has(id)) elements.set(id,element());return elements.get(id); };
  const steps = ['choose','inspect','understand'].map(step => { const n=element('li');n.dataset.step=step;return n; });
  el('file-inspection').querySelectorAll = () => steps;
  const document = {hidden:false, body:element('body'), getElementById:el, createElement:element, listeners:{},
    addEventListener(name, callback) { this.listeners[name] = callback; }};
  const token='A_z-9'.repeat(6)+'Z_', job='b'.repeat(32);
  let payload = {schema:'megalodon-file-inspection-status-v1',state:'idle',job_id:null,
    runtime:{state:'ready',message:'Pinned local inspector and isolation are available.'},max_bytes:67108864,report:null,token};
  const reply = (p, status=200) => ({ok:status>=200&&status<300,status,headers:{get:()=>null},text:async()=>JSON.stringify(p)});
  let handler = async () => reply(payload);
  const context = {document, localHudLaunch:{}, TextEncoder, TextDecoder, Uint8Array, Blob, AbortController,
    IntersectionObserver:class { constructor(callback) { observer=callback; } observe() {} },
    setTimeout(callback, delay) { timers.set(++timerId,{callback,delay});return timerId; },clearTimeout(id) { timers.delete(id); },
    fetch:async(path, options) => { requests.push({path,options});return handler(path,options); },
    URL:{createObjectURL(blob) { exports.push(blob);return 'blob:local-report'; },revokeObjectURL() {}},
    heartbeatState:{catalog:[{id:'file-inspector',one_click:true,summary:'Optional pinned runtime.'}],managementEnabled:true,submitting:false,job:null},
    toolManagementToken:()=>token,heartbeatStale:()=>false,startInstall:async(id,name,entry)=>{assert.equal(id,'file-inspector');assert.equal(name,'File inspector');assert.equal(entry.id,id);installed++;},
  };
  vm.runInNewContext(code,context);
  const text = n => n.textContent+' '+n.children.map(text).join(' '),settle=()=>new Promise(resolve=>setImmediate(resolve));
  const node=id=>el('file-inspection-'+id), changed=async file=>{node('input').files=file?[file]:[];await node('input').emit('change');};
  assert.equal(requests.length,0,'hidden panel does not poll or analyze');
  assert.equal(context.validFileInspectionReport(report),true);
  for(const bad of [null,{...report,raw:'SAMPLE_SECRET'},{...report,filename:'secret.exe'},
    {...report,structure:{...report.structure,path:'/home/private'}},
    {...report,tools:[...report.tools,{id:'other',state:'completed'}]},
    {...report,tools:[{...report.tools[0],state:'safe'},report.tools[1]]},
    {...report,tools:[{...report.tools[0],state:'failed'},report.tools[1]]},
    {...report,structure:null},
    {...report,identification:[{kind:'packer',name:'UPX'}]},
    {...report,state:'completed'},
    {...report,identification:[{kind:'packer',name:'x'.repeat(121)}]},
    {...report,unknowns:['x\nsecret']},{...report,unknowns:Array(17).fill('x')},
    {...report,structure:{...report.structure,slices:Array(17).fill(report.structure.slices[0]),slices_detected:17}},
    {...report,structure:{...report.structure,slices_detected:2}},
    {...report,structure:{...report.structure,slices_detected:17}},
    {...report,structure:{...report.structure,format:'ELF',slices_detected:2,slices:Array(2).fill(report.structure.slices[0])}},
    {...report,structure:{...report.structure,slices:[{...report.structure.slices[0],bits:128}]}},
    {...report,size_bytes:67108865},{...report,state:'safe'},{...report,inspected_at:'yesterday'}]) {
    assert.equal(context.validFileInspectionReport(bad),false,JSON.stringify(bad));
  }
  assert.equal(context.validFileInspectionStatus(payload),true);
  assert.equal(token.length,32);assert.ok(/[_-]/.test(token)&&/[A-Z]/.test(token),'fixture exercises real base64url configuration nonces');
  for(const bad of [{...payload,token:'bad'},{...payload,token:token+'a'},{...payload,token:token.slice(1)},{...payload,token:' '+token.slice(1)},{...payload,token:token+'\n'},{...payload,token:token.slice(0,-1)+'\n'},{...payload,token:token.slice(0,-1)+'/'},{...payload,job_id:token},{...payload,raw:'secret'}, {...payload,max_bytes:999},
    {...payload,runtime:{state:'ready',message:'x',path:'/secret'}},{...payload,report:{...report,hash:'secret'}}]) {
    assert.equal(context.validFileInspectionStatus(bad),false);
  }
  const file={name:'<img src=x onerror=alert(1)>.exe',size:64,contents:'SAMPLE_SECRET'};
  await changed(file);assert.equal(requests.length,0,'selection alone never sends the file');
  assert.match(node('selection').textContent,/<img src=x/);assert.match(node('status').textContent,/Nothing has been sent/);
  observer([{isIntersecting:true}]);await settle();assert.equal(requests.length,1);assert.equal(requests[0].options.method,undefined);
  assert.equal(node('run').disabled,false);
  payload={...payload,state:'partial',job_id:job,report};
  await node('run').emit('click');
  assert.equal(requests.filter(r=>r.options.method==='POST').length,1);
  const submission=requests.find(r=>r.path.endsWith('/run'));
  assert.equal(submission.options.body,file,'File object is submitted directly without reading or serializing its bytes');
  assert.equal(submission.options.headers['Content-Type'],'application/octet-stream');
  assert.equal(submission.options.headers['X-Megalodon-Config-Token'],token);
  assert.equal(submission.options.credentials,'same-origin');assert.equal(submission.options.mode,'same-origin');assert.equal(submission.options.redirect,'error');
  assert.ok(!Object.keys(submission.options.headers).some(k=>/filename|path/i.test(k)));
  assert.match(node('status').textContent,/Partial inspection/);
  assert.match(node('report-scope').textContent,/Report for the file you submitted[\s\S]*Partial coverage/);
  assert.match(text(node('tools')),/LIEF · structure: Completed[\s\S]*Detect It Easy · identification: Unsupported/);
  assert.match(text(node('technical')),/1 of 1/);
  assert.match(text(node('clues')),/Slice 1 \(arm64, 64-bit\): 1 writable\/executable region\./);
  assert.match(text(node('clues')),/Some legitimate runtimes/);
  assert.match(text(node('clues')),/LIEF · structure: Completed/);
  assert.match(text(node('clues')),/Detect It Easy · identification: Unsupported\. Identification clues are unavailable/);
  assert.doesNotMatch(text(node('clues')),/Reported packer|Packing or protection identified/);
  const walk=n=>[n,...n.children.flatMap(walk)];
  const disclosures=()=>walk(node('clues')).filter(n=>n.tag==='details');
  assert.equal(disclosures().length,1);
  assert.equal(disclosures()[0].open,undefined);
  assert.equal(disclosures()[0].children[0].attributes['aria-label'],'Why this appears: Writable and executable region');
  for(const label of ['Observed fact','Source','Meaning','Limit'])assert.match(text(disclosures()[0]),new RegExp(label));
  assert.equal(node('details').open,undefined,'technical details remain collapsed');
  await node('export').emit('click');assert.equal(exports.length,1);
  const exported=JSON.parse(await exports[0].text());assert.deepEqual(exported,report);
  assert.doesNotMatch(JSON.stringify(exported),/SAMPLE_SECRET|onerror=alert\(1\)>\.exe|token|job_id|filename|sha256|raw/);
  assert.equal(downloads[0].download,'megalodon-file-inspection.json');
  // Report refreshes exercise the actual renderer without running any analyzer.
  const show=async value=>{assert.equal(context.validFileInspectionReport(value),true);payload={...payload,state:value.state==='unsupported'?'failed':value.state,report:value};await node('check').emit('click');};
  const complete=JSON.parse(JSON.stringify(report));complete.state='completed';complete.tools[1].state='completed';
  complete.structure.slices_detected=3;
  complete.structure.slices.push({...complete.structure.slices[0],architecture:'x86_64',writable_executable:2},{...complete.structure.slices[0],architecture:'zero',writable_executable:0});
  complete.identification=[{kind:'packer',name:'UPX'},{kind:'protector',name:'Example protector'},{kind:'compiler',name:'GCC'},{kind:'compiler',name:'Clang'},{kind:'linker',name:'GNU ld'}];
  complete.clues.push({code:'packed',title:'Packing or protection identified',meaning:'Unused report wording.'});
  const unchanged=JSON.stringify(complete);await show(complete);
  assert.equal(disclosures().length,4,'packing and protector labels share one explanation');
  assert.equal(node('clues').children.filter(n=>n.children[0]?.textContent==='Packing or protection identified').length,1);
  assert.match(text(node('clues')),/Slice 2 \(x86_64, 64-bit\): 2 writable\/executable regions/);
  assert.doesNotMatch(text(node('clues')),/Slice 3|Unused report wording/);
  assert.match(text(node('clues')),/Reported packer label: UPX[\s\S]*Reported protector label: Example protector/);
  assert.match(text(node('clues')),/Reported compiler label: GCC[\s\S]*Reported compiler label: Clang/);
  assert.match(text(node('clues')),/Reported linker label: GNU ld/);
  assert.match(text(node('clues')),/signature matches, not a verified build history/);
  assert.equal(JSON.stringify(complete),unchanged,'explanations never mutate the report');
  await node('export').emit('click');assert.deepEqual(JSON.parse(await exports[1].text()),complete);
  // Untrusted strings stay text, and arbitrary supplied interpretations are unused.
  const hostile=JSON.parse(unchanged);hostile.identification[0].name='<img src=x onerror=alert(1)>';
  hostile.structure.slices[0].architecture='<svg onload=alert(1)>';
  hostile.clues[0].meaning='UNTRUSTED_INTERPRETATION';await show(hostile);
  assert.match(text(node('clues')),/<img src=x onerror=alert\(1\)>/);
  assert.match(text(node('clues')),/<svg onload=alert\(1\)>/);
  assert.doesNotMatch(text(node('clues')),/UNTRUSTED_INTERPRETATION/);
  assert.ok(!walk(node('clues')).some(n=>['img','svg'].includes(n.tag)));
  const unsupportedClues={...complete,structure:{...report.structure,slices:[{...report.structure.slices[0],writable_executable:0}]},identification:[]};
  await show(unsupportedClues);
  assert.equal(disclosures().length,0,'unsupported clues never invent evidence or interpretations');
  assert.match(text(node('clues')),/Supporting metadata is missing or inconsistent/);
  assert.doesNotMatch(text(node('clues')),/Some legitimate runtimes|Legitimate software also uses it/);
  for(const toolState of ['unavailable','unsupported','failed','timed_out','cancelled']){
    const partial={...report,state:toolState==='cancelled'?'cancelled':'partial',tools:[report.tools[0],{id:'die',state:toolState}]};
    await show(partial);assert.equal(disclosures().length,1);assert.match(text(node('clues')),/Identification clues are unavailable/);
    const onlyDie={...complete,structure:null,tools:[{id:'lief',state:toolState},complete.tools[1]],state:toolState==='cancelled'?'cancelled':'partial',clues:[complete.clues[1]]};
    await show(onlyDie);assert.equal(disclosures().length,3);assert.match(text(node('clues')),/Structural details are unavailable/);assert.doesNotMatch(text(node('clues')),/Slice 1|Writable and executable region/);
    const empty={...report,structure:null,identification:[],clues:[],tools:report.tools.map(t=>({...t,state:toolState})),state:toolState==='cancelled'?'cancelled':toolState==='unsupported'?'unsupported':'failed'};
    await show(empty);assert.equal(disclosures().length,0);assert.match(text(node('clues')),/This does not establish that the file is safe/);
  }
  await show({...complete,structure:{...report.structure,slices:[{...report.structure.slices[0],writable_executable:0}]},identification:[],clues:[]});
  assert.match(text(node('clues')),/No review clues were returned[\s\S]*does not establish that the file is safe/);
  await show({...report,clues:[{code:'unknown',title:'IGNORE',meaning:'UNTRUSTED_INTERPRETATION'}]});
  assert.match(text(node('clues')),/no reviewed explanation/);assert.doesNotMatch(text(node('clues')),/IGNORE|UNTRUSTED_INTERPRETATION/);
  await show(report);
  await changed({name:'different.bin',size:65});assert.equal(node('result').hidden,true,'selection clears previous report');
  await node('check').emit('click');assert.match(node('report-scope').textContent,/Earlier report[\s\S]*not associated/);
  await changed({name:'too-large.bin',size:67108865});assert.equal(node('run').disabled,true);assert.match(node('status').textContent,/larger than 64 MiB/);
  await node('check').emit('click');assert.equal(node('run').disabled,true,'refresh cannot enable oversized input');
  await changed({name:'empty.bin',size:0});assert.equal(node('run').disabled,true);assert.match(node('status').textContent,/empty/);
  payload={...payload,state:'idle',job_id:null,report:null,runtime:{state:'unavailable',message:'The optional inspector runtime is not installed.'}};
  await changed(file);await node('check').emit('click');assert.equal(node('run').disabled,true);assert.equal(node('install').hidden,false);assert.equal(node('install').disabled,false);
  await node('install').emit('click');assert.equal(installed,1);
  context.heartbeatState.managementEnabled=false;await node('check').emit('click');assert.equal(node('install').disabled,true);assert.equal(node('authorize').hidden,false);
  context.heartbeatState.managementEnabled=true;
  payload={...payload,runtime:{state:'ready',message:'Available.'}};await node('check').emit('click');
  let uploadResolve;
  handler=async(path,options)=>path.endsWith('/run')?await new Promise(resolve=>{uploadResolve=resolve;}):reply({...payload,state:'cancelled',job_id:job,report:null});
  const uploading=node('run').emit('click');await settle();assert.equal(node('input').disabled,true);assert.equal(node('cancel').disabled,false);
  await node('cancel').emit('click');assert.equal(submission.options.signal.aborted,false);
  const cancel=requests.find(r=>r.path.endsWith('/cancel'));
  assert.equal(cancel.options.body,'{}');assert.equal(cancel.options.headers['Content-Type'],'application/json');assert.equal(cancel.options.headers['X-Megalodon-Config-Token'],token);
  uploadResolve(reply({...payload,state:'running',job_id:job}));await uploading;
  assert.match(node('status').textContent,/Inspection cancelled/,'late upload response cannot revive a cancelled job');
  handler=async()=>reply({...payload,token:'invalid'});await node('check').emit('click');assert.equal(node('run').disabled,true);assert.match(node('status').textContent,/status is unavailable/);
  handler=async()=>reply({...payload,state:'failed',job_id:job,report:{...report,state:'unsupported',structure:null,identification:[],clues:[],tools:report.tools.map(t=>({...t,state:'unsupported'}))}});
  await node('check').emit('click');assert.match(node('status').textContent,/not supported/);assert.match(node('what').textContent,/could not establish/);
  const denied={error:'SERVER_ERROR_STRING_MUST_NOT_RENDER <img src=x>',code:'file_inspection_sign_in_required'};
  const ready={...payload,state:'idle',job_id:null,report:null};
  handler=async()=>reply(denied,403);await node('check').emit('click');
  assert.equal(node('run').disabled,true);assert.equal(node('sign-in').hidden,false);assert.equal(node('runtime').hidden,true);
  assert.equal(node('result').hidden,true);assert.equal(node('export').disabled,true,'sign-in denial clears earlier report from the active UI');
  assert.match(node('status').textContent,/requires local HUD sign-in/);assert.doesNotMatch(node('status').textContent,/SERVER_ERROR_STRING/);
  await changed(file);assert.match(node('status').textContent,/requires local HUD sign-in/);
  const beforeDeniedClick=requests.length;await node('run').emit('click');assert.equal(requests.length,beforeDeniedClick,'disabled inspection cannot submit or launch');
  handler=async()=>reply(ready);await node('check').emit('click');
  assert.equal(node('sign-in').hidden,true);assert.equal(node('runtime').hidden,false);assert.equal(node('run').disabled,false,'valid status recovers without auto-submission');
  const recovered=requests.length;await settle();assert.equal(requests.length,recovered);
  for(const [body,status] of [[{...denied,code:'different_error'},403],[denied,401]]){
    handler=async()=>reply(body,status);await node('check').emit('click');
    assert.equal(node('sign-in').hidden,true);assert.equal(node('run').disabled,true);
    assert.match(node('status').textContent,/status is unavailable/);assert.doesNotMatch(node('status').textContent,/SERVER_ERROR_STRING|requires local HUD sign-in/);
  }
  handler=async()=>reply(ready);await node('check').emit('click');
  handler=async()=>reply(denied,403);await node('run').emit('click');
  assert.equal(node('sign-in').hidden,false);assert.equal(node('run').disabled,true);assert.match(node('status').textContent,/requires local HUD sign-in/,'submission denial uses the same sign-in state');
  handler=async()=>reply(ready);await node('check').emit('click');
  let deniedUploadResolve;
  handler=async path=>path.endsWith('/run')?await new Promise(resolve=>{deniedUploadResolve=resolve;}):reply(denied,403);
  const deniedUpload=node('run').emit('click');await settle();await node('cancel').emit('click');
  assert.equal(node('sign-in').hidden,false);assert.equal(node('cancel').hidden,true);assert.equal(node('run').disabled,true);
  assert.match(node('status').textContent,/requires local HUD sign-in/);assert.doesNotMatch(node('status').textContent,/cancelled/i,'auth denial does not claim cancellation succeeded');
  deniedUploadResolve(reply({...ready,state:'running',job_id:job}));await deniedUpload;
  assert.match(node('status').textContent,/requires local HUD sign-in/,'late upload response cannot clear the denial');
  handler=async()=>reply(ready);await node('check').emit('click');assert.equal(node('sign-in').hidden,true);assert.equal(node('run').disabled,false);
  observer([{isIntersecting:false}]);assert.equal([...timers.values()].filter(t=>[1000,15000].includes(t.delay)).length,2,'only deferred export URL revocations remain while the panel is hidden');
  console.log('file inspection UI workflow passed');
}).on('error', error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
