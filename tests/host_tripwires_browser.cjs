const assert=require('node:assert/strict'),vm=require('node:vm');let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
 const {code,tripped,clear,unconfigured,unreadable,notFound,pending}=JSON.parse(input);
 function element(tag=''){const n={tag,textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink')}});return n;}
 const context={document:{createElement:element}};vm.runInNewContext(code,context);
 const text=n=>n.textContent+' '+n.children.map(text).join(' ');
 const render=value=>{const panel=element('div');context.renderHostTripwires(panel,value);return panel;};
 for(const value of [tripped,clear,unconfigured,unreadable,notFound])assert.equal(context.validHostTripwires(value),true,JSON.stringify(value).slice(0,300));

 const body=text(render(tripped));
 assert.match(body,/3 of 3 canary files tripped/);
 assert.match(body,/CRITICAL · Canary removed or replaced · wallet-recovery\.txt/);
 assert.match(body,/CRITICAL · Canary modified · ssh-key-backup\.txt/);
 assert.match(body,/CRITICAL · Login succeeded after failures · 198\.51\.100\.23/);
 assert.match(body,/HIGH · Failed login burst · 198\.51\.100\.23/);
 assert.match(body,/ATT&CK technique\s+T1110, T1078/);
 assert.match(body,/Most failed logins by source \(1\)[\s\S]*198\.51\.100\.23 · 8 failures/);
 assert.doesNotMatch(body,/\/tmp\/|\/home\//,'directory paths never reach the HUD');

 assert.match(text(render(clear)),/All 2 canary files are intact[\s\S]*No login findings in this log/);
 assert.match(text(render(unconfigured)),/No canary files are planted yet[\s\S]*megalodon canary plant/);
 assert.match(text(render(unreadable)),/auth log could not be read: .*adm group/);
 assert.match(text(render(notFound)),/No system auth log was found \(checked auth\.log, secure\)/);
 assert.match(text(render(pending)),/Reviewing tripwires/);assert.equal(context.hostTripwiresPending(pending),true);

 // Attacker-chosen usernames render as inert text.
 const hostile=JSON.parse(JSON.stringify(tripped));hostile.auth.findings[0].subject='<img src=x onerror=alert(1)>';
 assert.match(text(render(hostile)),/<img src=x/);

 const clone=v=>JSON.parse(JSON.stringify(v));
 const mutate=(fn)=>{const v=clone(tripped);fn(v);return v;};
 const forged=[null,{...tripped,action_authority:'block'},{...tripped,schema:'x'},{...tripped,extra:1},{...pending,extra:1},
  mutate(v=>{v.canary.findings[0].severity='LOW';}), mutate(v=>{v.canary.findings[0].rule_id='CANARY_DELETED_EVERYTHING';}),
  mutate(v=>{v.canary.state='clear';}), mutate(v=>{v.canary.findings_total=99;}), mutate(v=>{v.canary.findings[0].name='a\u0007b';}),
  mutate(v=>{v.auth.findings[0].severity='LOW';}), mutate(v=>{v.auth.findings[0].attack=['T0000'];}),
  mutate(v=>{v.auth.findings[0].rule_id='ROOTKIT';}), mutate(v=>{v.auth.findings_total=0;}),
  mutate(v=>{v.auth.severity_counts.CRITICAL=5;}), mutate(v=>{v.auth.top_failing_sources[0].source='evil.example';}),
  mutate(v=>{v.auth.findings=Array(17).fill(v.auth.findings[0]);}), mutate(v=>{v.auth.observed.failed_logins=-1;}),
  mutate(v=>{v.reviewed_at='yesterday';}), mutate(v=>{v.auth.state='ready';v.auth.extra=1;})];
 for(const bad of forged){
  const out=text(render(bad));assert.match(out,/unavailable|could not be read on this PC/);
  assert.doesNotMatch(out,/CRITICAL ·|HIGH ·/);assert.equal(context.hostTripwiresPending(bad),false);
 }
 console.log('host tripwires panel passed');
}).on('error',e=>{console.error(e);process.exitCode=1;});
