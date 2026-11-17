// Fixed network-defense controls: explicit actions, generation binding and stale authority.
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', async () => {
  const {code, fixture} = JSON.parse(input);
  const nodes = new Map(), requests = [], timers = new Map();
  let sequence = 0, payload = fixture, responseStatus = 200, hold = null;
  function element() {
    return {textContent:'', children:[], attributes:{}, dataset:{}, events:{}, value:'', hidden:false, disabled:false,
      setAttribute(k,v){this.attributes[k]=v;}, append(...v){this.children.push(...v);},
      replaceChildren(...v){this.children=v;}, addEventListener(k,v){this.events[k]=v;}, focus(){}};
  }
  const get = id => {
    if (id === 'workspace-setup') return null;
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  const context = {localHudLaunch:{}, softwareCatalog:[], TextEncoder, TextDecoder, Uint8Array, AbortController,
    document:{hidden:false, getElementById:get, createElement:element, addEventListener(){}},
    setTimeout(fn, ms){const id=++sequence;timers.set(id,{fn,ms});return id;},
    clearTimeout(id){timers.delete(id);},
    fetch:async (path,opts) => {
      requests.push({path,opts});
      if (hold) await hold;
      const status=responseStatus; responseStatus=200;
      return {status,ok:status>=200&&status<300,headers:{get:()=>null},text:async()=>JSON.stringify(payload)};
    }};
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const click = id => get(id).events.click();
  const posts = () => requests.filter(row=>row.opts.method==='POST');
  const refresh = () => click('support-config-retry');
  const controls = ['support-notifications-toggle','support-rules-stage','support-rules-activate','support-rules-check','support-rules-rollback'];
  const notice = {schema:'megalodon-desktop-notifications-v1',enabled:false,state:'disabled',pending_count:0,
    interval_seconds:60,last_result:'not_attempted',last_attempt_at:null,delivery_verified:false,action_authority:'none'};
  const rules = {schema:'megalodon-suricata-rules-v1',state:'unconfigured',checked_at:null,generation:null,
    interface:null,home_net:null,rule_count:0,native_test_passed:false,runtime_state:'not_checked',rollback:'none',message:'Not checked.'};
  const staged = {...rules,state:'staged',checked_at:'2026-11-16T18:00:00Z',generation:'a'.repeat(32),
    interface:'eth0',home_net:'192.168.1.0/24',rule_count:100,native_test_passed:true,rollback:'available'};
  const ready = (r=staged,n=notice) => ({...fixture,suricata_rules:r,desktop_notifications:n});
  const inputScope = () => {get('support-rules-home-net').value='192.168.1.0/24';get('support-rules-home-net').events.input();};
  vm.runInNewContext(code,context);
  await settle();
  assert.equal(requests.length,0,'hidden setup never performs an action or status read');
  await click('support-apps-configure'); await settle();
  for (const id of controls) {
    assert.equal(get(id).disabled,true,'older/missing status cannot authorize '+id);
    await click(id);
  }
  assert.equal(posts().length,0);

  payload=ready(rules); await refresh();
  assert.equal(get('support-notifications-toggle').disabled,false,'disabled preference can be explicitly enabled');
  assert.equal(get('support-rules-check').disabled,false);
  assert.equal(get('support-rules-stage').disabled,true,'staging needs an explicit protected-network scope');
  assert.equal(get('support-rules-activate').disabled,true);
  assert.equal(get('support-rules-rollback').disabled,true);
  inputScope(); assert.equal(get('support-rules-stage').disabled,false);
  payload=ready(staged,{...notice,state:'unavailable'}); await refresh();
  assert.equal(get('support-notifications-toggle').disabled,true);
  await click('support-notifications-toggle'); assert.equal(posts().length,0);
  for (const changed of [{...staged,native_test_passed:false},{...staged,state:'failed'},{...staged,generation:null}]) {
    payload=ready(changed); await refresh();
    assert.equal(get('support-rules-activate').disabled,true);
    await click('support-rules-activate'); assert.equal(posts().length,0);
  }

  payload=ready(); await refresh(); inputScope();
  const actions = [
    ['support-notifications-toggle',{action:'desktop_notifications',enabled:true}],
    ['support-rules-stage',{action:'suricata_rules_stage',interface:'eth0',home_net:'192.168.1.0/24'}],
    ['support-rules-activate',{action:'suricata_rules_activate',generation:staged.generation}],
    ['support-rules-check',{action:'suricata_rules_check'}],
    ['support-rules-rollback',{action:'suricata_rules_rollback'}],
  ];
  for (const [id, expected] of actions) {
    const before=posts().length;
    await click(id);
    assert.equal(posts().length,before+1);
    const request=posts().at(-1);
    assert.equal(request.path,'/api/support-config');
    assert.deepEqual(JSON.parse(request.opts.body),expected);
    assert.equal(request.opts.headers['X-Megalodon-Config-Token'],fixture.token);
  }
  const readOnlyCount=posts().length;
  await refresh(); await refresh();
  assert.equal(posts().length,readOnlyCount,'refresh does not replay completed changes');
  payload=ready(staged,{...notice,enabled:true,state:'ready'}); await refresh();
  await click('support-notifications-toggle');
  assert.deepEqual(JSON.parse(posts().at(-1).opts.body),{action:'desktop_notifications',enabled:false});

  // A rejected explicit operation never refreshes authority and retries itself.
  for (const [id] of actions) {
    payload=ready(); await refresh(); inputScope();
    const before=posts().length, allBefore=requests.length;
    responseStatus=403; await click(id);
    assert.equal(posts().length,before+1,id+' may only POST once after a 403');
    assert.equal(requests.length,allBefore+1,'rejected action does not silently refresh its token');
    assert.equal(get(id).disabled,true,'failed authority disables mutation');
    await refresh();
    assert.equal(posts().length,before+1,'manual retry reads status without replay');
  }

  // Queue activation behind a routine GET, then change its staged generation.
  payload=ready(); await refresh();
  let release;
  hold=new Promise(resolve=>release=resolve);
  const reading=refresh(); await settle();
  assert.equal(get('support-rules-activate').disabled,false);
  const beforeGenerationChange=posts().length;
  const activating=click('support-rules-activate'); await settle();
  assert.equal(posts().length,beforeGenerationChange);
  payload=ready({...staged,generation:'b'.repeat(32)});
  release(); hold=null; await reading; await activating;
  assert.equal(posts().length,beforeGenerationChange,'a changed generation needs another deliberate review and click');
  assert.match(get('support-config-status').textContent,/staged rules changed/i);
  await click('support-rules-activate');
  assert.deepEqual(JSON.parse(posts().at(-1).opts.body),{action:'suricata_rules_activate',generation:'b'.repeat(32)});

  // Schema corruption must disable controls, not upgrade telemetry into verified authority.
  for (const bad of [ready(staged,{...notice,delivery_verified:true}),ready(staged,{...notice,action_authority:'block'}),
    ready({...staged,generation:'../outside'}),ready({...staged,native_test_passed:'true'})]) {
    payload=bad; await refresh();
    assert.equal(get('support-rules-activate').disabled,true);
    assert.equal(get('support-notifications-toggle').disabled,true);
  }
}).on('error',error=>{console.error(error);process.exitCode=1;});
