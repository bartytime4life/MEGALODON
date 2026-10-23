const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {code,fixture}=JSON.parse(fs.readFileSync(0,'utf8'));
const nodes=new Map(),listeners={},requests=[],downloads=[],blobs=[];
class E {
  constructor(tag='div'){this.tag=tag;this.textContent='';this.children=[];this.events={};this.hidden=false;this.disabled=false;}
  append(...values){this.children.push(...values);}
  replaceChildren(...values){this.children=values;}
  addEventListener(name,fn){this.events[name]=fn;}
  click(){if(this.download)downloads.push({name:this.download,href:this.href});return this.events.click?.();}
  set innerHTML(_){throw Error('Investigation must render text safely');}
}
const get=id=>{if(!nodes.has(id))nodes.set(id,new E());return nodes.get(id);};
const text=n=>n.textContent+' '+n.children.map(text).join(' ');
let payload=fixture,hold=null;
const document={hidden:false,getElementById:get,createElement:tag=>new E(tag),addEventListener:(name,fn)=>listeners[name]=fn};
const context={document,Date,encodeURIComponent,setTimeout:fn=>fn(),
  Blob:class{constructor(parts,options){blobs.push({parts,options});}},
  URL:{createObjectURL:()=> 'blob:synthetic-note',revokeObjectURL:()=>{}},
  requestBoundedJSON:async(path,max,options)=>{requests.push({path,max,options});if(hold)await hold;return JSON.parse(JSON.stringify(payload));}};
vm.runInNewContext(code,context);
const select=ip=>listeners['megalodon:endpoint-selected']({detail:ip});
async function run(){
  assert.equal(requests.length,0);
  select('8.8.8.8');assert.equal(get('address-investigation-read').disabled,false);assert.equal(requests.length,0,'selection never starts a lookup');
  await get('address-investigation-read').click();
  assert.equal(requests[0].path,'/api/address-investigation?ip=8.8.8.8');assert.equal(requests[0].max,16384);assert.equal(requests[0].options.headers['X-Megalodon-Check'],'1');
  assert.match(text(get('address-investigation-result')),/Original address: not established/);
  assert.match(text(get('address-investigation-result')),/WireGuard-associated port/);
  assert.match(text(get('address-investigation-result')),/Packets: 3/);
  assert.match(text(get('address-investigation-result')),/Sent by this address: 250/);
  assert.match(text(get('address-investigation-result')),/TCP \/ 443/);
  assert.match(text(get('address-investigation-result')),/Capture gaps and drops: unknown/);
  const link=get('address-investigation-result').children.find(n=>n.tag==='a');
  assert.equal(link.href,'https://search.arin.net/rdap/');assert.ok(!link.href.includes('8.8.8.8'));assert.equal(link.referrerPolicy,'no-referrer');
  await get('address-investigation-save').click();
  assert.equal(downloads.length,1);assert.equal(blobs[0].options.type,'application/json');assert.equal(JSON.parse(blobs[0].parts[0]).original_address,null);
  assert.equal(JSON.parse(blobs[0].parts[0]).traffic.packets,3);
  let release;hold=new Promise(resolve=>release=resolve);
  const stale=get('address-investigation-read').click();select('1.1.1.1');release();await stale;hold=null;
  assert.equal(get('address-investigation-result').hidden,true);assert.equal(get('address-investigation-save').disabled,true,'old selection cannot export its note under a new address');
  payload={...fixture,observed_address:'1.1.1.1',person_identity:'forged person'};await get('address-investigation-read').click();assert.equal(get('address-investigation-result').hidden,true);assert.equal(get('address-investigation-save').disabled,true);
  payload={...fixture,observed_address:'1.1.1.1',registry_search_url:'https://example.invalid/?ip=1.1.1.1'};await get('address-investigation-read').click();assert.equal(get('address-investigation-result').hidden,true);
  for(const invalid of [-1,true,9007199254740992]){
    payload={...fixture,observed_address:'1.1.1.1',traffic:{...fixture.traffic,packets:invalid}};
    await get('address-investigation-read').click();assert.equal(get('address-investigation-result').hidden,true);assert.equal(get('address-investigation-save').disabled,true);
  }
  payload={...fixture,observed_address:'1.1.1.1',traffic:{...fixture.traffic,packets:null,bytes:0}};
  await get('address-investigation-read').click();assert.match(text(get('address-investigation-result')),/Packets: unavailable/);assert.match(text(get('address-investigation-result')),/Bytes: 0/);
  select('10.0.0.1');payload={...fixture,observed_address:'10.0.0.1',public_address:false,registry_search_url:null};await get('address-investigation-read').click();
  assert.equal(get('address-investigation-result').children.some(n=>n.tag==='a'),false);assert.match(text(get('address-investigation-result')),/private or reserved/);
  select(null);assert.equal(get('address-investigation-save').disabled,true);assert.equal(get('address-investigation-result').hidden,true);
  console.log('Offline address investigation, note export and selection safety passed');
}
run().catch(error=>{console.error(error);process.exitCode=1;});
