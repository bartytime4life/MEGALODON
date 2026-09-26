const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../dist/inventory.js'),'utf8');
const {validateInventorySummary:validate}=require('../dist/inventory.js');
const fixture=()=>({schema:'megalodon-nmap-inventory-v1',started_at:'2023-11-14T22:13:20Z',finished_at:'2023-11-14T22:13:30Z',hosts:[1,2],represented_hosts:[1,0],explicit_states:[1,0,0,0,1,0],grouped_states:[0,997,0,0,0,0],protocols:[1,1,0]});
test('inventory keeps grouped states and explicit protocols separate',()=>assert.deepEqual(validate(JSON.stringify(fixture())),fixture()));
for(const [label,mutate] of Object.entries({
 'extra identifier':d=>d.address='192.0.2.1','oversize counts':d=>d.hosts=[1000001,0],
 'negative count':d=>d.protocols[0]=-1,'protocol mismatch':d=>d.protocols[0]=2,
 'host mismatch':d=>d.represented_hosts=[2,0],'fraction':d=>d.hosts[0]=1.5,
 'missing field':d=>delete d.hosts,'wrong schema':d=>d.schema='live-inventory',
 'calendar':d=>d.started_at='2023-02-30T00:00:00Z','future':d=>d.finished_at='2099-01-01T00:00:00Z',
 'reversed time':d=>d.started_at='2023-11-15T00:00:00Z','no host but ports':d=>d.represented_hosts=[0,0]
}))test('refuses '+label,()=>{const d=fixture();mutate(d);assert.throws(()=>validate(JSON.stringify(d)));});
test('duplicate/escaped keys and excessive bytes refused',()=>{const text=JSON.stringify(fixture());for(const input of [text.replace('"hosts":','"hosts":[0,0],"hosts":'),text.replace('"hosts":','"\\u0068osts":[0,0],"hosts":'),' '.repeat(4097)])assert.throws(()=>validate(input));});
function dom(){class Element{constructor(){this.children=[];this.handlers={};this.textContent='';}replaceChildren(...x){this.children=x;}append(...x){this.children.push(...x);}setAttribute(){}addEventListener(n,f){this.handlers[n]=f;}}const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};const ctx={document,TextEncoder,TextDecoder};vm.createContext(ctx);vm.runInContext(source,ctx);return nodes;}
const file=d=>{const bytes=new TextEncoder().encode(JSON.stringify(d));return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};};
test('renders, preserves valid inventory on error, and clear wins pending import',async()=>{
 const n=dom(),load=f=>n.get('inventory-file').handlers.change({target:{files:[f]}});
 await load(file(fixture()));assert.equal(n.get('inventory-results').hidden,false);assert.equal(n.get('inventory-explicit').children.length,6);assert.equal(n.get('inventory-hosts').children[0].children[1].textContent,'1');assert.match(n.get('inventory-status').textContent,/Not live/);
 await load({size:4097,arrayBuffer:()=>assert.fail('must not read')});assert.match(n.get('inventory-status').textContent,/preserved/);assert.equal(n.get('inventory-results').hidden,false);
 let finish;const pending=load({size:100,arrayBuffer:()=>new Promise(r=>finish=r)});n.get('inventory-clear').handlers.click();finish(await file(fixture()).arrayBuffer());await pending;assert.equal(n.get('inventory-results').hidden,true);assert.equal(n.get('inventory-hosts').children.length,0);
});
test('inventory never adds network, storage or executable content',()=>assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/));
