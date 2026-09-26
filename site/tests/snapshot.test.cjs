const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {validateHudSnapshot}=require('../dist/snapshot.js');
const example=()=>({schema:'megalodon-hud-snapshot-v1',generated_at:'2026-09-20T12:00:00Z',start:'2026-09-20T11:00:00Z',end:'2026-09-20T12:00:00Z',events:3,findings:2,reported_bytes:'18446744073709551614',lanes:[1,1,1],timeline:[1,0,0,0,0,0,0,0,0,0,0,2],protocols:[2,1,0,0,0,0,0,0],sources:[3,0],severities:[1,0,1,0],detectors:[0,2,0],limited:true,quality:'degraded'});
test('valid snapshot retains exact large byte totals and historical date',()=>{assert.deepEqual(validateHudSnapshot(JSON.stringify(example())),example());});
for(const [name,change] of Object.entries({
 'extra sensitive field':x=>x.address='192.0.2.1',
 'wrong totals':x=>x.protocols[0]=3,
 'wrong lane count':x=>x.lanes=[3,0,0],
 'fake detector':x=>x.detectors.push(1),
 'negative records':x=>x.events=-1,
 'empty metadata':x=>x.events=0,
 'excess records':x=>x.events=501,
 'byte overflow':x=>x.reported_bytes='999999999999999999999',
 'fractional count':x=>x.severities[0]=0.5,
 'forged quality':x=>x.quality='safe',
 'invalid calendar':x=>x.start='2026-02-30T00:00:00Z',
 'future export':x=>x.generated_at='2099-01-01T00:00:00Z',
 'future observations':x=>x.end='2026-09-20T12:02:00Z',
 'reversed time':x=>x.start='2026-09-21T00:00:00Z'
}))test(`rejects ${name}`,()=>{const x=example();change(x);assert.throws(()=>validateHudSnapshot(JSON.stringify(x)));});
test('rejects duplicates, excessive nesting and oversized input',()=>{const text=JSON.stringify(example());for(const x of [text.replace('"events":3','"events":3,"events":3'),text.replace('"events":3','"events":3,"\\u0065vents":3'),'['.repeat(100)+']'.repeat(100),' '.repeat(16385)])assert.throws(()=>validateHudSnapshot(x));});
function dom(){
 class Element{constructor(){this.children=[];this.style={};this.handlers={};this.textContent='';}replaceChildren(...nodes){this.children=nodes;}append(...nodes){this.children.push(...nodes);}setAttribute(){}addEventListener(name,fn){this.handlers[name]=fn;}}
 const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};
 const context={document,TextEncoder,TextDecoder};vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../dist/snapshot.js'),'utf8'),context);return {nodes,context};
}
const file=value=>{const bytes=new TextEncoder().encode(JSON.stringify(value));return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};};
test('import renders real counts, clear removes data, older reads cannot restore it',async()=>{
 const {nodes}=dom(),input=nodes.get('snapshot-file');assert.equal(nodes.get('snapshot-events').textContent,'—');
 await input.handlers.change({target:{files:[file(example())]}});assert.equal(nodes.get('snapshot-events').textContent,'3');assert.equal(nodes.get('snapshot-lanes-chart').children.length,3);assert.equal(nodes.get('snapshot-timeline').children.length,12);
 let finish;const pending=input.handlers.change({target:{files:[{size:100,arrayBuffer:()=>new Promise(resolve=>finish=resolve)}]}});
 nodes.get('snapshot-clear').handlers.click();finish(await file(example()).arrayBuffer());await pending;assert.equal(nodes.get('snapshot-events').textContent,'—');
});
test('rejected file preserves prior summary and older import cannot win a race',async()=>{
 const {nodes}=dom(),input=nodes.get('snapshot-file');await input.handlers.change({target:{files:[file(example())]}});
 let finish;const pending=input.handlers.change({target:{files:[{size:100,arrayBuffer:()=>new Promise(resolve=>finish=resolve)}]}});
 await input.handlers.change({target:{files:[{size:16385,arrayBuffer:()=>assert.fail('must not read large file')}]}});
 finish(await file(example()).arrayBuffer());await pending;assert.match(nodes.get('snapshot-status').textContent,/Import rejected/);assert.equal(nodes.get('snapshot-events').textContent,'3');
});
test('summary UI has no network, persistent storage, HTML injection or command execution',()=>{const source=fs.readFileSync(require.resolve('../dist/snapshot.js'),'utf8');assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/);});
