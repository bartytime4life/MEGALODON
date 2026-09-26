const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../dist/clamav.js'),'utf8');
const {validateClamavSummary:validate}=require('../dist/clamav.js');
const fixture=()=>({schema:'megalodon-clamscan-summary-v1',exported_at:'2026-09-26T12:05:00Z',scan_start_local:'2026:09:26 12:00:00',scan_end_local:'2026:09:26 12:00:01',engine_version:'1.4.3',scanned_directories:2,scanned_files:10,infected_files:1,errors:0});
test('ClamAV summary validates saved counts without treating dates as UTC',()=>assert.deepEqual(validate(JSON.stringify(fixture())),fixture()));
for(const [label,mutate] of Object.entries({
 'private path':d=>d.path='/private/secret','unsupported schema':d=>d.schema='live-scan',
 'missing count':d=>delete d.scanned_files,'bad engine':d=>d.engine_version='secret',
 'fraction':d=>d.infected_files=.5,'negative':d=>d.infected_files=-1,
 'over count':d=>d.infected_files=11,'error':d=>d.errors=1,
 'future export':d=>d.exported_at='2099-01-01T00:00:00Z',
 'bad calendar':d=>d.scan_end_local='2026:02:30 12:00:01',
 'reversed interval':d=>d.scan_start_local='2026:09:27 12:00:00'
}))test('ClamAV import refuses '+label,()=>{const data=fixture();mutate(data);assert.throws(()=>validate(JSON.stringify(data)));});
test('ClamAV import refuses duplicate/escaped keys and excessive bytes',()=>{const input=JSON.stringify(fixture());for(const text of [input.replace('"errors":','"errors":0,"errors":'),input.replace('"errors":','"\\u0065rrors":0,"errors":'),' '.repeat(4097)])assert.throws(()=>validate(text));});
function dom(){class Element{constructor(){this.children=[];this.handlers={};this.textContent='';}replaceChildren(...x){this.children=x;}append(...x){this.children.push(...x);}setAttribute(){}addEventListener(n,f){this.handlers[n]=f;}}const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};const ctx={document,TextEncoder,TextDecoder};vm.createContext(ctx);vm.runInContext(source,ctx);return nodes;}
const file=d=>{const bytes=new TextEncoder().encode(JSON.stringify(d));return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};};
test('ClamAV charts render, preserve prior import on error, and clear cancels pending import',async()=>{
 const n=dom(),load=f=>n.get('clamav-file').handlers.change({target:{files:[f]}});
 await load(file(fixture()));assert.equal(n.get('clamav-results').hidden,false);assert.equal(n.get('clamav-detections').children[0].children[1].textContent,'1');assert.match(n.get('clamav-status').textContent,/Not live/);
 await load({size:4097,arrayBuffer:()=>assert.fail('must not read')});assert.match(n.get('clamav-status').textContent,/preserved/);assert.equal(n.get('clamav-results').hidden,false);
 let finish;const pending=load({size:100,arrayBuffer:()=>new Promise(r=>finish=r)});n.get('clamav-clear').handlers.click();finish(await file(fixture()).arrayBuffer());await pending;assert.equal(n.get('clamav-results').hidden,true);assert.equal(n.get('clamav-files').children.length,0);
});
test('ClamAV panel never adds network, storage or executable content',()=>assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/));
