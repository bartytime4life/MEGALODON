const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../dist/osquery.js'),'utf8');
const {validateOsqueryCount:validate}=require('../dist/osquery.js');
const fixture=()=>({schema:'megalodon-osquery-package-count-v1',exported_at:'2026-09-26T12:00:00Z',package_rows:42});
test('saved package count validates',()=>assert.deepEqual(validate(JSON.stringify(fixture())),fixture()));
for(const text of [JSON.stringify({...fixture(),path:'/secret'}),JSON.stringify({...fixture(),package_rows:-1}),JSON.stringify({...fixture(),package_rows:1.2}),JSON.stringify({...fixture(),exported_at:'2099-01-01T00:00:00Z'}),JSON.stringify(fixture()).replace('"package_rows":','"package_rows":1,"package_rows":'),' '.repeat(4097)])
  test('rejects unsupported count input',()=>assert.throws(()=>validate(text)));
function dom(){class Element{constructor(){this.children=[];this.handlers={};this.textContent='';}replaceChildren(...x){this.children=x;}append(...x){this.children.push(...x);}setAttribute(){}addEventListener(n,f){this.handlers[n]=f;}}const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};const ctx={document,TextEncoder,TextDecoder};vm.createContext(ctx);vm.runInContext(source,ctx);return nodes;}
const file=d=>{const bytes=new TextEncoder().encode(JSON.stringify(d));return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};};
test('import retains prior count on rejection and clear cancels pending read',async()=>{
  const n=dom(),load=f=>n.get('osquery-file').handlers.change({target:{files:[f]}});
  await load(file(fixture()));assert.match(n.get('osquery-count').textContent,/42 DEB/);
  await load({size:4097,arrayBuffer:()=>assert.fail('must not read')});assert.match(n.get('osquery-status').textContent,/preserved/);
  let finish;const pending=load({size:100,arrayBuffer:()=>new Promise(r=>finish=r)});n.get('osquery-clear').handlers.click();finish(await file(fixture()).arrayBuffer());await pending;
  assert.equal(n.get('osquery-results').hidden,true);assert.equal(n.get('osquery-count').textContent,'');
});
test('no implicit fetch, storage or execution',()=>assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/));
