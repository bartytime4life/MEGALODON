const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../dist/osquery.js'),'utf8');
const {validateOsqueryCount:validate}=require('../dist/osquery.js');
const fixture=()=>({schema:'megalodon-osquery-package-count-v1',exported_at:'2026-09-26T12:00:00Z',package_rows:42});
test('saved package count validates',()=>assert.deepEqual(validate(JSON.stringify(fixture())),fixture()));
for(const text of [JSON.stringify({...fixture(),path:'/secret'}),JSON.stringify({...fixture(),package_rows:-1}),JSON.stringify({...fixture(),package_rows:1.2}),JSON.stringify({...fixture(),exported_at:'2099-01-01T00:00:00Z'}),JSON.stringify(fixture()).replace('"package_rows":','"package_rows":1,"package_rows":'),' '.repeat(4097)])
  test('rejects unsupported count input',()=>assert.throws(()=>validate(text)));
function dom(){class Element{constructor(){this.children=[];this.textContent='';}replaceChildren(...x){this.children=x;}append(...x){this.children.push(...x);}setAttribute(){}}const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};const ctx={document,TextEncoder,globalThis:{}};vm.createContext(ctx);vm.runInContext(source,ctx);return {nodes,render:ctx.globalThis.megalodonCompanionRender.osquery};}
test('automatic package count renders without file controls',()=>{
 const {nodes:n,render}=dom();render(fixture(),'Automatic osquery aggregate');assert.equal(n.get('osquery-count').textContent,'42');assert.match(n.get('osquery-time').textContent,/2026-09-26T12:00:00Z/);assert.equal(n.get('osquery-results').hidden,false);assert.equal(n.has('osquery-file'),false);
});
test('no implicit fetch, storage or execution',()=>assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/));
