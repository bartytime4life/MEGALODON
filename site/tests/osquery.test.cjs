const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../dist/osquery.js'),'utf8');
const {validateOsqueryCount:validate}=require('../dist/osquery.js');
const fixture=()=>({schema:'megalodon-osquery-package-count-v1',exported_at:'2026-09-26T12:00:00Z',package_rows:42});
const current=(completion=null)=>({...fixture(),schema:'megalodon-osquery-package-count-v2',collection_completed_at:completion});
test('saved package count validates',()=>assert.deepEqual(validate(JSON.stringify(fixture())),fixture()));
test('new saved and locally collected counts validate separately',()=>{
 for(const data of [current(),current('2026-09-26T11:59:58Z')])assert.deepEqual(validate(JSON.stringify(data)),data);
});
for(const text of [JSON.stringify({...fixture(),path:'/secret'}),JSON.stringify({...fixture(),package_rows:-1}),JSON.stringify({...fixture(),package_rows:1.2}),JSON.stringify({...fixture(),exported_at:'2099-01-01T00:00:00Z'}),JSON.stringify(fixture()).replace('"package_rows":','"package_rows":1,"package_rows":'),' '.repeat(4097)])
  test('rejects unsupported count input',()=>assert.throws(()=>validate(text)));
for(const completion of [false,42,{},'','2026-09-26T12:00:01Z','2026-02-30T12:00:00Z','2026-09-26T11:59:58','2026-09-26T11:59:58+00:00'])
 test('rejects invalid collection completion '+JSON.stringify(completion),()=>assert.throws(()=>validate(JSON.stringify(current(completion)))));
test('versioned time fields are closed and required',()=>{
 for(const data of [{...fixture(),collection_completed_at:null},{...fixture(),schema:'megalodon-osquery-package-count-v2'},
                   {...current(),observed_at:'2026-09-26T11:59:58Z'},{...current(),schema:'megalodon-osquery-package-count-v3'}])
   assert.throws(()=>validate(JSON.stringify(data)));
 assert.throws(()=>validate(JSON.stringify(current()).replace('"collection_completed_at":','"collection_completed_at":null,"collection_completed_at":')));
});
function dom(){class Element{constructor(){this.children=[];this.textContent='';}replaceChildren(...x){this.children=x;}append(...x){this.children.push(...x);}setAttribute(){}}const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};const ctx={document,TextEncoder,globalThis:{}};vm.createContext(ctx);vm.runInContext(source,ctx);return {nodes,render:ctx.globalThis.megalodonCompanionRender.osquery};}
test('automatic package count renders without file controls',()=>{
 const {nodes:n,render}=dom();render(fixture(),'Automatic osquery aggregate');assert.equal(n.get('osquery-count').textContent,'42');assert.match(n.get('osquery-time').textContent,/2026-09-26T12:00:00Z/);assert.equal(n.get('osquery-results').hidden,false);assert.equal(n.has('osquery-file'),false);
});
test('legacy exports and watched reports never imply a known observation time',()=>{
 const {nodes:n,render}=dom();
 for(const data of [fixture(),current()]){
  render(data,'Watched report');
  assert.equal(n.get('osquery-time').textContent,'Observation time unknown. Processed 2026-09-26T12:00:00Z (UTC). Saved count.');
 }
});
test('collection completion stays distinct from processing and clears when a watched report replaces it',()=>{
 const {nodes:n,render}=dom();
 render(current('2026-09-26T11:59:58Z'));
 assert.equal(n.get('osquery-time').textContent,'Local collection completed 2026-09-26T11:59:58Z (UTC). Processed 2026-09-26T12:00:00Z (UTC). Saved count.');
 render(current());
 assert.match(n.get('osquery-time').textContent,/^Observation time unknown\./);
 assert.doesNotMatch(n.get('osquery-time').textContent,/11:59:58/);
 assert.throws(()=>render(current('2099-01-01T00:00:00Z')));
 assert.match(n.get('osquery-time').textContent,/^Observation time unknown\./);
});
test('no implicit fetch, storage or execution',()=>assert.doesNotMatch(source,/\bfetch\s*\(|XMLHttpRequest|WebSocket|localStorage|innerHTML|\beval\s*\(/));
