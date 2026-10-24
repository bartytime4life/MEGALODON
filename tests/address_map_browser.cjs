const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),{pathToFileURL}=require('node:url');
const {code,fixture,geometry,viewer}=JSON.parse(fs.readFileSync(0,'utf8'));
class E {
  constructor(){this.textContent='';this.children=[];this.events={};this.attrs={};this.disabled=true;this.hidden=false;this.messages=[];this.contentWindow={postMessage:(value,origin)=>this.messages.push({value,origin})};}
  append(...values){this.children.push(...values);}replaceChildren(...values){this.children=values;}
  addEventListener(name,fn){this.events[name]=fn;}setAttribute(k,v){this.attrs[k]=v;}getAttribute(k){return this.attrs[k]||null;}removeAttribute(k){delete this.attrs[k];}
  click(){return this.events.click?.();}set innerHTML(_){throw Error('Map evidence must render as text');}
}
const origin='http://127.0.0.1:1234',nodes=new Map(),listeners={},requests=[],blobs=[];
const el=id=>{if(!nodes.has(id))nodes.set(id,new E());return nodes.get(id);};
const text=n=>n.textContent+' '+n.children.map(text).join(' ');
let payload=fixture,hold=null;
const document={hidden:false,getElementById:el,createElement:()=>new E(),addEventListener:(name,fn)=>listeners[name]=fn};
vm.runInNewContext(code,{document,window:{location:{origin}},Date,encodeURIComponent,setTimeout:fn=>fn(),
  Blob:class{constructor(parts){blobs.push(parts);}},URL:{createObjectURL:()=> 'blob:synthetic',revokeObjectURL:()=>{}},
  requestBoundedJSON:async(path,max,options)=>{requests.push({path,max,options});if(hold)await hold;return JSON.parse(JSON.stringify(payload));}});
const select=ip=>listeners['megalodon:endpoint-selected']({detail:ip});
async function run(){
  select('8.8.8.8');assert.equal(requests.length,0);assert.equal(el('address-map-frame').getAttribute('src'),null);
  await el('address-map-read').click();
  assert.equal(requests[0].path,'/api/address-map?ip=8.8.8.8');assert.equal(requests[0].max,8192);assert.equal(requests[0].options.headers['X-Megalodon-Check'],'1');
  assert.match(text(el('address-map-evidence')),/50 km/);assert.match(text(el('address-map-evidence')),/not a street address or a person/);
  const frame=el('address-map-frame');assert.equal(frame.getAttribute('src'),'/address-map');frame.events.load();
  assert.equal(frame.messages[0].origin,origin);assert.equal(frame.messages[0].value.type,'megalodon:map-region');assert.equal(frame.messages[0].value.observed_address,undefined,'map renderer receives no peer IP');
  await el('address-map-save').click();assert.equal(JSON.parse(blobs[0][0]).physical_address,null);
  let release;hold=new Promise(resolve=>release=resolve);const pending=el('address-map-read').click();select('1.1.1.1');release();await pending;hold=null;
  assert.equal(frame.hidden,true);assert.equal(frame.getAttribute('src'),null);assert.equal(el('address-map-save').disabled,true);
  for(const invalid of [NaN,91,true]){payload={...fixture,observed_address:'1.1.1.1',location:{...fixture.location,latitude:invalid}};await el('address-map-read').click();assert.equal(frame.hidden,true);assert.equal(el('address-map-save').disabled,true);}
  payload={...fixture,observed_address:'1.1.1.1',physical_address:'forged street'};await el('address-map-read').click();assert.equal(el('address-map-save').disabled,true);
  payload={...fixture,observed_address:'1.1.1.1',location:{...fixture.location,accuracy_radius_km:null}};await el('address-map-read').click();assert.match(text(el('address-map-evidence')),/Accuracy radius unknown/);
  select('10.0.0.1');payload={...fixture,observed_address:'10.0.0.1',status:'unmapped',location:null};await el('address-map-read').click();assert.equal(frame.hidden,true);assert.match(text(el('address-map-evidence')),/Location unknown/);assert.equal(el('address-map-save').disabled,false);
  await el('address-map-save').click();assert.equal(JSON.parse(blobs[blobs.length-1][0]).location,null);

  const {radiusBoundary,regionZoom,EARTH_KM}=await import(pathToFileURL(geometry));
  const rad=x=>x*Math.PI/180;
  const distance=(a,b)=>2*EARTH_KM*Math.asin(Math.sqrt(Math.min(1,Math.sin(rad(b[1]-a[1])/2)**2+Math.cos(rad(a[1]))*Math.cos(rad(b[1]))*Math.sin(rad(b[0]-a[0])/2)**2)));
  for(const [lat,lon,radius] of [[37.5,-97.5,50],[0,0,1000],[89,0,500],[-89,0,500],[0,179.9,1000],[0,0,20000]]){
    const boundary=radiusBoundary(lat,lon,radius);assert.equal(boundary.type,'MultiLineString');
    for(const line of boundary.coordinates){assert.ok(line.length>=2);for(let i=0;i<line.length;i++){const p=line[i];assert.ok(p.every(Number.isFinite)&&Math.abs(p[0])<=180&&Math.abs(p[1])<=90);if(i)assert.ok(Math.abs(p[0]-line[i-1][0])<=180);assert.ok(Math.abs(distance([lon,lat],p)-radius)<Math.max(.001,radius*.001));}}
  }
  assert.equal(regionZoom(null),2);assert.equal(regionZoom(.001),5);assert.equal(regionZoom(20000),0);
  for(const args of [[91,0,1],[0,181,1],[0,0,0],[0,0,Infinity]])assert.throws(()=>radiusBoundary(...args));

  function boot(throws=false){
    const messages={},buttons=new Map(),parent={},made=[],removed=[];
    const element=id=>{if(!buttons.has(id))buttons.set(id,new E());return buttons.get(id);};
    class FakeMap {
      constructor(options){if(throws)throw Error('No WebGL');made.push(options);this.sources=options.style.sources;}
      on(event,fn){this[event]=fn;if(event==='load')fn();}getSource(name){return {setData:value=>this.sources[name].data=value};}
      touchZoomRotate={disableRotation:()=>{}};jumpTo(value){this.position=value;}getZoom(){return 2;}remove(){removed.push(true);}addControl(){}
    }
    const worker=[];
    vm.runInNewContext(viewer.replace(/^import .*;\n/gm,''),{document:{getElementById:element},parent,window:{location:{origin},addEventListener:(event,fn)=>messages[event]=fn},
      maplibregl:{Map:FakeMap,ScaleControl:class{},setWorkerUrl:value=>worker.push(value),setWorkerCount:value=>assert.equal(value,1)},radiusBoundary,regionZoom,Date});
    const send=(source=parent,sameOrigin=origin)=>messages.message({source,origin:sameOrigin,data:{type:'megalodon:map-region',location:fixture.location,snapshot_at:fixture.snapshot_at}});
    send({},origin);send(parent,'https://foreign.invalid');assert.equal(made.length,0);send();
    if(throws){assert.match(element('map-status').textContent,/graphics unavailable/);assert.equal(element('zoom-in').disabled,true);}
    else{assert.deepEqual(worker,['/assets/address-map/maplibre-gl-worker.mjs']);assert.equal(made.length,1);assert.equal(made[0].style.sources.land.data,'/assets/address-map/land.geojson');assert.equal(made[0].style.glyphs,undefined);assert.equal(element('zoom-in').disabled,false);messages.pagehide();assert.equal(removed.length,1);}
  }
  boot();boot(true);
  console.log('Local map selection, export, geographic radius and WebGL fallback passed');
}
run().catch(error=>{console.error(error);process.exitCode=1;});
