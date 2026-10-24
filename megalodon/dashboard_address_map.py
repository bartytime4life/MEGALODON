"""Local map document and explicit inspector controls; the HUD keeps its own CSP."""
from functools import lru_cache
import gzip
from importlib.resources import files
from io import BytesIO

MAP_HTML = r'''
<section class="ops-address-map" aria-labelledby="address-map-title">
  <h4 id="address-map-title">Approximate network location</h4>
  <p>Map the observed endpoint's recorded region. A VPN exit may be far from its user.</p>
  <button type="button" id="address-map-read" disabled>Show recorded region</button>
  <button type="button" id="address-map-save" disabled>Save location context</button>
  <p id="address-map-status" role="status">Select an observed address. Location requests stay on this computer.</p>
  <div id="address-map-evidence" hidden></div>
  <iframe id="address-map-frame" title="Approximate location of the selected network endpoint"
    sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer" hidden></iframe>
</section>
'''

MAP_CSS = r'''
.ops-address-map{margin:1rem;padding:1rem;border:1px solid var(--ops-line);background:#0d2630;border-radius:4px;min-width:0}
.ops-address-map h4{margin:0 0 .4rem;font-size:1rem}.ops-address-map p{font-size:.78rem;line-height:1.65;overflow-wrap:anywhere}
.ops-address-map iframe{width:100%;height:390px;margin-top:.7rem;border:1px solid var(--ops-line);border-radius:4px}
'''

MAP_JS = r'''
(() => {
  const el=id=>document.getElementById(id);if(!el('address-map-read'))return;
  const state={ip:null,serial:0,note:null,pending:false,loaded:false};
  const object=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
  const keys=(v,names)=>object(v)&&Object.keys(v).length===names.length&&names.every(k=>Object.hasOwn(v,k));
  const text=(v,max)=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v);
  const stamp=v=>v===null||(text(v,40)&&Number.isFinite(Date.parse(v)));
  const finite=(v,min,max)=>typeof v==='number'&&Number.isFinite(v)&&v>=min&&v<=max;
  function checked(v,ip){
    if(!keys(v,['schema','observed_address','snapshot_at','first_seen','last_seen','capture_state','status','location','location_role','original_address','person_identity','physical_address','network_access_performed','action_authority'])
      ||v.schema!=='megalodon-address-location-v1'||v.observed_address!==ip||!stamp(v.snapshot_at)||v.snapshot_at===null||!stamp(v.first_seen)||!stamp(v.last_seen)
      ||!['idle','starting','running','stopped','failed'].includes(v.capture_state)||!['mapped','unmapped'].includes(v.status)
      ||!['observed_network_endpoint','local_exit_anchor'].includes(v.location_role)||v.original_address!==null||v.person_identity!==null||v.physical_address!==null||v.network_access_performed!==false||v.action_authority!=='none')throw Error('Invalid location context');
    const p=v.location;
    if(v.status==='unmapped'){if(p!==null)throw Error('Unexpected position');return v;}
    if(v.location_role!=='observed_network_endpoint')throw Error('Exit anchor is not an endpoint location');
    if(!keys(p,['latitude','longitude','label','source','country','approximate','accuracy_radius_km','database_build_at','database_downloaded_at'])
      ||!finite(p.latitude,-90,90)||!finite(p.longitude,-180,180)||!text(p.label,160)||!text(p.source,128)||p.approximate!==true
      ||!(p.country===null||(typeof p.country==='string'&&/^[A-Z]{2}$/.test(p.country)))||!(p.accuracy_radius_km===null||finite(p.accuracy_radius_km,Number.MIN_VALUE,20000))
      ||!stamp(p.database_build_at)||!stamp(p.database_downloaded_at))throw Error('Invalid recorded position');
    return v;
  }
  const node=(tag,value)=>{const n=document.createElement(tag);n.textContent=value;return n;};
  const frame=el('address-map-frame');
  function controls(){el('address-map-read').disabled=!state.ip||state.pending;el('address-map-save').disabled=!state.note||state.pending;}
  function resetFrame(){state.loaded=false;frame.hidden=true;frame.removeAttribute('src');}
  function send(){if(state.loaded&&state.note?.location)frame.contentWindow.postMessage({type:'megalodon:map-region',location:state.note.location,snapshot_at:state.note.snapshot_at},window.location.origin);}
  frame.addEventListener('load',()=>{if(frame.getAttribute('src')==='/address-map'){state.loaded=true;send();}});
  function render(v){
    const out=el('address-map-evidence');out.replaceChildren();out.hidden=false;
    out.append(node('p',`${v.observed_address} · Snapshot: ${v.snapshot_at} · Capture: ${v.capture_state}`));
    if(!v.location){out.append(node('p',v.location_role==='local_exit_anchor'?'Location unknown. This local address cannot inherit this computer’s shared internet-exit anchor as an endpoint location. No endpoint position is exported.':'Location unknown. No map position was recorded for this address. Its retained traffic remains available in Address investigation.'));return;}
    const p=v.location;
    out.append(node('p',`${p.label} · ${p.source}`),node('p',`Database coordinates: ${p.latitude}, ${p.longitude}. These estimate a network endpoint, not a street address or a person.`),node('p',p.accuracy_radius_km===null?'Accuracy radius unknown. The marker does not imply building or street precision.':`Reported accuracy radius: ${p.accuracy_radius_km} km. The dashed boundary shows that distance from the database estimate; it does not verify the true location.`),node('p',`Database build: ${p.database_build_at||'unknown'} · Local database download: ${p.database_downloaded_at||'unknown'}`),node('p','Location uses the database loaded at this snapshot. It may not represent where this IP was during an earlier connection.'));
    frame.hidden=false;frame.setAttribute('src','/address-map');
  }
  document.addEventListener('megalodon:endpoint-selected',event=>{
    const ip=typeof event.detail==='string'&&/^[0-9a-fA-F:.]{2,45}$/.test(event.detail)?event.detail:null;if(ip===state.ip)return;
    state.ip=ip;state.serial++;state.note=null;state.pending=false;resetFrame();el('address-map-evidence').hidden=true;
    el('address-map-status').textContent=ip?'Ready to read local location context. No external lookup runs.':'Select an observed address. Location requests stay on this computer.';controls();
  });
  el('address-map-read').addEventListener('click',async()=>{
    if(!state.ip||state.pending||document.hidden)return;
    const ip=state.ip,serial=++state.serial;state.pending=true;state.note=null;resetFrame();el('address-map-evidence').hidden=true;controls();
    el('address-map-status').textContent='Reading recorded location context…';
    try{
      const value=checked(await requestBoundedJSON('/api/address-map?ip='+encodeURIComponent(ip),8192,{headers:{'X-Megalodon-Check':'1'}}),ip);
      if(serial!==state.serial||ip!==state.ip)return;
      state.note=value;render(value);el('address-map-status').textContent=value.location?'Local map context ready. Original source and physical address remain unknown.':'Location unknown; retained traffic can still be investigated and saved.';
    }catch(_){if(serial===state.serial)el('address-map-status').textContent='Location context could not be confirmed, or the address left the retained window. Select a current peer and retry.';}
    finally{if(serial===state.serial){state.pending=false;controls();}}
  });
  el('address-map-save').addEventListener('click',()=>{
    if(!state.note||state.pending)return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(state.note,null,2)+'\n'],{type:'application/json'})),link=document.createElement('a');
    link.href=url;link.download='megalodon-address-location.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    el('address-map-status').textContent='Location context download requested. This personal copy is outside automatic cleanup.';
  });
})();
'''

MAP_PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approximate network region</title>
<link rel="stylesheet" href="/assets/address-map/maplibre-gl.css">
<link rel="stylesheet" href="/assets/address-map/viewer.css">
<script type="module" src="/assets/address-map/viewer.mjs"></script></head>
<body><main><nav aria-label="Map controls"><button id="zoom-in" type="button" disabled>Zoom in</button>
<button id="zoom-out" type="button" disabled>Zoom out</button><button id="reset" type="button" disabled>Reset region</button></nav>
<p id="map-status" role="status">Map loading. Recorded location details remain available above if graphics are unavailable.</p>
<div id="map" aria-label="Approximate region; arrow keys pan and plus/minus keys zoom"></div>
<p class="credit">MapLibre GL JS 6.15.0 · Natural Earth reference outlines (public domain). No streets, external tiles or IP lookup.</p>
</main></body></html>'''.encode()

ASSETS = {'maplibre-gl.mjs':'text/javascript; charset=utf-8', 'maplibre-gl-worker.mjs':'text/javascript; charset=utf-8',
          'maplibre-gl.css':'text/css; charset=utf-8', 'viewer.mjs':'text/javascript; charset=utf-8',
          'geometry.mjs':'text/javascript; charset=utf-8', 'viewer.css':'text/css; charset=utf-8',
          'land.geojson':'application/geo+json', 'countries.geojson':'application/geo+json', 'states.geojson':'application/geo+json',
          'LICENSE.txt':'text/plain; charset=utf-8', 'manifest.json':'application/json'}
PACKED = frozenset({'maplibre-gl.mjs','maplibre-gl-worker.mjs','maplibre-gl.css',
                    'land.geojson','countries.geojson','states.geojson'})


def storage_name(name):
    return name+'.gz' if name in PACKED else name


@lru_cache(maxsize=len(ASSETS))
def asset(name):
    if name not in ASSETS:
        raise ValueError('Unknown map asset')
    with files('megalodon.assets').joinpath('address-map',storage_name(name)).open('rb') as source:
        raw = source.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:
        raise ValueError('Map asset exceeds its bound')
    if name in PACKED:
        try:
            with gzip.GzipFile(fileobj=BytesIO(raw)) as source:
                raw=source.read(2*1024*1024+1)
        except (OSError,EOFError):
            raise ValueError('Invalid compressed map asset') from None
        if len(raw)>2*1024*1024:
            raise ValueError('Decoded map asset exceeds its bound')
    return ASSETS[name], raw
