import * as maplibregl from './maplibre-gl.mjs';
import {radiusBoundary,regionZoom} from './geometry.mjs';

const status=document.getElementById('map-status'),buttons=['zoom-in','zoom-out','reset'].map(id=>document.getElementById(id));
let map=null,region=null;
const empty={type:'FeatureCollection',features:[]};
const feature=geometry=>({type:'FeatureCollection',features:[{type:'Feature',properties:{},geometry}]});
const finite=(v,min,max)=>typeof v==='number'&&Number.isFinite(v)&&v>=min&&v<=max;
function reset(){if(map&&region)map.jumpTo({center:[region.longitude,region.latitude],zoom:regionZoom(region.accuracy_radius_km)});}
function failed(){for(const button of buttons)button.disabled=true;status.textContent='Map graphics unavailable. Recorded coordinates, source, radius and traffic evidence remain available above.';const prior=map;map=null;if(prior)prior.remove();}
window.addEventListener('message',event=>{
  if(event.source!==parent||event.origin!==window.location.origin)return;
  const value=event.data,p=value?.location;
  if(value?.type!=='megalodon:map-region'||!p||p.approximate!==true||!finite(p.latitude,-90,90)||!finite(p.longitude,-180,180)
    ||!(p.accuracy_radius_km===null||finite(p.accuracy_radius_km,Number.MIN_VALUE,20000))||typeof value.snapshot_at!=='string'||value.snapshot_at.length>40||!Number.isFinite(Date.parse(value.snapshot_at)))return;
  region=p;
  if(Math.abs(p.latitude)>85.05112878){status.textContent='The recorded estimate is outside this map projection. Its coordinates and uncertainty remain available above.';return;}
  const point=feature({type:'Point',coordinates:[p.longitude,p.latitude]});
  const radius=p.accuracy_radius_km===null?empty:feature(radiusBoundary(p.latitude,p.longitude,p.accuracy_radius_km));
  status.textContent=`Snapshot ${value.snapshot_at}. ${p.accuracy_radius_km===null?'Accuracy radius unknown; marker is an approximate database estimate.':'Dashed boundary: reported '+p.accuracy_radius_km+' km radius. Polar portions can be clipped by this projection.'}`;
  try{
    if(map){map.getSource('estimate').setData(point);map.getSource('radius').setData(radius);reset();return;}
    maplibregl.setWorkerUrl('/assets/address-map/maplibre-gl-worker.mjs');maplibregl.setWorkerCount(1);
    map=new maplibregl.Map({container:'map',center:[p.longitude,p.latitude],zoom:regionZoom(p.accuracy_radius_km),minZoom:0,maxZoom:5,
      attributionControl:false,scrollZoom:false,dragRotate:false,pitchWithRotate:false,fadeDuration:0,
      style:{version:8,sources:{land:{type:'geojson',data:'/assets/address-map/land.geojson'},countries:{type:'geojson',data:'/assets/address-map/countries.geojson'},states:{type:'geojson',data:'/assets/address-map/states.geojson'},estimate:{type:'geojson',data:point},radius:{type:'geojson',data:radius}},
        layers:[{id:'ocean',type:'background',paint:{'background-color':'#102a38'}},
          {id:'land',type:'fill',source:'land',paint:{'fill-color':'#456573','fill-outline-color':'#6a8793'}},
          {id:'countries',type:'line',source:'countries',paint:{'line-color':'#aac2cb','line-width':1,'line-opacity':.6}},
          {id:'states',type:'line',source:'states',paint:{'line-color':'#adc3ce','line-width':.8,'line-opacity':.5}},
          {id:'radius',type:'line',source:'radius',paint:{'line-color':'#b9a4ff','line-width':2,'line-dasharray':[3,2]}},
          {id:'estimate',type:'circle',source:'estimate',paint:{'circle-radius':6,'circle-color':'#8de4d6','circle-stroke-color':'#ffffff','circle-stroke-width':1}}]}});
    map.touchZoomRotate.disableRotation();map.on('error',failed);map.on('webglcontextlost',failed);
    map.addControl(new maplibregl.ScaleControl({unit:'metric',maxWidth:100}),'bottom-left');
    map.on('load',()=>{for(const button of buttons)button.disabled=false;});
  }catch(_){failed();}
});
buttons[0].addEventListener('click',()=>{if(map)map.jumpTo({zoom:Math.min(5,map.getZoom()+1)});});
buttons[1].addEventListener('click',()=>{if(map)map.jumpTo({zoom:Math.max(0,map.getZoom()-1)});});
buttons[2].addEventListener('click',reset);
window.addEventListener('pagehide',()=>{if(map)map.remove();map=null;});
