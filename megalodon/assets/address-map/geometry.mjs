// Spherical distance boundary, not a confidence claim. Kilometres on a 6371.0088 km Earth.
export const EARTH_KM=6371.0088;
const radians=degrees=>degrees*Math.PI/180,degrees=value=>value*180/Math.PI;
export function radiusBoundary(latitude,longitude,radiusKm){
  if(![latitude,longitude,radiusKm].every(Number.isFinite)||Math.abs(latitude)>90||Math.abs(longitude)>180||radiusKm<=0||radiusKm>20000)throw Error('Invalid geographic radius');
  const lat=radians(latitude),lon=radians(longitude),distance=radiusKm/EARTH_KM,points=[];
  for(let i=0;i<128;i++){
    const bearing=2*Math.PI*i/128;
    const nextLat=Math.asin(Math.max(-1,Math.min(1,Math.sin(lat)*Math.cos(distance)+Math.cos(lat)*Math.sin(distance)*Math.cos(bearing))));
    const nextLon=lon+Math.atan2(Math.sin(bearing)*Math.sin(distance)*Math.cos(lat),Math.cos(distance)-Math.sin(lat)*Math.sin(nextLat));
    points.push([((degrees(nextLon)+540)%360)-180,degrees(nextLat)]);
  }
  points.push([...points[0]]);
  // Split at the dateline instead of drawing a chord across the whole map.
  const lines=[[[...points[0]]]];
  for(let i=1;i<points.length;i++){
    const a=points[i-1],b=points[i];let delta=b[0]-a[0];
    if(Math.abs(delta)>180){
      delta+=delta>0?-360:360;const edge=delta>0?180:-180;
      const crossing=a[1]+(b[1]-a[1])*(edge-a[0])/delta;
      lines[lines.length-1].push([edge,crossing]);lines.push([[-edge,crossing],[...b]]);
    }else lines[lines.length-1].push([...b]);
  }
  return {type:'MultiLineString',coordinates:lines};
}

export function regionZoom(radiusKm){
  return radiusKm===null?2:Math.max(0,Math.min(5,Math.log2(40075/(4*radiusKm))));
}
