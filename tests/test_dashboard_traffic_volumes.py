"""Traffic volume follows qualified records and never promotes stale data to live."""
import shutil
import subprocess

import pytest

from megalodon.dashboard_globe import GLOBE_JS


def test_volume_lanes_current_minute_freshness_and_refresh_recovery():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for dashboard JavaScript behavior')
    harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
let code = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', part => code += part);
process.stdin.on('end', async () => {
  const now = Date.now(), start = now - 3600000;
  const nodes = new Map();
  const node = () => ({textContent:'', style:{}, attrs:{}, hidden:false,
    setAttribute(k,v) {this.attrs[k]=v;}, replaceChildren() {}});
  const context = {Date, TextEncoder, TextDecoder,
    document:{hidden:false,createElement:node},
    state:{paused:false, config:{refresh_seconds:5}},
    byId:id => {if (!nodes.has(id)) nodes.set(id,node()); return nodes.get(id);},
    now,start};
  vm.createContext(context);
  vm.runInContext(code,context);
  const run = code => vm.runInContext(code,context);
  run('renderGlobeView = () => {}; refreshGlobeLocations = async () => {};');
  const events = Array.from({length:6},(_,i)=>({id:String(i+1),
    observed_at:new Date(now-1000*(i+1)).toISOString(),src_ip:'192.0.2.1'}));
  // Earlier peak establishes a shared volume scale; findings count events once.
  events.push(...Array.from({length:12},(_,i)=>({id:String(i+100),
    observed_at:new Date(now-130000-i*1000).toISOString(),src_ip:'192.0.2.2'})));
  context.page={traffic:{events,findings:[
    {event_id:'1',severity:'CRITICAL'}, {event_id:'1',severity:'HIGH'},
    {event_id:'1',severity:'LOW'}, {event_id:'2',severity:'HIGH'},
    {event_id:'3',severity:'MEDIUM'}]}};
  const model=run('globeHourModel(page,start,now,null,true)');
  assert.equal(model.index,59);
  assert.equal(model.bins[59].normal,3);
  assert.equal(model.bins[59].danger,2);
  assert.equal(model.bins[59].review,1);
  assert.equal(model.bins[59].count,6);
  assert.equal(model.peak,12);
  assert.equal(run('globeVolumeLevel(0,12)'), 'No returned records');
  assert.equal(run('globeVolumeLevel(4,12)'), 'Low volume');
  assert.equal(run('globeVolumeLevel(5,12)'), 'Moderate volume');
  assert.equal(run('globeVolumeLevel(8,12)'), 'Moderate volume');
  assert.equal(run('globeVolumeLevel(9,12)'), 'High volume');
  run('Object.assign(globeState.hour,{page,start,end:now,fetchedAt:now}); renderGlobeVolumes(null,now)');
  assert.equal(nodes.get('traffic-normal-meter').value,3);
  assert.equal(nodes.get('traffic-danger-meter').value,2);
  assert.equal(nodes.get('traffic-normal-meter').max,12);
  assert.equal(nodes.get('traffic-danger-meter').max,12);
  assert.match(nodes.get('traffic-volume-status').textContent,/every 5s/);
  assert.match(nodes.get('traffic-review-count').textContent,/1 records/);
  assert.match(nodes.get('traffic-volume-freshness').textContent,/Latest returned observation/);
  run('globeState.hour.partial=true; renderGlobeVolumes(null,now)');
  assert.match(nodes.get('traffic-volume-status').textContent,/Partial coverage/);
  run('globeState.hour.failed=true; renderGlobeVolumes(null,now)');
  assert.match(nodes.get('traffic-danger-count').textContent,/Previous snapshot/);
  assert.equal(nodes.get('traffic-danger-meter').value,2);
  assert.match(nodes.get('traffic-danger-meter').attrs['aria-valuetext'],/Previous snapshot/);
  run('globeState.hour.failed=false; renderGlobeVolumes(null,now+16000)');
  assert.match(nodes.get('traffic-volume-status').textContent,/Current readings unavailable/);
  run('state.paused=true; renderGlobeVolumes(null,now)');
  assert.match(nodes.get('traffic-volume-status').textContent,/Paused snapshot.*Refresh paused/);
  run('state.paused=false; document.hidden=true; renderGlobeVolumes(null,now)');
  assert.match(nodes.get('traffic-volume-status').textContent,/Refresh paused/);
  run('document.hidden=false; globeState.hour.live=false; globeState.hour.selectedAt=start+57*60000; renderGlobeVolumes(null,now)');
  assert.match(nodes.get('traffic-volume-status').textContent,/Historical selected minute/);
  assert.equal(nodes.get('traffic-normal-meter').value,12);
  // Moving Live forward ages previous events out rather than retaining a busy minute.
  const shifted=run('globeHourModel(page,start+120000,now+120000,null,true)');
  assert.equal(shifted.bins[59].count,0);
  run('globeState.hour.page=null; globeState.hour.failed=true; renderGlobeVolumes(null,now)');
  assert.equal(nodes.get('traffic-normal-meter').hidden,true);
  assert.equal(nodes.get('traffic-normal-count').textContent,'—');
  assert.match(nodes.get('traffic-volume-status').textContent,/Unavailable/);

  // Refresh retains bounded endpoint use, refuses overlap, and recovers from failure.
  let release, requests=0, nextTick, waitMs;
  context.window={setTimeout:(fn,ms)=>{nextTick=fn;waitMs=ms;return 1;}};
  context.requestRoomSnapshot=path=>{
    requests++;
    assert.match(path,/^\/api\/traffic-history\?start=/);
    return new Promise(resolve=>{release=resolve;});
  };
  context.validateHistory=(value,range)=>{
    assert.equal(range.end-range.start,3600000);
    assert.equal(range.before,null);
    return value;
  };
  run('globeState.hour.live=true; globeState.hour.partial=false;');
  const pending=run('refreshGlobeHour()');
  await run('refreshGlobeHour()');
  assert.equal(requests,1);
  release(context.page); await pending;
  assert.equal(nodes.get('traffic-normal-meter').hidden,false);
  assert.equal(nodes.get('traffic-normal-meter').value,3);
  context.requestRoomSnapshot=async()=>{throw new Error('invalid response');};
  await run('refreshGlobeHour()');
  assert.match(nodes.get('traffic-volume-status').textContent,/Previous snapshot/);
  context.requestRoomSnapshot=async()=>context.page;
  await run('refreshGlobeHour()');
  assert.doesNotMatch(nodes.get('traffic-volume-status').textContent,/Previous snapshot/);
  run('state.paused=true; startGlobeHour()');
  assert.equal(waitMs,5000);
  assert.match(nodes.get('traffic-volume-status').textContent,/Refresh paused/);
  await nextTick();
  assert.equal(waitMs,5000);
  process.stdout.write('traffic-volumes-verified\n');
});
"""
    result = subprocess.run([node, '-e', harness], input=GLOBE_JS, text=True,
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'traffic-volumes-verified\n'
