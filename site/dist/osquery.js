
function validateOsqueryCount(text,now=Date.now()) {
  const fail=()=>{throw new Error('Unsupported package count');};
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>4096)fail();
  let data;
  try {
    const keys=new Set();
    for(const token of text.match(/"(?:\\.|[^"\\])*"\s*:/g)||[]) {
      const key=JSON.parse(token.slice(0,token.lastIndexOf(':')).trim());if(keys.has(key))fail();keys.add(key);
    }
    data=JSON.parse(text);
  } catch {fail();}
  if(!data||Array.isArray(data)||!Object.hasOwn(data,'exported_at')||!Object.hasOwn(data,'package_rows'))fail();
  const legacy=data.schema==='megalodon-osquery-package-count-v1';
  if(legacy ? Object.keys(data).length!==3 :
     data.schema!=='megalodon-osquery-package-count-v2'||Object.keys(data).length!==4||!Object.hasOwn(data,'collection_completed_at'))fail();
  const timestamp=value=>{
    if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value))fail();
    const time=Date.parse(value);
    if(!Number.isFinite(time)||new Date(time).toISOString().slice(0,19)+'Z'!==value||time>now+60000)fail();
    return time;
  };
  const processed=timestamp(data.exported_at);
  if(!legacy&&data.collection_completed_at!==null&&timestamp(data.collection_completed_at)>processed)fail();
  if(!Number.isInteger(data.package_rows)||data.package_rows<0||data.package_rows>999999999)fail();
  return data;
}
if(typeof module!=='undefined')module.exports={validateOsqueryCount};
if(typeof document!=='undefined'&&document.getElementById('osquery-title')) {
  const node=id=>document.getElementById(id);
  function applyOsquery(data, source='Saved package count') {
    data=validateOsqueryCount(JSON.stringify(data));
    node('osquery-count').textContent=String(data.package_rows);
    const collection=data.collection_completed_at
      ? `Local collection completed ${data.collection_completed_at} (UTC).`
      : 'Observation time unknown.';
    node('osquery-time').textContent=`${collection} Processed ${data.exported_at} (UTC). Saved count.`;
    node('osquery-status').textContent=`${source} · saved count.`;
    node('osquery-status').setAttribute('data-state','ready');
    node('osquery-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).osquery=applyOsquery;

}
