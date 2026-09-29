
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
  if(!data||Array.isArray(data)||Object.keys(data).length!==3||data.schema!=='megalodon-osquery-package-count-v1'||!Object.hasOwn(data,'exported_at')||!Object.hasOwn(data,'package_rows'))fail();
  if(typeof data.exported_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.exported_at))fail();
  const time=Date.parse(data.exported_at);
  if(!Number.isFinite(time)||new Date(time).toISOString().slice(0,19)+'Z'!==data.exported_at||time>now+60000)fail();
  if(!Number.isInteger(data.package_rows)||data.package_rows<0||data.package_rows>999999999)fail();
  return data;
}
if(typeof module!=='undefined')module.exports={validateOsqueryCount};
if(typeof document!=='undefined'&&document.getElementById('osquery-title')) {
  const node=id=>document.getElementById(id);
  function applyOsquery(data, source='Saved package count') {
    data=validateOsqueryCount(JSON.stringify(data));
    node('osquery-count').textContent=String(data.package_rows);
    node('osquery-time').textContent=`Observed ${data.exported_at} (UTC). Saved count.`;
    node('osquery-status').textContent=`${source} · saved observation.`;
    node('osquery-status').setAttribute('data-state','ready');
    node('osquery-results').hidden=false;
  }
  (globalThis.megalodonCompanionRender??={}).osquery=applyOsquery;

}
