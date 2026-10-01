"""Local HUD poller for aggregate companion automation."""

COMPANION_JS = r'''
if (typeof localHudLaunch !== 'undefined' && typeof document !== 'undefined') {
  const ids = ['nmap', 'clamav', 'osquery'];
  const prefix = {nmap: 'inventory', clamav: 'clamav', osquery: 'osquery'};
  const display = {nmap: 'Nmap', clamav: 'ClamAV', osquery: 'osquery'};
  const seen = {};
  let inFlight = false;
  const workspace=document.getElementById('workspace-live'),history=document.getElementById('operations-history');
  const visible=()=>!document.hidden&&!(workspace&&workspace.hidden)&&!(history&&history.open===false);
  for (const id of ids) {
    const state = document.getElementById(prefix[id] + '-status');
    if (state) {
      state.textContent = 'Checking local collection…';
      state.setAttribute('data-state', 'checking');
    }
  }
  async function refreshCompanions() {
    if (!visible() || inFlight) return;
    inFlight = true;
    try {
      const response = await fetch('/api/companions', {cache: 'no-store'});
      if (!response.ok) throw new Error('companion feed unavailable');
      const body = await response.text();
      if (new TextEncoder().encode(body).byteLength > 16384) throw new Error('companion feed too large');
      const payload = JSON.parse(body);
      if (!payload || payload.schema !== 'megalodon-companion-automation-v1' ||
          !payload.results || !payload.status || !payload.advisory) throw new Error('invalid companion feed');
      for (const id of ids) {
        const label = document.getElementById(prefix[id] + '-automation');
        if (!label) continue;
        const state = document.getElementById(prefix[id] + '-status');
        const status = typeof payload.status[id] === 'string' ? payload.status[id].slice(0, 160) : 'unavailable';
        const advice = payload.advisory[id];
        label.textContent = 'Collector · ' + status;
        const adviceWrap = document.getElementById(prefix[id] + '-advisory-wrap');
        const adviceText = document.getElementById(prefix[id] + '-advisory');
        if (adviceWrap && adviceText) {
          adviceText.textContent = typeof advice === 'string' ? advice.slice(0, 1024) : '';
          adviceWrap.hidden = !adviceText.textContent;
        }
        const result = payload.results[id];
        if (result && globalThis.megalodonCompanionRender?.[id]) {
          const key = JSON.stringify(result);
          if (seen[id] !== key || document.getElementById(prefix[id] + '-results')?.hidden) {
            try {
              globalThis.megalodonCompanionRender[id](result, 'Automatic ' + display[id] + ' aggregate');
              seen[id] = key;
            } catch (_) {
              label.textContent = 'Collector · aggregate rejected; previous result, if any, remains saved.';
              if (state) state.setAttribute('data-state', 'warning');
              continue;
            }
          }
          if (state) {
            const completed = / · completed; saved aggregate$/.test(status);
            const collecting = /^Collecting local aggregate;|^Scanning configured files;|^waiting$/.test(status);
            state.setAttribute('data-state', completed ? 'ready' : collecting ? 'checking' : 'warning');
          }
        } else if (state) {
          state.textContent = status === 'waiting' ? 'Collection queued.' : status;
          state.setAttribute('data-state', status === 'waiting' ? 'checking' : 'warning');
        }
      }
    } catch (_) {
      for (const id of ids) {
        const label = document.getElementById(prefix[id] + '-automation');
        const state = document.getElementById(prefix[id] + '-status');
        if (label) label.textContent = 'Collector · local feed unavailable; any prior result remains saved.';
        if (state) state.setAttribute('data-state', 'warning');
      }
    } finally {
      inFlight = false;
    }
  }
  async function pollCompanions() {
    await refreshCompanions();
    setTimeout(pollCompanions, 15000);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshCompanions(); });
  if(history&&typeof history.addEventListener==='function')history.addEventListener('toggle',()=>{if(visible())refreshCompanions();});
  if(typeof MutationObserver!=='undefined'&&workspace)new MutationObserver(()=>{if(visible())refreshCompanions();}).observe(workspace,{attributes:true,attributeFilter:['hidden']});
  pollCompanions();
}
'''
