"""Local HUD poller for aggregate companion automation."""

COMPANION_JS = r'''
if (typeof localHudLaunch !== 'undefined' && typeof document !== 'undefined') {
  const ids = ['nmap', 'clamav', 'osquery'];
  const prefix = {nmap: 'inventory', clamav: 'clamav', osquery: 'osquery'};
  const seen = {};
  async function refreshCompanions() {
    if (document.hidden) return;
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
        const status = payload.status[id];
        const advice = payload.advisory[id];
        label.textContent = 'Local automation: ' + (typeof status === 'string' ? status.slice(0, 160) : 'unavailable') +
          (typeof advice === 'string' && advice ? ' · Qwen advisory: ' + advice.slice(0, 1024) : '');
        const result = payload.results[id];
        if (result && globalThis.megalodonCompanionRender?.[id]) {
          const key = JSON.stringify(result);
          if (seen[id] !== key || document.getElementById(prefix[id] + '-results')?.hidden) {
            globalThis.megalodonCompanionRender[id](result, 'Automatic ' + id + ' aggregate');
            seen[id] = key;
          }
        }
      }
    } catch (_) {
      for (const id of ids) {
        const label = document.getElementById(prefix[id] + '-automation');
        if (label) label.textContent = 'Local automation feed unavailable; any prior aggregate remains saved.';
      }
    }
  }
  async function pollCompanions() {
    await refreshCompanions();
    setTimeout(pollCompanions, 15000);
  }
  pollCompanions();
}
'''
