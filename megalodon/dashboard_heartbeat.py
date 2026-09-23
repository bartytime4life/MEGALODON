"""Status lights and one-click installs for the local HUD.

The heartbeat is polled only while the page is visible: once at launch, every
minute afterwards, immediately when the tab becomes visible again, and every
two seconds while an installation runs. The server caches each observation.
"""

HEARTBEAT_CSS = r"""
.hb-light { display:inline-block; flex:none; width:.7rem; height:.7rem; margin-right:.45rem; border-radius:50%; vertical-align:middle; background:#5d6f7a; box-shadow:0 0 0 2px rgba(0,0,0,.35); }
.hb-light.hb-green { background:#3ddc84; box-shadow:0 0 .45rem rgba(61,220,132,.8); }
.hb-light.hb-amber { background:#f5b642; box-shadow:0 0 .45rem rgba(245,182,66,.7); }
.hb-light.hb-red { background:#ff5c5c; box-shadow:0 0 .45rem rgba(255,92,92,.7); }
.hb-light.hb-pending { animation:hb-pulse 1s ease-in-out infinite; }
@keyframes hb-pulse { 50% { opacity:.35; } }
@media (prefers-reduced-motion: reduce) { .hb-light.hb-pending { animation:none; } }
.hb-detail { display:block; color:#adc1d0; font-size:.75rem; margin-top:.15rem; }
.hb-install { min-height:44px; padding:.6rem .9rem; border-radius:.5rem; border:1px solid #2f8f63; background:#123a2a; color:#c9ffe2; font:inherit; font-weight:700; cursor:pointer; }
.hb-install:disabled { opacity:.6; cursor:progress; }
.hb-install-log { margin:.4rem 0 0; padding:.5rem .6rem; max-height:9rem; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; border-radius:.4rem; background:#06121c; color:#cfe9f3; font-size:.72rem; }
.hb-summary { display:flex; flex-wrap:wrap; gap:.8rem; align-items:center; margin:.4rem 0 .8rem; font-size:.8rem; color:#bfd1dc; }
.hb-summary span { display:inline-flex; align-items:center; }
"""

HEARTBEAT_JS = r"""
const heartbeatState = {report: null, byId: new Map(), catalog: null, job: null, timer: 0, lastAt: 0, failed: false, failures: 0, polling: false};
const heartbeatLabels = {green: 'Presence observed', amber: 'Setup incomplete', red: 'Not found', grey: 'Status unknown'};
function heartbeatStale() {
  return heartbeatState.failed || Boolean(heartbeatState.report &&
    Date.now() - Date.parse(heartbeatState.report.checked_at) > 90000);
}
const heartbeatShelfIds = {python: 'core'};
function heartbeatToolId(id) { return Object.prototype.hasOwnProperty.call(heartbeatShelfIds, id) ? heartbeatShelfIds[id] : id; }
function heartbeatAge(iso) {
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (!Number.isFinite(seconds)) return '';
  const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}
function heartbeatText(tool) {
  if (heartbeatStale()) return heartbeatState.report ? 'Previous observation is stale · retrying while this tab is visible' : 'Heartbeat unavailable · retrying while this tab is visible';
  if (!tool) return heartbeatState.failed ? 'Heartbeat unavailable' : 'Checking…';
  const modelOnly = tool.light === 'amber' && tool.service !== 'stopped' && tool.model === 'missing';
  const parts = [modelOnly ? 'Ollama observed · example model not found'
    : tool.light === 'amber' && tool.service === 'stopped' ? 'Installed · expected process not observed'
    : tool.light === 'green' && tool.expects_service ? 'Installed · expected process observed'
    : heartbeatLabels[tool.light]];
  if (tool.expects_service && tool.service === 'unknown') parts.push('service observation incomplete');
  if (tool.service === 'running' && tool.running_since) parts.push(`up ${heartbeatAge(tool.running_since)}`);
  if (tool.model === 'missing') parts.push('example qwen2.5:7b manifest not found');
  else if (tool.model === 'present') parts.push('example qwen2.5:7b manifest observed');
  else if (tool.model === 'unknown') parts.push('example qwen2.5:7b presence unknown');
  if (tool.id === 'qwen') parts.push('not configured AI readiness');
  if (tool.installed === 'yes' && tool.installed_since) parts.push(`file metadata changed ${new Date(tool.installed_since).toLocaleDateString()}`);
  const history = heartbeatHistory(tool.id);
  if (history) {
    if (history.healthy_percent !== null && history.observed_seconds >= 60 && tool.installed === 'yes') parts.push(`green in ${history.healthy_percent}% of recorded observation time`);
    const changes = history.changes || [];
    if (changes.length > 1) {
      const last = changes[changes.length - 1], before = changes[changes.length - 2];
      parts.push(`${before.light} → ${last.light} at ${new Date(last.at).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}`);
    }
  }
  return parts.join(' · ');
}
function heartbeatHistory(toolId) {
  const history = heartbeatState.report && heartbeatState.report.history;
  const entry = history && history.tools && Object.prototype.hasOwnProperty.call(history.tools, toolId) ? history.tools[toolId] : null;
  return entry && Array.isArray(entry.changes) ? entry : null;
}
function heartbeatLight(id) {
  const toolId = heartbeatToolId(id);
  const light = document.createElement('i');
  light.setAttribute('data-heartbeat-tool', toolId); light.heartbeatTool = toolId;
  light.setAttribute('role', 'img');
  paintHeartbeatLight(light);
  return light;
}
function paintHeartbeatLight(light) {
  const toolId = light.heartbeatTool;
  const tool = heartbeatState.byId.get(toolId);
  const stale = heartbeatStale();
  const installing = !stale && heartbeatState.job && heartbeatState.job.state === 'running' && heartbeatState.job.tool === toolId;
  light.className = `hb-light hb-${tool && !stale ? tool.light : 'grey'}${installing || (!tool && !heartbeatState.failed) ? ' hb-pending' : ''}`;
  const text = installing ? (heartbeatState.job.action === 'start' ? 'Starting…' : 'Installing…') : heartbeatText(tool);
  light.setAttribute('aria-label', text); light.title = text;
}
function heartbeatDetail(id) {
  const detail = document.createElement('span'); detail.className = 'hb-detail';
  detail.setAttribute('data-heartbeat-detail', heartbeatToolId(id)); detail.heartbeatTool = heartbeatToolId(id);
  detail.textContent = heartbeatText(heartbeatState.byId.get(heartbeatToolId(id)));
  return detail;
}
function installControl(id, name) {
  const toolId = heartbeatToolId(id);
  const wrap = document.createElement('div'); wrap.setAttribute('data-heartbeat-install', toolId); wrap.heartbeatTool = toolId; wrap.toolName = name;
  paintInstallControl(wrap);
  return wrap;
}
function paintInstallControl(wrap) {
  const toolId = wrap.heartbeatTool, name = wrap.toolName;
  const entry = heartbeatState.catalog && heartbeatState.catalog.find(item => item.id === toolId);
  const tool = heartbeatState.byId.get(toolId);
  const job = heartbeatState.job;
  if (typeof wrap.replaceChildren === 'function') wrap.replaceChildren();
  if (!entry || toolId === 'core') return;
  const mine = job && job.tool === toolId;
  const model = entry.method === 'ollama';
  // `ollama pull` needs the server, so Qwen offers Start first when it is stopped.
  const needsModel = model && (!tool || (tool.model !== 'present' && tool.service !== 'stopped'));
  const installing = mine && job.state === 'running' && job.action !== 'start';
  if (entry.one_click && (needsModel || (!model && (!tool || tool.installed !== 'yes')) || installing)) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'hb-install';
    const running = job && job.state === 'running';
    button.textContent = mine && running ? 'Installing…' : model ? 'Download Qwen model' : `Install ${name}`;
    button.disabled = Boolean(running || heartbeatStale());
    button.title = entry.summary;
    button.addEventListener('click', () => startInstall(toolId, name, entry));
    wrap.append(button);
  } else if (tool && tool.installed === 'yes' && tool.expects_service && (tool.service === 'stopped' || (mine && job.action === 'start' && job.state === 'running'))) {
    if (entry.startable) {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'hb-install';
      const running = job && job.state === 'running';
      button.textContent = mine && running ? 'Starting…' : 'Start service';
      button.disabled = Boolean(running || heartbeatStale());
      button.title = `Starts the ${name} system service. A process observation does not establish health or integration.`;
      button.addEventListener('click', () => startInstall(toolId, name, entry, 'start'));
      wrap.append(button);
    } else if (entry.start_terminal) {
      wrap.append(textNode('p', `Start the service in a terminal: ${entry.start_terminal}`, 'hb-detail'));
    }
  } else if (!entry.one_click && entry.method === 'ollama' && (!tool || tool.installed !== 'yes')) {
    wrap.append(textNode('p', 'Install Ollama from its download page first; an Install button for the Qwen model then appears here.', 'hb-detail'));
  } else if (!entry.one_click && entry.method !== 'guided' && entry.terminal && (!tool || tool.installed !== 'yes')) {
    wrap.append(textNode('p', `One-click install needs a system password prompt (pkexec), which this computer lacks. Run in a terminal: ${entry.terminal}`, 'hb-detail'));
  }
  if (mine && job.output.length) {
    const log = textNode('pre', job.output.slice(-12).join('\n'), 'hb-install-log');
    log.setAttribute('aria-live', 'polite'); wrap.append(log);
  }
  const starting = mine && job.action === 'start';
  const alternative = starting ? entry.start_terminal : entry.terminal;
  if (mine && job.state === 'failed') wrap.append(textNode('p', `${starting ? 'Service start' : 'Install'} failed.${alternative ? ` Terminal alternative: ${alternative}` : ''}`, 'hb-detail'));
  if (mine && job.state === 'succeeded') wrap.append(textNode('p', `${starting ? 'Service-start command' : 'Installation command'} finished. Status is checked separately.`, 'hb-detail'));
}
function repaintHeartbeat() {
  if (typeof document.querySelectorAll !== 'function') return;
  document.querySelectorAll('[data-heartbeat-tool]').forEach(paintHeartbeatLight);
  document.querySelectorAll('[data-heartbeat-detail]').forEach(node => { node.textContent = heartbeatText(heartbeatState.byId.get(node.heartbeatTool)); });
  document.querySelectorAll('[data-heartbeat-install]').forEach(paintInstallControl);
  // The live light supersedes the launch-time PATH line and per-tool check buttons.
  const live = heartbeatState.byId.size > 0;
  document.querySelectorAll('.software-presence, .software-check').forEach(node => { if (!node.id || node.id !== 'software-check-python') node.hidden = live; });
  const summary = byId('hb-summary');
  if (summary && heartbeatStale()) {
    summary.replaceChildren(textNode('span', heartbeatText(null)));
    return;
  }
  if (summary && heartbeatState.report) {
    const count = light => heartbeatState.report.tools.filter(tool => tool.light === light).length;
    summary.replaceChildren(...['green', 'amber', 'red', 'grey'].map(light => {
      const item = document.createElement('span'); const dot = document.createElement('i'); dot.className = `hb-light hb-${light}`; dot.setAttribute('aria-hidden', 'true');
      item.append(dot, textNode('span', `${count(light)} ${heartbeatLabels[light].toLowerCase()}`)); return item;
    }), textNode('span', `Observed ${formatRefreshTime(new Date(heartbeatState.report.checked_at))} · presence checks do not verify health or integration`));
  }
}
async function heartbeatFetch(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(path, {cache: 'no-store', mode: 'same-origin', credentials: 'omit', redirect: 'error', signal: controller.signal, ...options,
      headers: {'Accept': 'application/json', 'X-Megalodon-Check': '1', ...(options.headers || {})}});
    const value = await response.json();
    if (!response.ok) { const error = new Error(value && value.error || 'Request failed'); error.status = response.status; throw error; }
    return value;
  } finally { window.clearTimeout(timeout); }
}
function validHeartbeat(value) {
  if (!value || value.schema !== 'megalodon-tool-heartbeat-v1' || !Array.isArray(value.tools) || value.tools.length !== workflowToolIds.length) throw new Error('Invalid heartbeat');
  const checkedAt = typeof value.checked_at === 'string' ? Date.parse(value.checked_at) : NaN;
  if (!Number.isFinite(checkedAt) || Date.now() - checkedAt > 90000 || checkedAt - Date.now() > 5000) throw new Error('Expired heartbeat');
  value.tools.forEach((tool, index) => {
    if (!tool || tool.id !== workflowToolIds[index] || !['green', 'amber', 'red', 'grey'].includes(tool.light)) throw new Error('Invalid heartbeat');
  });
  return value;
}
async function pollHeartbeat() {
  if (heartbeatState.polling) return;
  window.clearTimeout(heartbeatState.timer);
  if (document.visibilityState === 'hidden') return;
  heartbeatState.polling = true;
  try {
    const [report, install] = await Promise.all([heartbeatFetch('/api/heartbeat'), heartbeatFetch('/api/install')]);
    heartbeatState.report = validHeartbeat(report);
    heartbeatState.byId = new Map(report.tools.map(tool => [tool.id, tool]));
    heartbeatState.catalog = Array.isArray(install.tools) ? install.tools : null;
    const previous = heartbeatState.job;
    heartbeatState.job = install.job && install.job.state !== 'idle' ? install.job : null;
    if (previous && previous.state === 'running' && heartbeatState.job && heartbeatState.job.state !== 'running') {
      byId('setup-check-status').textContent = heartbeatState.job.state === 'succeeded' ? 'Installation finished. Status lights refreshed.' : 'Installation did not finish. See the tool for details.';
    }
    heartbeatState.failed = false; heartbeatState.failures = 0; heartbeatState.lastAt = Date.now();
  } catch (error) {
    heartbeatState.failed = true;
    heartbeatState.failures = Math.min(heartbeatState.failures + 1, 5);
  }
  heartbeatState.polling = false;
  repaintHeartbeat();
  const installing = heartbeatState.job && heartbeatState.job.state === 'running';
  const delay = heartbeatState.failed ? Math.min(60000, 5000 * 2 ** (heartbeatState.failures - 1)) : installing ? 2000 : 60000;
  if (document.visibilityState !== 'hidden') heartbeatState.timer = window.setTimeout(pollHeartbeat, delay);
}
async function startInstall(toolId, name, entry, action = 'install') {
  const starting = action === 'start';
  const question = starting ? `Start the ${name} service?\n\nIt keeps running until you stop it or restart the computer, and may start automatically at boot if its package enabled that.`
    : `Install ${name}?\n\n${entry.summary}`;
  if (!window.confirm(`${question}\n\nYour computer may ask for your password. MEGALODON never sees it.`)) return;
  try {
    const job = await heartbeatFetch('/api/install', {method: 'POST', body: JSON.stringify({tool: toolId, action}),
      headers: {'Content-Type': 'application/json', 'X-Megalodon-Install': '1'}});
    heartbeatState.job = job;
    byId('setup-check-status').textContent = `${starting ? 'Starting' : 'Installing'} ${name}… Approve the password prompt if one appears.`;
  } catch (error) {
    byId('setup-check-status').textContent = `${name} could not be ${starting ? 'started' : 'installed'}: ${error.message}.`;
  }
  repaintHeartbeat(); pollHeartbeat();
}
if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') window.clearTimeout(heartbeatState.timer);
  else {
    repaintHeartbeat();
    if (heartbeatState.failed || Date.now() - heartbeatState.lastAt > 60000) pollHeartbeat();
    else heartbeatState.timer = window.setTimeout(pollHeartbeat, Math.max(0, 60000 - (Date.now() - heartbeatState.lastAt)));
  }
});
"""
