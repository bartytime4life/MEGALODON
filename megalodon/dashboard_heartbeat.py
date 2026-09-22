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
const heartbeatState = {report: null, byId: new Map(), catalog: null, job: null, timer: 0, lastAt: 0, failed: false};
const heartbeatLabels = {green: 'Installed and healthy', amber: 'Installed · service not running', red: 'Not installed', grey: 'Status unknown'};
const heartbeatShelfIds = {python: 'core'};
function heartbeatToolId(id) { return Object.prototype.hasOwnProperty.call(heartbeatShelfIds, id) ? heartbeatShelfIds[id] : id; }
function heartbeatAge(iso) {
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (!Number.isFinite(seconds)) return '';
  const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}
function heartbeatText(tool) {
  if (!tool) return heartbeatState.failed ? 'Heartbeat unavailable' : 'Checking…';
  const modelOnly = tool.light === 'amber' && tool.service !== 'stopped' && tool.model === 'missing';
  const parts = [modelOnly ? 'Installed · Qwen model not downloaded' : heartbeatLabels[tool.light]];
  if (tool.service === 'running' && tool.running_since) parts.push(`up ${heartbeatAge(tool.running_since)}`);
  if (tool.model === 'missing' && !modelOnly) parts.push('Qwen model not downloaded');
  else if (tool.model === 'present') parts.push('Qwen model downloaded');
  if (tool.installed === 'yes' && tool.installed_since) parts.push(`installed ${new Date(tool.installed_since).toLocaleDateString()}`);
  return parts.join(' · ');
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
  const installing = heartbeatState.job && heartbeatState.job.state === 'running' && heartbeatState.job.tool === toolId;
  light.className = `hb-light hb-${tool ? tool.light : 'grey'}${installing || (!tool && !heartbeatState.failed) ? ' hb-pending' : ''}`;
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
    button.disabled = Boolean(running);
    button.title = entry.summary;
    button.addEventListener('click', () => startInstall(toolId, name, entry));
    wrap.append(button);
  } else if (tool && tool.installed === 'yes' && tool.expects_service && (tool.service === 'stopped' || (mine && job.action === 'start' && job.state === 'running'))) {
    if (entry.startable) {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'hb-install';
      const running = job && job.state === 'running';
      button.textContent = mine && running ? 'Starting…' : 'Start service';
      button.disabled = Boolean(running);
      button.title = `Starts the ${name} system service so its light can turn green.`;
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
  if (mine && job.state === 'succeeded') wrap.append(textNode('p', `${starting ? 'Service started' : 'Installed'}. The light updates automatically.`, 'hb-detail'));
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
  if (summary && heartbeatState.report) {
    const count = light => heartbeatState.report.tools.filter(tool => tool.light === light).length;
    summary.replaceChildren(...['green', 'amber', 'red', 'grey'].map(light => {
      const item = document.createElement('span'); const dot = document.createElement('i'); dot.className = `hb-light hb-${light}`; dot.setAttribute('aria-hidden', 'true');
      item.append(dot, textNode('span', `${count(light)} ${heartbeatLabels[light].toLowerCase()}`)); return item;
    }), textNode('span', `Heartbeat ${formatRefreshTime(new Date(heartbeatState.report.checked_at))}`));
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
  value.tools.forEach((tool, index) => {
    if (!tool || tool.id !== workflowToolIds[index] || !['green', 'amber', 'red', 'grey'].includes(tool.light)) throw new Error('Invalid heartbeat');
  });
  return value;
}
async function pollHeartbeat() {
  window.clearTimeout(heartbeatState.timer);
  if (document.visibilityState === 'hidden') return;
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
    heartbeatState.failed = false; heartbeatState.lastAt = Date.now();
  } catch (error) {
    heartbeatState.failed = true;
  }
  repaintHeartbeat();
  const installing = heartbeatState.job && heartbeatState.job.state === 'running';
  if (!heartbeatState.failed || installing) heartbeatState.timer = window.setTimeout(pollHeartbeat, installing ? 2000 : 60000);
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
  if (document.visibilityState === 'visible' && Date.now() - heartbeatState.lastAt > 60000) pollHeartbeat();
});
"""
