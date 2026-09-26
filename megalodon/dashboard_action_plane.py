"""Operator-facing entry points for bounded local HUD actions.

The browser can request a pure recurrence preview. It cannot supply a shell
command, script path, external endpoint, or job to the server.
"""

ACTION_PRESETS = {
    "daily": "FREQ=DAILY;COUNT=8",
    "weekdays": "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;COUNT=8",
    "weekly": "FREQ=WEEKLY;COUNT=8",
}

ACTION_HTML = """
<section class="action-plane" aria-labelledby="action-plane-title">
  <div class="action-plane-head">
    <div><p class="eyebrow">Operator actions</p><h3 id="action-plane-title" tabindex="-1">Action control plane</h3>
      <p>Choose a local task. Every action starts with your click; results show what was checked, prepared, or actually started.</p></div>
    <span class="action-mode">Local HUD · explicit actions</span>
  </div>
  <div class="action-plane-grid">
    <article class="action-card"><span class="action-card-kicker">This PC</span><h4>Check readiness</h4>
      <p>Read bounded runtime, data-source, executable, and process-name observations.</p>
      <button type="button" id="action-check-pc">Check this computer</button><a href="#setup-title">See detailed results</a></article>
    <article class="action-card"><span class="action-card-kicker">Evidence</span><h4>Review and export</h4>
      <p>Refresh saved metadata or preview the exact local report before downloading it.</p>
      <button type="button" id="action-refresh-evidence">Refresh metadata</button><a href="#room-reports-title">Open report builder</a></article>
    <article class="action-card"><span class="action-card-kicker">Companion apps</span><h4>Open or start</h4>
      <p>Open a configured local console, or start a supported installed service with launch-token authorization.</p>
      <a href="#app-service-start-title">Review service starts</a><a href="#app-viewer-title">Open app viewer</a></article>
    <article class="action-card"><span class="action-card-kicker">Scripting</span><h4>Reviewed scripts</h4>
      <p>Copy a fixed repository command for review in your own terminal. This page does not execute a supplied script.</p>
      <label for="action-script">Routine</label><select id="action-script"><option value="check">Check source launch</option><option value="plan">Show integration plan</option><option value="preview">Preview a schedule</option></select>
      <code id="action-script-command">./scripts/start-local.sh --check</code><button type="button" id="action-script-copy">Copy command</button></article>
  </div>
  <form id="action-schedule" class="action-schedule" autocomplete="off">
    <div><span class="action-card-kicker">Automations</span><h4>Preview a routine</h4>
      <p>See eight local and UTC times starting at the chosen first time. Previewing does not save, activate, or execute a job.</p></div>
    <div class="action-schedule-fields">
      <label for="action-schedule-start">First local time<input id="action-schedule-start" type="datetime-local" step="1" required></label>
      <label for="action-schedule-zone">Time zone<input id="action-schedule-zone" type="text" value="UTC" maxlength="128" required spellcheck="false" placeholder="America/Chicago"></label>
      <label for="action-schedule-preset">Repeat<select id="action-schedule-preset"><option value="daily">Daily</option><option value="weekdays">Weekdays</option><option value="weekly">Weekly</option></select></label>
      <button type="submit" id="action-schedule-preview">Preview times</button>
    </div>
    <p id="action-schedule-status" role="status" aria-live="polite">No routine is scheduled.</p>
    <ol id="action-schedule-results" class="action-schedule-results"></ol>
  </form>
  <p id="action-plane-status" class="action-plane-status" role="status" aria-live="polite">Ready for an explicit local action.</p>
</section>
"""

ACTION_CSS = """
.action-plane { margin:14px 22px 22px; padding:22px; border:1px solid #47636c; border-radius:16px; background:linear-gradient(135deg,#132d36,#0b1b25 68%); }
.action-plane-head { display:flex; justify-content:space-between; gap:20px; align-items:start; }
.action-plane-head h3 { margin:0 0 6px; font-size:1.5rem; color:#f0faf8; }
.action-plane-head p { margin:0; max-width:60ch; color:#b5cbd0; font-size:.81rem; line-height:1.5; }
.action-mode,.action-card-kicker { color:#a6f4df; font-size:.67rem; font-weight:800; letter-spacing:.08em; text-transform:uppercase; }
.action-mode { white-space:nowrap; border:1px solid #426e68; border-radius:999px; padding:8px 11px; }
.action-plane-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:20px; }
.action-card { display:flex; flex-direction:column; align-items:start; gap:9px; min-width:0; padding:15px; border:1px solid #35515c; border-radius:12px; background:#0a202a; }
.action-card h4,.action-schedule h4 { margin:0; font-size:1rem; color:#f0faf8; }
.action-card p,.action-schedule p { margin:0; color:#b7cbd1; font-size:.77rem; line-height:1.55; }
.action-card a { color:#8de7ef; font-size:.78rem; font-weight:700; }
.action-card button,.action-schedule button { min-height:44px; margin-top:auto; }
.action-card label,.action-schedule label { display:grid; gap:5px; width:100%; font-size:.76rem; color:#d1e3e7; }
.action-card select,.action-schedule input,.action-schedule select { width:100%; min-width:0; min-height:44px; background:#09202a; color:#eff9f8; border:1px solid #52717c; border-radius:8px; padding:8px; font:inherit; }
.action-card code { width:100%; overflow-wrap:anywhere; color:#d0e9de; font-size:.73rem; }
.action-schedule { display:grid; gap:13px; margin-top:12px; padding:17px; border:1px solid #35515c; border-radius:12px; background:#0a202a; }
.action-schedule-fields { display:grid; grid-template-columns:1.1fr 1fr .8fr auto; align-items:end; gap:10px; }
.action-schedule-results { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:6px; margin:0; padding:0; list-style:none; }
.action-schedule-results li { padding:9px 11px; border:1px solid #35515c; border-radius:8px; color:#d9ecee; font-size:.75rem; overflow-wrap:anywhere; }
.action-plane-status { margin:12px 0 0; color:#b7cbd1; font-size:.76rem; }
@media(max-width:1100px) { .action-plane-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media(max-width:720px) { .action-plane { margin:12px 14px; padding:15px; } .action-plane-head { display:block; } .action-mode { display:inline-block; margin-top:12px; } .action-schedule-fields { grid-template-columns:repeat(2,minmax(0,1fr)); } .action-schedule-results { grid-template-columns:1fr; } }
@media(max-width:480px) { .action-plane-grid,.action-schedule-fields,.action-schedule-results { grid-template-columns:1fr; } }
"""

ACTION_JS = r"""
const fixedActionCommands = Object.freeze({
  check: './scripts/start-local.sh --check',
  plan: 'python -m megalodon hub-plan --platform linux',
  preview: 'python -m megalodon automation-preview --dtstart 2026-09-28T09:00:00 --timezone America/Chicago --rrule FREQ=WEEKLY --limit 8'
});
const actionStatus = message => { byId('action-plane-status').textContent = message; };
byId('action-check-pc').addEventListener('click', () => {
  byId('setup-check').click(); actionStatus('Local check requested. Detailed results are on Home.');
});
byId('action-refresh-evidence').addEventListener('click', () => {
  byId('room-refresh').click(); actionStatus('Metadata refresh requested. Evidence results remain separate from tool checks.');
});
byId('action-script').addEventListener('change', () => {
  byId('action-script-command').textContent = fixedActionCommands[byId('action-script').value] || '';
});
byId('action-script-copy').addEventListener('click', async () => {
  const command = fixedActionCommands[byId('action-script').value];
  if (!command) return;
  try { await navigator.clipboard.writeText(command); actionStatus('Fixed command copied for review in your terminal. Nothing was executed.'); }
  catch (_) { actionStatus('Clipboard unavailable. Select and copy the displayed command manually.'); }
});
byId('action-schedule').addEventListener('submit', async event => {
  event.preventDefault();
  const button = byId('action-schedule-preview'), status = byId('action-schedule-status'), results = byId('action-schedule-results');
  const start = byId('action-schedule-start').value, zone = byId('action-schedule-zone').value.trim();
  const preset = byId('action-schedule-preset').value;
  results.replaceChildren(); button.disabled = true; status.textContent = 'Calculating preview…';
  try {
    const payload = await requestBoundedJSON('/api/automation-preview', 4096, {method:'POST',
      headers:{'Content-Type':'application/json','X-Megalodon-Preview':'1'},
      body:JSON.stringify({dtstart:start.length===16?start+':00':start,schedule_timezone:zone,preset})});
    if (payload.schema_version !== 'megalodon-automation-preview-v1'
        || payload.status !== 'preview_only' || !Array.isArray(payload.occurrences)
        || payload.occurrences.length > 8) throw new Error(payload.error_code || 'PREVIEW_UNAVAILABLE');
    for (const item of payload.occurrences) {
      if (!item || typeof item.local_time !== 'string' || typeof item.occurrence_at !== 'string'
          || !['normal','ambiguous','gap'].includes(item.dst_status)) throw new Error('PREVIEW_UNAVAILABLE');
      const row = document.createElement('li'); row.textContent = `${item.local_time.replace('T',' ')} (${zone}) → ${item.occurrence_at.replace('T',' ').replace('Z',' UTC')}${item.dst_status==='normal'?'':` · ${item.dst_status}`}`;
      results.append(row);
    }
    status.textContent = `Preview only: ${payload.occurrences.length} times calculated. No job was saved or run.`;
  } catch (error) { status.textContent = `Preview unavailable: ${String(error.message).slice(0,40)}. No job was saved or run.`; }
  finally { button.disabled = false; }
});
"""
