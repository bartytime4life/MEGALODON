"""Explicit, bounded local AI controls for the Investigate workspace."""

from .status_glossary import GLOSSARY_ANCHOR_ID

AI_PANEL = """
  <details class="panel ai-control" id="ai-control" aria-labelledby="ai-control-title" data-ai-phase="idle">
    <summary>
      <span class="ai-summary-title"><span class="ai-orb" aria-hidden="true"></span><span><strong id="ai-control-title">Local AI control</strong><small>Ask the selected local model about bounded MEGALODON metadata after a live model check.</small></span></span>
      <span class="ai-summary-meta"><span class="ai-badge" id="ai-badge" data-tone="idle">Not checked</span><span class="summary-action" id="ai-control-action">Open AI controls</span></span>
    </summary>
    <p class="ai-intro">Model output is advice. Tool selection passes through MEGALODON policy and every attempt gets an audit receipt. This HUD offers bounded reads and report snapshots; firewall application remains unavailable. (This panel's own states are explained in full below; other pages' statuses are in the <a href="#__GLOSSARY_ANCHOR__">status glossary</a>.)</p>
    <ol class="ai-steps">
      <li class="ai-step" id="ai-step-token" data-step-state="active">
        <span class="ai-step-index" aria-hidden="true">1</span>
        <label class="field" for="ai-token"><span>Operator token from the HUD terminal</span>
          <span class="token-field">
            <input id="ai-token" type="password" autocomplete="off" spellcheck="false" maxlength="64" placeholder="Paste the AI operator token">
            <button id="ai-token-toggle" class="button-secondary" type="button" aria-pressed="false">Show</button>
          </span>
          <small class="field-hint" id="ai-token-hint">Filled automatically when this HUD manages your local setup. Otherwise paste the token printed when the HUD started (for the background service: <code>journalctl --user -u megalodon-hud.service | grep "AI operator token"</code>). Press Enter to verify.</small>
        </label>
      </li>
      <li class="ai-step" id="ai-step-check" data-step-state="pending">
        <span class="ai-step-index" aria-hidden="true">2</span>
        <div class="ai-step-body">
          <span class="ai-step-label">Live model check</span>
          <button id="ai-check" type="button">Verify selected model</button>
          <small class="field-hint">Runs one short local inference. CPU models can take a few minutes on first load.</small>
        </div>
      </li>
      <li class="ai-step" id="ai-step-ask" data-step-state="pending">
        <span class="ai-step-index" aria-hidden="true">3</span>
        <div class="ai-step-body">
          <label class="field" for="ai-question"><span>Question</span><select id="ai-question">
            <option value="seeing">What is MEGALODON seeing?</option>
            <option value="changed">What changed during the last hour?</option>
            <option value="alerts">Why are recent alerts present?</option>
            <option value="integrations">Which integrations are available?</option>
            <option value="model">Is Ollama healthy and which local model is active?</option>
            <option value="safe">What can be safely fixed automatically?</option>
            <option value="plan">Prepare a remediation plan</option>
            <option value="report">Generate a security summary report</option>
          </select></label>
          <div class="ai-question-chips" id="ai-question-chips" role="group" aria-label="Question" hidden></div>
          <small class="field-hint">Fixed so every model tool call stays inside the audited policy; free text is not supported.</small>
          <div class="ai-ask-row">
            <button id="ai-ask" type="button" disabled>Ask locally</button>
            <button id="ai-cancel" class="button-secondary" type="button" hidden>Cancel</button>
          </div>
        </div>
      </li>
    </ol>
    <div class="ai-status" id="ai-status" data-tone="idle">
      <span class="ai-spinner" aria-hidden="true"></span>
      <p id="ai-state" role="status" aria-live="polite">AI has not been checked. It is disabled until configured and verified — choose a model in Setup, or run <code>megalodon ai doctor --config config/settings.toml</code>, then see docs/ai-control-plane.md.</p>
      <a class="ai-setup-link" id="ai-setup-link" href="#support-model-title" hidden>Open Setup → Local AI</a>
      <span class="ai-elapsed" id="ai-elapsed" aria-hidden="true" hidden></span>
      <span class="ai-progress" aria-hidden="true"></span>
    </div>
    <dl class="ai-result" id="ai-result" hidden>
      <div class="ai-result-inferred"><dt>INFERRED · local model advice</dt><dd id="ai-inferred"></dd></div>
      <div class="ai-result-observed"><dt>OBSERVED · broker output</dt><dd><pre id="ai-observed"></pre></dd></div>
      <div class="ai-result-meta"><dt>PROPOSED / APPROVED / APPLIED</dt><dd id="ai-action-state">No host action requested or approved.</dd></div>
      <div class="ai-result-meta"><dt>Receipt</dt><dd id="ai-receipt"></dd></div>
    </dl>
  </details>
"""
if "__GLOSSARY_ANCHOR__" not in AI_PANEL:
    raise AssertionError("glossary anchor placeholder missing from AI_PANEL")
AI_PANEL = AI_PANEL.replace("__GLOSSARY_ANCHOR__", GLOSSARY_ANCHOR_ID)

AI_CSS = """
.ai-control { --ai-tone: var(--muted); margin: 0 0 18px; }
.ai-control > summary { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 64px; padding: 14px 20px; cursor: pointer; list-style: none; }
.ai-control > summary::-webkit-details-marker { display: none; }
.ai-control[open] > summary { border-bottom: 1px solid var(--line); }
.ai-summary-title { display: flex; align-items: center; gap: 12px; min-width: 0; }
.ai-summary-title > span:last-child { display: grid; gap: 3px; min-width: 0; }
.ai-summary-title strong { font-size: .86rem; }
.ai-summary-title small { color: var(--muted); font-size: .72rem; line-height: 1.35; }
.ai-summary-meta { display: flex; align-items: center; gap: 12px; flex: none; }
.ai-orb { position: relative; flex: none; width: 30px; height: 30px; border-radius: 50%; border: 1px solid rgba(81, 230, 207, .4);
  background: radial-gradient(circle at 35% 30%, rgba(200, 255, 247, .55), rgba(81, 230, 207, .22) 45%, rgba(8, 24, 33, .9) 75%);
  box-shadow: 0 0 0 0 rgba(81, 230, 207, 0); transition: box-shadow .4s, border-color .4s, filter .4s; }
.ai-control[data-ai-phase="ready"] .ai-orb, .ai-control[data-ai-phase="done"] .ai-orb { border-color: rgba(61, 220, 132, .6); box-shadow: 0 0 18px rgba(61, 220, 132, .35); }
.ai-control[data-ai-phase="error"] .ai-orb { border-color: rgba(255, 117, 143, .55); filter: saturate(.4); }
.ai-control:is([data-ai-phase="checking"],[data-ai-phase="asking"]) .ai-orb { animation: ai-orb-pulse 1.6s ease-in-out infinite; }
@keyframes ai-orb-pulse { 50% { box-shadow: 0 0 22px rgba(81, 230, 207, .55); border-color: rgba(166, 244, 223, .8); } }
.ai-badge { display: inline-flex; align-items: center; gap: 6px; min-height: 26px; padding: 3px 10px; border: 1px solid var(--line); border-radius: 999px; background: rgba(4, 14, 20, .5); color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .04em; white-space: nowrap; transition: color .3s, border-color .3s, background-color .3s; }
.ai-badge::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; opacity: .85; }
.ai-badge[data-tone="busy"] { color: var(--cyan); border-color: rgba(110, 216, 255, .4); }
.ai-badge[data-tone="busy"]::before { animation: ai-blink 1s ease-in-out infinite; }
.ai-badge[data-tone="ok"] { color: #8ff0bf; border-color: rgba(61, 220, 132, .42); background: rgba(61, 220, 132, .08); }
.ai-badge[data-tone="warn"] { color: var(--amber); border-color: rgba(255, 209, 102, .4); background: rgba(255, 209, 102, .07); }
.ai-badge[data-tone="error"] { color: var(--rose); border-color: rgba(255, 117, 143, .45); background: rgba(255, 117, 143, .07); }
@keyframes ai-blink { 50% { opacity: .25; } }
.ai-intro { margin: 14px 20px 4px; color: var(--muted); font-size: .8rem; line-height: 1.5; }
.ai-steps { display: grid; grid-template-columns: minmax(260px, .85fr) minmax(320px, 1.4fr); grid-template-areas: "token ask" "check ask"; align-items: start; gap: 12px; margin: 0; padding: 12px 20px 14px; list-style: none; }
#ai-step-token { grid-area: token; }
#ai-step-check { grid-area: check; }
#ai-step-ask { grid-area: ask; align-self: stretch; }
.ai-step { position: relative; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 12px; align-items: start; min-width: 0; padding: 14px; border: 1px solid var(--line); border-radius: 12px; background: rgba(4, 15, 21, .32); transition: border-color .3s, background-color .3s, opacity .3s, box-shadow .3s; }
.ai-step[data-step-state="pending"] { opacity: .72; }
.ai-step[data-step-state="active"] { border-color: rgba(81, 230, 207, .4); background: rgba(81, 230, 207, .05); box-shadow: inset 0 1px rgba(255, 255, 255, .04), 0 10px 28px -22px rgba(81, 230, 207, .9); }
.ai-step[data-step-state="done"] { border-color: rgba(61, 220, 132, .3); }
.ai-step-index { position: relative; display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; border: 1px solid var(--line); color: var(--muted); font-size: .72rem; font-weight: 900; transition: color .3s, border-color .3s, background-color .3s; }
.ai-step[data-step-state="active"] .ai-step-index { color: #04202a; border-color: #7cf0e6; background: linear-gradient(135deg, #7cf0e6, #4fcfd8); }
.ai-step[data-step-state="done"] .ai-step-index { color: transparent; border-color: rgba(61, 220, 132, .55); background: rgba(61, 220, 132, .14); }
.ai-step[data-step-state="done"] .ai-step-index::after { content: "✓"; position: absolute; color: #8ff0bf; font-size: .8rem; }
.ai-step-body { display: grid; gap: 8px; align-content: start; min-width: 0; }
.ai-step-label { color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.ai-step .field { min-width: 0; }
.ai-step-body > button { justify-self: start; }
.field-hint { color: var(--muted); font-size: .72rem; line-height: 1.4; font-weight: 400; text-transform: none; letter-spacing: normal; }
.token-field { display: flex; gap: 6px; }
.token-field input { flex: 1; min-width: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .02em; }
.token-field button { padding: 0 12px; white-space: nowrap; min-width: auto; }
.ai-question-chips { display: flex; flex-wrap: wrap; gap: 6px; }
#ai-question-chips .ai-chip { min-height: 32px; padding: 5px 11px; border: 1px solid #3c6070; border-radius: 999px; background: rgba(10, 32, 42, .85); color: #cfe4ec; font-size: .74rem; font-weight: 650; line-height: 1.25; text-align: left; cursor: pointer; }
#ai-question-chips .ai-chip:hover:not(:disabled) { border-color: #75e6e1; color: #f2fffd; background: rgba(117, 230, 225, .1); }
#ai-question-chips .ai-chip[aria-pressed="true"] { border-color: #75e6e1; background: linear-gradient(135deg, rgba(117, 230, 225, .3), rgba(110, 216, 255, .14)); color: #effffd; }
#ai-question-chips .ai-chip:disabled { opacity: .5; cursor: default; }
.ai-question-native { position: absolute !important; width: 1px !important; height: 1px !important; min-height: 0 !important; padding: 0 !important; overflow: hidden; clip: rect(0 0 0 0); border: 0 !important; opacity: 0; pointer-events: none; }
.ai-ask-row { display: flex; flex-wrap: wrap; gap: 8px; }
#ai-ask:not(:disabled) { border-color: #7cf0e6; background: linear-gradient(135deg, #7cf0e6, #4fcfd8); color: #04202a; box-shadow: 0 6px 22px -12px rgba(117, 230, 225, .9); }
#ai-ask:not(:disabled):hover { background: linear-gradient(135deg, #a2f7ef, #68e0e6); }
.ai-status { position: relative; display: flex; align-items: flex-start; gap: 10px; margin: 0 20px 16px; padding: 12px 14px; overflow: hidden; border: 1px solid var(--line); border-left: 3px solid var(--ai-tone); border-radius: 10px; background: rgba(4, 14, 20, .42); transition: border-color .3s, background-color .3s; }
.ai-status[data-tone="busy"] { --ai-tone: var(--cyan); }
.ai-status[data-tone="ok"] { --ai-tone: #3ddc84; background: rgba(61, 220, 132, .05); }
.ai-status[data-tone="warn"] { --ai-tone: var(--amber); background: rgba(255, 209, 102, .045); }
.ai-status[data-tone="error"] { --ai-tone: var(--rose); background: rgba(255, 117, 143, .05); }
#ai-state { flex: 1; min-width: 0; margin: 0; color: #d3e6ea; font-size: .82rem; line-height: 1.5; }
#ai-state.ai-integrity-alert { color: var(--rose); font-weight: 700; }
.ai-spinner { display: none; flex: none; width: 16px; height: 16px; margin-top: 2px; border: 2px solid rgba(110, 216, 255, .25); border-top-color: var(--cyan); border-radius: 50%; animation: ai-spin .8s linear infinite; }
.ai-status[data-tone="busy"] .ai-spinner { display: block; }
@keyframes ai-spin { to { transform: rotate(360deg); } }
.ai-setup-link { flex: none; align-self: center; padding: 4px 10px; border: 1px solid rgba(255, 209, 102, .45); border-radius: 999px; color: var(--amber); font-size: .72rem; font-weight: 800; text-decoration: none; white-space: nowrap; }
.ai-setup-link:hover { background: rgba(255, 209, 102, .1); }
.ai-elapsed { flex: none; padding: 2px 8px; border-radius: 999px; background: rgba(110, 216, 255, .1); color: var(--cyan); font-size: .7rem; font-weight: 800; font-variant-numeric: tabular-nums; }
.ai-progress { position: absolute; left: 0; right: 0; bottom: 0; height: 2px; opacity: 0; background: linear-gradient(90deg, transparent, var(--cyan), transparent); background-size: 40% 100%; background-repeat: no-repeat; transition: opacity .3s; }
.ai-status[data-tone="busy"] .ai-progress { opacity: 1; animation: ai-progress 1.4s ease-in-out infinite; }
@keyframes ai-progress { from { background-position: -40% 0; } to { background-position: 140% 0; } }
.ai-result { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 0 20px 20px; }
.ai-result:not([hidden]) > div { animation: ai-reveal .45s cubic-bezier(.2, .8, .2, 1) both; }
.ai-result:not([hidden]) > div:nth-child(2) { animation-delay: .06s; }
.ai-result:not([hidden]) > div:nth-child(n+3) { animation-delay: .12s; }
@keyframes ai-reveal { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
.ai-result div { min-width: 0; border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; background: rgba(4, 15, 21, .3); }
.ai-result .ai-result-inferred { grid-column: 1 / -1; border-color: rgba(81, 230, 207, .32); background: linear-gradient(145deg, rgba(81, 230, 207, .08), rgba(8, 24, 33, .4)); }
.ai-result .ai-result-observed { grid-column: 1 / -1; }
.ai-result dt { color: var(--amber); font-size: .7rem; font-weight: 800; letter-spacing: .06em; }
.ai-result .ai-result-inferred dt { color: var(--aqua); }
.ai-result dd { margin: 6px 0 0; overflow-wrap: anywhere; line-height: 1.55; }
.ai-result .ai-result-inferred dd { color: var(--text); font-size: .9rem; }
.ai-result .ai-result-meta dd { color: #c9e1e6; font-size: .78rem; }
#ai-receipt { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .74rem; }
.ai-result pre { max-height: 260px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; padding: 10px; border-radius: 8px; background: rgba(3, 13, 19, .6); color: #cfe4ec; font: .74rem/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
@media (max-width: 900px) { .ai-steps { grid-template-columns: 1fr; grid-template-areas: "token" "check" "ask"; } }
@media (max-width: 640px) {
  .ai-control > summary { flex-wrap: wrap; padding: 12px 16px; }
  .ai-summary-meta { width: 100%; justify-content: space-between; }
  .ai-steps { padding: 10px 14px 12px; }
  .ai-intro { margin: 12px 16px 4px; }
  .ai-status, .ai-result { margin-left: 14px; margin-right: 14px; }
  .ai-result { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  .ai-orb, .ai-badge::before, .ai-spinner, .ai-progress, .ai-result > div { animation: none !important; }
  .ai-status[data-tone="busy"] .ai-progress { background: var(--cyan); opacity: .5; }
}
"""

AI_JS = r"""
const aiPanel = document.getElementById('ai-control');
const aiCheck = document.getElementById('ai-check');
const aiAsk = document.getElementById('ai-ask');
const aiState = document.getElementById('ai-state');
const aiStatusBox = document.getElementById('ai-status');
const aiBadge = document.getElementById('ai-badge');
const aiElapsed = document.getElementById('ai-elapsed');
const aiResult = document.getElementById('ai-result');
const aiTokenInput = document.getElementById('ai-token');
const aiTokenToggle = document.getElementById('ai-token-toggle');
const aiCancel = document.getElementById('ai-cancel');
const aiQuestion = document.getElementById('ai-question');
const aiQuestionChips = document.getElementById('ai-question-chips');
let aiBusy = false;
let aiActiveController = null;
let aiUserCanceled = false;
let aiVerified = false;
let aiTimeoutSeconds = null;
let aiElapsedTimer = null;
let aiPhase = 'idle';
const AI_STATE_TEXT = {
  disabled: 'Local AI is turned off. Choose a local model in Setup, or run megalodon ai doctor --config config/settings.toml and set [ai] enabled = true (see docs/ai-control-plane.md).',
  ollama_unavailable: 'Ollama is not reachable on loopback. Start Ollama (ollama serve) and verify again.',
  model_missing: 'The selected local model is not installed in Ollama.',
  model_available: 'The model tag is present but has not completed a live inference check.',
  model_loading: 'Another local AI request is already using the one inference slot. Try again in a moment.',
  concurrency_unavailable: "MEGALODON could not establish its own local concurrency lock, so no request to Ollama was attempted. This is a local platform or filesystem issue, not an Ollama or model problem.",
  model_ready: 'The model completed a live bounded inference check.',
  model_not_local: 'The selected model is not a local GGUF completion model (it may proxy a cloud model), so MEGALODON will not send it evidence.',
  request_timeout: 'The request to Ollama timed out.',
  cancelled: 'The check was cancelled before the model answered.',
  invalid_response: 'Ollama returned a response MEGALODON could not validate.',
  provider_error: 'Ollama returned an error for this request.',
  policy_rejection: 'The current configuration or model identity fails a fixed safety check.',
};
const AI_STATE_TONE = {model_ready: 'ok', model_available: 'warn', model_loading: 'warn', disabled: 'warn', cancelled: 'warn'};
const AI_STATE_BADGE = {model_ready: 'Model ready', model_available: 'Unverified', model_loading: 'Slot busy', disabled: 'AI off',
  ollama_unavailable: 'Ollama offline', model_missing: 'Model missing', cancelled: 'Cancelled', request_timeout: 'Timed out'};
const AI_ERROR_TEXT = {
  CONCURRENCY_LIMIT_REACHED: 'another AI request is already using the one local inference slot',
  CONCURRENCY_CONTROL_UNAVAILABLE: 'the local concurrency lock could not be acquired',
  MODEL_MISMATCH: 'Ollama now has a different copy of the selected model than MEGALODON pinned; open Setup → Local AI and press Use installed version',
  MODEL_MISSING: 'the selected model is no longer installed in Ollama; choose an installed model in Setup → Local AI',
  MODEL_NOT_LOCAL: 'the model is not a local completion model',
  OLLAMA_UNAVAILABLE: 'Ollama is not reachable on loopback',
  REQUEST_TIMEOUT: 'the local model did not finish within the configured timeout',
  REQUEST_CANCELLED: 'the request was cancelled',
  INVALID_RESPONSE: 'the model reply failed validation (it may have been too long or malformed)',
  PROVIDER_ERROR: 'Ollama returned an error',
  POLICY_REJECTION: 'the configuration failed a fixed safety check',
  DISABLED: 'local AI is turned off',
  REQUEST_TOO_LARGE: 'the request exceeded a fixed size limit',
  AUDIT_INTEGRITY: 'the local receipt ledger failed an integrity check',
  AUDIT_UNAVAILABLE: 'the local receipt ledger is unavailable',
  UNKNOWN_TOOL: 'the model selected a tool outside the permitted list',
  UNKNOWN_QUESTION: 'the question was not one of the fixed HUD questions',
  INVALID_ARGUMENTS: 'the request arguments failed validation',
  INVALID_TARGET: 'the requested target is not permitted',
  EVIDENCE_INVALID: 'the evidence returned by a tool failed validation',
  EVIDENCE_UNAVAILABLE: 'no stored MEGALODON evidence is available yet; start capture or import metadata, then ask again',
  TOOL_UNAVAILABLE: 'the selected tool is unavailable in this HUD',
  RESULT_TOO_LARGE: 'the tool result exceeded a fixed size limit',
  AI_UNAVAILABLE: 'the local AI service could not complete the request',
};
function aiErrorReason(code) {
  if (!code) return '';
  return ` Reason: ${AI_ERROR_TEXT[code] || code} (${code}).`;
}
function aiTokenErrorText(value) {
  const detail = value && typeof value.error === 'string' ? ` (${value.error})` : '';
  return `Operator token missing or incorrect${detail}. Re-copy the token printed in the HUD terminal at startup.`;
}
const AI_DRIFT = {
  MODEL_MISMATCH: {badge: 'Model changed', text: 'Ollama now has a different copy of the selected model than MEGALODON pinned. Open Setup → Local AI and press Use installed version'},
  MODEL_MISSING: {badge: 'Model missing', text: 'The selected model is no longer installed in Ollama. Open Setup → Local AI and choose an installed model'},
};
const AI_SETUP_CODES = new Set(['MODEL_MISMATCH', 'MODEL_MISSING', 'MODEL_NOT_LOCAL', 'DISABLED']);
function aiShowSetupLink(code) {
  const link = document.getElementById('ai-setup-link');
  if (link) link.hidden = !AI_SETUP_CODES.has(code);
}
async function aiLoadToken() {
  // The local Setup HUD hands its own page this launch's token; other modes keep manual entry.
  if (aiTokenInput.value.trim() || typeof fetch !== 'function') return false;
  try {
    const response = await fetch('/api/ai/token', {headers: {'X-Megalodon-Check': '1'}, cache: 'no-store', credentials: 'same-origin'});
    if (!response.ok) return false;
    const text = await response.text();
    if (text.length > 256) return false;
    const value = JSON.parse(text);
    if (!value || value.schema !== 'megalodon-ai-token-v1' || typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(value.token)) return false;
    if (aiTokenInput.value.trim()) return false;
    aiTokenInput.value = value.token;
    const hint = document.getElementById('ai-token-hint');
    if (hint) hint.textContent = 'Filled automatically for this HUD launch. Press Enter or Verify to check the model.';
    if (!aiBusy) aiSetPhase(aiPhase);
    return true;
  } catch (_) { return false; }
}
function aiSetStatus(text, tone = 'idle', badge = null) {
  aiShowSetupLink(null);
  aiState.textContent = text;
  aiStatusBox.setAttribute('data-tone', tone);
  aiBadge.setAttribute('data-tone', tone);
  if (badge) aiBadge.textContent = badge;
}
function aiSetPhase(phase) {
  aiPhase = phase;
  aiPanel.setAttribute('data-ai-phase', phase);
  const hasToken = aiTokenInput.value.trim().length > 0;
  const steps = {
    'ai-step-token': hasToken ? 'done' : 'active',
    'ai-step-check': aiVerified ? 'done' : (hasToken ? 'active' : 'pending'),
    'ai-step-ask': aiVerified ? 'active' : 'pending',
  };
  Object.entries(steps).forEach(([id, state]) => { const node = document.getElementById(id); if (node) node.setAttribute('data-step-state', state); });
}
function aiStartElapsed(hint) {
  const started = Date.now();
  let hinted = false;
  clearTimeout(aiElapsedTimer);
  aiElapsed.hidden = false; aiElapsed.textContent = '0 s';
  const tick = () => {
    const seconds = Math.floor((Date.now() - started) / 1000);
    aiElapsed.textContent = seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, '0')} s`;
    if (!hinted && seconds >= 20 && hint && !aiUserCanceled) { hinted = true; aiState.textContent = hint; }
    aiElapsedTimer = setTimeout(tick, 1000);
  };
  aiElapsedTimer = setTimeout(tick, 1000);
}
function aiStopElapsed() { clearTimeout(aiElapsedTimer); aiElapsedTimer = null; aiElapsed.hidden = true; }
function aiDeadlineMs(calls) {
  // The server enforces each model call's own deadline; the browser only stops waiting after all of them.
  const perCall = Number.isInteger(aiTimeoutSeconds) && aiTimeoutSeconds > 0 ? aiTimeoutSeconds : 1800;
  return (calls * perCall + 30) * 1000;
}
const AI_QUESTION_SECONDS = 600;
function aiQuestionDeadlineMs(question) {
  // Both model calls share one 600 s server budget; the model-health tool adds its own live check.
  const perCall = Number.isInteger(aiTimeoutSeconds) && aiTimeoutSeconds > 0 ? aiTimeoutSeconds : 1800;
  return (AI_QUESTION_SECONDS + (question === 'model' ? perCall : 0) + 30) * 1000;
}
function aiBuildQuestionChips() {
  const options = [...aiQuestion.options];
  aiQuestionChips.replaceChildren(...options.map(option => {
    const chip = document.createElement('button');
    chip.type = 'button'; chip.className = 'ai-chip'; chip.dataset.value = option.value;
    chip.textContent = option.textContent.trim();
    chip.addEventListener('click', () => {
      if (aiQuestion.disabled) return;
      aiQuestion.value = option.value;
      aiQuestion.dispatchEvent(new Event('change', {bubbles: true}));
    });
    return chip;
  }));
  aiQuestion.classList.add('ai-question-native');
  aiQuestion.tabIndex = -1; aiQuestion.setAttribute('aria-hidden', 'true');
  aiQuestionChips.hidden = false;
  aiSyncQuestionChips();
}
function aiSyncQuestionChips() {
  if (aiQuestionChips.hidden || !aiQuestionChips.querySelectorAll) return;
  aiQuestionChips.querySelectorAll('.ai-chip').forEach(chip => {
    chip.setAttribute('aria-pressed', chip.dataset.value === aiQuestion.value ? 'true' : 'false');
    chip.disabled = aiQuestion.disabled;
  });
}
aiQuestion.addEventListener('change', aiSyncQuestionChips);
try { aiBuildQuestionChips(); } catch (_) { /* the native select remains usable */ }
aiTokenToggle.addEventListener('click', () => {
  const showing = aiTokenInput.type === 'text';
  aiTokenInput.type = showing ? 'password' : 'text';
  aiTokenToggle.textContent = showing ? 'Show' : 'Hide';
  aiTokenToggle.setAttribute('aria-pressed', String(!showing));
});
aiTokenInput.addEventListener('input', () => { if (!aiBusy) aiSetPhase(aiPhase); });
aiTokenInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') { event.preventDefault(); if (!aiBusy) aiCheck.click(); }
});
aiPanel.addEventListener('toggle', event => {
  document.getElementById('ai-control-action').textContent = event.currentTarget.open ? 'Close AI controls' : 'Open AI controls';
  if (event.currentTarget.open) aiLoadToken();
});
async function aiRequestServerCancel() {
  // Frees the one inference slot on the server; aborting the browser fetch alone would not.
  try {
    await fetch('/api/ai/cancel', {method: 'POST', body: '{}', cache: 'no-store', credentials: 'same-origin',
      headers: {'X-Megalodon-AI-Token': aiTokenInput.value, 'Content-Type': 'application/json'}});
  } catch (_) { /* the server deadline still bounds the request */ }
}
aiCancel.addEventListener('click', () => {
  aiUserCanceled = true; aiCancel.disabled = true;
  aiSetStatus('Cancelling the local model request…', 'busy');
  aiRequestServerCancel().finally(() => { if (aiActiveController) aiActiveController.abort(); });
});
async function aiFetch(path, header, body = null, deadlineMs = 50000) {
  const controller = new AbortController();
  aiActiveController = controller;
  const timer = setTimeout(() => { aiRequestServerCancel(); controller.abort(); }, deadlineMs);
  const options = {headers: {[header]: '1', 'X-Megalodon-AI-Token': aiTokenInput.value},
                   cache: 'no-store', credentials: 'same-origin', signal: controller.signal};
  try {
  if (body !== null) {
    options.method = 'POST'; options.body = JSON.stringify(body);
    options.headers = {'X-Megalodon-AI-Token': aiTokenInput.value,
                       'Content-Type': 'application/json'};
  }
  const response = await fetch(path, options);
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^[0-9]{1,5}$/.test(declared) || Number(declared) > 16384)) throw new Error('AI response exceeded the display limit');
  if (!response.body || !response.body.getReader) throw new Error('AI response stream unavailable');
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    size += part.value.byteLength;
    if (size > 16384) { await reader.cancel(); throw new Error('AI response exceeded the display limit'); }
    chunks.push(part.value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  chunks.forEach(chunk => { bytes.set(chunk, offset); offset += chunk.byteLength; });
  const responseText = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  const value = JSON.parse(responseText);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('AI response invalid');
  return {response, value};
  } finally { clearTimeout(timer); if (aiActiveController === controller) aiActiveController = null; }
}
function aiBeginBusy(button, label) {
  aiBusy = true; aiUserCanceled = false;
  aiCheck.disabled = true; aiAsk.disabled = true; aiQuestion.disabled = true; aiSyncQuestionChips();
  button.textContent = label; button.setAttribute('aria-busy', 'true');
  aiCancel.hidden = false; aiCancel.disabled = false;
  aiState.classList.remove('ai-integrity-alert');
}
function aiEndBusy() {
  aiBusy = false; aiStopElapsed();
  aiCheck.disabled = false; aiCheck.textContent = 'Verify selected model'; aiCheck.removeAttribute('aria-busy');
  aiAsk.disabled = !aiVerified; aiAsk.textContent = 'Ask locally'; aiAsk.removeAttribute('aria-busy');
  aiQuestion.disabled = false; aiSyncQuestionChips();
  aiCancel.hidden = true;
}
aiCheck.addEventListener('click', async () => {
  if (aiBusy) return;
  if (!aiTokenInput.value.trim() && !(await aiLoadToken())) {
    aiSetStatus('Paste the AI operator token first. The background HUD writes it to its log: journalctl --user -u megalodon-hud.service | grep "AI operator token".', 'warn', 'Token needed');
    aiTokenInput.focus(); return;
  }
  aiBeginBusy(aiCheck, 'Checking…');
  aiSetPhase('checking');
  aiSetStatus('Checking the configured model with one bounded local inference…', 'busy', 'Checking');
  aiStartElapsed('Still checking. Loading a local model on CPU can take a few minutes the first time.');
  let phase = 'error';
  try {
    const {response, value} = await aiFetch('/api/ai/status', 'X-Megalodon-AI-Check', null, aiDeadlineMs(1));
    if (response.status === 403) { aiVerified = false; aiSetStatus(aiTokenErrorText(value), 'error', 'Token rejected'); return; }
    if (!response.ok || value.schema !== 'megalodon-ai-status-v1') throw new Error('AI status unavailable');
    if (Number.isInteger(value.timeout_seconds)) aiTimeoutSeconds = value.timeout_seconds;
    aiVerified = value.state === 'model_ready';
    phase = aiVerified ? 'ready' : 'error';
    const drift = AI_DRIFT[value.error_code];
    // Model drift is the operator's next step, so lead with it instead of the generic safety-check line.
    const summary = drift ? `${drift.text} (${value.error_code}).`
      : `${AI_STATE_TEXT[value.state] || `Unrecognized status (${value.state}).`}${aiErrorReason(value.error_code)}`;
    aiSetStatus(`${summary} Model ${value.model || 'unknown'}. Inference verified: ${value.inference_verified === true ? 'yes' : 'no'}.`,
      drift ? 'warn' : AI_STATE_TONE[value.state] || 'error', drift ? drift.badge : AI_STATE_BADGE[value.state] || 'Not ready');
    aiShowSetupLink(value.error_code);
  } catch (err) {
    aiVerified = false;
    if (err && err.name === 'AbortError') {
      phase = 'idle';
      aiSetStatus(aiUserCanceled ? 'AI check canceled by operator.' : 'AI check timed out client-side.', 'warn', aiUserCanceled ? 'Cancelled' : 'Timed out');
    } else {
      aiSetStatus('AI check failed. Core MEGALODON remains available.', 'error', 'Check failed');
    }
  } finally { aiEndBusy(); aiSetPhase(phase); if (aiVerified) aiAsk.focus({preventScroll: true}); }
});
aiAsk.addEventListener('click', async () => {
  if (aiBusy || aiAsk.disabled) return;
  const question = aiQuestion.value;
  aiBeginBusy(aiAsk, 'Asking…');
  aiResult.hidden = true;
  aiSetPhase('asking');
  aiSetStatus('Waiting for local AI analysis (up to 10 minutes): the model picks one permitted tool, then explains its result…', 'busy', 'Thinking');
  aiStartElapsed('Still working. Local models can take several minutes on CPU; the server stops the question after 10 minutes.');
  let phase = 'ready';
  try {
    const {response, value} = await aiFetch('/api/ai/ask', 'X-Megalodon-AI-Ask', {question}, aiQuestionDeadlineMs(question));
    if (response.status === 403) { aiSetStatus(aiTokenErrorText(value), 'error', 'Token rejected'); phase = 'error'; return; }
    if (response.status === 409) { aiSetStatus('Another local operation is in progress. Try again shortly.', 'warn', 'Busy'); return; }
    if (value.error_code === 'REQUEST_TIMEOUT' && !response.ok) {
      phase = 'error';
      aiSetStatus('AI request timed out before a complete answer was returned.', 'warn', 'Timed out');
      return;
    }
    if (value.schema === 'megalodon-ai-answer-v1' && value.state === 'failed') {
      phase = 'error';
      aiSetStatus(`AI request failed.${aiErrorReason(value.error_code)}`, value.error_code === 'REQUEST_CANCELLED' ? 'warn' : 'error', 'Failed');
      aiShowSetupLink(value.error_code);
      return;
    }
    if (!response.ok || value.schema !== 'megalodon-ai-answer-v1') throw new Error('AI request unavailable');
    document.getElementById('ai-observed').textContent = value.observed === null || value.observed === undefined
      ? 'No broker output: the selected tool did not complete.' : JSON.stringify(value.observed, null, 2);
    document.getElementById('ai-inferred').textContent = value.inferred || 'No validated model explanation returned.';
    document.getElementById('ai-action-state').textContent = `Tool ${value.tool}; authority level ${value.authority_level}; state ${value.execution_state}. Reports are stored in the AI receipt ledger; no host security change is applied.`;
    document.getElementById('ai-receipt').textContent = value.receipt_id || 'No receipt';
    aiResult.hidden = false;
    if (value.error_code) {
      phase = 'error';
      aiSetStatus(`AI completed with an error.${aiErrorReason(value.error_code)}`, 'warn', 'Partial');
      aiShowSetupLink(value.error_code);
      if (value.error_code === 'AUDIT_INTEGRITY') { aiState.classList.add('ai-integrity-alert'); aiStatusBox.setAttribute('data-tone', 'error'); aiBadge.setAttribute('data-tone', 'error'); }
    } else {
      phase = 'done';
      aiSetStatus('Observed data and model inference are shown separately.', 'ok', 'Answered');
    }
  } catch (err) {
    phase = 'error';
    if (err && err.name === 'AbortError') {
      aiSetStatus(aiUserCanceled ? 'AI request canceled by operator. No partial model output is shown.' : 'AI did not return a complete answer within 10 minutes. No partial model output is shown.', 'warn', aiUserCanceled ? 'Cancelled' : 'Timed out');
    } else {
      aiSetStatus('AI request failed. No partial model output is shown.', 'error', 'Failed');
    }
  } finally { aiEndBusy(); aiSetPhase(phase); }
});
"""
