"""Explicit, bounded local AI controls for the Investigate workspace."""

AI_PANEL = """
  <details class="panel ai-control" id="ai-control" aria-labelledby="ai-control-title">
    <summary><span><strong id="ai-control-title">Local AI control</strong><small>Ask Qwen about bounded MEGALODON metadata after a live model check.</small></span><span class="summary-action" id="ai-control-action">Open AI controls</span></summary>
    <p>Model output is advice. Tool selection passes through MEGALODON policy and every attempt gets an audit receipt. This HUD offers bounded reads and report snapshots; firewall application remains unavailable.</p>
    <div class="ai-controls">
      <button id="ai-check" type="button">Check Ollama and Qwen</button>
      <label class="field" for="ai-token"><span>Operator token from the HUD terminal</span>
        <span class="token-field">
          <input id="ai-token" type="password" autocomplete="off" spellcheck="false" maxlength="64">
          <button id="ai-token-toggle" type="button" aria-pressed="false">Show</button>
        </span>
      </label>
      <label class="field" for="ai-question"><span>Question</span><select id="ai-question">
        <option value="seeing">What is MEGALODON seeing?</option>
        <option value="changed">What changed during the last hour?</option>
        <option value="alerts">Why are recent alerts present?</option>
        <option value="integrations">Which integrations are available?</option>
        <option value="model">Is Ollama healthy?</option>
        <option value="safe">What can be safely fixed?</option>
        <option value="plan">Prepare a remediation plan</option>
        <option value="report">Generate a security summary report</option>
      </select></label>
      <button id="ai-ask" type="button" disabled>Ask locally</button>
      <button id="ai-cancel" class="button-secondary" type="button" hidden>Cancel</button>
    </div>
    <p id="ai-state" role="status" aria-live="polite">AI has not been checked. It is disabled until configured and verified.</p>
    <dl class="ai-result" id="ai-result" hidden>
      <div><dt>OBSERVED · broker output</dt><dd><pre id="ai-observed"></pre></dd></div>
      <div><dt>INFERRED · Qwen advice</dt><dd id="ai-inferred"></dd></div>
      <div><dt>PROPOSED / APPROVED / APPLIED</dt><dd id="ai-action-state">No host action requested or approved.</dd></div>
      <div><dt>Receipt</dt><dd id="ai-receipt"></dd></div>
    </dl>
  </details>
"""

AI_CSS = """
.ai-control { margin: 0 0 18px; }
.ai-control > p { margin: 14px 20px; color: var(--muted); font-size: .84rem; line-height: 1.5; }
.ai-controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: end; padding: 4px 20px 14px; }
.ai-controls .field { min-width: min(100%, 280px); flex: 1; }
.token-field { display: flex; gap: 6px; }
.token-field input { flex: 1; min-width: 0; }
.token-field button { padding: 0 10px; white-space: nowrap; min-width: auto; }
.ai-result { display: grid; gap: 12px; margin: 0 20px 20px; }
.ai-result div { min-width: 0; border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
.ai-result dt { color: var(--amber); font-size: .75rem; font-weight: 700; }
.ai-result dd { margin: 6px 0 0; overflow-wrap: anywhere; line-height: 1.5; }
.ai-result pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; font: inherit; }
#ai-state.ai-integrity-alert { color: var(--rose); font-weight: 700; }
"""

AI_JS = r"""
const aiCheck = document.getElementById('ai-check');
const aiAsk = document.getElementById('ai-ask');
const aiState = document.getElementById('ai-state');
const aiResult = document.getElementById('ai-result');
const aiTokenInput = document.getElementById('ai-token');
const aiTokenToggle = document.getElementById('ai-token-toggle');
const aiCancel = document.getElementById('ai-cancel');
let aiBusy = false;
let aiActiveController = null;
let aiUserCanceled = false;
const AI_STATE_TEXT = {
  disabled: 'Local AI is turned off in configuration.',
  ollama_unavailable: 'Ollama is not reachable on loopback.',
  model_missing: 'The configured Qwen model is not installed in Ollama.',
  model_available: 'The model tag is present but has not completed a live inference check.',
  model_loading: 'The model is busy or still starting, so the readiness check did not complete.',
  model_ready: 'The model completed a live bounded inference check.',
  request_timeout: 'The request to Ollama timed out.',
  invalid_response: 'Ollama returned a response MEGALODON could not validate.',
  policy_rejection: 'The current configuration or model identity fails a fixed safety check.',
};
const AI_ERROR_TEXT = {
  CONCURRENCY_LIMIT_REACHED: 'another AI request is already using the one local inference slot',
  CONCURRENCY_CONTROL_UNAVAILABLE: 'the local concurrency lock could not be acquired',
  MODEL_MISMATCH: 'the installed model digest does not match the pinned configuration',
  REQUEST_TOO_LARGE: 'the request exceeded a fixed size limit',
  AUDIT_INTEGRITY: 'the local receipt ledger failed an integrity check',
  UNKNOWN_TOOL: 'the model selected a tool outside the permitted list',
  UNKNOWN_QUESTION: 'the question was not one of the fixed HUD questions',
  INVALID_ARGUMENTS: 'the request arguments failed validation',
  EVIDENCE_INVALID: 'the evidence returned by a tool failed validation',
};
function aiErrorReason(code) {
  if (!code) return '';
  return ` Reason: ${AI_ERROR_TEXT[code] || code} (${code}).`;
}
aiTokenToggle.addEventListener('click', () => {
  const showing = aiTokenInput.type === 'text';
  aiTokenInput.type = showing ? 'password' : 'text';
  aiTokenToggle.textContent = showing ? 'Show' : 'Hide';
  aiTokenToggle.setAttribute('aria-pressed', String(!showing));
});
document.getElementById('ai-control').addEventListener('toggle', event => {
  document.getElementById('ai-control-action').textContent = event.currentTarget.open ? 'Close AI controls' : 'Open AI controls';
});
aiCancel.addEventListener('click', () => { aiUserCanceled = true; if (aiActiveController) aiActiveController.abort(); });
async function aiFetch(path, header, body = null) {
  const controller = new AbortController();
  aiActiveController = controller;
  const timer = setTimeout(() => controller.abort(), 50000);
  const options = {headers: {[header]: '1', 'X-Megalodon-AI-Token': document.getElementById('ai-token').value},
                   cache: 'no-store', credentials: 'omit', signal: controller.signal};
  try {
  if (body !== null) {
    options.method = 'POST'; options.body = JSON.stringify(body);
    options.headers = {'X-Megalodon-AI-Token': document.getElementById('ai-token').value,
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
aiCheck.addEventListener('click', async () => {
  if (aiBusy) return;
  aiBusy = true; aiUserCanceled = false; aiCheck.disabled = true; aiAsk.disabled = true;
  aiCheck.textContent = 'Checking…'; aiCancel.hidden = false;
  aiState.classList.remove('ai-integrity-alert');
  aiState.textContent = 'Checking the configured model with one bounded local inference…';
  try {
    const {response, value} = await aiFetch('/api/ai/status', 'X-Megalodon-AI-Check');
    if (!response.ok || value.schema !== 'megalodon-ai-status-v1') throw new Error('AI status unavailable');
    const summary = AI_STATE_TEXT[value.state] || `Unrecognized status (${value.state}).`;
    aiState.textContent = `${summary}${aiErrorReason(value.error_code)} Model ${value.model || 'unknown'}. Inference verified: ${value.inference_verified === true ? 'yes' : 'no'}.`;
    aiAsk.disabled = value.state !== 'model_ready';
  } catch (err) {
    aiState.textContent = err && err.name === 'AbortError'
      ? (aiUserCanceled ? 'AI check canceled by operator.' : 'AI check timed out client-side.')
      : 'AI check failed. Core MEGALODON remains available.';
  } finally { aiBusy = false; aiCheck.disabled = false; aiCheck.textContent = 'Check Ollama and Qwen'; aiCancel.hidden = true; }
});
aiAsk.addEventListener('click', async () => {
  if (aiBusy || aiAsk.disabled) return;
  aiBusy = true; aiUserCanceled = false; aiAsk.disabled = true; aiResult.hidden = true;
  aiAsk.textContent = 'Asking…'; aiCancel.hidden = false;
  aiState.classList.remove('ai-integrity-alert');
  aiState.textContent = 'Requesting one bounded local analysis…';
  try {
    const question = document.getElementById('ai-question').value;
    const {response, value} = await aiFetch('/api/ai/ask', 'X-Megalodon-AI-Ask', {question});
    if (!response.ok || value.schema !== 'megalodon-ai-answer-v1') throw new Error('AI request unavailable');
    document.getElementById('ai-observed').textContent = JSON.stringify(value.observed, null, 2);
    document.getElementById('ai-inferred').textContent = value.inferred || 'No validated model explanation returned.';
    document.getElementById('ai-action-state').textContent = `Tool ${value.tool}; authority level ${value.authority_level}; state ${value.execution_state}. Reports are stored in the AI receipt ledger; no host security change is applied.`;
    document.getElementById('ai-receipt').textContent = value.receipt_id || 'No receipt';
    aiResult.hidden = false;
    if (value.error_code) {
      aiState.textContent = `AI completed with an error.${aiErrorReason(value.error_code)}`;
      if (value.error_code === 'AUDIT_INTEGRITY') aiState.classList.add('ai-integrity-alert');
    } else {
      aiState.textContent = 'Observed data and model inference are shown separately.';
    }
  } catch (err) {
    aiState.textContent = err && err.name === 'AbortError'
      ? (aiUserCanceled ? 'AI request canceled by operator. No partial model output is shown.' : 'AI request timed out client-side. No partial model output is shown.')
      : 'AI request failed. No partial model output is shown.';
  } finally { aiBusy = false; aiAsk.disabled = false; aiAsk.textContent = 'Ask locally'; aiCancel.hidden = true; }
});
"""
