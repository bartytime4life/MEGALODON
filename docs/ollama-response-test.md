# Connect and test an installed Ollama model

Setup → Local AI distinguishes Ollama connection from acceptance of AI
analysis. **Refresh installed models**, choose a local model and compute mode,
**Save model**, then **Test selected model**. Changes must be saved before
testing. The test runs off the HTTP request thread; collection continues.
**Cancel model test** stays available while it runs. Viewing, polling, startup
and keep-ready never start this test.

This is one explicit fixed diagnostic, including while the release is
`UNBOUND`. It sends only:

> Reply with exactly READY and nothing else. Do not add punctuation.

No user prompt, network observations, audit data, personal paths, tools or model
output can become test input. The protected same-origin/operator-token route
accepts only `{"action":"model_test"}` or `{"action":"model_test_cancel"}`.
It accepts no URL, model name, digest, endpoint, prompt, options or command.
The model and compute preference come from the server's saved selection.

The provider validates disabled state and settings before effects, admits only
the compiled literal `127.0.0.1:11434` transport, and refuses unknown, unavailable
or wildcard listener posture. It rechecks the selected tag/digest around model
metadata and again after the reply. Metadata must identify a local GGUF model
with text completion; remote-host/model declarations are rejected. These are
provider observations, not publisher authentication or loaded-byte attestation.

The internal transport exception admits only exact request bodies for tag GET,
selected-model show POST and the compiled diagnostic generate POST. A different
prompt, model, endpoint, method, path, option, lease, tool or request shape is
rejected before connection. Ordinary requests without the explicit test
descriptor retain their UNBOUND denial, including an otherwise identical body.
This revises only deliberate response testing; historical #704/#446 zero-effect
evidence retains its original source and scope.

The test uses a 512-token context, 32 generated tokens, deterministic sampling,
the saved CPU/automatic compute choice, and a 60-second Ollama idle lease. It
may load the selected model. The client deadline is the saved response limit,
capped at five minutes. It shares the existing one-generation slot and private
cross-process request lock, bounded framing/body parser, deadline guard and
client-side cancellation. It neither pulls weights nor changes/stops Ollama or
another service. Cancellation aborts this client's request; it does not prove
that a shared daemon immediately stops its computation. Native kernel stalls,
provider process containment and resource exhaustion remain separate concerns.

Only a normally completed response for the exact requested model, containing
the literal READY result and a still-matching tag, passes. Errors are fixed
codes and bounded explanations. The app retains result state, selected model,
compute choice, times and duration in memory for this launch. It does not retain
raw output, update the operational response-observation cache, create a binding,
claim loaded-byte identity, or write telemetry/audit records. Changing the model,
digest, compute mode or enabled state invalidates this test result.

**Passed means the fixed local response test completed.** It does not accept
the model for live-analysis prompts, detector decisions, collector advice,
broker tools, model keep-ready workers or firewall actions. Those paths remain
release-fenced under `local_model_runtime` and its existing acceptance evidence.

The supporting-app indicator reports Ollama reachability/observed process
presence separately from the AI hold. A valid explicit catalog read and a
currently observed installed/running Ollama process can show a green presence
indicator with **Ollama connected · AI analysis paused**. It never says a recent
AI response or operational readiness was verified by that read. Stale heartbeat
reads still become unknown. The connection timestamp is the installed-list
check time, not continuous HTTP monitoring; an observed stopped/unknown process
does not receive that green override. A failed explicit list refresh clears the
prior connection result.

Tests cover fixed-shape refusal before effects, default UNBOUND/disabled denials,
model/digest/cloud/capability changes, invalid responses, cancellation before and
during work, native Linux loopback requests with the real transport guard and
process lock, and protected UI/action behavior. Inert fixture replies do not
establish an actual installed-model response; that remains an explicit operator
test after installation.
