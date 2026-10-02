# Choose a local AI model

Open **Setup → Local AI · Ollama**. Choose an installed model, choose CPU or
Ollama automatic compute, set the response limit, then press **Use selected model**. MEGALODON saves the
exact installed digest and verifies one short response. **Verify selected model**
retries that check; **Refresh installed models** only reads metadata.

The same selection serves endpoint analysis in the HUD, automatic collector
advice, and the separately authorized AI broker. Selecting a model grants no
shell access, firewall permission, or automatic response authority. Existing
fixed defense workflows still require their own operator actions and OS
authorization. Models can advise about observed evidence; they cannot establish
that an address is hostile or execute their generated commands.

## Availability and compute

- Only installed, local GGUF text-completion models can be selected. Embedding
  models, cloud-backed models, invalid identifiers and changed digests are
  rejected before an evidence prompt is sent. Some installed artifacts may appear
  in the list but fail the completion-capability check when selected.
- The adapter verifies the loopback listener, exact tag digest, and `/api/show`
  local completion capabilities before each response. A loopback Ollama service
  alone does not establish that a model runs locally. Metadata replies have a
  separate 256-KiB bound because model descriptions include tensor names and
  licenses. Generated-response and protocol-framing limits remain unchanged.
- CPU is the default for short background advice. Automatic compute lets Ollama
  choose GPU use and can compete with models in other applications. Large models
  have a five-minute default response budget, adjustable from 1 to 1,800 seconds. Metadata checks retain their separate three-second budget. **Cancel AI request** interrupts MEGALODON’s current inference without stopping Ollama or capture. Context remains
  capped at 4,096 tokens and output at 256 tokens; endpoint proposals use 128.
- Responses use the model's chat template, request no thinking output, and set
  `keep_alive: 0`. Other applications can keep or reload the same model.
- The UI distinguishes installed availability, loaded allocation, a completed
  response, and the latest failed attempt. Loaded allocation includes CPU/GPU
  memory reported by Ollama; it is not MEGALODON process RSS or GPU utilization.
  Metadata refreshes are shared and cached for 30 seconds, without model inference;
  a busy provider lock is retried after two seconds.
  Actions labels a model as having a recent AI response only for five minutes
  after an accepted response while the current artifact remains available.
  After that, it shows the model as available and asks for a new verification.
  Setup displays the last accepted response and last attempt separately.
  Last-response observations are held in memory and reset on service restart;
  existing evidence and response receipts follow managed retention.

A selection is persisted even if its subsequent response verification fails;
Setup says so and offers verification again or another model. Existing installed
models are never removed or downloaded by selection. A fresh installation can
use **Configure Ollama access** for local-only listening, then choose its installed
model. This service configuration requires system authorization.

## Persistence and interfaces

The owner-private `~/.config/megalodon/qwen-profile.json` filename remains for
upgrade compatibility. New records use `megalodon-local-model-v2` with `model`,
`model_digest`, `timeout_seconds`, and `compute_mode` (`cpu` or `auto`). Existing two-field pinned
Qwen profiles and v1 profiles continue to load. Older explicitly configured timeout values remain until changed in Setup. A profile must be atomically saved before the
running selection changes. The HUD's saved selection overrides base `[ai]`
settings; standalone callers can use `compute_mode` in their AI settings.

`GET /api/support-config` adds a bounded `model` observation and up to 64 installed
model choices. Its existing header and same-origin protections apply. Closed
POST actions include `model_refresh`, `model_cancel`, and `model_select`; selection requires
`model`, `model_digest` and `compute_mode` in addition to `action`, with optional integer `timeout_seconds` (1–1,800) for older-client compatibility. The legacy
`qwen_check` action now verifies the selected model. No action accepts a provider
URL, path, prompt, shell command or arbitrary compute options. The legacy broker
continues to require its separate launch authorization token.

Original fingerprint-pinned Qwen run-count and anomaly contracts remain separate;
this selector does not silently broaden their model admission rules.

## Longer jobs and collector priority

HUD endpoint analysis, Setup verification and collector advice run in background
workers. The legacy AI status and ask interfaces remain synchronous; their
requests can take the configured model budget. Each collector can
queue one latest completed aggregate for advice; newer queued aggregates replace
older pending advice, without replacing recorded collector results. A slow model
does not delay inventory collection or report watching. Setup shows the current
request start time and its response limit. The protected cancellation action
remains available while a synchronous compatibility request owns the mutation
lock; other configuration actions still require that lock.
Shutdown cancels this process’s active provider connection. It does not kill the
Ollama daemon or change other applications’ model settings.
