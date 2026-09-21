# Local AI control plane (draft, opt-in)

The control path is `Qwen -> bounded literal-loopback adapter -> closed request
validator -> fixed tool registry -> policy -> application adapter -> private
SQLite receipt`. The model never receives a shell, executable name, SQL
statement, filesystem path, network destination, credential, or approval token
as a tool argument. Its text is advice, not evidence or authorization.

This is separate from the original fingerprint-pinned run-count Qwen advisory
and offline anomaly advisory. Those policies and their callers are unchanged.
Issue [#261](https://github.com/bartytime4life/MEGALODON/issues/261) still
requires exact provider containment, model provenance, adversarial corpus and
independent review before operational acceptance. The Ollama manifest digest
below pins the locally observed tag, not publisher authenticity or the bytes
actually loaded into memory.

## Explicit configuration

`[ai]` in `config/settings.toml` defaults to `enabled = false`, provider
`ollama`, fixed endpoint `http://127.0.0.1:11434`, installed tag
`qwen2.5:7b-instruct-fp16`, and observed manifest digest
`59805ce4a4046be2d8f63231a78daacd2e66f5dccf1a64d0d138ebeeb26ff16c`.
The request timeout is at most 15 seconds, context at most 4096 tokens, and
output at most 256 tokens. Model and endpoint cannot come from a model reply or
HTTP request. Changing the TOML pin requires an operator edit and review.

Before every inference, the adapter observes `/proc/net/tcp{,6}` and refuses
an absent, non-loopback, or inconclusive listener; it then checks the exact tag
digest using one bounded `GET /api/tags`. Inference uses one non-streaming
`POST /api/generate` on the existing literal-loopback transport with no proxy,
DNS, redirect, retry, cloud fallback or model-requested tool field. The
transport uses the existing one-slot process lock, response-framing budget,
and active deadline. A successful TCP connection or tag lookup is never
reported as `model_ready`; one bounded validated inference must complete.
The status states are `disabled`, `ollama_unavailable`, `model_missing`,
`model_available`, `model_loading`, `model_ready`, `request_timeout`,
`invalid_response`, and `policy_rejection`.

## Tool and authority contract

Every request is a JSON object with exactly `tool`, `arguments`, and `reason`.
The full request is capped at 2048 bytes. Tool results and receipt events are
capped at 8192 bytes. Arguments have closed per-tool schemas; unknown fields,
commands, URLs, paths, wildcards, oversized values and unsupported destinations
are refused. The broker stores a SHA-256 digest of the model request, not a raw
prompt. Durations and fixed error codes accompany durable state transitions.

| Level | Tools | Result |
| --- | --- | --- |
| 0 observe | `megalodon.status`, `megalodon.telemetry.summary`, `megalodon.alerts.query`, `megalodon.integrations.status`, `megalodon.model.status`, `megalodon.action.status` | Read a bounded projection and record `observed`. Integration status is a static catalog, not an installed or connected claim. |
| 1 bounded application action | `megalodon.report.generate` | Generate one small metadata-only report inside the AI receipt ledger; record `applied`. No external file or host control is changed. |
| 2 operator-confirmed proposal | `megalodon.firewall.block.plan` | Validate one global IP against the configured allowlist, require a 60–3600 second duration, record `awaiting_confirmation`, and display exact parameters, effect, risk, rollback and expiry. There is **no apply route**, even after a confirmation. |
| 3 prohibited | shell, sudo, arbitrary subprocess, filesystem, package, network destination, credential, policy edit, audit edit, firewall apply | Reject unknown tool or field with a `failed` receipt. |

The current HUD offers fixed question IDs and permits only the Level 0 tools
listed for each question, plus the Level 1 report tool for the report question.
Qwen selects one tool by JSON; the broker validates the selection before reading
data. A second bounded request may explain the resulting typed projection.
Unexpected tool selection and malformed model output fail closed. Stored
traffic is limited to qualified metadata and detector IDs/severity/timestamps;
packet payloads, hashes of payloads, raw messages, raw JSON and arbitrary
evidence text are never forwarded. Source authenticity, coverage, host safety
and inference accuracy remain unproved.

## Receipts and HUD

`megalodon-ai-receipts.db` is an application-owned private SQLite database
beside the configured audit database. If the telemetry database occupies that
filename or one of its SQLite sidecar names (`-wal`, `-shm`, or `-journal`),
the AI ledger uses `megalodon-ai-receipts-ledger.db` instead so telemetry can
never be mistaken for ledger state. The broker writes `not_attempted` before
execution, then a terminal event (`observed`, `applied`, `failed`, or
`awaiting_confirmation`). Events contain UUID, UTC timestamp, model, request
digest, tool, validated arguments, authority level, authorization source,
state, bounded result/error, duration and finding references. Each event hashes
the previous event hash and its own canonical content. This is a local
integrity chain against a trusted checkpoint, **not** a signature or protection
against someone who can rewrite the database and its head.
Action-status lookups now verify the retained sequence, canonical payloads,
hash links, and receipt state transitions before returning a stored state. A
broken chain returns `AUDIT_INTEGRITY`; an interrupted request remains
`not_attempted`, never a completed action. `ReceiptStore.verify_chain()` also
returns the current sequence and head for comparison with an independently
retained head. Without that external checkpoint, a complete rewrite of the
database and its hashes remains undetectable.

`GET /api/ai/status` requires `X-Megalodon-AI-Check: 1` plus the per-launch
operator token and performs one
explicit local inference check. It is never polled automatically. The HUD
question route is `POST /api/ai/ask` with a body of exactly one fixed question
ID. It requires the per-launch token printed in the HUD terminal, exact
same-origin `Origin`, exact bound `Host`, JSON content type, and a body no larger
than 256 bytes. The token is held in memory and is not persisted or placed in
the served JavaScript. The HUD separates OBSERVED broker output from INFERRED
model text and displays the operation state and receipt ID. No browser request
can apply firewall changes or choose an arbitrary executable, file or URL.

## Operator setup and checks

1. Run `.venv312/bin/python -m megalodon ai doctor --config config/settings.toml`.
   It does not change systemd, the firewall or packages. It creates only an
   application-owned doctor receipt when the private ledger is writable.
2. Correct any non-loopback Ollama bind in the existing systemd override under
   operator/root authority, preserving `OLLAMA_MODELS`. On the inspected host,
   the following explicit operator command narrows both inbound and outbound
   network access without moving model storage:

   ```bash
   cat <<'EOF' | sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null
   [Service]
   Environment="OLLAMA_HOST=127.0.0.1:11434"
   Environment="OLLAMA_MODELS=/var/snap/ollama/common/models"
   IPAddressDeny=any
   IPAddressAllow=127.0.0.0/8 ::1/128
   EOF
   sudo systemctl daemon-reload
   sudo systemctl restart ollama
   ```

   Confirm effective `systemctl show ollama -p IPAddressDeny -p IPAddressAllow
   -p Environment` and `ss -lntp '( sport = :11434 )'` before enabling AI.
   The provider process still needs separate filesystem/resource review.
3. Review the exact local model manifest and provenance; then set `[ai]
   enabled = true` in the operator-selected TOML file.
4. Run `.venv312/bin/python -m megalodon hud --config config/settings.toml`.
   Copy the ephemeral AI token from that terminal into the Local AI control in
   Investigate. Click **Check Ollama and Qwen**, then choose a fixed question.

For a CLI tool request, pass one closed JSON object to `megalodon ai tool
--request '...'`. The CLI is operator-invoked; it is not a shell tool exposed to
Qwen. `ai ask --question seeing` runs the same two-stage model/broker path.
All commands fail without affecting core capture, detection or ordinary HUD
reads when Ollama is missing, slow or refused.

## Remaining gates

This draft does not configure the separately operated Ollama service, prove
outbound denial or loaded artifact authenticity, prove GPU acceleration,
install packages, expose the HUD remotely, authenticate an external identity,
restore live firewall application, deploy, release or merge. Level 2 execution
requires a separate exact-action operator approval mechanism and the existing
firewall restoration gate; no model or CLI confirmation can bypass it.
