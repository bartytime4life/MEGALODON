# Local AI control plane (draft, opt-in)

The installed HUD also provides [security knowledge and pattern reviews](security-knowledge.md).
Its read-only broker tools are `megalodon.knowledge.search` (one bounded query)
and `megalodon.patterns.status` (baseline coverage and four review summaries).
They confer no host authority. Automatic pattern explanations use the selected
local model and the same single-inference gate, with manual requests taking
priority over background work. Existing operator tokens and response approval
remain required for the original action routes.

The control path is `selected local model -> bounded literal-loopback adapter -> closed request
validator -> fixed tool registry -> policy -> application adapter -> private
SQLite receipt`. The model never receives a shell, executable name, SQL
statement, filesystem path, network destination, credential, or approval token
as a tool argument. Its text is advice, not evidence or authorization.

This is separate from the original fingerprint-pinned run-count Qwen advisory
and offline anomaly advisory. Those policies and their callers are unchanged.
The acceptance requirements recorded in
[#261](https://github.com/bartytime4life/MEGALODON/issues/261) cover exact provider
containment, model provenance, adversarial corpus and independent review.
An issue closure or passing doctor output does not supply that evidence. The Ollama manifest digest
below pins the locally observed tag, not publisher authenticity or the bytes
actually loaded into memory.

## Explicit configuration

`[ai]` in `config/settings.toml` defaults to `enabled = false`, provider
`ollama`, fixed endpoint `http://127.0.0.1:11434`, configured candidate tag
`qwen2.5:7b-instruct-fp16`, and observed manifest digest
`59805ce4a4046be2d8f63231a78daacd2e66f5dccf1a64d0d138ebeeb26ff16c`.
The request timeout defaults to 300 seconds and is bounded at 1,800 seconds, context at most 4096 tokens, and
output at most 256 tokens. Readiness, ordinary advice and defense requests all
set the processing batch to 64 tokens to reduce temporary GPU memory demand.
Fixed AI questions share a separate ten minute limit across tool selection and
the follow-up explanation. The HUD waits for the answer until that limit and
then shows a timeout error; the explicit model check retains its shorter client limit.
This is an [Ollama runner option](https://github.com/ollama/ollama/blob/main/api/types.go),
not a change to the context or output limit. Model and endpoint cannot come from a model reply. The protected
[Setup model selector](local-model-selection.md) can pin an installed local
completion model for the HUD and backend. Provider destination remains fixed.
CPU compute is the default; automatic compute is an explicit operator choice.

Before every inference, the adapter observes `/proc/net/tcp{,6}` and refuses
an absent, non-loopback, or inconclusive listener; it then checks the exact tag
digest using one bounded `GET /api/tags`, then checks `/api/show` for local GGUF
completion capabilities and rejects cloud model references. Inference uses one non-streaming
`POST /api/generate` on the existing literal-loopback transport with no proxy,
DNS, redirect, retry, cloud fallback or model-requested tool field. The
transport uses the existing one-slot process lock, response-framing budget,
and active deadline. A successful TCP connection or tag lookup is never
reported as `model_ready`; one bounded validated inference must complete.
The status states are `disabled`, `ollama_unavailable`, `model_missing`,
`model_available`, `model_loading`, `concurrency_unavailable`, `model_ready`,
`request_timeout`, `invalid_response`, `provider_error`, `model_not_local`, and `policy_rejection`.
`model_loading` means another request already holds the one inference slot;
`concurrency_unavailable` means MEGALODON's own local lock could not be
established (an unsupported platform or a filesystem fault), so no request
to Ollama was attempted at all.

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
The selected model selects one tool by JSON; the broker validates the selection before reading
data. A second bounded request may explain the resulting typed projection.
Unexpected tool selection and malformed model output fail closed. Tool
selections with non-string names are routed to a failed `UNKNOWN_TOOL`
receipt before evidence reads or a follow-up explanation request. Telemetry
summary accepts only `window_minutes`; the `limit` argument belongs to alerts
queries. Unsupported argument fields and non-string report types produce
`INVALID_ARGUMENTS` receipts without tool execution. Stored
traffic is limited to qualified metadata and detector IDs/severity/timestamps;
packet payloads, hashes of payloads, raw messages, raw JSON and arbitrary
evidence text are never forwarded. Source authenticity, coverage, host safety
and inference accuracy remain unproved.

## Receipts and HUD

`megalodon-ai-receipts.db` is an application-owned private SQLite database
beside the configured audit database. If the telemetry database occupies that
filename, a case-fold-equivalent alias, or one of its SQLite sidecar names
(`-wal`, `-shm`, or `-journal`), the AI ledger uses
`megalodon-ai-receipts-ledger.db` instead so telemetry can never be mistaken
for ledger state. The broker writes `not_attempted` before
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

### 1. Keep AI disabled during initial diagnostics

Run from the repository root using its already prepared Python environment;
`python` below must resolve to that environment's interpreter. Inspect the
operator-selected TOML first and keep `[ai] enabled = false` for this step.
Do not overwrite an existing configuration merely to copy an example.

```bash
python -m megalodon ai doctor --config config/settings.toml
```

The doctor honors the configured enablement flag; it never temporarily enables
AI. With AI disabled, neither its status probe nor model inventory contacts
Ollama. `model_status.state` is `disabled`, `inference_verified` is `false`, and
`model_inventory.error_code` is `DISABLED`. False model-installed/health checks
in that result mean **not verified while disabled**, not proof that the model
is absent or broken. The command exits nonzero rather than claiming readiness.

This is still **not a no-effect inventory command**: it observes local listener
and executable/device presence, attempts the fixed `nvidia-smi` and read-only
`systemctl show` diagnostics, and writes an application-owned doctor receipt
when the separate private ledger is writable. It does not install software,
edit configuration, change the firewall, or start/restart a service.

| Configuration | Provider activity from `ai doctor` |
| --- | --- |
| `enabled = false` (default) | No tag lookup or generation request. Local diagnostics and the separate doctor receipt remain. |
| `enabled = true` | An active readiness challenge through the existing listener/manifest admission, plus a tag inventory lookup. It can invoke the already operated provider; it is not a passive check. |

### 2. Review host and model evidence before enabling inference

Keep any host changes separate from MEGALODON diagnostics. Identify the actual
installation method, serving identity, effective unit/drop-ins and model-store
location. Preserve the existing service configuration and storage path; a path
from an earlier host observation is not a default for another installation.
Do not replace `override.conf` or the vendor unit wholesale. Prepare a scoped,
reviewed change and recovery plan under separate operator authority before
editing or restarting anything.

The [provider hardening guidance](qwen-provider-hardening.md) describes candidate
controls and their limitations; its examples are not an applied or accepted
configuration. A loopback listener and the doctor's
`ollama_egress_restricted` configuration hint do not prove outbound denial,
process ownership, wrapper-only access, or artifact authenticity. Missing or
inconclusive evidence remains a HOLD, not permission to relax a check.

Record the exact owner-selected model/runner/artifact binding and provenance,
provider containment, bounded lifecycle/resource behavior, signed adversarial
evaluation and independent security disposition before operational acceptance.
These decisions are separate from CI, an issue's open/closed label, a manifest
match, or a `model_ready` response. Do not publish private paths, environment
values, tokens, provider responses or local evidence in public fixtures.

### 3. Perform an explicitly authorized active check

Only after the relevant operator decisions, set `[ai] enabled = true` in the
reviewed TOML. Running the doctor again now authorizes an active readiness
probe, not just local diagnostics. There is no separate no-probe switch in this
command. A successful challenge validates the response, not provider acceptance.

To use the HUD after the same authorization, run:

```bash
python -m megalodon hud --config config/settings.toml
```

Copy the ephemeral AI token from that terminal into the Local AI control in
Investigate. **Check Ollama and Qwen** is an active inference check. Fixed
questions can also invoke Qwen; neither operation grants host or firewall
application authority.

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

## Evidence context v1 (implementation milestones 1–2)

`megalodon/ai_context.py` validates a closed application projection and builds
bounded deterministic facts. PRs #492 and #493 introduced and corrected that
pure contract. The endpoint adapter now admits committed packet/flow metadata
through it; provider acceptance, fixed-question comparisons, statement-level
answer grounding, evaluation and the native pilot remain separate milestones.

### Endpoint adapter and fallback

`endpoint_context.retained_context()` reads the preceding hour ending at the
last completed UTC second. It uses retained-reader watermarks and packet
qualification, scans at most 20,000 candidate records in pages of at most 512 records, and
selects at most 24 address-matching records. Only closed protocol/port/TCP-flag
fields and supported linked detector IDs enter the packet. Unknown fields,
free text, names, payloads, action details and raw sensor IDs are omitted.
Packet records and flow update records remain distinct; flow updates are not
unique connections. Collection groups bind an application-owned segment and
admitted interface, with no cross-segment/device identity inference. Missing
interfaces establish no interface coverage guarantee.

The pure builder does not truncate. If a selected projection exceeds its byte
or node budget, the adapter removes records from the end until it fits and sets
`coverage.truncated`. Hitting either read/selection bound also sets that flag
conservatively. Coverage always declares `incomplete_window`; source errors or
withheld malformed rows add `source_gap`. No comparison or reference-library
claim is supplied on this generic observation path. A context without qualified
protocol/detail evidence skips inference and reports `insufficient_context`.

`explain_device()` persists the measured review before its single existing
256-token inference request. The exact context supplied as E1 is also returned
to the facts view. Missing evidence avoids inference entirely. Unavailable
providers, timeout, cancellation and rejected responses preserve deterministic
facts with distinct states. The application fixes the next step to observation;
generic model output cannot select containment. The existing 4,096-byte prompt,
provider gate, manual priority and automatic hourly budget remain unchanged.

Subject, snapshot hash and selected-model settings identity bind the result.
Source units, earliest segment expiry, shortened retention and compaction are
checked before save and on later reads; a changed model invalidates its ready
answer. Re-analysis of retained endpoint reviews uses the same context. The
Defense job has a random request ID. The browser records that ID and the local
selection generation at submission, so A→B→A changes invalidate an outstanding
answer even when its content hash is unchanged. Dependency expiry is also
checked before browser rendering, and a failed status refresh hides the answer.

Only managed source-dependent review records retain rich context. The action
ledger continues to retain only a review ID and `not_attempted` action status.
Synthetic tests and inert browser checks cover this implementation; they do not
qualify any model artifact, authorize live inference, or satisfy issue #446.

`IntelligenceService.context_for_device()` is a separate read-only candidate
projection over the same retained endpoint read. It calls `build_context` with
exact reference identities returned by the validated local library and refuses
requested identities absent from that result; source availability and library
membership are checked again before return. The final source check uses a
fresh clock after library revalidation; expiry
during either read fails closed without changing the snapshot's observation time.
It reports no baseline, incompatible learned counts, expired source
dependencies, partial coverage or truncation as unavailable comparison states.
The existing learned flow counts
deduplicate updates and are never relabeled `retained_record_count`. This method
does not invoke a provider, persist a review, change a HUD question or retain
its result. The existing `explain_device()` path still supplies no comparison
or reference-library claim to inference. Richer model-answer integration,
three-mode evaluation, owner binding and acceptance remain separate.

The HUD endpoint inspector now exposes this projection through an explicit
**Read retained facts** control and the protected read-only context route.
It works independently of the Defense job, audit readiness and selected AI
provider. The view separates packet records from flow updates and displays
missing/truncated coverage, source observation age, local reference identities
and the finite unavailable-comparison reason. Read serials and selection
generations reject stale responses; visible facts refresh every five seconds
and hide on failed checks, declared expiry, inactivity or a stale check age.
No model call, review write, rich-context persistence or inference adoption
occurs through this route. Dependency revalidation is sequential and polling
has a finite observation gap; it is not independent provenance/privacy acceptance.

The inventory below was checked against
`main@b195866bc6f79594a90b7452425e95ace2c2d2e7`, the capability plan's baseline.
It describes implemented behavior rather than granting authority or replacing
the separate Airlock policies.

| Entry point | Reads and sends | Retention and effects |
| --- | --- | --- |
| `IntelligenceService.context_for_device()` | Reads the bounded retained endpoint selection, qualifies local library identities and reports unavailable comparison reasons. The HUD facts control uses its protected GET route. Sends nothing to a model. | Returns a packet without a review write or long-lived copy. Visible facts revalidate on each refresh and hide when checks fail; later callers must revalidate dependencies. |
| `IntelligenceService.explain_device()` | Reads the bounded retained endpoint selection and sends the same generic context as E1, with no comparison or library references. | Persists a managed review and dependency-aware explanation or fallback; the application fixes the workflow to observation. |
| `IntelligenceService.analyze()` / `_explain()` | A retained deterministic pattern candidate, facts, missingness, and up to three reference excerpts. Shared one-inference provider gate, manual priority, existing four-attempt automatic hourly budget. | Persists managed explanation or failure state only while dependencies remain valid; cancellation and expired sources prevent a successful retained answer. `report_context()` reads these managed reviews with dependencies. |
| `Defense._work()` fallback analysis (when intelligence is absent) | Existing endpoint projection: IP/scope/local status, packet/byte/connection counts, ports, flags, up to three names and two findings. Separate two-field answer contract. | Defense receipts retain results. A model proposal is not approval; fixed operator action routes remain separate. This broader fallback is not the new context's admission policy. |
| `ai_interface.ask()` fixed HUD/CLI questions | One model-selected permitted broker tool, then an explanation of that tool's typed result. `changed` can currently select an alert projection or review references; it does **not** guarantee a before/after comparison. | Broker persists request digest, validated arguments, outcome and result. `patterns.status` deliberately stores review IDs rather than source-expiring facts. The explanation is returned separately. `integrations.status` is explicitly a static catalog. |
| `CompanionAutomation._publish()` / `_explain()` | Completed collector aggregate counts, only when the existing companion-advice configuration allows it. Separate bounded advice queue and selected-model adapter. | Managed companion aggregate and advisory records, plus in-memory latest summaries. Advisory records currently lack an explicit originating segment dependency; their age alone is not proof of coupled expiry. Collection/host workflows have their own existing authority. |
| `advisory.preflight_advisory()` / `invoke_qwen_advisory()` | Fingerprint-pinned, closed `local-model-advisory-v1` registry, explicit model/limits, six aggregate run fields and a fixed question. | Preflight is pure; admitted invocation may use its separate literal-loopback adapter. Callers own any result persistence. No shared context extension or implicit registry approval. |
| `anomaly_advisory.preflight_anomaly_advisory()` / `invoke_qwen_anomaly_advisory()` | Separate `local-model-anomaly-advisory-v1` registry and selection pin; recomputed deterministic dossier, bounded windows and candidate IDs. | Separate output/citation admission and caller-owned result retention. This remains distinct from run-count advisory, selected-model HUD tools, and the new candidate context. |

These differences are integration work, not evidence that the new helper can
safely replace all prompts. In particular, rich context must never be copied
into the longer-lived broker ledger. The fallback's names, companion prose and
reference excerpts are **not** admitted by this candidate contract.

### Input boundary and field review

The input is a built-in Python dictionary with exactly `schema`, `subject`,
`window`, `as_of`, `sources`, `records`, `coverage`, `comparison`, and
`references`. Its schema is `megalodon-ai-context-input-v1`. No JSON parsing,
store lookup, provider access, clock read or mutation occurs in the builder.
A future JSON caller must reject duplicate keys before constructing this input.
All nested objects are closed; unknown fields are errors, not silently removed.

| Field | Candidate v1 contract |
| --- | --- |
| `subject` | One operator-selected literal IPv4/IPv6 address; normalized, with no hostname, scoped IPv6 zone or identity inference. V1 does not yet accept a finding-only or subjectless time-window selection. |
| `window`, `as_of` | UTC Unix integer seconds. Window is `{start,end}`, half-open, positive and at most 3,600 seconds; its end cannot exceed `as_of`. A reviewed caller must supply a fresh observation time. The pure builder cannot detect a replayed old clock value. |
| `sources` | At most 24 `{id,kind,expires_at}` declarations. IDs are 32 lowercase hex digits; kind is `packets`, `flows` or `baselines`. Each referenced source must exist in this input, have the matching kind, and expire strictly after `as_of`. Duplicate and unused declarations fail. This validates a dependency closure, not authenticity or actual on-disk existence. |
| `records` | At most 24 closed projected records. Required: `{ref,source,scope_id,kind,observed_at,src_ip,dst_ip,missing}`. The reference is an existing `segment:positive_record_id`, never a newly invented evidence ID. Time must be inside the selected window and the selected subject must be an endpoint. Peer addresses are used for qualification but omitted from output. |
| Source and scope | Packet source is `accepted packet metadata`; flow sources are `suricata-eve`, `zeek-conn` and `zeek-sample`. Kind must match. `scope_id` is a 32-hex opaque application identifier for the selected sensor/collection/interface scope. It is not a device identity or a payload hash. The endpoint adapter binds an admitted segment and interface; changing either changes the identifier. No raw interface label, path or command is sent. |
| Optional measured fields | `protocol`, `src_port`, `dst_port`, `tcp_flags`, `findings`. Protocols: TCP, UDP, ICMP, ICMPV6, SCTP, DNS, OTHER, UNKNOWN. Ports are integers 0–65535 and require TCP/UDP/SCTP. TCP flags are distinct members of SYN, ACK, FIN, RST, PSH, URG, ECE, CWR and require TCP. V1 excludes bytes, application/service labels, names and arbitrary metadata. |
| `missing` | Exactly the omitted optional fields, each with `not_collected`, `not_qualified` or (only for ports/flags on a known inapplicable protocol) `not_applicable`. No null or invented zero stands for missing evidence. Present and missing cannot coexist for the same field. |
| `findings` | Up to three `{id,rule}` objects per packet record, using actual linked positive numeric detection IDs and PORT_SCAN/SYN_FLOOD/DNS_TUNNELING. Output qualifies IDs with the source segment and `finding` namespace; duplicate finding IDs fail. A flow must omit this field and declare its missingness; even `findings: []` is rejected on flows because it would falsely assert a qualified absence. Flow alerts, regenerated detections, severity changes, free-text evidence and inferred incidents are outside v1. An empty qualified packet list and uncollected findings remain different. |
| `coverage` | Exactly `{truncated,missing}`: a boolean plus unique fixed codes `source_gap`, `incomplete_window`, `sensor_disagreement`, `no_qualified_records`. The last code is required exactly when the detailed record selection is empty. These describe selected evidence, not complete capture. |
| `references` | At most three `{source,edition,id}` references; source-specific edition and identifier grammar for ATT&CK, ATLAS, D3FEND, OWASP LLM and CISA KEV as listed below. The exact qualified library identity is preserved without aliases or edition rewriting. No titles, excerpts, URLs or user prose. Syntax does not prove membership; the read-only candidate adapter takes identities from the validated local library API. |

The candidate reference grammar follows the bundled library's identities:

| Source key | Edition shape and bundled example | Identifier families |
| --- | --- | --- |
| `attack` | `YYYY-MM-DD`, e.g. `2026-08-05` | Techniques/subtechniques (`T1046`, `T1071.004`) and mitigations (`M1016`). |
| `atlas` | `YYYY.MM`, e.g. `2026.09` | Techniques/subtechniques (`AML.T0051`), case studies (`AML.CS0000`) and mitigations (`AML.M0001`). |
| `d3fend` | Three numeric version components of 1–3 digits each, e.g. `1.6.0` | Alphabetic initial character followed by at most 99 letters/digits/dots/underscores/hyphens, including `NetworkTrafficAnalysis`, `ARMA_Model` and `CWE-1050`. |
| `owasp` | `YYYY`, e.g. `2026` | Two-digit LLM identifiers, e.g. `LLM01`. |
| `kev` | `YYYY.MM.DD`, e.g. `2026.10.01` | CVE identifiers, e.g. `CVE-2004-1464`. The library's source key is `kev`, not an invented `cisa-kev` alias. |

Regression tests verify the starter bundle's checked-in digest and exercise
every bundled reference identity unchanged. Edition shape validation is not a
calendar, publication, source-membership or authenticity assertion; the future
library resolver retains that responsibility. New source formats require an
explicit contract change rather than automatic acceptance of arbitrary text.

Payloads, payload-derived hashes, raw logs, credentials, command lines, paths,
URLs, arbitrary free text and executable/tool fields are rejected at every
object boundary. Only exact built-in JSON-like types are accepted, with no
custom conversion hooks. Booleans are not integers. Floating-point values,
non-ASCII/control text, deeply nested/cyclic structures and overlong values fail
with fixed `ContextError.code` strings that do not echo input.

Source declarations and qualified counts are **application assertions**. The
helper cannot authenticate fabricated but structurally valid references,
counts, scope identifiers, eligibility claims or expiry dates. A future adapter
must read these from canonical evidence under its existing admission rules;
neither model output nor arbitrary HUD JSON may supply them. This is the field
review boundary, not a general-purpose telemetry ingestion API.

### Deterministic projection and comparison

Output `megalodon-ai-context-v1` groups by `(source, kind, scope_id)` and records
the selected record count, first/last observed time and exact evidence IDs.
`packet_records` and `flow_records` remain separate. A flow update is a retained
record, **not** a newly established connection. Counts across sensors or scopes
are never added together. Ports retain their protocol and source/destination
role; flags may overlap, so their counts must not be summed as packet totals.

A histogram is emitted only when that field exists for every selected record
in the group. Otherwise fixed missing reasons replace the entire histogram;
partial observations cannot masquerade as a complete count. Qualified findings
are still retained when other rows lack finding coverage, accompanied by the
missing-finding reason. No finding is synthesized from a port, flag or reference.
No application, device identity, benign verdict or complete-capture conclusion
is generated.

`comparison` is one of these closed shapes:

- `{state:"unavailable",reason:...}` with `not_requested`, `no_baseline`,
  `incomplete_hours`, `incompatible_sources`, `source_expired` or `truncated`.
  There is no delta or implied “unchanged.”
- `{state:"available",current:[...],previous:[...]}` with one to four compatible
  groups on each side. Each supplied hourly summary is exactly
  `{ref,subject,source,scope_id,kind,start,end,count,basis,eligible}`. Its reference
  must resolve to a retained baseline segment. `basis` must explicitly be
  `retained_record_count`, count is a nonnegative safe integer, and `eligible`
  must be true. The current window must be an aligned completed UTC hour; the
  previous window is the immediately preceding full hour. Subject, source,
  measurement and scope must match across the two sides, with no duplicate
  summary IDs/groups. Each selected detail group must be covered, and its
  selected count cannot exceed the corresponding hourly count. Truncation or
  incomplete/disagreeing coverage refuses an available comparison.

The builder computes `current_count - previous_count`, retains both counts,
the prior window and both summary references, and reports **two eligible hours
per comparison group**. This is a pairwise comparison, not the existing pattern
engine's 24-hour learned baseline and not evidence of sensor completeness.
Existing flow baselines deduplicate connection updates: their `count` must not
be relabeled `retained_record_count`. Milestone 3 needs a reviewed compatible
read projection before connecting this candidate comparison to a HUD question.
An empty detailed selection can coexist with an explicitly qualified zero
hourly count; missing summaries cannot be converted to that zero.

The existing completed-hour processor now separately records
`endpoint-hour-count-v2` rows in managed `baselines` storage. These use schema
`megalodon-endpoint-hour-count-v2` and count every admitted retained update,
including repeated updates of one flow. Each endpoint is counted once per row;
source, packet/flow kind and the segment/interface scope remain separate. The
learned baseline dictionary and its deduplication rules do not consume these
rows, including after restart. Restore queries exclude count receipts before
they consume the existing learned/review row and scan quotas. No comparison, HUD question or provider input
adopts them yet.

Receipt eligibility means one aligned completed UTC hour was read to fixed
source watermarks, with no read gap, malformed row or bound exceeded. The read
is limited to 24 source units, 20,000 candidate row positions and 128 endpoint
groups, within the processor's existing work deadline and a separate eight
second work deadline. Checks occur between bounded reads; database calls are
not preempted. Every included original packet must have an admitted capture
relationship. Source watermarks, qualified packet event IDs, retention expiry and
source membership are checked again after reading. A changing, retired or
expired source withholds all summaries; an empty read does not invent zero.
The initial and final source selections include verified `packet_rollups`
replacements. Their presence withholds the whole hour as `incompatible_sources`,
including flow summaries: compacted conversations are not original retained
records and their counts are not silently substituted or omitted. An incomplete
compaction build still uses its authoritative original packet unit.
An unavailable count read preserves the existing pattern result and records a
finite `endpoint_counts` state in its hour-coverage row. A failed count write
does not advance the hour checkpoint.

Each count receipt retains its read digest, source watermarks, declared source
expiry, `as_of` and original source dependencies. `capture_complete` is always
false: a complete traversal of retained qualified records does not prove
continuous collection, full traffic visibility or device identity. Stable IDs
identify a repeated identical snapshot; an interrupted retry may retain more
than one physical row, so a future consumer must deduplicate IDs and must never
sum repeated receipts. Changed snapshots have different IDs and require an
explicit selection rule. Source checks and later persistence are sequential,
with a finite race interval. Future comparison admission must revalidate raw
sources, summary source units, expiry, compatible scopes and exactly two hours;
receipt shape or a stored `eligible` flag alone is insufficient.
Segment rotation changes scope identity; cross-segment comparisons remain
incompatible until a separately reviewed scope-continuity contract exists.

Historical `endpoint-hour-count-v1` receipts remain stored as history. Their
producer could omit compacted packets while returning eligible flow counts;
future comparison admission must reject that version. Repaired v2 read digests
bind the schema and generate distinct logical IDs. Restore excludes both v1
and v2 count sources from learned/review quotas; neither version is adopted
into a learned baseline, HUD comparison or provider input by this change.

### Budgets, binding and lifetime

Input is capped at 32,768 canonical ASCII JSON bytes, 2,048 visited values,
depth eight, bounded containers and 128-character strings. Integer counts are
at most `2**53 - 1`. Output including `snapshot_sha256` is capped at **3,072
bytes**, reserving at least 1,024 bytes for instructions within the existing
4,096-byte prompt. Twenty-four records are an upper bound, not a guarantee that
every combination fits. An oversized projection raises `CONTEXT_TOO_LARGE`;
the builder neither widens a limit nor silently discards measurements. The endpoint
caller also checks the complete composed prompt.

Canonical JSON uses sorted object keys, compact separators and ASCII escaping;
sets of records, groups, references and dependencies have deterministic order.
`snapshot_sha256` hashes the full output before that field is added. It binds
the projected content and dependency declarations, **not** source authenticity,
the full original records, loaded model bytes, or a request-generation token.
Input dictionaries/lists are never mutated or retained by reference in output.

Runtime integration must bind the selected subject, snapshot hash, exact model
identity and a separate request-generation token. A-to-B-to-A selections can
produce the same content hash; that alone cannot reject an old request. Sources
and library editions must be revalidated before inference, display and saving.
Retained explanations belong only in managed dependency-aware storage and must
expire with their sources. Do not put this packet or rich explanations into
the broker's longer-lived receipt ledger. Core facts must survive provider
failure, cancellation, timeout, invalid output and unavailable context.

### Qualification preparation and next delivery gate

The existing [issue #446 owner-decision packet](qwen-446-owner-decision-packet.md)
remains the evidence register. `config/model-bindings/qwen.unbound.json` is
still **UNBOUND**. Its historical Ollama/tag observations are not fresh provider
inspection. No model is selected, pulled, invoked, reconfigured or restarted
by this change; no private telemetry is used. The exact provider build, artifact
component hashes/provenance, template/quantization, effective no-cloud settings,
outbound-denial evidence, resource/cancellation qualification, independent
review and owner acceptance remain **NOT_RECORDED / NOT_RUN**, as applicable.

Preparation for the later three-mode evaluation is recorded here so passing
contract tests cannot be mistaken for model benefit:

| Case class | Current synthetic contract evidence | Later evaluation evidence still needed |
| --- | --- | --- |
| Ordinary backups, updates, health checks; benign port changes | Typed observations and port counts remain observations without an application or threat verdict. | Identical frozen cases in deterministic template, existing model context and richer context modes; held-out cases separate from tuning. |
| Positive detector fixtures | Supplied linked deterministic finding IDs/rules survive; unknown rules and extra fields are rejected. | Statement-level citation membership plus independently assessed semantic support, unsupported claims and operator usefulness. |
| Missing/stale/truncated evidence and sensor disagreement | Explicit missing reasons; expired dependencies and incompatible/partial comparisons are refused. | Correct answer/abstention/rejection/timeout/cancellation/unavailable states, source retirement, report expiry and preserved core reads. |
| Injection, prohibited fields, fabricated references | Closed keys and bounded identifier syntax; no model or tool execution. Structural reference checks do not prove source membership. | Frozen adversarial corpus and denominators for unknown IDs, privacy leakage and accepted/displayed failures, separately from raw attempts. |
| Resource limits and cancellation | Input/output/cardinality limits and no-effect sentinels exercise the pure builder. | p50/p95 provider latency, memory, timeout/cancellation behavior and recording impact on the owner-selected host. No numeric improvement or resource acceptance claim yet. |

The next review is this contract, its field/privacy choices, scope identity,
count semantics, dependency validation and synthetic tests. Subsequent draft
changes add endpoint projection/fallback (described above), truthful fixed-question
comparisons, grounded answer/UI/report integration, and the offline three-mode
harness in the plan's order. That review must precede model runtime wiring.
The native pilot, operational inference on private metadata, owner binding,
independent acceptance, merge, release and deployment retain their separate
gates. No test result here supplies those decisions.
