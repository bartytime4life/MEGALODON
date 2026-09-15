# MEGALODON Automation Contract

**Status:** Stage 0 data contract implemented; scheduler and execution design proposed  
**Date:** 2026-09-08  
**Audience:** MEGALODON maintainers, reviewers, operators, and future scheduler implementers  
**Repository baseline:** [bartytime4life/MEGALODON](https://github.com/bartytime4life/MEGALODON) at ec53f5968e498b1ebee00b11119b216ba1812699

> This document turns the attached Pasted markdown.md seed analysis into a reviewable contract for a future scheduling and execution subsystem. It does not claim that a scheduler, model runner, automation API, or automation database table exists today. No firewall action, remote dashboard exposure, or autonomous response is authorized by this document.

## Implemented Stage 0 boundary

The repository now carries a [draft JSON Schema and deterministic fixtures](../contracts/automation/v1/README.md)
for the create payload, activation prerequisites, bounded policy, and immutable
run-snapshot shape. This is contract evidence only. It adds no scheduler loop,
recurrence calculation, persistence, model invocation, CLI/API operation,
network access, shell access, or firewall authority. The overall design remains
proposed; later stages require separate review.

| Layer | Current state | What that state proves |
| --- | --- | --- |
| Stage 0 schema, fixtures, and tests | Implemented on `main` | Closed structural shapes and fixed no-network/no-firewall authority |
| Recurrence semantics and parser | Proposed | Design requirements only; no occurrence calculation |
| Ledger, scheduler, and jobs | Proposed | No tables, claims, worker loop, retries, or execution |
| Model/output adapters and actions | Proposed and separately gated | No model call, publication, external side effect, or response authority |


## Executive decision

The attached analysis correctly identifies the first three values needed to describe an automation:

1. a human-readable name;
2. an instruction-bearing prompt; and
3. an iCalendar rrule describing recurrence.

Those fields are not sufficient to execute a reliable security automation. A production-safe contract also needs an explicit recurrence anchor and time-zone policy, a resolved model and storage target, a lifecycle state, an immutable run snapshot, an idempotency key, bounded execution controls, and an audit record.

The proposed compatibility rule is:

- **Create-time minimum:** accept name, prompt, and rrule as the smallest useful input shape.
- **Activation-time minimum:** require a validated dtstart, an IANA schedule_timezone, a resolvable model_id, a permitted folder_id or controlled default, and bounded execution policy.
- **Run-time minimum:** snapshot the effective prompt, schedule revision, model, storage target, and policy before execution. A later edit must not change the meaning of a run that has already been claimed.
- **MEGALODON safety rule:** the first implementation may schedule observation, replay, retention, and report jobs, but it must not grant an automation direct firewall mutation or arbitrary shell/tool access.

## 1. Source interpretation and authority

The attached file is a prior response that interprets an Automation entity with fields including name, prompt, rrule, model_id, folder_id, status, created_at, updated_at, and runs. It is useful as a requirements seed, but it is not a normative schema or API contract: it does not define identifiers, time zones, recurrence anchors, validation errors, retry behavior, concurrency, authorization, retention, or the boundary between model output and system action.

The current repository is a small local-first network-defense MVP. Its adopted documents define an observe-only default, metadata-only events, fixed detections, SQLite audit storage, an explicit firewall plan/application boundary, a loopback dashboard, and fail-closed behavior for unsafe response:

- [README.md](../README.md) describes the current commands, storage, and safety defaults.
- [SPECIFICATION.md](../SPECIFICATION.md) defines the current MVP data contracts, action statuses, and non-goals.
- [SECURITY_REVIEW.md](../SECURITY_REVIEW.md) identifies the remaining production gates, including rollback, privilege, dashboard authentication, feed policy, and false-positive measurement.

The current main snapshot does not contain an automation table, scheduler, model adapter, folder service, RRULE parser, or automation API. This contract is therefore a proposal for a future slice, not a statement of current implementation.

## 2. Why the seed fields need expansion

| Seed field | Useful meaning | Missing decision that blocks safe execution |
| --- | --- | --- |
| name | Human-facing label | Uniqueness, length, control-character policy, and whether it is mutable |
| prompt | Task instructions | Trust boundary, size, versioning, dynamic-data separation, output contract, and secret handling |
| rrule | Recurrence pattern | Start instant, IANA time zone, DST behavior, allowed frequency, end condition, and canonicalization |
| model_id | Model selection | Registry ownership, availability, capability limits, version pinning, and fallback behavior |
| folder_id | Output organization | Logical-vs-filesystem meaning, authorization, default target, retention, and path-traversal prevention |
| status | Automation lifecycle | Legal states, transitions, who may change them, and what happens to already claimed runs |
| created_at / updated_at | Record timestamps | UTC representation, clock assumptions, revision ordering, and optimistic concurrency |
| runs | Execution history | Immutable snapshots, occurrence identity, attempt history, output limits, error taxonomy, and audit retention |

The most important omission is the recurrence anchor. [RFC 5545](https://datatracker.ietf.org/doc/html/rfc5545) defines DTSTART as the first instance used to build a recurrence set; an RRULE without a defined start and time-zone interpretation cannot produce a stable schedule. The second major omission is run identity: a mutable automation row is not enough to explain what prompt, model, and policy actually produced a historical output.

## 3. Goals and non-goals

### Goals

- Represent recurring work using a standard recurrence grammar rather than inventing a cron dialect.
- Make every scheduled occurrence deterministic, deduplicated, bounded, and inspectable.
- Keep model execution subordinate to application policy and least privilege.
- Preserve the exact effective inputs and policy needed to reproduce or explain a run.
- Reuse MEGALODON's existing fail-closed, metadata-only, local-first posture.
- Give maintainers a staged path from schema fixtures to read-only scheduling before any higher-risk action is considered.

### Non-goals for the first automation slice

- No arbitrary Python, shell, SQL, HTTP, browser, or firewall command execution from a prompt.
- No automatic permanent blocks, route changes, DNS changes, service changes, or kernel changes.
- No remote multi-user automation API before authentication, authorization, CSRF protection, and audit review exist.
- No assumption that a model's text output is evidence, authorization, or a successful action.
- No promise of exactly-once external side effects. The first contract provides at-most-once claim semantics locally and requires idempotency for any later external adapter.
- No unbounded prompt, output, retry, recurrence, or run-history growth.

## 4. Terminology

- **Automation:** The mutable user-owned definition: instructions, schedule, policy references, and lifecycle state.
- **Occurrence:** One scheduled point in the recurrence set, identified by the automation revision and its scheduled instant.
- **Run:** The immutable execution record for one occurrence and its attempts.
- **Attempt:** One execution try inside a run. Retries must not create a second logical occurrence.
- **Model registry:** An application-owned mapping from a stable model_id to a permitted local or remote adapter. The prompt cannot select an arbitrary endpoint.
- **Folder:** A logical, authorization-checked destination for outputs and reports. It is not a raw filesystem path supplied to a command.
- **Policy snapshot:** The effective limits and permissions used by a run, including timeout, output size, retry, tool, and data-sharing rules.

## 5. Canonical data model

The following is the proposed v1 contract. Names may be mapped to Python dataclasses or SQLite columns, but the semantics must remain stable.

### 5.1 Automation

| Field | Type | Required | Contract |
| --- | --- | --- | --- |
| id | opaque string/UUID | system | Stable identifier; never derived from name and never reused |
| name | string | create | 1–120 Unicode characters; reject control characters and surrounding-only whitespace |
| prompt | string | create | Bounded instruction text; stored as user data and never granted privileges |
| rrule | string | create | Bare RFC 5545 recurrence rule, canonicalized with FREQ first; an RRULE prefix may be accepted at the edge and removed on storage |
| dtstart | RFC 3339 timestamp or local date-time plus zone | activation | First occurrence anchor; must be synchronized with the rule |
| schedule_timezone | IANA zone name | activation | Explicit schedule basis such as UTC or America/Chicago; fixed offsets alone are insufficient for DST-aware local schedules |
| dst_policy | enum | activation for non-UTC | One of reject, skip, shift_forward, fold_earlier, or fold_later; v1 default is reject until chosen explicitly |
| model_id | registry key | resolved | Optional at create edge only when a safe project default exists; always resolved and snapshotted before activation/run |
| folder_id | logical destination key | resolved | Optional at create edge only when a safe project default exists; never a raw path or arbitrary URL |
| status | enum | system | draft, active, paused, disabled, or archived; new records start draft |
| revision | positive integer | system | Incremented on semantic edits; used for optimistic concurrency and run snapshots |
| next_run_at | UTC RFC 3339 timestamp | system | Derived cache, not the sole source of truth; recomputed from the active revision |
| last_run_at | UTC RFC 3339 timestamp/null | system | Last terminal run time, not last attempt time |
| timeout_seconds | positive integer | resolved | Hard upper bound for one attempt; must be capped by application policy |
| max_output_bytes | positive integer | resolved | Output cap applied before persistence or publication |
| retry_max_attempts | bounded integer | resolved | Includes the first attempt; only transient failures may retry |
| concurrency_policy | enum | resolved | v1 default skip_if_running; alternatives require explicit review |
| created_at | UTC RFC 3339 timestamp | system | Immutable creation instant |
| updated_at | UTC RFC 3339 timestamp | system | Last successful mutation instant |

created_at and updated_at are transport values. SQLite may store them as text, but the application must emit one canonical UTC representation and test ordering. [RFC 3339](https://datatracker.ietf.org/doc/rfc3339/) exists to reduce timestamp ambiguity; [RFC 9557](https://www.rfc-editor.org/info/rfc9557/) extends the format for additional information such as a zone name. For the first implementation, store the schedule zone in its own field and keep persisted event/run timestamps in canonical UTC.

### 5.2 AutomationRun

The attached seed lists id, prompt, status, output, model_id, created_at, and updated_at under runs. Those fields remain useful, but a safe run record must show which occurrence and revision produced them.

| Field | Type | Contract |
| --- | --- | --- |
| id | opaque string/UUID | Stable logical run identifier |
| automation_id | opaque string/UUID | Parent automation |
| automation_revision | positive integer | Immutable definition revision used by the run |
| occurrence_at | UTC RFC 3339 timestamp | Scheduled occurrence instant in UTC |
| idempotency_key | bounded string, unique | automation_id + revision + occurrence_at; prevents duplicate logical runs |
| status | enum | scheduled, claimed, running, succeeded, failed, timed_out, cancelled, skipped, or blocked |
| attempt | positive integer | Current/last attempt number |
| prompt | bounded string or controlled snapshot reference | Effective prompt used; avoid copying sensitive data into broad logs |
| prompt_sha256 | hex string | Integrity and correlation value for the effective prompt |
| model_id | registry key | Resolved model at claim time, not a later default |
| folder_id | logical destination key | Resolved destination at claim time |
| policy_snapshot_json | bounded JSON object | Timeout, retry, tool, data-sharing, and output limits |
| started_at / finished_at | UTC RFC 3339/null | Execution interval; null until known |
| output | bounded structured value/null | Validated result; not automatically trusted evidence or an action authorization |
| output_sha256 | hex string/null | Integrity/correlation value for persisted output |
| error_code | enum/null | Stable machine-readable failure category |
| error_message | bounded string/null | Redacted operator-facing detail |
| created_at / updated_at | UTC RFC 3339 timestamps | Run record lifecycle |

The run snapshot is the principal reproducibility control. Editing an automation must create a new revision for future occurrences; it must not rewrite a claimed or terminal run.

### 5.3 Proposed result envelope

Model output should be normalized before storage. A first read-only result envelope can be:

~~~json
{
  "decision": "ANSWER|ABSTAIN|DENY|ERROR",
  "summary": "bounded operator-facing summary",
  "evidence_refs": ["event:123", "detection:456"],
  "limitations": ["source is replay data"],
  "requested_actions": [],
  "model_id": "local:qwen-approved-v1",
  "prompt_sha256": "...",
  "generated_at": "2026-09-06T16:00:00Z"
}
~~~

requested_actions are proposals until an application-owned policy gate and, for high-risk actions, a human approval step accept them. A free-form model sentence must never be parsed as a shell command or firewall instruction.

## 6. Schedule contract

### 6.1 RFC 5545 rules

The stored rrule uses the RFC 5545 recurrence grammar. FREQ is required; UNTIL and COUNT are optional but mutually exclusive; COUNT includes the initial DTSTART occurrence. The recurrence set is derived from the start anchor plus recurrence and exception data, so the anchor cannot be implicit.

Accepted examples:

~~~text
FREQ=DAILY;INTERVAL=1
FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR
FREQ=MONTHLY;BYMONTHDAY=1
FREQ=HOURLY;INTERVAL=6;COUNT=8
~~~

The v1 validator should:

1. accept one rule only and normalize the optional RRULE prefix;
2. require exactly one FREQ and place it first in canonical output;
3. reject duplicate rule parts, unknown rule parts, malformed values, and COUNT plus UNTIL together;
4. reject SECONDLY and unbounded high-frequency schedules in the first implementation;
5. cap INTERVAL, COUNT, and estimated occurrence density under application policy;
6. require dtstart to match the rule pattern; and
7. compute and persist the next occurrence in UTC only after validation succeeds.

The RFC allows a recurring rule without COUNT or UNTIL to continue indefinitely. That is valid for a deliberately active long-lived automation, but the UI/API must make the absence of an end boundary visible and apply rate, retention, and disable controls.

### 6.2 Time zones and daylight saving time

Do not interpret rrule in the machine's ambient time zone. Store an IANA zone name and use Python's [zoneinfo](https://docs.python.org/3/library/zoneinfo.html) implementation or an equivalent, pinned and tested time-zone database. The zone name is part of the schedule meaning; -05:00 alone cannot express future daylight-saving transitions.

For non-UTC schedules, activation must choose a DST policy. The fail-closed v1 default is reject: refuse activation when the next occurrence is ambiguous or nonexistent unless the caller explicitly selects a policy. That makes spring-forward gaps and fall-back duplicate wall times visible rather than silently shifting work.

The scheduler must record both:

- the intended local occurrence (dtstart/zone interpretation); and
- the resolved UTC occurrence used as occurrence_at and the idempotency key.

This permits operators to distinguish a schedule change from a clock or time-zone-data change.

### 6.3 Missed occurrences

The scheduler must not create an unbounded backlog after downtime. Each automation needs an explicit catch-up policy:

- skip_missed — create no historical runs and advance to the next future occurrence;
- run_latest — create one run for the latest due occurrence;
- replay_bounded — create at most N due runs within a configured look-back window.

The v1 default is skip_missed for security and resource predictability. Any skipped occurrence gets a run/audit record with status skipped and reason missed_schedule, so silence is not confused with success.

## 7. Lifecycle and state transitions

Automation control state and run execution state are separate. A paused automation can have a currently running run; pausing prevents new claims but does not silently kill existing work.

~~~mermaid
stateDiagram-v2
    [*] --> draft
    draft --> active: validate_and_activate
    active --> paused: pause
    paused --> active: resume
    active --> disabled: disable
    paused --> disabled: disable
    disabled --> active: explicit_reenable
    draft --> archived: archive
    paused --> archived: archive
    disabled --> archived: archive
~~~

State invariants:

- draft and paused create no new scheduled claims.
- active is allowed only when the schedule, model, folder, and policy resolve successfully.
- disabled requires explicit re-enable and should preserve history.
- archived is terminal for the definition; historical runs remain readable.
- An update that changes prompt, rrule, dtstart, schedule_timezone, model_id, folder_id, or execution policy increments revision.
- Every mutation records actor/source, old state, new state, revision, and reason.

Run transitions are narrower:

~~~mermaid
flowchart TD
    scheduled[scheduled] --> claimed[claimed]
    claimed --> running[running]
    running --> succeeded[succeeded]
    running --> failed[failed]
    running --> timed_out[timed_out]
    scheduled --> skipped[skipped]
    claimed --> cancelled[cancelled]
    failed --> scheduled_retry[scheduled retry]
    scheduled_retry --> claimed
~~~

No terminal run may return to running. A retry is another attempt on the same logical run, not a second occurrence.

## 8. Execution and reliability rules

### 8.1 Claiming and idempotency

The scheduler should claim due work transactionally. The database must enforce a unique idempotency_key for each automation revision and occurrence. A safe claim sequence is:

1. read active definitions and their current revision;
2. calculate due occurrences using the stored schedule zone and policy;
3. insert the occurrence with status scheduled using the unique key;
4. atomically transition one eligible row to claimed;
5. snapshot prompt, model, folder, and policy;
6. execute within the bounded attempt deadline; and
7. write a terminal status and outcome in the same audit domain.

The unique key protects against duplicate scheduler loops and process restarts. It does not make an external side effect exactly once; every future adapter must accept the key and implement its own idempotent behavior.

### 8.2 Concurrency

The default skip_if_running policy allows at most one active run per automation. It is the safest default for local SQLite and for jobs that may inspect the same event store. A future queue_one or bounded parallel(N) mode must declare resource limits and be tested against duplicate claims, database locks, and output contention.

### 8.3 Timeouts and retries

Each attempt has a hard timeout. The scheduler must classify failures before retrying:

| Failure class | Example | Default action |
| --- | --- | --- |
| validation | Bad RRULE, invalid model, oversized prompt | Fail without retry; require definition repair |
| authorization | Folder not permitted, adapter not allowed | Block without retry; record policy reason |
| transient_dependency | Temporary model/backend unavailability | Bounded retry with backoff |
| timeout | Adapter exceeds deadline | Bounded retry only if the adapter is idempotent |
| output_invalid | Schema or size violation | Fail; do not publish invalid output |
| internal | Unhandled application error | Fail, alert, and preserve diagnostic reference |

Retries must have a maximum attempt count, maximum elapsed window, capped delay, and jitter. A retry must not expand the permissions, input scope, or timeout budget. If a run has an uncertain external side effect, mark it blocked or failed for review instead of blindly repeating it.

### 8.4 Manual run-now

run-now is an explicit operator request, not a mutation of the recurrence set. It gets a distinct trigger type and idempotency key, records the actor and reason, and still passes the same validation, policy, timeout, output, and audit gates. It must not rewrite next_run_at or consume COUNT unless the caller explicitly requests that behavior.

## 9. Prompt, model, and data boundaries

### 9.1 Prompt is not authority

An automation prompt is untrusted configuration data relative to the enforcement layer. It may describe a task, desired output, and evidence references, but it cannot grant itself tools, change the model registry, select a filesystem path, disable logging, or authorize firewall application.

If a run includes event metadata, documents, network observations, or model-retrieved text, place that material in a clearly marked data channel. Do not concatenate it into the instruction channel. OWASP identifies both direct and indirect prompt injection and recommends constrained behavior, expected-output validation, least privilege, human approval for high-risk actions, and clear separation of external content. See [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

### 9.2 Model registry

model_id is an opaque application registry key, not a user-provided URL, command, or arbitrary provider string. A registry entry should declare:

- adapter name and pinned model/version;
- local/remote execution boundary;
- maximum input and output size;
- supported output schema;
- data-sharing and retention characteristics;
- allowed tool set, which is empty for the first read-only slice; and
- health/availability state.

If a model is unavailable or no longer permitted, the run is blocked with a stable error code. Silent fallback to a different model is prohibited because it breaks reproducibility and may change data-sharing behavior.

### 9.3 Folder boundary

folder_id identifies a logical destination handled by an application-owned storage adapter. It must not be interpolated into a shell command or treated as a path. The adapter validates ownership, write permission, quota, retention, and allowed MIME/content type before the run is allowed to publish output. If a folder is deleted or access is revoked, the run fails closed and preserves the result only in the audit-safe failure record if policy permits.

### 9.4 Output handling

Model output is untrusted. Before persistence or publication, the application must validate its structure, enforce a byte/line limit, redact configured secrets, and attach provenance references. Invalid output becomes output_invalid; it must not be rendered as raw HTML, executed, or treated as a firewall plan.

## 10. Audit, privacy, and retention

MEGALODON already treats SQLite as an audit store for events, detections, and actions. Automation records should extend that audit surface rather than create an opaque parallel history. The [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) recommends recording the “when, where, who and what” of events, protecting logs, excluding data that is not legally sanctioned, and separating operational/audit purposes where their retention needs differ. NIST's [SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) likewise frames log management as an infrastructure and process that must cover generation, storage, access, and disposal.

Minimum audit fields for an automation mutation or run:

- event time in UTC;
- automation/run/attempt identifiers;
- actor or trigger source (operator, scheduler, recovery);
- automation revision and schedule fingerprint;
- effective model and folder identifiers;
- action taken and outcome status;
- reason/error code;
- prompt and output digests, not unbounded copies in general logs;
- evidence references and limitation flags; and
- retention/deletion decision where applicable.

Do not persist packet payloads, credentials, API tokens, unrestricted model context, or raw external documents merely because a prompt can reference them. Use bounded, validated metadata consistent with MEGALODON's metadata-only boundary. Retention must be explicit: define separate periods for definitions, run outputs, and audit events, and record purge actions. A future scheduled purge job should itself be read-only/planned until the retention policy and deletion audit are tested.

## 11. Proposed SQLite extension

The following is an implementation sketch, not a migration to apply yet. It shows the minimum relationships and uniqueness constraints that the current flat entity description lacks.

~~~sql
CREATE TABLE IF NOT EXISTS automations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    prompt TEXT NOT NULL,
    rrule TEXT NOT NULL,
    dtstart TEXT NOT NULL,
    schedule_timezone TEXT NOT NULL,
    dst_policy TEXT NOT NULL,
    model_id TEXT NOT NULL,
    folder_id TEXT NOT NULL,
    status TEXT NOT NULL,
    revision INTEGER NOT NULL,
    next_run_at TEXT,
    last_run_at TEXT,
    timeout_seconds INTEGER NOT NULL,
    max_output_bytes INTEGER NOT NULL,
    retry_max_attempts INTEGER NOT NULL,
    concurrency_policy TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS automation_runs (
    id TEXT PRIMARY KEY,
    automation_id TEXT NOT NULL REFERENCES automations(id),
    automation_revision INTEGER NOT NULL,
    occurrence_at TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    prompt TEXT,
    prompt_sha256 TEXT NOT NULL,
    model_id TEXT NOT NULL,
    folder_id TEXT NOT NULL,
    policy_snapshot_json TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    output_json TEXT,
    output_sha256 TEXT,
    error_code TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_automations_due
    ON automations(status, next_run_at);
CREATE INDEX IF NOT EXISTS idx_automation_runs_parent
    ON automation_runs(automation_id, occurrence_at);
CREATE INDEX IF NOT EXISTS idx_automation_runs_status
    ON automation_runs(status, updated_at);
~~~

Migration requirements:

- use an explicit schema version and a reversible backup before applying;
- enable the same foreign-key and WAL settings as the current Store;
- use parameterized writes only;
- never rewrite existing event/detection/action rows;
- test duplicate occurrence insertion and concurrent claim behavior;
- make any schema migration a separate reviewed change from scheduler execution.

## 12. API and CLI surface

The first implementation should be CLI/local-service oriented. A remote HTTP API is a separate security boundary. If an API is later exposed, use versioned, authenticated endpoints with optimistic concurrency.

### Definition operations

| Operation | Effect | Safety requirement |
| --- | --- | --- |
| create | Store a validated draft definition | Never starts execution |
| validate | Return normalized schedule/model/folder/policy errors | No database mutation beyond optional diagnostic record |
| activate | Move draft to active | Revalidate all resolved dependencies and record revision |
| pause | Stop future claims | Existing run continues under its snapshot unless separately cancelled |
| resume | Re-enable future claims | Apply missed-occurrence policy explicitly |
| disable | Stop scheduling until explicit re-enable | Preserve definition and history |
| archive | Terminally retire definition | Historical runs remain readable |
| run-now | Create a manual run | Record actor, reason, and separate trigger type |

### Read operations

- get automation returns the definition, revision, next occurrence, and validation health.
- list automations is bounded and filterable by status.
- list runs is bounded, paginated, and never returns unrestricted prompt/output history by default.
- get run returns the run snapshot, outcome, evidence references, and limitations.

If these become HTTP routes, use revision checks for edits, do not expose the raw SQLite file, and do not bind beyond loopback until authentication and authorization are implemented. The current repository's dashboard is intentionally read-only and loopback-bound by default; the automation API must not weaken that boundary.

## 13. Integration with the current MEGALODON MVP

The safest first job classes are:

1. **Health summary:** read current event/detection/action counts and produce a bounded report.
2. **Offline replay:** process a named, permitted JSONL fixture and record the resulting evidence.
3. **Retention plan:** calculate records eligible for purge and produce a reviewable plan; do not delete until a separately approved retention operation exists.
4. **Evidence report:** assemble existing detection/action references without adding packet payloads or unsupported threat attribution.

The first automation adapter must not:

- call the live firewall mutation path;
- invoke sudo, shell=True, arbitrary subprocesses, or arbitrary network endpoints;
- turn a CRITICAL detection into a permanent or unattended block;
- bind the dashboard or API to a remote interface;
- send IPs, DNS names, or event metadata to an external model/feed without an explicit data-sharing policy; or
- treat a model output as proof of malicious intent.

The current [SPECIFICATION.md](../SPECIFICATION.md) already states that automatic response is future work and that action statuses must distinguish not_attempted, suppressed, planned, applied, and failed. Automation runs should preserve that distinction when they generate a plan or recommendation. A scheduled plan is not an applied action.

## 14. Verification plan

No implementation should be accepted until the following cases are covered by deterministic fixtures and hosted CI.

### Schema and validation

- minimum create payload accepts name, prompt, and rrule but remains draft;
- missing/blank/control-character names are rejected;
- oversized prompt, output, error, and metadata values are rejected or bounded;
- FREQ missing, duplicate rule parts, malformed values, unknown values, and COUNT plus UNTIL are rejected;
- dtstart/zone mismatch is rejected;
- unavailable model and unauthorized folder fail closed;
- a definition cannot activate with an unresolved dependency.

### Time and recurrence

- daily, weekly, monthly, count-bounded, and until-bounded rules produce expected occurrences;
- DTSTART is the first occurrence and does not drift after restart;
- UTC schedule behavior is stable;
- spring-forward gap and fall-back ambiguity follow the explicit DST policy;
- duplicates from two scheduler loops collapse to one idempotency key;
- downtime follows the selected missed-occurrence policy and records skipped work.

### Lifecycle and execution

- draft/paused/disabled definitions do not create new claims;
- activation increments and freezes a revision;
- prompt/model/folder/policy edits do not alter an already claimed run;
- concurrent workers cannot claim the same occurrence;
- timeout, transient retry, permanent failure, cancellation, invalid output, and blocked authorization each produce the correct terminal record;
- retries preserve the same logical run and do not widen permissions.

### Security and privacy

- prompt injection strings in event metadata remain data and cannot alter the system policy;
- model output cannot invoke shell, firewall, or arbitrary tool code;
- secrets and raw payloads are not copied into prompts, outputs, or logs;
- folder identifiers cannot become filesystem traversal or command arguments;
- local-only operation remains the default;
- no scheduler test mutates the host firewall or sends data to an external service.

### Audit and operations

- every state transition and run has actor/trigger, revision, timestamps, status, and reason;
- audit records remain readable after definition archival;
- retention and purge actions are bounded and auditable;
- output and run listing are paginated and size-limited;
- restart recovery leaves no claimed run without a recovery decision;
- the dashboard can display scheduler health without exposing raw secrets or payloads.

## 15. Staged implementation plan

| Stage | Deliverable | Exit condition |
| --- | --- | --- |
| 0. Contract | JSON fixtures, enums, validation errors, and this document | **Implemented:** deterministic Stage 0 schema tests pass; semantics beyond the structural contract remain future gates |
| 1. Parser | RRULE/DTSTART/time-zone normalization and occurrence fixtures | Exact fixture expectations pass, including DST policy |
| 2. Ledger | SQLite migrations for definitions/runs and idempotent claim transaction | Restart/concurrency tests pass without model execution |
| 3. Read-only scheduler | Health, replay, retention-plan, and report jobs | Hosted tests prove no firewall, shell, or remote side effect |
| 4. Model adapter | Bounded local adapter with structured output validation | Prompt/data separation, output limits, and model registry tests pass |
| 5. Approval boundary | Explicit human review for any action proposal | Approval/audit/rollback contract is reviewed independently |
| 6. Higher-risk actions | Separate design for enforcement adapters | Only after the existing security-review gates are closed with evidence |

Each stage should be a separate reviewable change. A scheduler implementation must not be smuggled into a documentation or schema PR, and a model adapter must not be used to bypass the firewall approval boundary.

## 16. Open decisions before implementation

These questions remain deliberately unresolved and should be answered in a follow-up design review rather than inferred in code:

1. Which exact RRULE library and version will be supported, and what subset is acceptable on Python 3.11?
2. Is UTC the only active schedule zone in v1, or will named local zones be enabled with the explicit DST policy above?
3. Should prompt snapshots be retained as encrypted content, a controlled file reference, or only a digest plus versioned source?
4. What is the approved model registry and which local Qwen/Ollama adapters, if any, are allowed?
5. What is the logical folder service and retention policy for run outputs?
6. What is the recovery decision for a process that exits after an external adapter may have performed a side effect?
7. Which operator identity and approval record are required before any action proposal can become an applied firewall operation?
8. What exact local/remote boundary, authentication, and authorization model would be required before an automation API leaves loopback?

Until those decisions have authoritative answers, the safe status is **proposed, not active**.

## 17. Evidence and sources

### Project sources

- Attached input: Pasted markdown.md, supplied with the documentation request on 2026-09-06.
- [MEGALODON README](https://github.com/bartytime4life/MEGALODON/blob/ec53f5968e498b1ebee00b11119b216ba1812699/README.md)
- [MEGALODON completed specification](https://github.com/bartytime4life/MEGALODON/blob/ec53f5968e498b1ebee00b11119b216ba1812699/SPECIFICATION.md)
- [MEGALODON architecture security review](https://github.com/bartytime4life/MEGALODON/blob/ec53f5968e498b1ebee00b11119b216ba1812699/SECURITY_REVIEW.md)

### External authoritative sources

- [RFC 5545 — iCalendar recurrence rules](https://datatracker.ietf.org/doc/html/rfc5545)
- [RFC 3339 — Internet timestamps](https://datatracker.ietf.org/doc/rfc3339/)
- [RFC 9557 — timestamps with additional information](https://www.rfc-editor.org/info/rfc9557/)
- [Python zoneinfo — IANA time-zone support](https://docs.python.org/3/library/zoneinfo.html)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)

The standards and guidance above support the schedule grammar, timestamp/time-zone handling, schema validation, prompt/data separation, logging, and retention recommendations. They do not prove that the proposed MEGALODON automation subsystem exists or that the proposed controls have been implemented.
