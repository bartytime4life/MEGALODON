# MEGALODON architecture security review

## HUD usability boundary

The `hud` launch alias inspects bounded executable metadata once before listening,
using the existing readiness contract. HTTP only returns that cached snapshot;
there is no probe, installation, service-control or model-invocation endpoint.
PATH entries can refer to mounts/symlinks, so the finite probe count is not a
filesystem-latency guarantee. Ordinary `dashboard` startup does not inspect tools.
The first-launch exception tolerates only a missing audit source, with 503
telemetry responses. Unsafe or invalid existing stores remain refused.

Companion-console bookmarks are explicit browser navigation, not embedded
consoles or backend connections. A fixed fourteen-tool registry restricts storage;
only HTTP(S) addresses without userinfo, query strings or fragments are accepted.
Stored values are validated again when loaded. Addresses stay in browser
localStorage for that origin, or page memory if storage is unavailable. They
must not contain credentials. Clicking a console or official guide leaves the
dashboard and may access the network; that does not change backend egress policy.
Terminal commands are copied only after a click, never executed. Optional startup
paths are quoted as single POSIX shell arguments and are not stored or opened by
the browser. These controls do not assert installation, health or authority.

## Executive result

The supplied architecture is a useful decomposition for a defensive product,
but its example implementation is not safe to deploy. The highest-risk defects
are command injection, unrestricted automatic blocking, lack of rollback, and
an unauthenticated remote-capable dashboard. The MVP in this folder retains the
capture → analysis → policy → audit → dashboard shape while making observation
the default. For the evaluation-release candidate, firewall response is
plan-only and every retained live-apply route fails closed before it can inspect
or change the host.

This review separates three evidence levels: implemented safeguards in the
current code, adopted but inert contracts, and controls still required before
operational use. Passing CI or closing a contract/test issue does not promote a
proposal into a runtime capability or satisfy independent review.

See the [red, blue, and purple security practice](docs/red-blue-security-guide.md)
for authorized adversarial validation and future-AI gates. That guide adds no
model runtime, tool authority, or firewall authorization.

The [incident-informed model containment review](docs/model-containment-review.md)
adds a source-pinned threat mapping and exact-denial regressions through the
explicitly enabled Qwen provider entry point. Application-level refusal and
literal-loopback transport do not establish containment of the separately
operated provider, its shared services or its own outbound connections.

The offline reference and synthetic evaluation commands are documented in
[docs/reference-data.md](docs/reference-data.md). They do not start ingestion
or the dashboard, populate the audit store, or invoke response policy. The
existing dashboard separately reuses the IANA loader for bounded, manual
Reference Library lookups. This is a read-only context connection, not a
telemetry join, a corpus-execution endpoint, or evidence of an observed service.

The separate [Alert Workload Lab](docs/alert-workload-lab.md) computes exact
binary-classification expectations from explicit hypothetical assumptions.
It does not load observed data or reference assets, invoke a model, or measure
detector accuracy. Unit/denominator labels, `hypothetical-only` / `uncalibrated`
quality, and an explicit undefined PPV when no alerts are expected prevent the
calculator from silently presenting its assumptions as observed evidence.
An external consumer can still misrepresent a copied result; no mathematical
ratio establishes an incident verdict or authority to act.

## Read-only Suricata evidence view

The optional `dashboard --suricata-db` path loads one bounded startup snapshot
from the explicitly selected existing private v1 store. It preserves Linux
non-root capability-free admission, descriptor identity, sidecar/WAL refusal and
the OFD read lock. Recent runs are validated completely before any of their
metadata is exposed; arbitrary stored text is bounded before Python decoding.
The query-only authorizer, cooperative five-second budget and 64 KiB response
ceiling fail closed with no partial rows. HTTP serves immutable owned bytes,
so browser refresh cannot reread, migrate, repair, reconcile or write the store.
A startup snapshot is not sensor liveness; stored totals are not validation of
all historical rows, and producer-reported blocking is not a MEGALODON action.
The budget cannot interrupt a stalled filesystem. Native producer acceptance
and independent operational review remain separate. See the
[projection contract](docs/suricata-evidence-projection.md).

## Findings and corrections

The separately versioned [offline anomaly pipeline](docs/anomaly-pipeline.md)
adds descriptive candidate evidence and one explicit analyst command. Its
Qwen policy is independently pinned, recomputes evidence before admission and
shares the original transport limits. Model denial/failure preserves the
deterministic dossier; unexpected provider exceptions mark request accounting
unknown. It does not add live detection, persistence, automatic analysis or
response authority. The original run-count API remains library-only.

The [result-integrity repair](docs/advisory-result-integrity.md) addresses
non-normal completions being accepted as answers, invisible control text
reaching consumers, and malformed provider returns escaping triage's evidence
preservation boundary. Shared validation replaces duplicate dashboard rules;
unknown completion is distinct from a verified no-request. These consistency
checks do not authenticate model bytes, verify generated claims, remove Unicode
homoglyph risks or attest provider egress containment.

| Severity | Original design issue | Consequence | MVP correction |
| --- | --- | --- | --- |
| Critical | `subprocess.Popen(..., shell=True)` builds a capture command from interface/filter input | Shell injection and ambiguous tshark argument parsing | No shell; optional Scapy adapter and typed JSONL input |
| Critical | Firewall commands interpolate an IP into shell strings | Command injection and malformed rules | Plan-only output uses fixed `nft` argv built from validated `ipaddress` values; live application is unsupported in the evaluation-release candidate |
| High | Critical findings permanently auto-block an IP | False positives can cut off users, services, or an upstream network | Automatic and operator-requested live blocking are unsupported; proposed blocks remain time-limited plans only |
| High | No allowlist precedence or protected-network policy | A detector can block loopback, private ranges, or management paths | Allowlist precedence and non-global rejection are enforced while producing plans; no live action follows |
| High | No rollback, expiry, or action ledger | Operators cannot explain or safely undo a response | Supported plans are recorded in SQLite and block plans are time-limited; an unsupported apply request produces no false `applied` receipt, and live mutation stays disabled until the restoration gate below is met |
| High | GUI design does not define authentication or bind address | A dashboard could expose threat data and controls on the LAN/WAN | Read-only dashboard binds to `127.0.0.1`, has no control endpoints, uses a separate `mode=ro`/`query_only`/SQL-authorized store, bounds its polling and recent-row budget, selects only the five recent-detection fields used by the UI, validates closed response shapes before replacing state, and serves same-origin assets under a no-inline CSP |
| High | A loopback listener trusts any HTTP `Host` value | DNS rebinding could let a foreign browser origin read local telemetry | Every dashboard `GET` requires one exact bound-loopback `Host` value and is rejected before routing or SQLite access when the value is missing, repeated, foreign, non-canonical, or names the wrong port |
| High | Offline reports could become a path-driven disclosure or analyzer trigger | A web request could expose case data, traverse local files, or start hostile-input processing | One operator-selected private report set is checked and its summary inputs are validated at startup; paths, records, evidence details, remote binds, uploads, and analyzer controls are excluded |
| High | Raw payload hash/contents are part of the capture concept | Payload-derived identifiers can still disclose sensitive data; storage creates a forensic liability | Metadata-only event model; payloads are not represented or stored |
| Medium | Promiscuous capture is treated as a convenience | Requires privilege and may capture traffic outside the operator’s authority | Optional live capture is explicit, interface-specific, and documented as privileged |
| Medium | External feeds are called synchronously with no privacy contract | IP/domain disclosure, rate-limit failures, stale reputation, and API-key leakage | Feeds are out of MVP scope; later adapters must be cached, signed, rate-limited, and opt-in |
| Medium | A local language-model integration can leak telemetry, follow redirects or proxies, hallucinate authority, or exhaust resources | Sensitive disclosure, accidental egress, misleading verdicts, and an action-confused UI | The optional internal adapter reruns the pinned metadata-only Airlock, connects only to literal `127.0.0.1:11434`, exposes no endpoint or raw-prompt option, follows no redirects, reads no proxy or DNS configuration, and bounds concurrency, deadline, cancellation, request, HTTP protocol framing, response body, generation, output, and display text. The original run-count policy's untrusted result may be supplied at dashboard startup for one immutable, bounded, text-only receipt; the separate offline anomaly command requires explicit enablement and preserves evidence independently. Neither policy grants a dashboard request/retry/poll path, storage, detection authority, or response authority |
| Medium | Registry assignments can be mistaken for observed services or threat verdicts | Analysts may overstate what a port implies and create false confidence or false positives | Bundled IANA service/port and protocol records are explicitly context hints only; they never establish observation, endorsement, safety, malicious intent, or a verdict |
| Medium | Reference or evaluation assets can be truncated, substituted, or partially loaded | Lookup and detector receipts could silently describe different evidence | Versioned manifests pin every deterministic shard, count, byte length, and digest; all declared data and closed records validate before lookup or evaluation |
| Medium | A synthetic detector suite can be presented as operational accuracy evidence | Deterministic expected counts may be confused with representative false-positive or efficacy measurement | The 12-scenario, 6,492-event corpus is metadata-only, documentation-address-only, and labeled `synthetic-only` / `uncalibrated`; its evaluator has no network, store, persistence, action, or subprocess path |
| Medium | YAML rules imply arbitrary field/operator expansion | Unvalidated rules can create denial-of-service or unsafe actions | MVP rules are fixed and typed; a future rule schema must be allowlisted and versioned |
| Medium | No IPv6 handling in the firewall examples | Incomplete protection and accidental IPv4-only assumptions | Plan generation uses separate validated IPv4/IPv6 nftables sets; this does not imply live enforcement |
| Medium | No database schema, retention, or transaction policy | Unbounded growth and incomplete evidence | Exact SQLite schema, atomic per-event event/detection/action/link/counter WAL transactions, staged detector state, explicit run outcomes and orphan reconciliation, private POSIX writer/migration paths, a separately constrained dashboard reader, a finite high-water stop, and preview-bound retention batches; operational retention values and native capacity evidence remain open |
| Medium | GUI threat map can create a false precision problem | IP geolocation can expose or misrepresent people and locations | No map in MVP; future map must show uncertainty and avoid precise residential claims |
| Low | `sqlite3` is listed as a pip requirement | It is part of Python’s standard library; install instructions are misleading | No runtime dependency for SQLite |
| Low | `tshark>=1.4.0` is treated as a normal Python package | System Wireshark availability and bindings are different concerns | Scapy is an optional Python extra; tshark is not required by the MVP |

### Evaluation-release firewall containment ([#65](https://github.com/bartytime4life/MEGALODON/issues/65))

Live firewall application is unsupported in the evaluation-release candidate.
The retained `firewall-install --apply` and `block --apply` CLI routes exit with
status 2 and the fixed diagnostic
`megalodon: live firewall application is unsupported in this evaluation release`
before configuration loading or backend construction. The corresponding direct
backend calls raise `FirewallError` with
`live firewall application is unsupported in this evaluation release` before
platform or host inspection, target/reason/confirmation validation, executable
lookup, privilege checks, or process creation.

The compatibility flags remain parsed so an old or scripted apply request fails
explicitly instead of silently becoming a dry run. The refusal opens no audit
store and emits no fabricated `applied` receipt. Non-apply install and block
planning, including their existing `planned` SQLite receipts, remain available
and do not execute `nft`.

Issue #65 therefore has an implemented evaluation-containment boundary, not a
restored mutation capability or production approval. Its exact-head validation,
independent review, and issue lifecycle remain separate gates.

### Dashboard reference and static-integration boundary

The implemented HTTP surface includes `/api/integrations` and the three
`/api/reference/status`, `/api/reference/port`, and `/api/reference/protocol`
GET routes. Their presence must not be obscured by the standalone evaluator's
no-dashboard side-effect boundary. The complete route inventory is in
[SPECIFICATION.md section 6](SPECIFICATION.md#6-dashboard-contract), with exact
HTTP contracts in [docs/dashboard-http-contract.md](docs/dashboard-http-contract.md).

`DashboardHandler` checks the bound-loopback Host before routing. The integration
route returns only the closed built-in workflow map: it reads no telemetry and
performs no installation, host probe, process launch, or provider request.
Reference routes likewise do not read or write the audit store. They use the
process-local `ReferenceLibrary`, whose default instance lazily loads the full
IANA bundle once and keeps only a bounded in-memory lookup cache. Library
failure remains a fixed unavailable/integrity disposition until process restart;
a status recheck is not a file reload, maintenance operation, or network update.
These route-local boundaries do not remove the dashboard CLI's existing private
telemetry-store startup requirements.

The reference client validates the returned query against the submitted query,
bundle identity and provenance against the accepted status, and match counts
against the relevant source total. Returned rows are limited to eight, with
explicit truncation for larger match counts. It rejects contradictory
truncation/status claims and action/persistence/network flags.
Provenance is rendered as text; registry URLs are not contacted. Recheck and
clear controls change the displayed context without authorizing a tool or
changing SQLite. A transient request failure can preserve explicitly labeled
stale context, whereas a rejected lookup response or declared bundle failure
clears it and disables lookup; see the
[Reference Library recovery contract](docs/reference-library-recovery.md).

The server's bundle-byte validation and the browser's response-consistency
validation are different checks. Neither proves publisher authenticity,
observed-service identity, traffic safety, or malware attribution. Synthetic
regressions and passing CI are not independent review or rendered-browser
acceptance. This documentation reconciles the existing connections; it grants
no new endpoint, source, execution, remote-access, or response authority.

## Threat model

The MVP assumes an operator is defending a Linux host or small lab network and
may receive malformed or adversarial network metadata. It protects against:

- malformed event input and invalid addresses;
- accidental command execution through event fields;
- accidental host-firewall mutation, including through retained apply routes;
- stale, repeated, or noisy detections overwhelming the action path;
- malformed, incomplete, or tampered bundled reference/evaluation data being
  used without validation;
- dashboard exposure caused by a careless bind address;
- loss of an audit trail for supported planning and suppression decisions;
- partial run evidence or consumed detector cooldown after a rejected event-bundle
  write; and
- ambiguous exhaustion/event-limit receipts or silently ignored orphaned runs.

It does not yet protect against a compromised kernel, a malicious root user,
kernel-level packet forgery, an attacker who can write directly to the database,
or a distributed sensor fleet. Those require a separate trust-boundary design.

The literal-loopback Qwen boundary also does not attest the bytes behind an
operator-created Ollama model alias. It checks the registry pin and exact model
ID in the terminal provider response without performing model discovery or a
second provider request. A malicious local process already able to bind or
interpose on port 11434 remains outside this slice's trust proof.

## Required controls before production use

1. Threat-feed adapters need a written data-sharing policy, cache freshness,
   feed signature verification, API-key isolation, and failure behavior.
2. Live capture has a fixed fail-closed 1,024-event application queue, but still
   needs a privilege model, service account, systemd sandboxing, kernel-buffer
   loss telemetry, and production resource/load acceptance.
3. Firewall application is unsupported for the evaluation-release candidate.
   Restoring it requires an independently reviewed design with durable intent
   recorded before mutation, exact operator authority and target, allowlist precedence,
   non-global rejection, conflict detection with the host’s existing firewall
   manager, finite expiry, post-action readback, a terminal outcome, tested
   rollback, and explicit reconciliation for uncertain or interrupted attempts.
   Passing plan-only tests or closing #65's containment slice does not satisfy
   that restoration gate.
4. The dashboard needs authentication and CSRF protection if it ever exposes
   control operations or binds beyond localhost.
5. The repository has bounded synthetic detector and service-to-ledger fixtures,
   including a manifest-pinned corpus explicitly labeled `synthetic-only` and
   `uncalibrated`, but still needs representative privacy-reviewed replay and
   false-positive measurement before operational interpretation. Neither a
   passing corpus result, a detection, nor a quality label authorizes automated
   response.
6. Before a real Qwen invocation is treated as accepted operator capability,
   bind the registry model ID to an operator-verified local Ollama alias and
   artifact receipt, validate installed-provider compatibility and cancellation
   behavior, and obtain independent security review. Dashboard projection,
   persistence, background execution, and model-driven action remain separate
   gates.

## Open control register

**Currentness note.** Every GitHub issue cited by number in this register
(#3, #7, #25, #65, #66, #67, #68, #191, #194, #196, #198, #203, and the
others linked below) is now closed. A closed issue is a lifecycle event,
not a claim that its row's "Remaining control" text is satisfied — some
rows' remaining work landed in the closing pull request (for example #7's
browser-acceptance evidence now runs as this repository's
`browser-acceptance` CI job), while others were closed without the
described control existing (#3 was closed `not_planned`: the repository
owner adopted the fast, AI-reviewed, owner-directed merge workflow instead
of building a server-enforced independent-review floor, so this table's
"Enforce and evidence an independent approval path" remains not built by
owner decision, not merely unfinished). Treat each row's evidence and
remaining-control text on its own merits; do not infer resolution from
issue closure alone.

### Control disposition

This register uses three dispositions. They are evidence classifications, not
GitHub issue states:

- **Delivered** means the repository contains the named implementation,
  contract, test, or receipt. It does not imply deployment, operator
  acceptance, supported-platform status, or security approval beyond the
  cited evidence.
- **Explicitly declined** means the owner made a recorded policy choice not to
  build that control. The closed issue remains the decision record and must
  not be reopened merely because the control is absent.
- **Untracked acceptance obligation** means a claim is intentionally withheld
  until external, operator, native-platform, installed-runtime, or independent
  evidence exists. Issue counts are point-in-time observations; these
  obligations are not silently converted into completed work. New roadmap
  issues #254–#261 track bounded follow-up work after the original register.

The server-enforced independent-approval floor from #3 is **explicitly
declined** under the owner-adopted fast, AI-reviewed, owner-directed merge
workflow. This does not turn automated review into independent human approval.
Independent review requested by individual rows remains an **untracked
acceptance obligation**, not a promise to restore the declined server rule.

| Untracked acceptance bundle | Evidence still required | Claims withheld until then |
| --- | --- | --- |
| Operator acceptance | Dashboard operator acceptance and finite retention-policy values on an authorized host | Operator-approved dashboard or continuous operation |
| Native Windows | Core execution, private NTFS ACLs, loopback UI/browser behavior, and exact-platform receipts | Windows support or parity |
| Installed runtime | Intended TShark/Suricata revisions, capture-loss behavior, threaded/native-stall interruption, and long-running exhaustion behavior | Installed-sensor compatibility or continuous monitoring |
| Local model | Operator-owned Ollama alias/artifact, lifecycle, compatibility, cancellation, and independent security review | Accepted Qwen capability or model authority |
| Independent evidence | Exact-head and independent review where a row expressly requires it, without creating a server-enforced approval claim | Independent acceptance, production approval, or release authority |

These bundles preserve acceptance obligations beyond the delivered code. The
subsequent M01–M04 roadmap tracks currentness (#254), licensing (#255), recovery
(#256), telemetry/detection qualification (#257–#259), Linux release evidence
(#260), and provider containment (#261). Those issue scopes do not prove any
acceptance gate complete or reopen #3, #7, #25, #27, #28, #65–#68, #165, #191,
#194, #196, #198, or #203. A future issue should be created only
when an owner authorizes a concrete execution environment and acceptance
scope.

The [repository currentness contract](docs/repository-currentness.md) binds
selected readbacks and claim references to a point-in-time commit. Its
validation result is not independent approval or a timeless security posture.

| Gate | Repository evidence | Remaining control |
| --- | --- | --- |
| Aggregate JSONL input budget ([#203](https://github.com/bartytime4life/MEGALODON/issues/203)) | Every returned JSONL line counts toward a fixed 256 MiB UTF-8 budget before classification or parsing; owned UTF-8 files preserve LF/CRLF/CR bytes; the first excess line fails with a record-free capture error and no further logical line read | Borrowed text streams must preserve newlines for original-byte accounting; decoder read-ahead is not bounded by this counter. Revalidate exact-head behavior on intended Linux files and pipes; retain the separate event, skipped-line, elapsed-deadline, storage, and cleanup controls |
| Independent review ([#3](https://github.com/bartytime4life/MEGALODON/issues/3)) | CI and merge history exist; #3 records the owner-adopted fast, AI-reviewed, owner-directed merge workflow | **Explicitly declined:** no server-enforced independent-approval floor is planned under the recorded owner decision. Do not describe automated review as independent human approval |
| Firewall containment ([#65](https://github.com/bartytime4life/MEGALODON/issues/65)) | Evaluation apply routes fail with one fixed diagnostic before configuration, host, executable, privilege, or process work; plan-only receipts remain | Complete exact-head validation and independent review; design durable intent, outcome readback, expiry, rollback, and reconciliation before any separate restoration proposal |
| Dashboard acceptance ([#7](https://github.com/bartytime4life/MEGALODON/issues/7)) | Loopback, read-only, bounded implementation exists; a real headed-Chrome CI job (`.github/workflows/browser-acceptance.yml`, `tests/browser_native_profile.py`) exercises the five-field privacy-minimized HTTP projection, native window visibility, and refresh/pause/resume behavior — see [docs/dashboard-browser-acceptance.md](docs/dashboard-browser-acceptance.md) | That suite's own text states its existence "is not acceptance, independent review, or a supported-platform promise"; independent human review and operator acceptance evidence remain outstanding |
| Dashboard storage isolation ([#66](https://github.com/bartytime4life/MEGALODON/issues/66)) | Separate least-data reader requires an existing compatible private POSIX store with rename-resistant trusted ancestry; pins the database inode; requires SQLite to resolve the configured private path; holds a stable parent-entry generation; revalidates sidecars; uses `mode=ro` plus `query_only`; and denies non-dashboard SQL | Obtain independent review and native Windows ACL evidence; keep successful WAL coordination confined to a dedicated verified private directory |
| Ingestion atomicity ([#67](https://github.com/bartytime4life/MEGALODON/issues/67)) | Per-event event/detection/action/link/counter atomicity, post-commit detector state, explicit terminal reasons, uncertain-commit poisoning, concurrent-start refusal, bounded orphan readback, pinned reconciliation, and v1/v2 backup migration are implemented with synthetic tests | Complete exact-head CI and independent review; do not infer exactly-once intake, power-loss recovery, alert lifecycle, or production approval |
| Whole-service resource bounds ([#68](https://github.com/bartytime4life/MEGALODON/issues/68), [#191](https://github.com/bartytime4life/MEGALODON/issues/191), [#194](https://github.com/bartytime4life/MEGALODON/issues/194), [#196](https://github.com/bartytime4life/MEGALODON/issues/196), [#198](https://github.com/bartytime4life/MEGALODON/issues/198)) | Detector windows, capture queues, API result sets, offline inputs, subprocess output, storage intake, and internal retention transactions have finite limits; the CLI requires an explicit positive event ceiling for JSONL/stdin and Scapy; JSONL iterators refuse after 65,536 skipped blank/comment lines; an optional single-OS-thread Linux alarm bounds sample/JSONL source work, refuses a blocked or pre-existing pending alarm signal, unavailable `/proc/self/task` or signal-state inspection, multiple OS threads, and threaded Scapy use, rechecks the alarm mask, pending set, and OS-thread count inside protected setup, restores the observed mask and handler when setup mutations or pending-signal inspection are interrupted, treats interrupted arming as live until cancellation, reads back interrupted competing-timer restoration and restores a displaced timer when the swap was incomplete, dispatches a post-arm pending deadline under its own handler, preserves active or concurrently armed process timers, blocks the alarm before cancellation, re-enters protected teardown after interrupted successful unmasking, completes cleanup decisions before re-raising interruption from cleanup-mask entry or post-cancel inspection, and restores the prior handler only after the original mask is restored and timer inactivity is confirmed; each retention apply is bound to an exact preview and deletes at most 256 explicit rows | Add portable/Windows and threaded-capture interruption plus whole-command deadline controls, select operator retention values, and prove installed-capture loss behavior, uninterruptible native stalls, long-running storage/exhaustion, and any future delivery queue before claiming continuous monitoring |
| TShark compatibility ([#25](https://github.com/bartytime4life/MEGALODON/issues/25)) | A prepared-host UID-1000 header-only probe passed at [`main@7ad539c`](https://github.com/bartytime4life/MEGALODON/commit/7ad539ccd33687725d18ee8a8cedcc84073c3609) with `/usr/bin/tshark` from Wireshark 4.2.2 package `4.2.2-1.1build3` | Revalidate the intended artifact/revision; arbitrary-capture containment, live capture, installation, and operation remain separate gates |
| Native Windows ([#27](https://github.com/bartytime4life/MEGALODON/issues/27)) | Static acceptance matrix and Linux-run unsupported-operation controls exist | Native core, NTFS ACL, loopback UI/browser, and exact-platform execution receipts |
| Retention/storage ([#28](https://github.com/bartytime4life/MEGALODON/issues/28)) | Per-write rollback coverage, a storage high-water stop, and preview-bound finite deletion batches exist | Select finite policy values and validate native operational failure/recovery; no cleanup job or secure-erasure claim exists |
| Reference/evaluation integrity | Privacy-minimized IANA data is manifest-pinned in deterministic shards no larger than 76 KiB; the complete 12-scenario synthetic corpus validates before an in-memory detector run | Establish a reviewed maintenance cadence and provenance receipt for each future snapshot; use representative authorized replay before any accuracy or operational-efficacy claim |
| Local Qwen advisory ([#165](https://github.com/bartytime4life/MEGALODON/issues/165)) | Fingerprint-pinned Airlock, an internal literal-loopback concurrency-one provider boundary, and one immutable startup-supplied receipt projected read-only in **Deep analysis & context**, with bounded routing/rendering and adversarial negative controls | Verify a real operator-owned model alias/artifact and installed Ollama lifecycle on an authorized host; keep dashboard invocation/retry/polling, persistence, background operation, detection authority, and action authority absent |

Suricata issues [#9](https://github.com/bartytime4life/MEGALODON/issues/9)
and [#24](https://github.com/bartytime4life/MEGALODON/issues/24) closed their
record and reader **contract** gates. No runtime reader, durable importer,
installed-sensor compatibility, or response path follows from those closures.

## Windows/Linux extension: proposed controls, not completed validation

The [platform baseline](docs/platform-baseline.md) is the canonical proposed
configuration and installation guide. The review above concerns the Linux MVP
and original design findings; it is not independent Windows security approval.
The offline implementation depends on Linux privilege/capability checks,
descriptor-based file access, `/proc`, process groups, and a fixed
`/usr/bin/tshark`. Retained firewall apply routes are refusal surfaces only:
they stop with the fixed evaluation-release diagnostic before configuration,
platform/host, executable, privilege, or process work. There is no live Linux or
Windows firewall-apply backend in the evaluation-release candidate. Native Windows parity
is unproven; existing Linux checks must not be removed to advertise it.

| Boundary | Required Windows/guest control | Current status |
| --- | --- | --- |
| Local storage | Private local NTFS ACLs; reject unsafe shared/redirected locations; review database/WAL/report permissions | Proposed Windows acceptance work; POSIX modes alone are insufficient |
| Hostile input files | Reviewed handles and identity; reparse-point, device, UNC, alternate-stream and race defenses; finite limits | No native Windows offline adapter is approved |
| Analyzer execution | Fixed executable/argv, trusted configuration, bounded pipes/runtime/resources, reliable child-tree termination, no egress | A Windows executable path alone does not supply containment |
| Capture drivers | Verify maintenance, signed provenance, privileges, licensing, and explicit operator capture authority | Native Windows live capture excluded; Npcap is not an open-source baseline dependency |
| Guest networking | Validate guest/host scope and loopback behavior; no assumption of full host visibility or firewall control | WSL is development-only here, not the hostile-capture isolation baseline |
| Host response | Preserve existing firewall/endpoint protection; prove durable intent, outcome readback, expiry/recovery, reconciliation, and operator authorization separately | No Linux or Windows apply backend in the evaluation-release candidate; no services or scheduled cleanup installed |
| Sensor/file tools | Separate packet, flow, alert and file-scan semantics; allowlist fields; never import payloads or payload hashes | Suricata has a bounded completed-file reader and an explicit operator-invoked publication transaction; no sensor, raw-EVE watcher, IPS, ClamAV, or osquery runtime integration |

The read-only `megalodon capabilities` command reports fixed support states from
repository data. It deliberately does not inspect executables, versions,
drivers, services, configuration, privileges, sockets, or network reachability.
Its output cannot establish installation, provenance, compatibility, isolation,
or authorization to run an external tool.

The companion `megalodon hub-plan` command is also static and non-executing. It
maps each catalog component exactly once to a closed source kind, owner,
input/output contract, entry point, launch policy, data boundary, action
boundary, and next gate. It accepts no executable, argv, endpoint, SQL, path,
credential, or action field and performs no probe, process launch, network
request, persistence, capture, or host change. See
[the integration hub contract](docs/integration-hub.md). Runtime orchestration
remains a separate review boundary.

The core demonstration needs neither root nor Administrator. Windows evaluation
must use synthetic inputs until native compatibility and privacy gates pass.
The dashboard remains read-only and loopback-bound; no remote exposure exception
is created. External application installation is not evidence that MEGALODON
has gained that application's protection or detection capability.

Software/rule/signature downloads require a deliberate maintenance process,
not telemetry uploads. The bundled IANA snapshot has no runtime network or
automatic update path; replacing it is a separate reviewed repository change,
not a service lookup. Keep raw captures, sensor logs, SQLite data, and personal
paths out of repository and Drive evidence packets. Redaction does not authorize
sharing. Upstream licensing/platform sources and exact configuration requirements
are recorded in the baseline; do not silently bundle restricted components.

Acceptance requires Linux regression evidence, native Windows tests and ACL/UI
readback, installed-tool compatibility where applicable, and independent human
review. Issue #3's review-control gate remains separate from green CI. Nothing
here authorizes a firewall operation, driver installation, scheduled task,
remote listener, autonomous response, merge, release, or deployment.
