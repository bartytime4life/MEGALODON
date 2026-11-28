# Current state and evidence boundaries

## November 26 source and acceptance map

**Source basis (America/Chicago)** — [`main@e2bafb3f52d5d7f827557d83b43c81017f645a4b`](https://github.com/bartytime4life/MEGALODON/commit/e2bafb3f52d5d7f827557d83b43c81017f645a4b),
tree `ccf2d076c7c0f2b9fd56b5727770498176cdcffe`, merged through [PR #918](https://github.com/bartytime4life/MEGALODON/pull/918).
All 1,393 tracked blobs were matched and the reconstructed Git tree reproduced
the same tree ID. The [catalog](documentation-map.md) accounts for all 234
tracked Markdown paths. The specification and security review define the
contracts. Historical records below retain the scope and source of their runs.

**How to read this page.** **OBSERVED** means source, GitHub state or a hosted
result was directly read. **VERIFIED** means a named check was rerun in this
audit. A successful scoped test supports only the property and environment
it exercised. Source availability, a configured installation, native execution,
independent review, owner approval, and release or publication each require
their own evidence.

### What the source implements

| Area | OBSERVED at the pinned tree | Evidence still needed |
| --- | --- | --- |
| Network core and storage | Bounded packet metadata admission, fixed SYN/port/DNS heuristics, private SQLite, linked event/detection/run records, retention and bounded reads. Extra [threat signals](threat-detection.md) use separate inputs and settings. [Core specification](../SPECIFICATION.md) · [storage](storage-layout.md) | Representative traffic and independent labels, source-loss accounting, long-running load, and production alert workload. No packet payloads or payload-derived hashes in the packet evidence ledger. |
| HUD and evidence | Linux loopback UI, Findings and provenance inspector, Sensors, connection views, retained history, reports, Help, and protected Setup/actions. Evidence readers and separately authorized action routes have distinct contracts. [HTTP contract](dashboard-http-contract.md) · [operator guide](wiki/operator-guide.md) | Current owner-PC installation and accessible real-data walkthrough, including degraded source states and assistive technology. Hosted browser cases use controlled fixtures. |
| Offline and optional sources | Bounded JSONL and offline TShark/Zeek inputs, pinned Suricata closed-profile producer/reader/consumer contracts, scoped optional ClamAV/Lynis/AIDE/Nmap workflows and configured background collection. [Offline analysis](offline-analysis.md) · [companions](background-tools.md) · [integrations](integration-hub.md) | Distinguish tool presence, running status, admitted data and producer qualification. [Zeek #445](https://github.com/bartytime4life/MEGALODON/issues/445) remains open. Fixture coverage does not qualify native Zeek or a deployed Suricata, live capture or IPS. |
| Layered detection | Retained pattern reviews combine bounded evidence and disclose uncertainty. The documented rolling comparison produced reviews in **8 of 10 investigation-useful** and **4 of 10 ordinary** synthetic cases. Five indeterminate cases are outside those denominators. [Evaluation and oracle limits](layered-evaluation.md#current-rolling-window-comparison) | Representative independent labels, deployment exposure/time denominators, false-alarm workload, source overlap and loss, and acceptance thresholds. Synthetic results are workload examples. |
| Host posture and live watches | Baseline/drift checks, observations for process ancestry, credentials, egress, containers, persistence, boot, binaries, logs and other host surfaces. Scoped Linux exec/connect tracing adds short-lived observations and exposes gaps. [Scheduling and coverage](scheduling.md) · [host security](host-security.md) | Distribution/kernel/privilege coverage, buffer loss under sustained load, native journald rotation/vacuum, and clean install or upgrade acceptance. A baseline describes the files and state read during a window. |
| Host reports and local review | `megalodon report` reads saved checks, watch history, incidents and setup. `megalodon review` can run a fixed command after confirmation. Listener and web-root watch history uses separate bounded logs. [Report and review](security-report.md) · [results source](../megalodon/results.py) | Account coverage, migration under live operating conditions, operator workflow and alert delivery. A missing input is visible where the report can identify it. |
| Response and containment | The metadata planner records plans. The Linux HUD has separate scoped, expiring containment and host-input policy. The host response engine records decisions in shadow mode. Separate policy-pinned, default-off enforcement can act only through configured guards and records recovery outcomes. [Host protection](host-protection.md) · [response](response-engine.md) · [enforcement](enforcement.md) | Native installed-policy verification and rollback evidence. Timed process recovery depends on later invocations, access to the same journal and usable target identity. [Recovery acceptance](enforcement-recovery-acceptance.md) |
| Artifacts and external delivery | Explicit confined structural/file identification and optional YARA inspection, evidence collection and verification, opt-in alerts/heartbeat/shipping/fleet workflows. [File inspection](file-inspection.md) · [collection](evidence-collection.md) · [shipping](evidence-shipping.md) · [fleet](fleet.md) | Per-tool confinement and coverage on the target, review of enabled destinations and data, delivery failure and recovery drills. Host bundles and reports can contain sensitive local artifacts and are distinct from packet metadata. |
| Model preparation and AI | Explicit installed-model discovery/selection, saved preferences, offline component verification/staging, and a fixed no-telemetry diagnostic have separate scopes. Canonical record is `UNBOUND`, operator decision `NOT_RECORDED`, and operational generation is refused before provider access. [Binding record](../config/model-bindings/qwen.unbound.json) · [runtime fence](qwen-runtime-unbound.md) | [#446](https://github.com/bartytime4life/MEGALODON/issues/446) was closed by the owner on November 2 Central time. Authenticated provenance, loaded-byte attestation, signed corpus/model evaluation, provider confinement, independent review and acceptance remain unproved by that closure. [#732](https://github.com/bartytime4life/MEGALODON/issues/732) remains open for model staging/library follow-up. |
| Stage 0 | Fresh-process application latch refuses named entry points, with source/wheel parity and scoped effect tripwires. Fixed companion schedules and host watch schedules belong to other modes. [Application fence](offline-analysis.md#stage-0-application-entry-fence--issue-750) | [#750](https://github.com/bartytime4life/MEGALODON/issues/750) remains open for immutable OS-level isolation, complete entry/descendant coverage and acceptance. A process-local fence cannot undo work that already started. |
| Installation and recovery | Per-user Linux installation, loopback service and opt-in login startup. Explicit SQLite backup/restore targets new databases. Host backup/test receipt validation is read-only and leaves `restore_eligible` false. [Setup](local-pc-setup.md) · [SQLite recovery](sqlite-recovery-contract.md) · [host receipt scope](host-backup-evidence.md) | An installed workstation, real backups and restore drill, native storage fault evidence and an operator-approved recovery path. Synthetic recovery and source/wheel smoke cover bounded scenarios. |
| Platform, delivery and publication | Linux is the reference. Windows and macOS have narrow synthetic CI jobs. Packaging, Wiki projection and release-evidence workflows have separate entry points. The Site is a separately published address-free snapshot viewer. [Platform gates](platform-baseline.md) · [release evidence](ubuntu-release-evidence.md) · [Site scope](../site/README.md) | Native platform parity, an accepted release packet and current Wiki/Site parity. GitHub's releases endpoint returned no published releases when inspected. |

### Recent merged changes and pending work

| Change | What the evidence covers | Remaining limit |
| --- | --- | --- |
| [#902–#908](https://github.com/bartytime4life/MEGALODON/pull/908) | Bounded kernel-record use for short-lived process/connection observations and scheduler wiring, with unit and synthetic controls for attribution and dropped records. | Kernel/privilege variants, read failures, actual ring-buffer loss, and live workload under the installed service profile. |
| [#909](https://github.com/bartytime4life/MEGALODON/pull/909), [#910](https://github.com/bartytime4life/MEGALODON/pull/910), [#912](https://github.com/bartytime4life/MEGALODON/pull/912) | Checks separate findings from execution or delivery errors. Enforcement orders containment before collection when both are authorized. Log/journal checks preserve the reviewed verification floor. An unreadable required archive digest remains a gap and is retried. | Native journald rotation and vacuum acceptance remain open. Scope includes reviewed logs that could be read and compared. [Log guide](log-integrity.md) |
| [#911](https://github.com/bartytime4life/MEGALODON/pull/911), [#913](https://github.com/bartytime4life/MEGALODON/pull/913)–[#917](https://github.com/bartytime4life/MEGALODON/pull/917) | Guided review and coverage-aware reports. Listener/web-root history is retained per watch. Fixture regressions cover one-time migration, retries, order, file admission and lock refusal. | The migration lock is advisory. A report reflects saved results, accessible configuration and recorded gaps. [Merged #918](https://github.com/bartytime4life/MEGALODON/pull/918) restores tamper finding summaries, subjects, timestamps and gaps after the limited #916 output. [Tamper guide](tamper-detection.md) |


### Merged after this audit basis

These are not part of the pinned audit above. Each PR's own description lists its tests, mutation controls
and hosted checks; the hosted checks passed on each merged head, and its merged tree was compared with the
tree tested before it.

| Change | What the evidence covers | Remaining limit |
| --- | --- | --- |
| [#920](https://github.com/bartytime4life/MEGALODON/pull/920) ([`208923a`](https://github.com/bartytime4life/MEGALODON/commit/208923acef2c27629d377834f065e89664a6ca01)) | OBSERVED: `AUTOMATED_CAMPAIGN` in the response engine, for one address making many different attempts of several kinds within minutes, CRITICAL across two sensors. The network sensor keeps running when one packet crosses four rules. Unit, property and end-to-end tests with mutation controls. [Guide](automated-campaigns.md) | Measures pace and breadth, not who is typing. One address at a time: a campaign spread over many addresses is not joined. No live attack traffic. |
| [#921](https://github.com/bartytime4life/MEGALODON/pull/921) ([`87cb4e4`](https://github.com/bartytime4life/MEGALODON/commit/87cb4e44ceff2d9a92c4cd99fd3479fcba608e4f)) | OBSERVED: a finding counts against the address it says acted (its source, or its one address), so an address under attack is never taken for the attacker. | A finding naming several addresses and no source is not counted. |
| [#922](https://github.com/bartytime4life/MEGALODON/pull/922) ([`f84f4c8`](https://github.com/bartytime4life/MEGALODON/commit/f84f4c8b32efadc09991cade0e206556150ebcd8)) | OBSERVED: the auth log as a response source (`auth_log`). Failed-login bursts, spraying and logins after failures are decided once across passes, and count toward campaigns. `ignore_addresses` keeps the owner's scanners out. Tests use findings built from placeholders. [Response engine](response-engine.md) | No live auth log in the test environment; reading logs is covered by auth-review's own tests. Suricata alerts stay out of responses. |
| [#923](https://github.com/bartytime4life/MEGALODON/pull/923) ([`237c606`](https://github.com/bartytime4life/MEGALODON/commit/237c6069265e73eb3aed02f34203eb76ca060c86)) | OBSERVED: agent lures (`canary plant --lure`). A note to AI agents names an account no one has; a login tried as it is `LURE_FOLLOWED` (CRITICAL), with how soon after the note was read. A campaign that followed a lure is reported as AI-driven. [Host tripwires](host-tripwires.md#agent-lures-catching-an-ai-agent-at-work) | Evidence, not certainty: a careful person can follow a lure, and so would the owner's own assistants if one were planted where they work. `noatime` filesystems give no timing. |
| [#924](https://github.com/bartytime4life/MEGALODON/pull/924) ([`4296200`](https://github.com/bartytime4life/MEGALODON/commit/429620032fc83cfa1c2468339875dba14dbf9ebd)) | OBSERVED: the systemd journal as the auth log (`auth_log = "journal"`, `auth-review --journal`), read only with `journalctl`. A repeat within auth-review's cooldown is held back across passes, however a read starts. The real `journalctl` (systemd 255) was run against an empty journal. | No journal with entries was available, so reading real entries is not shown; the format is the documented `short-iso-precise`, and a line of it parses. |
| [#925](https://github.com/bartytime4life/MEGALODON/pull/925) ([`3481efc`](https://github.com/bartytime4life/MEGALODON/commit/3481efc0b08dc92b4bb6ccdb94819886d7d43b00)) | OBSERVED: web lures. The lure also names a page no page links to; a request for it in an nginx or Apache access log is `LURE_FOLLOWED` (`web-review`, `web_log`). `--web-readable` lets a web server running as another user serve the note. | No real web server was available; the formats are shown read with placeholder lines. Only lure pages are looked for. Behind a reverse proxy on another machine, the address logged is the proxy's. |
| [#927](https://github.com/bartytime4life/MEGALODON/pull/927) ([`c9e0e31`](https://github.com/bartytime4life/MEGALODON/commit/c9e0e31b25ee4cc6bfc0bc02e6dba1a1348c02ee)) | OBSERVED: campaigns are also judged by network (a /24, or an IPv6 /64, settable). Different attempts from at least `min_addresses` (3) of its addresses within minutes are one `AUTOMATED_CAMPAIGN`, which names and would block those addresses, never the network. This lifts #920's one-address limit. [Guide](automated-campaigns.md#spread-over-one-network) | One network at a time: a campaign spread over unrelated networks (a botnet, residential proxies) is not joined. Unrelated attackers in one busy shared range would be. No live attack traffic. |
| [#928](https://github.com/bartytime4life/MEGALODON/pull/928) ([`26947a1`](https://github.com/bartytime4life/MEGALODON/commit/26947a15947f3b5becc8400384621e4a8331ebc8)) | OBSERVED: follow-up to #927, which merged before these were pushed. One attack repeated from many addresses no longer crowds out different ones in what a network keeps between passes. An address ignored or protected since its attempts no longer counts toward its network, and is not named. | As for #927. |
| [#929](https://github.com/bartytime4life/MEGALODON/pull/929) ([`500120b`](https://github.com/bartytime4life/MEGALODON/commit/500120b2a4afcddefa7a8d56f6b1e58690e30b1a)) | OBSERVED: opt-in live check (`MEGALODON_TEST_LIVE_JOURNAL=1`). Placeholder messages written to a real systemd 255 journal are read back: auth and authpriv but not daemon, times in UTC to the microsecond, and the engine reads it without a gap. This lifts #924's empty-journal limit. [Host tripwires](host-tripwires.md) | Run here against a journald started by hand, not by systemd. |
| [#930](https://github.com/bartytime4life/MEGALODON/pull/930) ([`01af530`](https://github.com/bartytime4life/MEGALODON/commit/01af5307ffa6c482e0067f3b8392f043e7fa66cd)) | OBSERVED: opt-in live check (`MEGALODON_TEST_LIVE_NGINX=1`) against a real nginx 1.24, its workers as `nobody`. Only a `--web-readable` note is served. nginx's own access log is read, and a request for the lure's page is `LURE_FOLLOWED`, decided by the engine. This lifts #925's no-real-server limit for nginx. | Apache not tried. Loopback only. |
| [#931](https://github.com/bartytime4life/MEGALODON/pull/931) ([`5531622`](https://github.com/bartytime4life/MEGALODON/commit/5531622f0de89243f351142f07aca781b205dd5d)) | OBSERVED: opt-in live check (`MEGALODON_TEST_LIVE_SSHD=1`) against a real OpenSSH 9.6 sshd and journal. One password login as the lure's account, from a client reading none of the machine's SSH settings. sshd's own lines are `LURE_FOLLOWED`, each of its two messages alone too, and the engine decides it. | The journal, not rsyslog's `/var/log/auth.log`: installing rsyslog was not allowed here. Loopback only. |
| [#932](https://github.com/bartytime4life/MEGALODON/pull/932) ([`df0b4b6`](https://github.com/bartytime4life/MEGALODON/commit/df0b4b6f6d38ddd4f1fd96dd072afc7bb8bf74da)) | OBSERVED: the live sshd check also tries five wrong passwords then a key login as `nobody`, from a loopback address of the run's own. The result is `AUTH_SUCCESS_AFTER_FAILURES`, CRITICAL, decided by `guessed-login` with the account linked, and the same lines with one refusal fewer are not reported. Each run decides only its own logins. | A key login after password failures; `Accepted password` is covered by auth-review's own tests. Loopback only. |
| [#937](https://github.com/bartytime4life/MEGALODON/pull/937) ([`6bbc6ea`](https://github.com/bartytime4life/MEGALODON/commit/6bbc6ea3b5b41ef1fff69d8b0b215ed6353731fd)) | OBSERVED: the live nginx check behind a real nginx reverse proxy. Without `real_ip`, the server logs the proxy's address. Trusting that proxy alone, it logs each client, and the engine names and links the client. A forged `X-Forwarded-For` is ignored, through the proxy or not. The docs give that configuration, lifting #925's proxy limit. [Host tripwires](host-tripwires.md) | Apache's `mod_remoteip` not tried. No chain of proxies or CDN ranges. Loopback, plain HTTP. |

#933 to #936 came from a separate line of work and were merged in between. Their rows give what their own
descriptions say; their merged trees were not compared here with a tree tested before them.

| Change | What its description covers |
| --- | --- |
| [#933](https://github.com/bartytime4life/MEGALODON/pull/933) ([`5355979`](https://github.com/bartytime4life/MEGALODON/commit/53559792641a7e98700c05e58dda123daff7ee21)) | Per its description: a protected shared address (this PC, its gateway or DNS server) no longer lets one destination's finding corroborate another's. It stays in evidence. [Response engine](response-engine.md) |
| [#934](https://github.com/bartytime4life/MEGALODON/pull/934) ([`e037356`](https://github.com/bartytime4life/MEGALODON/commit/e03735689cf07c844345495e1d26523405d378ea)) | Per its description: malformed Zeek decoder output is rejected before any of that sample is forwarded or kept, and the sampler no longer stays stuck collecting. [Background tools](background-tools.md) |
| [#935](https://github.com/bartytime4life/MEGALODON/pull/935) ([`a0db475`](https://github.com/bartytime4life/MEGALODON/commit/a0db475f06d59f0931a366bb286e837538df6e7b)) | Per its description: a HUD AI cancellation is bound to the request it was made for, so a late one cannot abort a newer request. [AI control plane](ai-control-plane.md) |
| [#936](https://github.com/bartytime4life/MEGALODON/pull/936) ([`2040ecb`](https://github.com/bartytime4life/MEGALODON/commit/2040ecb1d530bdc4dc2f2b0f67731420b4115e38)) | Per its description: two native test fixtures keep the copied `sleep` program's name, so multicall implementations run them. |

### Local audit evidence

- **VERIFIED** the repository static audit and Python compilation, CLI and
  report help, Wiki projection, catalog coverage and local Markdown links.
  Static results cover source structure and navigation targets. Browser
  interaction evidence is in the hosted lane below.
- **VERIFIED** the 25-case layered replay at this source. It produced 39
  individual candidates and 13 layered reviews, checked 841 evidence
  references and found zero provenance errors or permutation differences.
  The operational accuracy fields remain unset.
- **Local test boundary.** The selected regression suite, including the #918 output regression,
  reported 1,299 passes, eight native skips and one `STORAGE_PATH:UNSAFE_ANCESTOR` failure
  also reproduced at the untouched source. The full suite on the preceding #917 tree
  was non-green in this sandbox. Path-ancestry and permission restrictions
  dominated its failures and setup errors. The hosted checks below provide
  the separate CI results for the exact source.

### Checks tied to the source and preceding tree

**OBSERVED** at the #918 tree. The final candidate
`b00451b9682066c3edef9d8c55d6180b4d350ca2` matches the
merged tree above. Its hosted runs passed [CI](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508274),
[Linux browser](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508202),
[CodeQL](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508332),
[Stage 0 parity](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508233),
[Qwen scoped acceptance](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508427),
[host protection](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508512),
[Windows synthetic core](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508280),
[macOS synthetic sample](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508457),
[Ubuntu rehearsal](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508196),
[Linux installer](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508281),
[installed-wheel recovery](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508226),
and [release subjects](https://github.com/bartytime4life/MEGALODON/actions/runs/45881508542).
These are hosted candidate checks with the same scope boundaries described
below. The separate [merged-source host protection run](https://github.com/bartytime4life/MEGALODON/actions/runs/45882904676)
also passed. See the [merged commit's checks](https://github.com/bartytime4life/MEGALODON/commit/e2bafb3f52d5d7f827557d83b43c81017f645a4b/checks)
for subsequent push results.

**OBSERVED** at the preceding #917 tree. The earlier November 26 push runs
point to `4b39b0820bfc527de88813f999ddefcea643d93c`. PR #917's final head,
`ed04179b157bc904abc479d77a81a53bcdbf75de`, has the identical Git tree. Its
PR-only runs remain candidate runs, even though the source bytes match.

| Check | Result and scope |
| --- | --- |
| [Push CI 45879634003](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634003) | Passed source tests, wheel smoke, CLI, native loopback sender/socket-holder and measured cadence fixtures, offline layered replay, and isolated SQLite lock acceptance. The two identity-artifact jobs were skipped on this push. |
| [Linux browser 45879634094](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634094) | Passed the pinned hosted browser matrix. Covers controlled HUD interaction and recorded browser cases. |
| [CodeQL 45879634015](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634015) | Passed the Python analysis job. The underlying security alert disposition and independent review are separate evidence. |
| [Host protection 45879634039](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634039) | Passed packet checks in fresh user/network namespaces. Owner-PC policy and coexistence remain separate. |
| [Qwen 45879634032](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634032) · [Stage 0 parity 45879634009](https://github.com/bartytime4life/MEGALODON/actions/runs/45879634009) | Passed scoped disabled/UNBOUND checks and named source/wheel projection parity. No real-provider or general OS containment result follows from either lane. |
| [Windows 45876858011](https://github.com/bartytime4life/MEGALODON/actions/runs/45876858011) · [macOS 45876857515](https://github.com/bartytime4life/MEGALODON/actions/runs/45876857515) | Passed synthetic core/sample fixtures at the final candidate. Full Windows/macOS support remains outside that evidence. |
| [Linux installer 45876858013](https://github.com/bartytime4life/MEGALODON/actions/runs/45876858013) · [recovery rehearsal 45876857532](https://github.com/bartytime4life/MEGALODON/actions/runs/45876857532) · [installed-wheel recovery 45876857605](https://github.com/bartytime4life/MEGALODON/actions/runs/45876857605) · [release subjects 45876857565](https://github.com/bartytime4life/MEGALODON/actions/runs/45876857565) | Passed the named hosted fixture/packaging lanes at the final candidate. No owner workstation deployment, real host-file restore, or accepted release was inferred. |

**Lifecycle readback.** The active [main ruleset](https://github.com/bartytime4life/MEGALODON/rules/22394782)
requires strict `test` status and records zero required approving reviews. The
[separate review ruleset](https://github.com/bartytime4life/MEGALODON/rules/24377756)
requests Copilot review for drafts. Branch-protection details returned 403 to
this audit, so those rulesets are the verified read boundary. The project
[owner lifecycle procedure](exact-head-owner-lifecycle.md) remains separate.
The #917 merge head also had two failed and one cancelled lifecycle runs
triggered by issue comments. Those runs and the successful push checks establish
different facts. No independent approval or release is inferred from them.

## Historical November 17 source and candidate

Merged source: [`main@dee4027a8541335f43460d6bef37024606f4bfdf`](https://github.com/bartytime4life/MEGALODON/commit/dee4027a8541335f43460d6bef37024606f4bfdf).
PR #780 delivered finite host-input protection; #779 delivered the qualified
Playwright 1.65.2 profile and fifteen-wheel browser closure. Their source and
hosted validation do not establish installation or live-PC protection.

The [November 17 review candidate](repo-app-review-2026-11-17.md), later merged in
[PR #781](https://github.com/bartytime4life/MEGALODON/pull/781), added an
[offline security-science lab](security-science-lab.md), direct Help routes to
PC protection, truthful library failure/recovery, single-flight library status
and protection-refresh admission/visibility fixes. It also excludes contradictory
comparison-hour copies and explains the actual cadence tolerance in Findings. The documentation
catalog and Wiki source were also refreshed. Candidate verification is reported
at its own PR head.

## November 17 merged host-protection source

Merged in PR #780 after network setup PR #778, the source adds an explicit
stateful Linux host-input policy with client-scoped service exceptions, kernel
lease expiry, receipt-backed apply/check/remove and browser controls. The
operator authorizes a finite policy; packet drops then occur in the kernel
without an AI decision. The core detection planner remains non-mutating.
[Workflow, recovery, tests and coverage limits](host-protection.md).

Source delivery does not establish installation, native OS authorization,
independent review or protection of the user's live PC. The dated sections below
retain their original source and validation scope.

## November 11 source orientation

**Source basis:** [`main@418fa54474f3f77d0758e94aab5735a516d8c43b`](https://github.com/bartytime4life/MEGALODON/commit/418fa54474f3f77d0758e94aab5735a516d8c43b),
tree `f0e47918ed0f6715197e944e6cb18e221ea498d5`. PR [#774](https://github.com/bartytime4life/MEGALODON/pull/774)
merged at `2026-11-12T00:03:54Z` (November 11 in America/Chicago). This is the November 11 reading. The November 26 map above supplies the
current orientation. Earlier sections remain historical at their own pins.

| Task | Implemented behavior | Meaning / guide |
| --- | --- | --- |
| Choose the next evidence task | Guided HUD recommendation, direct Findings/connections/Reports routes, closed optional-app inventory | Uses a validated current snapshot; unavailable, stale, paused, stopped capture and empty sensor windows remain distinct. Navigation and refresh do not start tools. [HUD guide](dashboard-operations.md#read-the-interface-in-evidence-order) |
| Inspect sensor context | Connection-summary guidance works independently of packet-capture state; alert context routes to the connection lens | Sensor observations are separate from the saved Findings queue and from unique incidents. [Source and coverage](background-tools.md) |
| Search and change selection | Query and selection revisions reject obsolete successes and failures; reports retain only the current selection's document and findings | A→B→A and browser-history restoration are covered. [Knowledge](security-knowledge.md), [Reports](efficient-recording-reports.md), [Setup](setup-console.md) |
| Read local learning and setup status | Paused learning is labeled explicitly; failed configuration reads mark Traffic and Local AI unavailable without erasing the saved model | Saved baseline, explanation activity, app heartbeat and model readiness remain separate observations. [Setup](setup-console.md), [learning](security-knowledge.md) |
| Compare historical patterns | Indexed eligible history and exact count-based protocol-share comparisons | No rounded threshold decision, new risk score or field-accuracy claim. [Comparison arithmetic](security-knowledge.md#exact-comparison-arithmetic-and-indexed-history) |
| Read resource percentages and reports | CPU tick deltas aggregate before conversion; intermediate resource means retain precision until final output | Counts, denominators and missing values keep their own meaning. [Recording and reports](efficient-recording-reports.md) |

These changes follow [#769](https://github.com/bartytime4life/MEGALODON/pull/769),
[#771](https://github.com/bartytime4life/MEGALODON/pull/771),
[#772](https://github.com/bartytime4life/MEGALODON/pull/772),
[#773](https://github.com/bartytime4life/MEGALODON/pull/773) and
[#774](https://github.com/bartytime4life/MEGALODON/pull/774). The code paths and
regression selections are indexed in the [refresh record](documentation-refresh-2026-11-11.md).

### Verification and remaining gates

The merged tree is byte-identical to PR #774's tested candidate
`316ece33fe5067eeabf49a9ef5e7fd80ba563e34`. Its recorded local full suite passed
**7,843 tests and 743 subtests**, with **27 explicit native/platform skips**.
The candidate also passed **18 hosted technical checks**, including
[CI](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825489),
[browser acceptance](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825538)
and [CodeQL](https://github.com/bartytime4life/MEGALODON/actions/runs/43120825649).
These remain candidate receipts, not newly executed post-merge or documentation
checks. Synthetic desktop, tablet and phone checks and package verification
have their own [recorded limits](documentation-refresh-2026-11-11.md#application-evidence-carried-forward).

Fresh issue readback found [#750](https://github.com/bartytime4life/MEGALODON/issues/750)
(partial Stage 0 no-effect boundary), [#732](https://github.com/bartytime4life/MEGALODON/issues/732)
(model staging/library follow-up) and [#445](https://github.com/bartytime4life/MEGALODON/issues/445)
(exact Zeek producer qualification) open. This is a dated issue observation,
not permission to operate or a claim that these are the only remaining gates.
Operational model generation remains [UNBOUND](qwen-runtime-unbound.md);
source delivery, owner merge authorization, installation, real sensor/model
acceptance, release and deployment remain separate. The documentation refresh
does not change an installed PC or publish a Site.

## November 9 source orientation

**Source basis:** [`main@d03bc43d13a9f030cfcff7eb8beaea5fc318abae`](https://github.com/bartytime4life/MEGALODON/commit/d03bc43d13a9f030cfcff7eb8beaea5fc318abae).
This section describes the inspected source. It supplies no new hosted CI,
rendered-browser, installed-PC, native-parser or real-model acceptance result.
The October records below retain their original pins and check receipts.

| Task | Implemented source behavior | Boundary / guide |
| --- | --- | --- |
| Inspect a downloaded program | Signed-in Linux HUD submission; bounded structural and identification adapters; completed metadata survives a later adapter's isolation-setup refusal | Optional runtime and host isolation prerequisites; partial coverage stays visible; the submitted program is never launched and receives no safety verdict. [Inspection guide](file-inspection.md) |
| Prepare and review local model files | Explicit installed-model discovery/selection, offline file verification, pinned GGUF staging and source/license review controls | Maintenance and the separate fixed response diagnostic do not activate operational inference. The release fence remains **UNBOUND**, including for other model families. [Model library](model-library.md), [runtime hold](qwen-runtime-unbound.md) |
| Select the Stage 0 application boundary | A one-way, process-local latch exposes the in-memory status command and refuses ordinary CLI dispatch plus named HUD, provider, companion, installer, startup/reopen and native TShark entries | Partial [#750](https://github.com/bartytime4life/MEGALODON/issues/750) implementation; trusted Python entry fences are not OS network/filesystem containment or universal helper coverage. [Exact scope](offline-analysis.md#stage-0-application-entry-fence--issue-750) |

Use a fresh process for Stage 0. Selection cannot stop existing workers or undo
earlier activity; ordinary fresh-process installed operation retains its separate
authority. Synthetic regression coverage and boundary status do not supply
producer qualification, model provenance, loaded-byte verification, independent
review or owner acceptance. Historical issue closure does not lift the model
hold. The maintained guides above describe the current operator steps; the
[November 9 improvement record](project-improvements-20261109.md#follow-up-retained-history-and-setup-focus) preserves its
separate local validation scope.

## October 27 reading

**Source basis:** [`main@7c912322b12fe40fbe92de79b32fdc678054a3da`](https://github.com/bartytime4life/MEGALODON/commit/7c912322b12fe40fbe92de79b32fdc678054a3da);
tree `f56752b3cd5d4aa9e70d058f6474ae6c5a37f862`. Source files were reconstructed
in an isolated snapshot and all **1,033 Git blob identities** matched this tree
before editing. The primary checkout's unfinished application work was preserved.

| Read now | Observed source behavior | Limit |
| --- | --- | --- |
| [Findings](findings-review.md) | Refine a bounded returned page, inspect a finding, request optional local advice and save an assessment | Empty results, severity and model text do not establish safety or malicious intent |
| [Setup](setup-console.md) | Source/tool configuration and selected-model readiness controls | Presence, operation, admitted data and model qualification stay separate |
| [Atlas](live-connection-globe.md) | Recorded send/receive directions at approximate IP locations | Arcs are endpoint illustrations, not physical packet routes |
| [Recovery evidence](host-backup-evidence.md) | Two receipt hashes pinned by a separate operator-controlled trust record | Trust is not independently hash-pinned; rewriting all three files can forge evidence; no host-file restore |
| [Qwen record](https://github.com/bartytime4life/MEGALODON/blob/7c912322b12fe40fbe92de79b32fdc678054a3da/config/model-bindings/qwen.unbound.json) | Canonical owner binding remains UNBOUND / NOT_RECORDED | A working runtime model or zero-effect test does not complete canonical acceptance |

The [three investigation journeys](wiki/investigation-journeys.md) connect these
surfaces. [This documentation pass](documentation-refresh-2026-10-27.md) records
its tests, visual provenance and omissions. The October 22 implementation
inventory below remains historical at its own pin; it is not a fresh hosting,
queue, platform or installed-PC observation.

### October 27 source-head checks

These are observed GitHub results for the exact source SHA, separate from this
documentation candidate's checks:

| Workflow | Result | Meaning |
| --- | --- | --- |
| [CI 40552674917](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674917) | success | Hosted repository checks; not installed-host acceptance |
| [CodeQL 40552674698](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674698) | success | Static-analysis result; not independent security clearance |
| [Qwen zero-effect 40552674943](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674943) | success | Named zero-effect workflow; not real-provider containment or canonical model acceptance |
| [Linux browser 40552674797](https://github.com/bartytime4life/MEGALODON/actions/runs/40552674797) | cancelled | No successful exact-source-head browser result claimed |

## Historical October 22 source orientation

**Documentation basis — October 22, 2026 (America/Chicago).**
Source: [`main@2cb706039724d9ea0bda09cbd3c17698b15ba55c`](https://github.com/bartytime4life/MEGALODON/commit/2cb706039724d9ea0bda09cbd3c17698b15ba55c);
tree `3c4773603fa90e13d627d0fb107b45f8e986b079`.

**OBSERVED** below means source or authoritative external state was read in this
pass. **VERIFIED** requires a named local check and its result. Code presence,
passing CI, approval, merge, publication and installed-host acceptance are
different facts. This page is descriptive; the specification and security
review retain their normative authority.

## What exists at this pin

| Area | OBSERVED implementation | Limit / primary source |
| --- | --- | --- |
| Metadata core | Typed `PacketEvent`, three fixed heuristics, private SQLite audit | No packet payloads or payload-derived hashes. [Models](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/models.py), [detector](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/detector.py), [specification](../SPECIFICATION.md) |
| Linux workspace | HUD, Findings, Sensors, Setup, Reports, Evidence and Help | Core reader and protected action routes have different authority. [HTTP contract](dashboard-http-contract.md) |
| Finding inspector | Finding → linked event → ingestion run; distinct clocks | Bounded returned-page evidence, not sensor liveness. [Control room](control-room-contract.md#qualified-finding-evidence-inspector) |
| History and reporting | Segments, compact summaries, local visual reports and fixed schedules | Defaults: 14 days / 20 GiB; reports 9 AM local time. Gaps and source units remain explicit. [Managed history](managed-evidence.md), [reports](efficient-recording-reports.md) |
| Sources and companions | Twelve catalog entries; bounded TShark, Zeek, Suricata and separate HUD collector paths | Installed/running/configured/admitted are distinct. Static plans execute nothing. [Offline analysis](offline-analysis.md), [background tools](background-tools.md) |
| Host review | Lynis, AIDE, hardening posture, persistence, passive gateway and own-account process/network context | Source-specific coverage and bounds; no compromise verdict. [Host security](host-security.md) |
| Recovery readiness | Validated AIDE projection; missing backups/causality/conflict evidence stays visible | Always `restore_eligible=False`, `backup_state=not_integrated`. [Projection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/recovery_readiness.py), [PR #664](https://github.com/bartytime4life/MEGALODON/pull/664) |
| External backup evidence | Read-only trust/backup/isolated-test receipt admission; raw-byte pins, identities, chronology and expiry | Opens no backup, runs no test and grants no host restore. [Contract](host-backup-evidence.md), [validator](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/backup_evidence.py), [PR #665](https://github.com/bartytime4life/MEGALODON/pull/665) |
| Local models | Optional installed-model selection, bounded explanations, closed proposals; listener admission precedes inventory | Runtime selection is distinct from canonical Airlock acceptance. [Provider](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/megalodon/ai_provider.py), [PR #663](https://github.com/bartytime4life/MEGALODON/pull/663), [model selection](local-model-selection.md) |
| Firewall interfaces | Legacy CLI apply refuses; separate protected Linux HUD temporary containment exists | Documentation grants no permission to operate it. [Defense contract](visual-operations-defense.md) |
| Desktop lifecycle | Private per-user install/update/rollback; managed user HUD; optional login startup | Saved monitoring choices retain separate scope. [Setup](local-pc-setup.md) |
| Browser qualification | Playwright 1.64.0, exact native-focus driver profile and lock from merged #660 | No operational/platform acceptance follows from a dependency repair. [Dependency policy](dependency-policy.md), [browser acceptance](dashboard-browser-acceptance.md) |
| License | Apache-2.0 | Artifact notices, provenance and release gates remain separate. [LICENSE](../LICENSE), [NOTICE](../NOTICE) |

## Hosting observation

The Sites service was re-read in this pass: existing **PC Snapshot Console v67**,
owner-private access configuration, same Site identity and current URL. This is
an **OBSERVED metadata result**, not a rendered browser test or a new deployment.
No Site source, audience or deployment was changed. Current deployment-source
parity and installed-PC revision remain UNKNOWN. The
[documented viewer](../site/README.md) imports address-free summaries into tab
memory and has no live PC connection. Older empty-410 retirement records remain
historical; v67 metadata does not recreate their source proofs.

## Corrections to older orientation material

| Older claim | Present interpretation |
| --- | --- |
| “The whole application is read-only/plan-only” | True for named core reader / legacy CLI interfaces; protected Linux HUD workflows are separate |
| “No scheduler, feed or watcher exists” | General automation remains inert; fixed local schedules, configured collectors and explicit public reference refreshes exist |
| “File changes prove malware or recoverability” | AIDE differences lack malicious causality and host restoration authority |
| “Valid backup receipts mean backups are integrated” | They are external evidence admission only; no executable host-recovery integration |
| “A working local model completes Qwen acceptance” | Runtime selection is separate; canonical record remains UNBOUND / NOT_RECORDED |
| “Playwright 1.64.0 is an open proposal” | Superseded by merged #660; earlier 1.63.0 timeout and macOS fixture failures keep their original run identities |
| “No license” or old issue counts | Historical research; Apache-2.0 exists and live tracking must be re-read |

## Remaining public gates

At this readback there were two open issues and no open PRs before this
documentation branch. These queue facts are dated observations, not acceptance.

| Issue | Gate |
| --- | --- |
| [#445](https://github.com/bartytime4life/MEGALODON/issues/445) | One exact Zeek offline producer qualification; owner selection is not producer acceptance |
| [#446](https://github.com/bartytime4life/MEGALODON/issues/446) | Canonical Qwen binding, zero-effect, containment and evaluation acceptance; [record](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/config/model-bindings/qwen.unbound.json) remains UNBOUND / NOT_RECORDED |

Merged #662 changes the macOS fixture/workflow qualification, not production
ancestry policy. Native JSONL/browser, Intel, second-major-version and retained
operator evidence remain separate in the [macOS M-track](macos-core-acceptance.md).
Neither source presence nor synthetic Windows/macOS jobs establish Linux parity.

## Exact source-head checks observed

GitHub returned these completed results for the exact source SHA above:

| Workflow / run | OBSERVED result / scope |
| --- | --- |
| [CI 39878396530](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396530) | success; repository workflow result, not installed-host acceptance |
| [Linux browser acceptance 39878396547](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396547) | success; hosted browser suite, not a fresh documentation-candidate run |
| [CodeQL 39878396556](https://github.com/bartytime4life/MEGALODON/actions/runs/39878396556) | success; static-analysis workflow result, not whole-product security clearance |

The earlier `0acdf72` browser timeout and #660/#661 macOS `/var` failures
remain in their historical run/PR records. They are not current-head failures.
No native macOS/Windows, release, recovery, producer or real-model acceptance at
this pin is claimed from these three runs. The [owner lifecycle contract](exact-head-owner-lifecycle.md)
retains its workflow-trust and enforcement limits; no protection setting changed.

## What the visuals prove

Original Findings captures come from PR #654, candidate
`424d957472ad121becec635171bc281bec2de995`,
[run 39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
The animated walkthrough adds emphasis to a still image; it is not a recording
of a running session. Other new animations are technical diagrams built from
public constants. [Asset provenance](../assets/docs/README.md) records bytes,
scope and still alternatives. No private workstation or Drive data is published.

The October 1 98.1% write-reduction benchmark is a finite historical synthetic
measurement with increased query p95. It is not a current performance guarantee.
[Tradeoff and source](wiki/engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff).

## Keep the documentation current

Read code/tests at a named revision; update maintained guides when behavior
changes; preserve original dates, pins and results in historical records.
Validate the complete catalog, local links and generated Wiki. The Wiki's
post-merge publisher owns native publication; a draft does not update it live.
[Current polish scope](documentation-polish-2026-10-22.md) and
[earlier October 22 reconciliation](documentation-refresh-2026-10-22.md)
record separate passes, not interchangeable test receipts.
