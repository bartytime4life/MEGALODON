# Unified roadmap: repository reconciliation

## Issue-state correction — 2026-09-25

GitHub issue readback at
[`main@eb6176cdfda43b912f39b3e31b6f3f0fbe1431af`](https://github.com/bartytime4life/MEGALODON/commit/eb6176cdfda43b912f39b3e31b6f3f0fbe1431af)
(2026-09-23T22:44:50Z, merged [#403](https://github.com/bartytime4life/MEGALODON/pull/403)):
**one** open issue exists,
[#345](https://github.com/bartytime4life/MEGALODON/issues/345) (native macOS
`STORAGE_PATH:DATABASE_CHANGED` diagnosis). Zero open pull requests. This
corrects the "#260, #261, and #327 remain open" / "#327 is open" /
"#261 remains open" phrasing still below (2026-09-21 and earlier) and in the
Zeek/Ollama rows of the 2026-09-23 register directly beneath this note: those
three issues closed on 2026-09-22, one day before that register's own pin.

- [#260](https://github.com/bartytime4life/MEGALODON/issues/260) (Ubuntu
  release-candidate evidence plan) closed via merged
  [#366](https://github.com/bartytime4life/MEGALODON/pull/366) with
  disposition **PARTIAL**: the nine-check/two-artifact packet, artifact
  notice/license review, operator drill and exact-candidate owner/independent
  disposition remain undelivered per the issue's own closing comment.
- [#261](https://github.com/bartytime4life/MEGALODON/issues/261) (Ollama/Qwen
  provider acceptance) closed via merged
  [#364](https://github.com/bartytime4life/MEGALODON/pull/364) and
  [#378](https://github.com/bartytime4life/MEGALODON/pull/378). #378 adds a
  `local_model_readiness` packet that cross-checks the existing binding,
  identity, containment, evaluation and request contracts for internal
  agreement; the canonical `config/model-bindings/qwen.unbound.json` still
  reports `UNBOUND / OWNER_MODEL_BINDING_NOT_RECORDED`, and #378's own body
  lists evidence-origin authentication, loaded-runtime-byte attestation,
  independent security acceptance and owner final acceptance as HOLDs it does
  not clear. Issue closure records that the tracked infrastructure gap is
  filled, not that a model is bound or accepted.
- [#327](https://github.com/bartytime4life/MEGALODON/issues/327) (Zeek
  producer profile and schema-drift qualification) closed via merged
  [#350](https://github.com/bartytime4life/MEGALODON/pull/350), which is an
  explicit placeholder scaffold (`zeek-PLACEHOLDER-UNSELECTED-conn-json-v1`,
  declared version `0.0.0`) matching the shape of the qualified Suricata
  producer contract. It selects no real producer version, does not touch
  `megalodon/offline/zeek.py`, and does not cover the TSV adapter path. No
  successor issue tracks the remaining owner-selection gate at this readback.

No new open issue currently tracks the residual #261/#327 gaps described
above; treat that as a tracking gap, not a signal the gaps closed with their
issues. This section adds no runtime code, schema, release, deployment, or
acceptance authority; it corrects only which GitHub issues are open and what
their closing pull requests actually deliver, cross-checked against each
closing PR's own body rather than issue-title text alone.

On this checkout (branch `agent/acceptance-contract-integrity-20260909` after
merging `origin/main` through #403), `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
PYTEST_PLUGINS= PYTEST_ADDOPTS= python -m pytest -ra` reports **3684 passed,
5 skipped, 203 subtests passed, 2 failed** in 66s. Both failures are in
`tests/test_provider_containment.py`
(`test_nothing_listening_is_reported_as_no`,
`test_loopback_listener_is_observed_and_self_owned`) and reproduce because
this sandbox container exposes no `/proc/net/tcp6` at all (no IPv6 stack),
which the module's own conservative-by-design `listening: "unknown"`
handling for an unreadable table reports honestly rather than guessing "no";
the module's other tests pin exactly that behavior as intended. This is a
sandbox artifact of this run, not a code regression, and is not evidence
about any other host.

## Current suite claims and acceptance register — 2026-09-23

Implementation inventory basis:
[`28436055449f8d7ba0662da699da24c53153ba09`](https://github.com/bartytime4life/MEGALODON/commit/28436055449f8d7ba0662da699da24c53153ba09),
read from fetched `origin/main` on 2026-09-23. This includes the #385 heartbeat
observation correction; the earlier inventory at `758648c` is superseded.
Source paths in the suite-wide table refer to that baseline; the companion
detail below has its own later source pin. This reconciliation corrects catalog
descriptions without adding runtime capabilities. **OBSERVED source**
means the implementation and named tests were inspected, not that every test
was rerun or an installed system was accepted. Current GitHub issue/check,
Drive and hosted Site states were not refreshed for this register. A closed
issue, merged PR, test fixture or passing synthetic check is not an acceptance
receipt. Older readbacks below retain their original dates and scope.

This is the full-suite coordination index. The
[security control register](../SECURITY_REVIEW.md#open-control-register) still
owns delivered, explicitly declined and outstanding security dispositions;
[Ubuntu candidate coverage](ubuntu-candidate-coverage.md) owns release evidence;
and the linked specialist contracts own their input and authority boundaries.
Do not create another release schema or silently promote proposed capabilities.
P1 means reconcile or validate an existing claim before expanding it; P2 means
separately scoped follow-up. Priorities grant no host or publication authority.

For each pytest selection below, run `python -m pytest -ra <listed paths>` from
the repository root in its supported Python environment, with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTEST_PLUGINS=''` and `PYTEST_ADDOPTS=''`.
`not_run` means that row's complete selection was not run for this register;
source presence is not a substitute. The bounded catalog verification is
recorded separately below. Use synthetic fixtures only; installed producers,
real telemetry, model calls and host changes require their separate gates.

| ID / priority | Exact source and observed implementation | Reproducible selection / current evidence | Missing work or acceptance gate |
| --- | --- | --- | --- |
| CORE / P1 | [capture](../megalodon/capture.py), [detector](../megalodon/detector.py), [service](../megalodon/service.py): bounded sample/JSONL metadata and three fixed detections with atomic service-to-ledger decisions. | `not_run`: `tests/test_capture.py tests/test_detector.py tests/test_service_acceptance.py`; [synthetic detector receipt](detector-acceptance.md). | Representative privacy-reviewed replay and false-positive measurement; sustained resource/capture-loss evidence. Synthetic counts do not prove operational efficacy or continuous monitoring. |
| STORE / P1 | [storage](../megalodon/storage.py), [CLI recovery workflow](../megalodon/sqlite_recovery_workflow.py): private bounded audit, explicit retention and backup/restore. | `not_run`: `tests/test_storage.py tests/test_storage_failures.py tests/test_sqlite_recovery_runtime.py tests/test_sqlite_recovery_native_failures.py`. | Operator retention values and retained recovery drill; high-write WAL, physical exhaustion, hard-kill/power-loss, clock rollback and platform confidentiality evidence. See [recovery contract](sqlite-recovery-contract.md). |
| HUD / P1 | [dashboard](../megalodon/dashboard.py), [traffic](../megalodon/dashboard_traffic.py), [assets](../megalodon/dashboard_assets.py): loopback telemetry reads, history, filters and reports. Separate AI and installer routes mean the entire HUD is not read-only. | `not_run`: `tests/test_dashboard.py tests/test_dashboard_store.py tests/test_dashboard_traffic.py tests/test_dashboard_history.py tests/test_dashboard_boundaries.py`; real browser: `python tests/browser_native_profile.py` in the [prepared browser environment](dashboard-browser-acceptance.md). | Verify mutation authorization and operator UX at the candidate head. The heartbeat correction below does not establish whole-HUD operator acceptance, capture health or remote-control readiness. |
| DESKTOP / P1 | [local installer](../megalodon/local_install.py), [tool installer](../megalodon/tool_installer.py), [heartbeat](../megalodon/tool_heartbeat.py): per-user bootstrap plus separate fixed install/start recipes. #385 prevents unknown observations from appearing healthy, marks stale checks grey, refuses expired cache success and excludes unobserved history gaps; green means observed presence, not health. | Full selection `not_run`: `tests/test_local_install.py tests/test_local_setup.py tests/test_tool_heartbeat.py`. **VERIFIED heartbeat subset:** `tests/test_heartbeat_observation.py tests/test_tool_heartbeat.py` — 23 passed below. | Installation and service changes need explicit operator authority. Presence, running, configured, connected and accepted are different states. Failed-upgrade and host-specific package/service/operator acceptance remain separate from synthetic heartbeat checks. |
| OFFLINE / P1 | [TShark](../megalodon/offline/tshark.py), [Zeek](../megalodon/offline/zeek.py), [Community ID](../megalodon/offline/community_id.py): Linux bounded offline adapters and non-authoritative grouping. | `not_run`: `tests/test_offline.py tests/test_zeek_producer_contract.py`; [Zeek producer scaffold](../contracts/zeek-conn-log/v1/producer/README.md). | Intended installed TShark revision; exact owner-selected Zeek build/field set, real JSON and TSV fixtures, schema drift, loss/asymmetry and CLI/report evidence. The placeholder `0.0.0` profile is not a qualified producer. |
| SURICATA / P1 | [raw-EVE converter](../megalodon/offline/suricata_eve.py), [consumer](../megalodon/offline/suricata_consumer.py), [projection](../megalodon/suricata_projection.py): pinned 8.0.7 alert-only completed-file conversion, envelope intake, durable publication/reconciliation and read-only startup view. | `not_run`: `tests/test_suricata_raw_eve.py tests/test_suricata_consumer_runtime.py tests/test_suricata_reconciliation.py tests/test_dashboard_suricata.py`. | Exact installed producer and operational privacy/loss acceptance. No sensor, watcher, mixed-EVE firehose, ruleset manager or IPS is supplied. See [producer contract](../contracts/suricata-eve/v1/producer/README.md). |
| ANALYSIS / P2 | [reference loader](../megalodon/reference/loader.py), [offline triage](../megalodon/offline/triage.py), [posture](../megalodon/posture.py): pinned context, synthetic evaluation and deterministic baseline/anomaly analysis. | `not_run`: `tests/test_reference_data.py tests/test_anomaly_triage.py tests/test_baseline_comparison.py tests/test_posture.py`. | Reviewed snapshot maintenance and representative efficacy evidence. IANA assignments and static posture are context, not observed services, live host assessments or threat verdicts. See [reference data](reference-data.md) and [anomaly pipeline](anomaly-pipeline.md). |
| EXCHANGE / P1 | [STIX reader](../megalodon/threat_context.py), [SIEM projections/writer](../megalodon/siem_export.py): bounded local context and ECS/OCSF output; SOAR remains inert contract only. | `not_run`: `tests/test_threat_context.py tests/test_siem_export.py`; [exchange contract](external-exchange-contract.md). | Verify all-or-nothing publication on write failure before claiming that guarantee. No TAXII/feed client, SIEM delivery, collector control, credentials, retries or response authority. |
| AI / P1 | [original advisory](../megalodon/qwen_advisory.py), [anomaly command](../megalodon/offline/anomaly.py), [broker](../megalodon/ai_broker.py), [provider](../megalodon/ai_provider.py): separate optional bounded policies, operator CLI and token-gated HUD, fixed tools and private receipts. | `not_run`: `tests/test_advisory.py tests/test_anomaly_advisory.py tests/test_ai_control.py tests/test_dashboard_ai_control.py tests/test_local_model_readiness.py`; [AI control plane](ai-control-plane.md). | Owner-selected artifact/alias, loaded identity, provider containment, authenticated signed-corpus results and independent disposition. [Readiness](local-model-readiness.md) can establish packet consistency, not accepted operation. No firewall application follows. |
| LIFECYCLE / P2 | [alert engine](../megalodon/alert_lifecycle.py), [recurrence preview](../megalodon/automation_schedule.py): process-local transitions/inert outbox and pure bounded schedule calculations. | `not_run`: `tests/test_alert_lifecycle_engine.py tests/test_automation_schedule.py tests/test_automation_rrule_boundaries.py`. | Schedule semantics need exact-head regression evidence; persistent lifecycle identity/storage/UI wiring and scheduler/workers/delivery remain separate proposed slices. See [wiring survey](alert-lifecycle-wiring-survey.md) and [automation contract](automation-contract.md). |
| TOOLS / P1 | [capability catalog](../megalodon/capabilities.py), [hub](../megalodon/hub.py), [readiness](../megalodon/readiness.py): static plans and bounded executable-presence observations. | **VERIFIED synthetic checks** within the focused run below: `tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py`; [integration hub](integration-hub.md). | Python/SQLite are core; Git maintains a checkout. TShark, Zeek, Suricata, Scapy, nftables and Ollama/Qwen retain their separate scopes above/below. ClamAV is manual; osquery, Nmap, OSSEC, Greenbone, Zabbix and Nagios have proposed ingestion relationships. Docker/Compose serve only the chosen Greenbone route. Installation is not integration. See [individual companion claims](#individual-companion-claims) for versions, prerequisites, contracts, checks and gates. |
| RESPONSE / P1 | [firewall](../megalodon/firewall.py): finite inert nftables plans and fixed live-apply refusal. | `not_run`: `tests/test_firewall.py`; [security containment gate](../SECURITY_REVIEW.md#evaluation-release-firewall-containment-65). | Preserve refusal. A future restoration requires separately reviewed durable intent, exact authority, readback, expiry, rollback and uncertain-outcome reconciliation. No live firewall test or host operation is authorized here. |
| PLATFORMS / P2 | [Windows job](../.github/workflows/windows-synthetic-core.yml), [macOS sample job](../.github/workflows/macos-m1-synthetic.yml): additive exact-head synthetic lanes exist; Linux remains the reference. | `not_run`: `tests/test_windows_core_acceptance.py tests/test_platform_baseline.py`; hosted/native runs need their own exact-head receipts. | Windows Server CI is not Windows 11 W1 acceptance; obtain NTFS/loopback/browser evidence. macOS needs the separate architecture, JSONL/browser and privacy receipts. Native offline adapters need new reviewed designs. See [Windows](windows-core-acceptance.md) and [macOS](macos-core-acceptance.md) gates. |
| SITE / P1 | [Site mirror](../site/README.md): disconnected reference console, manual local readiness import and browser-local notes; no local telemetry feed. | `not_run`: `node --test site/tests/*.test.cjs`; [source/deployment receipt](site-source-alignment.md). | Fresh exact-version deployment/source comparison and rendered acceptance if publication is requested. Repository tests do not prove hosted parity or grant external access. |
| RELEASE / P1 | [release collector](../tools/ubuntu_release_evidence.py), [packet generator](../tools/release_evidence_packet.py), [coverage index](../tools/ubuntu_candidate_coverage.py): evidence tooling and ephemeral wheel/sdist workflows exist; Apache-2.0 source/package metadata is delivered. | `not_run`: `tests/test_ubuntu_release_evidence.py tests/test_release_subjects.py tests/test_release_evidence_packet.py tests/test_ubuntu_candidate_coverage.py tests/test_license_metadata.py`. | Complete nine checks/two artifacts, retained operator recovery and authenticated seven-gate coverage at one candidate. [Release evidence](ubuntu-release-evidence.md) and artifact notice/license review remain distinct from source licensing. No tag, release, merge or deployment follows. |

### Individual companion claims

**OBSERVED source on 2026-09-23:** this expansion was inspected at
[`main@7ddb96d559ffc204e30eb2fbe06b6eb577fead66`](https://github.com/bartytime4life/MEGALODON/commit/7ddb96d559ffc204e30eb2fbe06b6eb577fead66).
It extends the existing register; it does not refresh the other suite rows or
their historical test results. Platform statuses come from the
[capability catalog](../megalodon/capabilities.py); workflow input/output and
authority come from the [hub declarations](../megalodon/hub.py) and
[hub contract](integration-hub.md#closed-workflow-map). Linux is the reference.
Windows and macOS do not inherit Linux acceptance; `other` below includes macOS.
Upstream availability, package ranges and example model tags are not qualified
MEGALODON versions. **UNKNOWN** means no accepted integration version is recorded.

Only Python 3.11+ with SQLite is required for the synthetic core; Git maintains
a source checkout. The [setup guide](companion-setup.md) makes Docker Engine and
Compose prerequisites only for the selected Greenbone container route. None of
the thirteen companions below is required to open the HUD. The
[download index](software-downloads.md) owns publisher links; installation and
service changes require separate operator authority. The
[fixed maintenance recipes](../megalodon/tool_installer.py) are distinct from
data integration: default-disabled, token-gated HUD maintenance can install
selected packages or start selected existing services. A table's absent importer
or sensor-control integration does not deny those separate maintenance actions.

The named test selections are reproducible targets, **not_run for this
documentation pass**, not installed-tool acceptance. Run them using the pytest
environment above. The common catalog selection is
`tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py`; it checks
static scope and bounded discovery only. Proposed rows cite the existing hub's
input/output proposals: no versioned runtime importer or reader contract is
claimed where one has not been delivered. Stored, installed, running, connected,
healthy and verified remain separate states.

| Companion / claim status and outcome | Platform and version claim | Prerequisites and configuration | Input/output and privacy boundary | Reproducible check / evidence; remaining gate |
| --- | --- | --- | --- | --- |
| **Wireshark/TShark — OBSERVED optional adapter:** inspect saved packet metadata with [TShark](../megalodon/offline/tshark.py); Wireshark GUI use is separate. | Linux adapter; Windows manual saved-capture use; other unsupported. Candidate accepted version **UNKNOWN**. [Historical receipt](offline-analysis.md#recorded-prepared-host-receipt): TShark 4.2.2, package `4.2.2-1.1build3`, at `7ad539c`, not this candidate. | Reviewed system `/usr/bin/tshark`; non-root, capability-free Linux, private input/output roots and external process containment. Keep capture permission disabled; no Python analyzer dependency. | Permitted PCAP/PCAPNG → private `offline-run-v1` packet reports. Fixed fields only; no payload, protocol tree, capture hash, live capture or name lookup. | `tests/test_offline.py`; separately authorized `MEGALODON_TEST_TSHARK=1 ... -k system_tshark_headers_only` as documented in [offline validation](offline-analysis.md#validation-and-evidence-limits). Gate: exact installed revision, containment and representative compatibility evidence; a header-only pass is narrower. |
| **Zeek — OBSERVED optional importer:** [closed JSON/TSV `conn.log`](../megalodon/offline/zeek.py) → flow evidence. | Linux; Windows guest-only; other unsupported. Accepted producer **UNKNOWN**. [Producer scaffold](../contracts/zeek-conn-log/v1/producer/README.md) uses deliberate `0.0.0`; README's pinned 8.0.10 build recipe is not producer qualification. | Separately produced completed file, private roots, Linux non-root admission, explicit format and actual declared version. MEGALODON never launches Zeek. | Closed connection fields → private flow reports with `operator_declared_unverified` version provenance. Flow counts stay separate from packet counts; no arbitrary protocol logs. | `tests/test_offline.py tests/test_zeek_producer_contract.py`; scaffold fixtures are synthetic. Gate: owner-selected exact build/fields, real JSON and TSV positives/negatives, drift, loss/asymmetry and CLI/report receipts, tracked by [#327](https://github.com/bartytime4life/MEGALODON/issues/327). |
| **Suricata — OBSERVED implemented alert intake:** completed-file conversion, durable publication/reconciliation and read-only startup view. | Linux APIs; Windows contract-only; other unsupported. Raw-EVE profile exactly **8.0.7**; installed acceptance **UNKNOWN**. | [Producer contract](../contracts/suricata-eve/v1/producer/README.md): completed dedicated alert-only EVE, payload/packet/application metadata disabled, exact digest and closed producer/run/ruleset identity; non-root capability-free main thread, private file and pre-created private store. | Pinned EVE or [contract envelope](../contracts/suricata-eve/v1/README.md) → immutable external-alert publication → explicit transaction/reconciliation receipt. No mixed firehose, watcher, ruleset management or IPS. [Startup projection](suricata-evidence-projection.md) does not refresh automatically. | `tests/test_suricata_raw_eve.py tests/test_suricata_consumer_runtime.py tests/test_suricata_reconciliation.py tests/test_dashboard_suricata.py`. Gate: exact installed producer, operational privacy/loss and retained evidence; package installation or service start does not satisfy it. |
| **Scapy — OBSERVED optional capture:** [selected-interface metadata](../megalodon/capture.py). | Linux only; Windows/other unsupported. Declared extra `scapy>=2.5,<3`; accepted installed artifact **UNKNOWN**. | Capture extra in the actual MEGALODON interpreter; explicit interface and separately granted capture authority. [Standalone setup](companion-setup.md#scapy-install-without-capture-privileges) does not establish the HUD environment's package state. | Scapy packets → validated `PacketEvent` metadata through a bounded queue. No raw packet storage, crafting or injection feature; no payload-derived hashes. | `tests/test_capture.py`; [setup checks](companion-setup.md#what-the-indicators-actually-mean) distinguish package metadata from capture permission. Gate: least-privilege native capture, backpressure/loss and sustained resource receipts. |
| **Ollama/Qwen — OBSERVED optional advisory policies:** original [run-count API](local-model-advisory-contract.md), separate [anomaly](anomaly-triage.md) and [AI CLI/HUD](ai-control-plane.md). | Original workflow Linux `manual_only`, Windows contract-only, other unsupported; no accepted provider/model version. `qwen2.5:7b` is a mutable example, not selected artifact identity. | Separately operated local provider; fixed literal IPv4 loopback, explicit opt-in, reviewed registry/artifact binding and policy-specific authorization. Original API has no CLI; separate AI entry points must satisfy their own contracts. | Bounded approved metadata projection → untrusted advisory/receipt; separate optional private AI writes do not mutate core telemetry. No raw traffic, model-granted command/firewall authority or assumed provider containment. | `tests/test_advisory.py tests/test_anomaly_advisory.py tests/test_ai_control.py tests/test_dashboard_ai_control.py tests/test_local_model_readiness.py`; [readiness evidence](local-model-readiness.md). Gate: owner-selected artifact, loaded identity, provider containment, signed corpus and independent disposition ([#261](https://github.com/bartytime4life/MEGALODON/issues/261)). |
| **nftables — OBSERVED plan only:** [finite inert response plans](../megalodon/firewall.py). | Linux planning; Windows/other unsupported. Runtime version not applicable: no live backend runs. | Validated global non-allowlisted target, bounded reason/expiry and policy. Installing `nft` is not required to format plans and grants no apply authority. | Validated target → planned action record/review commands only. Every retained live-apply route is refused before host/process work. | `tests/test_firewall.py`; [containment gate](../SECURITY_REVIEW.md#evaluation-release-firewall-containment-65). Preserve refusal. Restoration needs separately reviewed durable intent, authority, expiry, readback, rollback and uncertain-outcome reconciliation. |
| **ClamAV — OBSERVED standalone manual companion:** local file scanning outside MEGALODON. | Linux/Windows manual-only; other proposed. Qualified integration version **UNKNOWN**; no importer exists. | Optional scanner, separately reviewed engine and signature-database currency; package dependencies may add an updater. [Platform guidance](platform-baseline.md#6-optional-analyzers-and-w2-guest-configuration) is not permission to scan or update. | Hub `manual-file-scan`: no MEGALODON input/output, file content/hash, scan-result intake, removal or quarantine. | Common catalog selection; [hub scope](integration-hub.md#closed-workflow-map). Gate for any integration: versioned result contract, retention and false-positive review; operator evidence must distinguish engine and signatures. |
| **osquery — PROPOSED endpoint inventory:** hub `endpoint-inventory`. | Proposed on Linux/Windows/other; integration version **UNKNOWN**. | Optional vendor package and role/query-pack decision; no configured MEGALODON query, daemon, schedule or remote enrollment. | No current input/output. [Hub proposal](../megalodon/hub.py) requires closed endpoint fields; no arbitrary SQL, process environment or command-line dump. | Common catalog selection establishes only the proposed scope. Gate: versioned table/field/query contract, privacy review and bounded positive/hostile fixtures before an importer. |
| **Nmap — PROPOSED inventory import:** hub `network-inventory-import`. | Linux/Windows proposed; other unsupported; integration version **UNKNOWN**. | Optional standalone package; future operator-supplied completed report. HUD installation does not run a scan or choose targets. | [Hub proposal](../megalodon/hub.py): completed XML → source-qualified inventory; no current importer, scan launch, NSE/script or service-banner intake. | Common catalog selection. Gate: versioned XML/field contract, entity/parser defenses, explicit size limits, privacy review and adversarial fixtures before runtime import. |
| **OSSEC — PROPOSED host-integrity import:** hub `host-integrity-import`. | Linux/Windows proposed; other unsupported; integration version **UNKNOWN**. | Owner chooses server/agent and vendor configuration. Separate authorized HUD maintenance can start fixed existing OSSEC/Wazuh units; no importer is thereby configured. | [Hub proposal](../megalodon/hub.py): completed JSON alerts → source-qualified findings; no current intake, file content, process environment, unrestricted logs, enrollment or active-response integration. | Common catalog selection; `tests/test_tool_management.py` tests separate maintenance authorization synthetically. Gate: versioned alert contract, redaction/privacy review, size limits and representative hostile fixtures. |
| **Greenbone — PROPOSED vulnerability-report import:** hub `vulnerability-report-import`. | Linux proposed; Windows guest-only; other unsupported; integration version **UNKNOWN**. | [Selected container route](companion-setup.md#greenbone-prepare-inspect-then-explicitly-start) needs separately reviewed Docker/Compose, images, mounts, ports, privileges and feeds. Configuration, images, containers and healthy scanner are distinct observations. | [Hub proposal](../megalodon/hub.py): completed GMP XML → source-qualified review candidates; no importer, scanner/feed/task/target control, credentials or raw-response intake. | Common catalog selection and `tests/test_companion_setup.py` cover static/synthetic guidance. Merged [#397](https://github.com/bartytime4life/MEGALODON/pull/397) makes saved compose metadata alone yield unknown installation; `tests/test_greenbone_presence.py tests/test_tool_heartbeat.py` target that distinction without Docker inventory. Delivered observation code is not installed acceptance. Gates: versioned XML/entity/size/privacy contract, separately authorized installation and feed/login/health evidence. |
| **Zabbix — PROPOSED availability reader:** hub `zabbix-availability-read`. | Linux/Windows proposed; other unsupported; integration version **UNKNOWN**. | Select classic agent, Agent 2 or server explicitly; the fixed HUD package recipe selects `zabbix-agent`. No MEGALODON endpoint, credential or poller is configured. | [Hub proposal](../megalodon/hub.py): future source-qualified availability summary; no current API input, host/event intake, acknowledgement, configuration change or remote command. | Common catalog selection; `tests/test_tool_management.py` covers separate fixed maintenance, not service health. Gate: read-only API/field allowlist, credential policy, request budgets and failure/fixture review. |
| **Nagios Core — PROPOSED availability reader:** hub `nagios-availability-read`. | Linux proposed; Windows guest-only; other unsupported; integration version **UNKNOWN**. | Separately configured server/plugins or reviewed `nagios4` package; installation may start a web service. No MEGALODON CGI endpoint or credentials configured. | [Hub proposal](../megalodon/hub.py): future source-qualified availability summary; no current CGI/status-archive input, poller, command pipe, acknowledgement or remote command. | Common catalog selection; `tests/test_tool_management.py` covers separate fixed maintenance only. Gate: read-only CGI/field contract, credential policy, request budgets and failure/fixture review. |

This expansion records source and acceptance targets only. Documentation/link
checks cannot establish any installed, connected, healthy or accepted companion.
The verification receipts that follow belong to the earlier suite-wide
reconciliation, not new executions of these per-companion selections.

### Reconciliation verification

**VERIFIED on 2026-09-23 after merging `2843605`:** Linux / CPython 3.12.3,
in the isolated candidate checkout with the catalog correction in this change.
The focused command below passed **64 tests**, including its synthetic UI-map
checks. The separate heartbeat selection passed **23 tests**. Compilation and
both static CLI commands also passed;
the CLI receipts retained false execution/installation/network effects and
the existing platform statuses. The final candidate commit/tree belongs in the
PR or handoff receipt, not a self-referential source pin in this document.

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  PYTHONDONTWRITEBYTECODE=1 python -m pytest -ra -p no:cacheprovider \
  tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py \
  tests/test_integration_map_states.py tests/test_documentation_currentness.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  PYTHONDONTWRITEBYTECODE=1 python -m pytest -ra -p no:cacheprovider \
  tests/test_heartbeat_observation.py tests/test_tool_heartbeat.py
python -m compileall -q megalodon tests
python -m megalodon capabilities --platform linux
python -m megalodon hub-plan --platform linux
```

The earlier 64-test result for candidate `a8ff7b0` remains historical evidence;
the reruns above establish the refreshed candidate's focused check results.
All named Python check paths and 75 local documentation links in the three
reconciled documents were checked for existence. These checks do not supply
the unperformed per-row, browser, installed-tool, platform or release evidence.
The release index must retain `not_performed` evidence pointers for absent
receipts. Its seven gates are artifact notice/license, SBOM, provenance,
operator recovery, optional-source behavior, owner disposition and independent
disposition. The independent-evidence requirement in that contract does not
reinstate the separately declined server-enforced approval floor.

## Historical readback — 2026-09-21, later observed main

At `main@97c5798f53b539bbcb487eaa7c8ff07ac0344041` (tree
`6384a3fe4e743cbce274d654b413f8a07c1e4cff`), #334 has merged the
browser-local ingestion report change: a valid all-source run receipt can be
exported when the separate traffic projection is unavailable. It preserves
the v1/v2 API and store schema and does not record adapter identity or
accepted/rejected input counts. This merge is a code disposition, not a
sensor-health or release-acceptance receipt. Issues #260, #261, and #327
remain open at this readback.

## Historical readback — 2026-09-21, main after #333

At `main@374190a57791f9ac19afeefd78afbd18d9b68919` (tree
`376a6151a11faae2e055ec711a081de785e3f9e2`), #330 adds verification
before AI action-status readback, #331 retains exact-head temporary wheel/sdist
subjects, #332 adds source-qualified ingestion-run v2 reads, and #333 corrects
current Site/wiki copy about the optional AI POST. GitHub reports CI, Linux
browser acceptance, CodeQL, and wiki publication workflows successful on this
commit. Those are exact-revision execution receipts, not host, producer,
operator, platform, or release acceptance.

Issues #260, #261, and #327 remain open at this readback. The release packet
generator already produces digest-bound SBOM/provenance output from a complete
candidate; the newer subject workflow alone does not supply that candidate's
nine-check packet or disposition. No Zeek producer profile has been selected
in #327. The model containment gate in #261 remains open. The last documented
owner-only Console publication is v30 in
[the Site receipt](site-source-alignment.md); repository source changes and a
successful repository workflow do not establish a newer hosted version or local
telemetry connection. See the [proposed opportunity map](system-opportunity-map.md)
for candidate slices and their separate evidence gates.

## Historical readback — 2026-09-21

At `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`, the local desktop
installer and guided checks from #323 are merged, while the owner-only hosted
Console v30 remains a disconnected reference surface. GitHub records #259
closed after scoped owner acceptance; that accepts the bounded synthetic
registry/report implementation, not independent review or operational accuracy.
#327 is open for the exact Zeek producer profile and schema-drift evidence left
after #258 closed. #260 remains open despite #318–#322 and #324/#326 tooling
and synthetic CI recovery receipts. #261 remains open with an unbound collector.
See the [current alignment record](document-alignment-2026-09-21.md) for the
telemetry test limit and the [Site receipt](site-source-alignment.md) for the
publication identity. Due dates, release, sensor operation, and model
acceptance are not supplied by this readback.

## Historical readback — issue acceptance reconciliation

OBSERVED on 2026-09-20 at
[`main@f3bf5d6a08c64363651e17fae07ff2e88386c0c0`](https://github.com/bartytime4life/MEGALODON/commit/f3bf5d6a08c64363651e17fae07ff2e88386c0c0).
PRs #301–#307 are merged. The prior repair backlog below is historical.

| Issue | Delivered | Remaining gate |
| --- | --- | --- |
| #258 / M02 (closed completed) | #299 Community ID vectors and pure grouping; #302 bounded inputs, valid seeds and distinct-source matches. | Issue body still lists owner-selected producer profile and closed schema-drift fixtures; closure does not prove them. installed-producer/loss evidence remains separate. CLI integration is still proposed. |
| #259 / M02 | #294 registry/report and #296 corrected fixture mapping plus displayed corpus totals regression. All three rule versions remain 1.0.0; registry metadata is 1.0.1. | Exact-head scoped owner/independent acceptance remains unrecorded. Representative operational accuracy is outside this synthetic delivery and must not be inferred. |
| #260 / M03 | Currentness, SQLite recovery and Apache-2.0 prerequisites are delivered; #297 provides the closed evidence contract and incomplete identity collector. | Complete nine-check/two-artifact evidence, retained operator drill, SBOM/provenance and exact-candidate disposition. The collector crash and stale license blocker were repaired by merged #306. |
| #261 / M04 | #300 containment contract plus #301 corpus identity and deterministic malformed-input denials. | Exact owner-selected model bytes, authorized host collector, signed adversarial corpus and independent candidate security review. Collection remains unbound. |

GitHub now shows #259–#261 open and #258 closed completed. The latter
still describes missing producer qualification; preserve that evidence gap. No issue closure,
independent review, release, deployment or host acceptance is implied by tests.
The merged #260 collector repair preserves historical blocked-license packets but emits
`not_assessed` for new identity collection because it does not inspect license
or artifact metadata. All other gates and effect prohibitions remain fixed.

The local setup changes are delivered by merged PR #307. The hosted
Console is a separate owner-private static publication; current source and
publication identities are recorded in [the Site receipt](site-source-alignment.md).
See [the document alignment record](document-alignment-2026-09-20.md) for local,
GitHub, Wiki and Drive ownership. Matching source does not establish sensor
health or operator acceptance.

## Historical readback — merged contracts, remaining acceptance

OBSERVED on 2026-09-20 at
[`main@9c2675b8dbc8bbae319525803e28a0542031c8b2`](https://github.com/bartytime4life/MEGALODON/commit/9c2675b8dbc8bbae319525803e28a0542031c8b2).
The supplied architecture and research roadmap are historical planning inputs.
The September 17 baseline and delivery sequence below are retained as historical
evidence, not a current backlog or authority to operate a sensor or model.

| Track | Implementation now present | Remaining gate |
| --- | --- | --- |
| License | [#298](https://github.com/bartytime4life/MEGALODON/pull/298) merged Apache-2.0 and package metadata; #255 is closed. | Release artifacts, SBOM/provenance and publication are separate; do not repeat the old no-license blocker. |
| Suricata | Completed raw-EVE profile/converter, durable consumer and read-only projection are in source. | Native producer and operator acceptance remain distinct from synthetic tests; no sensor or watcher is started. |
| Zeek / #258 | [#299](https://github.com/bartytime4life/MEGALODON/pull/299) merged the offline Community ID API and literal vector tests. | Exact producer profiles, schema-drift fixtures and CLI/report integration remain open. Current correlation requires follow-up on invalid seeds, bounded source consumption and source identity. |
| Detector evidence / #259 | Registry metadata 1.0.1 and the corrected synthetic fixture mapping are present. | Exact-head owner/independent acceptance and representative operational evidence are separate; synthetic counts are not accuracy. |
| Ubuntu / #260 | Closed release-evidence schema, validator and incomplete identity collector are present. | Operator recovery and retained release evidence remain incomplete; identity collection does not publish a release. |
| Local model / #261 | [#300](https://github.com/bartytime4life/MEGALODON/pull/300) merged containment-contract scaffolding. The collector still emits unbound. | Corpus-ID completeness/schema parity and malformed-input refusals require repair. No exact model selection or provider containment acceptance follows from this contract. |
| Defense Console | Owner-private v26 is deployed from Sites source `64d626ac40e30e1bd10d18569918364a90e7176a`. | Three repository mirror files lag at this main pin; this candidate restores parity. No local runtime feed or host control is added. |

The open issue readback contains #258, #259, #260 and #261. PR #300 merged during
this inspection; its earlier non-draft/open state and original review findings
remain historical evidence. Its merged validator still accepts a missing
candidate corpus ID and an overlong ID, despite the review findings. Do not
equate merged scaffolding or passing checks with acceptance of #261.

The next reviewable work is bounded correlation repair, containment validator
repair, parser-test isolation, and this source/document alignment. Each belongs
in an `agent/*` draft PR with current-head tests. These independent slices do
not select model artifacts, invoke tools on the host, or expand runtime authority.
See [the current Site receipt](site-source-alignment.md) for exact source and
deployment identities. This readback is not a validated currentness manifest.

## Historical baseline — September 17

Status: **OBSERVED implementation baseline with remaining acceptance gates**, refreshed 2026-09-17.
Repository basis: [`main@77f082a0548e64f97090c94dd11503a68ca05d99`](https://github.com/bartytime4life/MEGALODON/commit/77f082a0548e64f97090c94dd11503a68ca05d99).
This record reconciles the supplied *MEGALODON — Unified Architecture, Safety,
and Roadmap* with code, contracts, and live GitHub issue dispositions. It does
not adopt the supplied document wholesale or replace the specification and
security review. Tests described below are existing evidence surfaces, not a
new claim of native operational acceptance.

## Historical synthesis assessment

Keep the local, metadata-only evidence appliance as the immediate product.
Separate source observations, fixed detections, policy plans, model advice, and
presentation. Grow integrations through bounded completed evidence with explicit
provenance and failure states. Preserve a read-only loopback dashboard, inert
firewall plans, operator-owned retention, and advisory-only AI. Core operation
must not require a subscription, vendor account, or hosted Site.

## Historical corrections against the September 17 baseline

| Source claim | Disposition at this pin | Repository evidence / remaining gate |
| --- | --- | --- |
| Trust-kernel work must first implement firewall containment, separate dashboard reads, and atomic events | **STALE as implementation backlog.** These controls exist; their acceptance limits remain separate. | `megalodon/firewall.py`, `dashboard_connections.py`, `storage.py`, `tests/test_storage_failures.py`, and the open-control register in `SECURITY_REVIEW.md`. Do not recreate them or claim every operating environment is accepted. |
| Suricata is only contract/import-level and needs its durable consumer | **STALE.** Completed-file reader, explicit atomic consumer, and exact unknown-commit reconciliation exist. | `megalodon/offline/suricata.py`, `suricata_consumer.py`, `suricata_store.py`; closed [#221](https://github.com/bartytime4life/MEGALODON/issues/221) and [#231](https://github.com/bartytime4life/MEGALODON/issues/231). No raw-EVE converter, watcher, sensor launch, or IPS follows. |
| An absolute storage ceiling is still undecided | **PARTLY STALE.** The dedicated Suricata v1 store has a fixed logical 512 MiB ceiling: 131,072 pages of 4 KiB, with no freelist credit. | `contracts/suricata-eve/v1/consumer/README.md`. Per-transaction reservation and free-space checks apply. This is not a whole-disk ceiling, retention duration, automatic deletion policy, or budget for every store. |
| The model process has no reachable filesystem writes or network egress beyond loopback | **UNPROVED.** Client admission and transport are bounded; the separately operated Ollama/model process is not confined by these Python controls. | `docs/model-containment-review.md`: provider identity, loaded-artifact attestation, host-wide concurrency, and direct/transitive provider egress need separate evidence. |
| Every Qwen invocation already lands in the evidence store | **NOT IMPLEMENTED by the original advisory API.** Caller-visible bounded receipts do not imply durable persistence. | `megalodon/qwen_advisory.py` and `docs/model-containment-review.md`; startup receipt display is separate from invoking or storing model results. |
| Q2 follow-up can reuse an advisory while no model output may become later model input | **CONFLICT.** The supplied Q2 wording does not define a consistent input boundary. | Keep Q2 proposed. Any future follow-up needs a closed question enum and original deterministic evidence references; no free-text prior model output or session transcript is authorized by this record. |
| Automation can progress from an inert contract to annotations, schedules, or notifications | **PROPOSED only.** Existing schema tests do not establish a runtime parser/evaluator/executor. | `contracts/automation/v1`, `docs/automation-contract.md`. Each runtime stage needs its own bounded contract, deterministic refusal cases, receipts, and review. |
| Apache-2.0 is settled pending sign-off | **UNDECIDED.** No root license is present at this pin; a recommendation is not a grant. | A license choice and any required attribution review remain an explicit owner decision. No license text is installed by this change. |
| macOS TShark support is a path/packaging question | **INCORRECT for the current Linux boundary.** Admission and descriptor access are Linux-specific. | `offline/common.py` requires Linux and `/proc/self/status`; `offline/tshark.py` uses `/proc/self/fd`. The corrected [macOS proposal](macos-core-acceptance.md) requires a native design and acceptance record. |

The source's references to a nonexistent section 16 and its inconsistent input
count are editorial defects, not missing repository requirements. Its supplied
incident case study is research input; this pass does not authenticate or repeat
its external incident claims. The existing source-pinned containment review
preserves the distinction between supplied bytes and publisher authenticity.

## Historical dependency-ordered delivery

Slices 1–3 were delivered by merged PRs #239/#241/#243 and corrected by #244.
Their presence is not installed-producer, visual or operational acceptance.
PR #245 delivered the simpler HUD launch. PR #269 delivered the bounded STIX
reader; PR #270 integrated the complete currentness schema; PR #271 delivered
the SQLite recovery contract. Deployment evidence remains separately pinned in
the source-alignment receipt.

| Priority | Candidate | Acceptance boundary |
| --- | --- | --- |
| 1 | **Delivered #239:** read-only Suricata evidence projection | Read one existing private exact-schema store, preserve descriptor identity and snapshot locks, bound query and output work, validate source-qualified run/receipt/alert data, and return unavailable without partial rows on ambiguity. Never invoke a consumer or migrate/repair a store. |
| 2 | **Delivered #241:** local tool-readiness report | Explicit operator command, fixed executable names, bounded PATH inspection, no execution/network. Executable presence is neither an installation attestation, compatibility proof, nor running-service health. Unchecked is distinct from missing. |
| 3 | **Delivered #241/#243; corrected by #244:** Defense Console readiness and lifecycle guidance | Hosted telemetry stays unavailable with no generated observations. Accept only a bounded locally selected readiness report in page memory; manual notes persist separately in browser storage. No upload, host probe, command execution or runtime data connection. Preserve private Site identity. |
| 4 | Installed-producer acceptance | Operator-supplied authorized completed evidence, exact producer/version/platform, representative negative cases and timing/resource receipts. A green synthetic parser test or PATH presence report cannot satisfy this gate. |
| 5 | Next adapter or AI field expansion | One closed versioned input proposal, privacy review, explicit source/count units, hostile fixtures, and independent review before broader operational claims. Keep Q2/Q4 and automation side effects proposed. |

The local dashboard and hosted Defense Console are separate products. The
dashboard may read bounded local evidence through explicit operator startup;
the Site is a static reference console with no runtime feed. A Site update or matching GitHub
source mirror cannot establish local sensor liveness or operational acceptance.

## Historical high-level sequence

A historical selected-field currentness capture at 2026-09-17T16:35:48Z–16:35:50Z,
against `2e5099fcec2d1a08007efab70b4607cd5ba652ac`,
observed eight open issues (#254–#261), zero open pull requests, zero releases,
four successful exact-head checks, three successful exact-head workflows, and
active ruleset 22394782 with strict required `test` but zero required
approvals. The manifest validated against the pinned commit/tree. It is not
owner acceptance or independent review, so #254 remains an explicit disposition
gate.

The later `77f082a` readback found the same eight open issues and no open PRs
or releases; all four exact-commit checks and three workflows succeeded.
PR #271 is merged, so recovery-contract delivery is complete even though #256
remains open. See [the alignment record](document-alignment-2026-09-17.md) for
the observation scope; this update is not a new validated currentness manifest.

| Order | Work | Smallest safe outcome |
| --- | --- | --- |
| 0 | #254 currentness disposition | Preserve the immutable receipt and obtain explicit maintainer disposition; do not promote selected-field validation into broad acceptance |
| 1 | #256 SQLite recovery | Contract and standalone engine are on `main`; review the explicit operator-workflow PR and retain native failure/operator acceptance as later evidence gates |
| 2 | #255 license decision | Obtain the owner's actual choice and only then align root/package/SBOM metadata; no release follows automatically |
| 3 | #257 Suricata raw-EVE profile | Select one exact producer profile and close a privacy-minimal converter contract before code or sensor integration |
| 4 | #258 Zeek/correlation qualification | Pin producer profiles and treat Community ID as a non-authoritative grouping hint |
| 5 | #259 detector registry/evaluation | Version the three existing deterministic rules and require corpus, denominator, quality, and uncertainty context |
| 6 | #260 Ubuntu release evidence plan | Define an evidence packet after recovery and license gates; do not tag, publish, or deploy |
| 7 | #261 Ollama/Qwen containment | Post-RC operator-host acceptance only; no new model, tool, persistence, or action authority |

This ordering favors recovery and truthful claims over new ingestion breadth.
The telemetry and model tracks may be designed in parallel, but their runtime
or acceptance claims remain blocked by their named prerequisites.

## Evidence and ownership handoff

For every candidate record the base and final head, changed paths, exact test
commands/results, inherited or environmental failures, draft PR URL and hosted
checks. For Site changes record project/version/source commit, unchanged access,
browser evidence, mirror equality and rollback version. Update the existing
Drive coordination log with those facts while preserving historical checkpoints.

Repository source changes use `agent/*` draft PRs. Green CI and an independent AI
review remain distinct from an owner merge decision and native operational
acceptance. No merge, release, protection change, model request, host operation,
automatic retention, or live-response authority is created by this roadmap.

Before adopting any later source-document stage, resolve its contradictions and
pin it again against current code. A blank approval appendix stays blank until
the actual owner makes that decision.
