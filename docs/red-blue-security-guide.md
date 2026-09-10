# Red, blue, and purple security practice

> **Status:** Defensive process guide. MEGALODON currently has no AI model,
> model API, training or fine-tuning pipeline, retrieval/embedding store, or
> autonomous agent. The AI risks below are gates for a future proposal, not
> implemented capabilities or permission to deploy them.

## Purpose and authority boundary

MEGALODON is a local-first network evidence and decision-support system. Its
detections are hypotheses for operator review. They do not establish malicious
intent or authorize a host change.

Red-team work in this project is adversarial validation within a separately
authorized scope: reviewers try to make a defined component violate a
documented invariant using synthetic or explicitly authorized evidence.
Blue-team work implements the defensive controls and, within a separately
authorized operating scope, operates and checks them. Purple-team work turns
each finding and fix into shared threat language, regression evidence, and an
independently reviewed release gate.

An untrusted red-team input or finding, model response, dashboard event,
detection, or imported record must never directly:

- apply a firewall change;
- start a scan, sensor, analyzer, or arbitrary process;
- select an executable, argument list, credential, endpoint, SQL statement, or
  filesystem path;
- write provider state;
- bind a dashboard beyond the approved loopback boundary; or
- promote its own change, approve its own pull request, or waive a release gate.

A blue-team code change may define a fixed executable or argument list only
inside the repository's existing review and acceptance boundaries. The change
does not grant itself operational authority and must not derive commands,
credentials, paths, endpoints, queries, or actions from an untrusted artifact.

The current dashboard is an operator-driven local read surface, not a promise of
continuous security-operations monitoring. Live firewall application remains
unsupported. Its stored-priority comparison is a sequential read-side count
signal, not an alert lifecycle or a capture/ingestion-health claim.

## Team responsibilities

| Team | Responsibility in MEGALODON | Required output |
| --- | --- | --- |
| Red | Test whether a scoped component can violate privacy, integrity, availability, or authority boundaries | A reproducible finding with affected invariant, bounded fixture, observed result, impact, and no live side effect |
| Blue | Implement and operate the smallest defensive control that closes the finding | A reviewable patch, fixed failure behavior, focused regression, recovery note, and updated contract |
| Purple | Translate the finding into shared coverage and verify the control remains effective | Threat-to-control mapping, regression ownership, red-team retest, exact-head CI evidence, and independent review |

Red and blue are functions, not permanent identities. The same person may help
both functions during development, but issue
[#3](https://github.com/bartytime4life/MEGALODON/issues/3) still requires an
eligible independent reviewer for the approval gate.

## Current defensive validation map

These are repository controls, not instructions for attacking a live system.

| Surface | Red-team validation objective | Blue-team control | Regression evidence |
| --- | --- | --- | --- |
| Event and configuration input | Confirm malformed, type-confused, oversized, or unexpected fields cannot expand authority | Closed models, strict parsing, bounded integers and text, validated IP addresses, fixed detector inputs | `tests/test_model_boundaries.py`, `tests/test_validation.py`, `tests/test_config.py`, `tests/test_cli.py` |
| Firewall boundary | Confirm every retained apply route refuses before configuration, host inspection, executable lookup, privilege work, or process creation | Plan-only nftables-shaped output, fixed arguments, allowlist precedence, global-address checks, finite proposed expiry, fixed live-apply refusal | `tests/test_firewall.py`, `tests/test_cli.py`, `tests/test_service.py`, `tests/test_service_acceptance.py` |
| Dashboard listener | Confirm unsafe or ambiguous binds and untrusted `Host` values fail before routing or storage access | Numeric IPv4 loopback only, exact canonical `Host` validation, no mutating data route, bounded polling and result limits | `tests/test_dashboard_binding.py`, `tests/test_dashboard.py` |
| Dashboard storage | Confirm a missing, unsafe, replaced, linked, or incompatible database cannot be initialized or migrated by the reader | Separate existing-database reader, private POSIX path and inode/entry checks, hardlink and sidecar validation, SQLite `mode=ro`, `query_only`, exact-schema validation, and a five-field projection; independent review and native Windows ACL evidence remain open in [#66](https://github.com/bartytime4life/MEGALODON/issues/66) | `tests/test_storage.py`, `tests/test_dashboard_binding.py`, `tests/test_dashboard.py` |
| Dashboard triage semantics | Try to make bounded returned rows look like a complete alert stream, incident state, or capture-health proof; inject malformed client responses and invalid timestamps | Closed response-shape validation, exact local filters, at most 12 time bins, explicit stale preservation, and a sequential stored-count signal that never claims unique/new/resolved alerts | `tests/test_dashboard.py` |
| Storage and run integrity | Confirm failed writes, interruption, full-disk behavior, incompatible schemas, and partial runs cannot be mistaken for reconciled success | Per-event event/detection/action/link/counter commits, post-commit detector state, explicit exhaustion/limit/interruption/failure reasons, uncertain-commit poisoning, bounded orphan readback, pinned reconciliation, and verified v1/v2 backup migration are implemented; power-loss, exactly-once, capacity, and independent-review claims remain open | `tests/test_service_acceptance.py`, `tests/test_storage_failures.py`, `tests/test_storage_schema.py`, `tests/test_ingestion_runs.py` |
| Offline evidence | Confirm hostile files, links, path replacement, analyzer output, and resource pressure cannot escape the offline boundary | Fixed executable and arguments, descriptor-relative validation, finite file/record/pipe/runtime limits, private redacted atomic reports, no egress or firewall path | `tests/test_offline.py`, `tests/test_dashboard.py` |
| Resource pressure | Confirm configured counts, windows, state, files, subprocess output, API results, and reports fail closed at their limits | Existing finite validation and per-component caps; whole-service storage and overload acceptance remains open in [#68](https://github.com/bartytime4life/MEGALODON/issues/68) | `tests/test_detector.py`, `tests/test_detector_acceptance.py`, `tests/test_config.py`, `tests/test_offline.py` |
| Future integrations | Confirm a contract cannot silently become runtime execution or new authority | Static capabilities and hub plans; Suricata and automation contracts remain inert until separate runtime gates pass | `tests/test_capabilities.py`, `tests/test_hub.py`, `tests/test_suricata_reader_contract.py`, `tests/test_automation_contract.py` |

The blueprint dependency order still applies: finish the trust kernel—firewall
containment, dashboard read isolation, transaction integrity, and resource
bounds—before adding runtime integrations. The first proposed runtime slice is
one bounded Suricata EVE reader. AI integration is not an earlier shortcut.

## Future AI integration gates

[NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1) treats red-teaming as
structured testing for adverse behavior and includes prompt injection,
adversarial inputs, data poisoning, membership inference, and model extraction
among relevant resilience and privacy tests. The
[OWASP Top 10 for LLM and Generative AI Applications 2025](https://genai.owasp.org/llm-top-10/)
provides a complementary application-risk taxonomy. These risks become relevant
only if a concrete AI component is proposed.

| Future risk | Minimum gate before implementation |
| --- | --- |
| Direct or indirect prompt injection | Treat telemetry, logs, documents, retrieved text, and user content as data only. Separate instructions from evidence; use a closed input/output schema and test that data cannot grant tools or authority. |
| Sensitive disclosure, membership inference, or model extraction | Supply only the least data required; exclude credentials, payloads, private evidence, and hidden configuration; add privacy canaries, redaction tests, retention limits, and output review. |
| Supply-chain compromise | Pin and record model, provider, artifact, adapter, dataset, license, digest, provenance, and update policy. Review egress and secret handling before any dependency is added. |
| Data/model poisoning or vector/embedding weaknesses | Define trusted sources, provenance, validation, quarantine, rollback, and re-evaluation after any training, fine-tuning, or retrieval change. MEGALODON has none of these pipelines today. |
| Improper output handling or misinformation | Treat output as untrusted advisory text. Validate a closed schema, preserve uncertainty and citations, prevent raw HTML/code execution, and require human interpretation. Model output cannot create evidence. |
| Excessive agency or tool misuse | Default to no tools and no write authority. Any future tool must be individually allowlisted, schema-bound, rate-limited, auditable, cancellable, and isolated. No model may apply a firewall change or initiate another active operation. |
| System-prompt leakage | Store no secrets in prompts. Assume instructions can be disclosed and ensure disclosure cannot weaken authentication, authorization, privacy, or action gates. |
| Unbounded consumption | Set input, token, output, time, concurrency, retry, storage, and cost limits; provide cancellation, degraded-state behavior, and load regressions. |

Use [MITRE ATLAS](https://atlas.mitre.org/) to give future AI findings stable
adversary-behavior identifiers where applicable. A taxonomy mapping is
supporting evidence, not proof that a control works.

## Purple-team evidence loop

1. Authorize a narrow scope, owner, environment, synthetic or approved fixture,
   privacy class, stop condition, and prohibited side effects.
2. Record the red-team case as an invariant and expected safe outcome. Keep
   operational exploit details out of public artifacts.
3. Implement the smallest blue-team control with deterministic failure behavior,
   bounded logging, and recovery guidance.
4. Add a regression that fails before the fix and passes after it; update the
   corresponding specification, threat map, and open-control entry.
5. Re-run the scoped red-team case, full exact-head CI, and an eligible
   independent review. Preserve unresolved limitations; do not self-approve.

A future AI change must also identify its exact model/provider, lifecycle stage,
data flow, egress, secrets, tools, permissions, retention, monitoring, rollback,
kill switch, and incident owner. An advisory model must remain unable to cross
the evidence-to-action boundary even if every content safeguard fails.

## Project-source basis

The following supplied project sources informed the sequencing and authority
boundaries:

- `MEGALODON_Advancement_Blueprint(1).docx`
- `MEGALODON Local Command Center Integration Blueprint(1).pdf`

They are historical planning evidence, not executable build inputs or
current-state authority. Checked-in code, tests, and adopted contracts at an
exact commit determine runtime implementation. Issues, pull requests, CI, and
reviews supply delivery and gate evidence; they cannot create a capability.

Additional references:

- [NIST AI 600-1, *Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile*](https://doi.org/10.6028/NIST.AI.600-1)
- [OWASP Top 10 for LLM and Generative AI Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Novee red-team/blue-team glossary](https://novee.security/glossary/red-team-blue-team/)
- [CybExer red, blue, and purple team overview](https://cybexer.com/blog/red-team-vs-blue-team-vs-purple-team-the-difference-and-how-ai-changes-each)

The Novee and CybExer pages support the plain-language role terminology. NIST,
OWASP, and MITRE supply the risk-management and threat-taxonomy basis.
