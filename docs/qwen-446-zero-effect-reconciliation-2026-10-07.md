# Issue #446 zero-effect reconciliation — 2026-10-07

## Basis and conclusion

Readback basis: [current main `579e4de218ea5effb2750984b04288b52b01c51f`](https://github.com/bartytime4life/MEGALODON/commit/579e4de218ea5effb2750984b04288b52b01c51f),
[open issue #446 and its three comments](https://github.com/bartytime4life/MEGALODON/issues/446),
and the [merged owner-decision packet](qwen-446-owner-decision-packet.md).
Source positions below refer to that main commit; this change modifies only tests
and documentation. The companion PR records the exact tested candidate commit.
Main advanced from the initially inspected `2d2aa8e` through #514 during the
inspection; its packaging/inventory change leaves the traced runtime, binding
and acceptance sources unchanged.

The disabled provider admission/inventory/generation paths, disabled direct
Airlock advisory, disabled in-memory HUD question handler, and canonical UNBOUND
assessor have bounded deterministic rejection evidence. **The combined
disabled-and-UNBOUND issue-level zero-effect checkbox remains HOLD.** Doctor
intentionally invokes diagnostics and persists an audit receipt; canonical
UNBOUND does not gate enabled runtime requests; cached dashboard model telemetry
can schedule and contact the catalog even with AI disabled. No runtime policy or
owner decision is changed by this reconciliation.

## Entry-point trace and exact evidence

All new test names below are in [tests/test_qwen_zero_effect.py](../tests/test_qwen_zero_effect.py).
They use prepared repository fixtures, synthetic procfs tables, memory receipts,
and request/thread tripwires. They never invoke a model or start a provider.

| Entry point | Current trace | Deterministic evidence and limit |
| --- | --- | --- |
| Provider admission | `megalodon/ai_provider.py:_admitted` (195): disabled check precedes posture and `/api/tags`; enabled identity checks precede posture, tags and `/api/show`. | `test_disabled_provider_denies_without_any_io[admitted]`: repeated `DISABLED`, no posture or I/O. Enabled invalid identities remain governed by runtime configuration, not canonical binding. |
| Inventory | `ai_provider.py:inventory` (266): disabled check precedes `_request('/api/tags', ...)`. | `test_disabled_provider_denies_without_any_io[inventory]`: exact false presence/digest fields and `DISABLED`, repeated with all effect sentinels. Enabled inventory has no canonical binding or posture admission check. |
| Generation | `ai_provider.py:generate` (356) obtains in-process scheduling/observation state, then `_generate` (286) calls `_admitted`; denied admission never enters `_request`. | `test_disabled_provider_denies_without_any_io[generate/background]`: repeated `DISABLED`, no new worker, request or persistence, final in-memory `running` false. These cases start with an idle generation slot. Timestamped in-memory observations are not zero mutation; preemption of an already-active request and host-wide model inactivity are not established. |
| Provider status | `ai_provider.py:status` (438): posture **first**, then `generate` for `probe=True`, or `_admitted` for `probe=False`. | `test_disabled_status_reads_synthetic_posture_but_has_no_effects[False/True]`: real posture parser reads two synthetic procfs tables per call, then deterministic `disabled / DISABLED`, inference false, provider availability unknown. No provider socket/process/write/thread start. Status is not a no-read API; listener/PID/cgroup reads can occur on a real unprivileged host. |
| CLI doctor | `megalodon/cli.py:_ai` (954), doctor branch (966–1018): `_load` reads config, posture, `status(probe=True)`, inventory, `nvidia-smi`, `systemctl show`, filesystem checks, `ReceiptStore` and one appended doctor event. | Existing `tests/test_ai_doctor_consent.py:test_doctor_preserves_disabled_setting_without_provider_io`: `_request` tripwire, three listener cases, two fixed mocked diagnostic commands and one memory receipt. It proves disabled consent/provider rejection; it expressly **does not prove no subprocess or no database write**. `systemctl show` is an observation, not service management; its subprocess still violates the literal zero-subprocess requirement. |
| Broker | `megalodon/ai_broker.py:Broker.dispatch` (374): receipt append **before validation**; `_execute` (416) dispatches `megalodon.model.status` to probing status; final append follows. `ReceiptStore` (149) opens/creates its directory/database, establishes WAL/schema and commits events. | `test_disabled_broker_model_status_has_no_provider_effect_but_still_audits`: disabled model result, ordered `not_attempted`/`observed` memory events, no provider effects. `tests/test_ai_control.py:test_audit_failure_precedes_any_tool_execution` proves audit gating, not zero writes. Broker has no blanket AI-enabled/binding gate on its fixed tools. `_plan` (461) creates a proposal; it does not apply the firewall. |
| Question selection | `megalodon/ai_interface.py:ask` (36): known question, then disabled rejection before generation or broker dispatch. | `test_disabled_question_stops_before_model_reader_or_receipts`: `DISABLED` with no reader/receipt capabilities. CLI `_ai` opens `ReceiptStore` before calling `ask`, so the entire CLI question command is not covered by this zero-write result. |
| HUD question | `megalodon/dashboard.py:_ai_ask` (1331): effective support configuration or handler AI setting is checked before operator envelope, body reads, model selection or receipt creation. | `test_disabled_dashboard_question_has_no_body_model_or_audit_io[handler/support_config]`: in-memory handler returns 403 with body/socket capabilities absent. Existing `tests/test_dashboard_ai_control.py:test_ai_ask_disabled_has_no_model_or_audit_path` also covers local HTTP routing. The new property test starts no HTTP server; response delivery and HTTP authentication are outside its no-I/O scope. |
| HUD explicit status | `dashboard.py:do_GET` (651–666): disabled `/api/ai/status` calls `status(probe=False)`; enabled probing requires explicit check header/token. | `test_disabled_dashboard_status_inherits_read_only_posture_boundary`: synthetic procfs reads, disabled response, no provider effects. Existing `test_ai_status_requires_explicit_check_and_never_claims_tcp_ready` in `test_dashboard_ai_control.py` covers enabled route authorization with a fake status provider. |
| HUD cached model telemetry | `megalodon/support_config.py:SupportConfiguration.snapshot` (293–304) → `megalodon/model_telemetry.py:ModelTelemetry.snapshot` → worker `_refresh` → `ai_provider.model_catalog` (246) → posture then `/api/tags`, **before** disabled `status(probe=False)`. | `test_disabled_telemetry_still_schedules_a_refresh_without_starting_it` reaches a thread-start tripwire; `test_canonical_unbound_is_not_a_universal_runtime_gate[disabled_telemetry]` directly exercises refresh and reaches a `/api/tags` tripwire. Neither starts a thread nor contacts the provider. This disproves a dashboard-wide disabled zero-socket/no-background-worker claim. `loaded_model` (424) is another caller-admitted helper without its own disabled/binding gate; telemetry calls it only after `model_available`. |
| Direct Airlock advisory | `megalodon/qwen_advisory.py:invoke_qwen_advisory` (686) → pure `preflight_advisory` → `_invoke_admitted` (731): Airlock denial or missing explicit enablement returns before process lock, HTTP connection and watchdog. | `test_advisory_denial_precedes_every_effect`: disabled `EXPLICIT_ENABLEMENT_REQUIRED`; enabled bad pin `REGISTRY_FINGERPRINT_MISMATCH`; wrong artifact `MODEL_NOT_APPROVED`; forbidden projection `REQUEST_SHAPE_INVALID`; repeated identical display/reason results, provider request false and unchanged inputs. Existing `test_one_exact_qwen_request_returns_closed_advisory_result` uses an enabled synthetic registry/fake provider, showing canonical UNBOUND is not consulted. |
| Anomaly Airlock advisory | `qwen_advisory.py:invoke_qwen_anomaly_advisory` (710) → separate anomaly preflight → same `_invoke_admitted`. | Existing `tests/test_anomaly_advisory.py:test_prompt_construction_and_invalid_invocation_have_zero_io` covers invalid request and disabled invocation with file/socket/SQLite/process/HTTP traps. Shared transport effects are additionally guarded by the direct advisory tests; no separate native anomaly acceptance is claimed. |
| UNBOUND readiness | `megalodon/local_model_readiness.py:assess_readiness` (129–189): canonical binding hash, named UNBOUND hold; any supplied identity/profile/containment/evaluation/request refuses. | `test_canonical_unbound_assessor_is_pure_and_cannot_promote` uses the actual canonical record, tests all five smuggled evidence inputs and repeated deterministic results under all effect sentinels; no authority flag is true. The CLI validators read repository JSON/schema and print stdout; they are not no-read entry points. |

Background advice also calls `ai_provider.generate`: `megalodon/intelligence.py:explain`
(25), `analyze` (273), `_explain` (300), `tick` (430) and `start` (449) use separate
pattern enabled/automatic settings, checkpoints and worker threads;
`megalodon/defense.py` records actions before model analysis. Disabled provider
generation does not infer that those surrounding workers, checkpoints, receipts
or an already-running external model are inactive. These lifecycle paths were
traced in source, not operated or promoted by this test run.

## Zero-effect requirement matrix

`no_effects` in the new test module installs fail-on-attempt sentinels for the
current file/process/network/database/thread/firewall surfaces and records
attempts even if a caller catches the assertion. Its scope is the prepared
function invocation, excluding imports, fixture reads and pytest's own output.
No existing SQLite connection or writable file handle is supplied to the pure
cases. Memory-receipt, synthetic-read and request/thread-tripwire exceptions are
explicit in their test names and assertions; they are not native observations.

| #446 requirement | Evidence that can close a bounded subclaim | Remaining exclusion / HOLD |
| --- | --- | --- |
| Zero DNS | `socket.getaddrinfo`, host-name and reverse-name resolution sentinels in disabled provider, advisory, question and UNBOUND tests; existing literal transport test `tests/test_qwen_advisory.py:test_literal_connection_uses_ipv4_socket_without_name_resolution`. | Literal loopback client evidence does not prove provider-side/transitive egress or native host containment. |
| Zero HTTP/provider socket | `_request`, literal HTTP constructor, `socket.socket` and `create_connection` traps; disabled status exercises real parser with synthetic tables. | Enabled admission/inventory ignore canonical UNBOUND; disabled cached telemetry reaches catalog request seam. The issue-level universal claim is false at this basis. |
| Zero subprocess / shell | `subprocess` start/run helpers, `os.system`, fork/spawn/exec sentinels on the scoped rejecting/pure functions. | Doctor runs `nvidia-smi` and `systemctl show`; its existing tests explicitly expect both commands. No native doctor was run. |
| Zero filesystem/database write | File-open (including read mode), descriptor-write, directory/create/rename/link/permission/truncate and `sqlite3.connect` traps; ReceiptStore constructor trap on the zero-audit cases. | Doctor and broker persist receipts; CLI opens audit store before disabled question rejection; automatic advice can checkpoint before denied generation. Status deliberately reads procfs. |
| Zero service action | No process starts or file writes can reach service-management commands from the tested pure/rejection paths. Source doctor command is fixed `systemctl show`, not start/restart/enable. | Separate Setup/service workflows have their own authority. No native service state or complete dashboard/host zero-effect claim follows. |
| Zero firewall change | `NftablesFirewall.available/install/plan_block/block` and process/file traps; broker proposal/application separation in `tests/test_ai_control.py:test_levels_and_receipts_keep_planning_separate_from_execution`. | Fixed operator defense actions and their authorization are outside disabled provider rejection; binding/readiness grants no action authority. |
| Zero background-model activity | `Thread.start`, provider request and process-start traps for disabled direct/manual/background generation and pure UNBOUND assessment. | Cached telemetry schedules while disabled; pattern workers have separate lifecycle controls. Tests prove no new model invocation on scoped denied paths, not absence or termination of an already-running host/provider model. |

## Acceptance disposition

| Issue #446 acceptance item | Current evidence / disposition |
| --- | --- |
| Exact owner binding decision recorded, or status explicitly UNBOUND | **UNBOUND alternative evidenced.** Canonical record validates unchanged; `operator_decision.status=NOT_RECORDED`, alias/provider/artifact/host/registry values remain unset. This supports recording the explicit hold, not an owner selection or approval. |
| Disabled and UNBOUND zero-effect regressions at one exact head | **Partial evidence only; combined checkbox HOLD.** Pure/disabled rejection cases pass; doctor audit/diagnostic effects, enabled runtime UNBOUND gap and disabled telemetry exceptions remain. Owner disposition must define whether doctor/audit/read-only diagnostics are excluded or require a separately reviewed implementation change. A universal runtime binding gate and disabled telemetry repair are not implemented here. |
| Cross-binding assessor no stronger than CANDIDATE_PACKET_CONSISTENT | **Existing completed ceiling reconfirmed.** Actual readback is UNBOUND, with all authority false; synthetic consistency tests do not confer acceptance. |
| Complete privacy-minimized signed seven-category corpus manifest | **HOLD.** Inspected evaluation contract/`contracts/local-model-evaluation/v1/fixtures/accepted-synthetic.json` supplies synthetic structural evidence. The owner packet still lacks a frozen authenticated candidate-bound corpus/manifest, detached signature, key fingerprint and verification receipt. No corpus execution or observed `0/N` result is generated. |
| Evidence origin / loaded bytes dispositioned | **HOLD.** API tag/manifest or prior response success cannot authenticate provider/artifact origin or attest bytes loaded during a specific inference. Owner disposition and native evidence are not inferred from assertions or fixtures. |
| Exact-head independent security review | **HOLD for this candidate.** No independent review is created by these tests or this analysis. |
| Separate owner acceptance | **HOLD.** No acceptance decision, model operation, release, deployment, host action or detector/action authority is granted. |

The repository also contains [docs/audit/local-model-acceptance.json](audit/local-model-acceptance.json),
dated October 1, with historical installed-source/inference/browser/static-review
claims at different source and scan heads. Preserve that record as historical
evidence. It supplies neither this candidate's zero-effect run nor the missing
#446 owner binding, authenticated signed corpus, loaded-byte attestation or
exact-head independent acceptance; it is not erased or upgraded here.

## Validation and reproducibility

Local focused run: **245 passed**, including **25 new cases**. Python 3.12.14,
pytest 9.1.1, jsonschema 4.26.0, PyYAML 6.0.3; ambient pytest plugins disabled,
cache provider disabled. This is a local focused profile, not the repository's
locked CPython 3.11 CI/full-suite/native profile. The exact candidate SHA and CI
status belong in the companion PR's validation record.

```bash
git rev-parse HEAD
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_ADDOPTS='' python -m pytest -p no:cacheprovider -ra \
  tests/test_qwen_zero_effect.py tests/test_ai_doctor_consent.py \
  tests/test_ai_control.py tests/test_dashboard_ai_control.py \
  tests/test_qwen_advisory.py tests/test_anomaly_advisory.py \
  tests/test_local_model_binding.py tests/test_local_model_readiness.py \
  tests/test_model_selection.py
python tools/local_model_binding.py validate config/model-bindings/qwen.unbound.json
python tools/local_model_readiness.py --binding config/model-bindings/qwen.unbound.json
```

Canonical binding validation returned `validated / UNBOUND`; readiness returned
`UNBOUND / OWNER_MODEL_BINDING_NOT_RECORDED`, binding SHA-256
`6ebb5b746edb09845fc9d63fd5688409f049d8471744732fb55510e21ed29287`, packet SHA-256
`918109945774d6fe3c2fa00b35c999f26e56d208e5bbc1aa1d9ef578286187ff`.
These are canonical JSON consistency digests, not artifact hashes or signatures.

No model pull/start/query/backgrounding, native diagnostic execution, service or
firewall operation, host configuration change, release or acceptance occurred
in this reconciliation. Test-environment setup, repository reads, local test
fixtures and the reviewable Git change are outside the tested runtime boundary.
