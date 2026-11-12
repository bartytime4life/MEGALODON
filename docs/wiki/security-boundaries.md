# Security Boundaries

> Current source orientation: `main@418fa54474f3f77d0758e94aab5735a516d8c43b` (November 11, 2026, America/Chicago). Earlier pinned links retain their historical source scope. This documents existing interfaces; it authorizes no model, sensor, service or firewall operation.

The local HUD has real, scoped operator actions. Its safety depends on keeping evidence reads, model advice, configuration, privileged execution and acceptance distinct.

## Controls that matter

- **Metadata core:** typed inputs, fixed heuristics, quotas, source identity and private storage. Packet payloads and payload-derived hashes are outside the core event model.
- **Local requests:** numeric loopback binding, Host/Origin/request checks, scoped tokens where required, and local-user admission. A loopback address alone is not sufficient authority.
- **Private storage:** ownership/path/identity admission, transactional writes and bounded managed capacity. Telemetry-reader APIs do not migrate or create the core audit database.
- **Fixed workflows:** untrusted events, browser fields, filenames, prompts and model text cannot select arbitrary executable paths, shell code, SQL, targets or provider endpoints.
- **Visible failure:** unavailable, unknown, stale and ambiguous outcomes remain explicit. A source alert, model explanation or app badge is not proof of compromise or protection.
- **Current view identity:** report documents/pages, reference search results and saved device reviews follow their entity/query plus view revision. Stale successes and failures cannot replace a newer selection. A failed support-status read clears current capture/model summary claims; learning paused is not active monitoring.

The guided HUD opens existing views or refreshes current observations. It starts
no collector, model or host action. Its sensor-observation route points to
connection context, not the separate admitted Findings queue; connection-summary
evidence does not require packet capture. AI stays optional. The
[source-bound guidance tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_guided_overview.py)
and [asynchronous-view tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_intelligence_ui.py)
cover these UI boundaries; they do not establish installed-host acceptance.

## Defaults and enabled workflows

A fresh configuration does not mutate the firewall. The installed launcher can start/reuse the local user HUD service; login autostart is separate. HUD companion jobs and report scheduling have documented local defaults. Saved monitoring choices can resume capture. Explicit support configuration may install fixed packages, start configured services, or invoke OS authorization. These effects must not be described as a universally read-only application.

[Support configuration](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/support-configuration.md) and [companion collection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/companion-automation.md) define the exact scope. The static workflow catalog remains non-executing.

## Temporary defense and recovery

Legacy firewall CLI `--apply` flags refuse before host interaction. The separate HUD containment workflow supports a currently observed public endpoint through preview, operator confirmation and OS approval. It protects local/reserved/allowlisted and observed DNS/remote-access services, uses only its fixed managed nftables table, and gives each element a five-minute kernel timeout. Model proposals never authorize application.

Audit admission precedes requested actions. Failed or ambiguous helper results retain review/release paths; a receipt hash chain is not protection against an owner rewriting the ledger. See [the defense contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/visual-operations-defense.md) and [failure and refusal tests](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/tests/test_defense.py).

Backup/restore uses explicit commands and new destinations. Restoring does not automatically activate the database or complete native recovery acceptance.

## Egress and advice

There is no core telemetry cloud-analytics/SIEM/SOAR upload path. Separately opted-in location requests, support downloads and externally opened companion consoles have their own network behavior. Location providers see this PC’s connection address; peer locations are looked up locally.

The canonical [Qwen record at the current source](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/config/model-bindings/qwen.unbound.json) remains UNBOUND with no recorded owner decision. The [release fence](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/docs/qwen-runtime-unbound.md) refuses operational generation for every model family before provider access. Explicit bounded catalog/selection and the fixed no-telemetry READY diagnostic are separate exceptions; neither enables operational explanations or accepts a model. Historical advisory code constrains evidence and proposal vocabulary but does not override this fence. [#446](https://github.com/bartytime4life/MEGALODON/issues/446) tracks its acceptance evidence; model text grants no execution authority.

Read [the security review](https://github.com/bartytime4life/MEGALODON/blob/main/SECURITY_REVIEW.md), [the maintained specification](https://github.com/bartytime4life/MEGALODON/blob/main/SPECIFICATION.md) and [the current validation record](https://github.com/bartytime4life/MEGALODON/blob/main/docs/documentation-refresh-2026-11-11.md) for contracts and remaining gates. Documentation updates do not operate a model, collector, service or firewall and are not a security certification.

## Host references and publication

Lynis suggestions, AIDE differences and Spamhaus/IPsum matches stay contextual.
A public-reference refresh downloads fixed resources; it uploads no private
network evidence and triggers no containment. The separate hosted snapshot
viewer imports an address-free summary in tab memory; it cannot query localhost
or operate the host. See [host-security limits](https://github.com/bartytime4life/MEGALODON/blob/main/docs/host-security.md)
and [the snapshot scope](https://github.com/bartytime4life/MEGALODON/blob/main/site/README.md).

## Recovery evidence and current technical detail

Setup now includes read-only recovery readiness and separately pinned external
backup/isolated-test receipts. The validator opens no backup and runs no test;
host restoration remains unavailable and `restore_eligible` is false. AIDE,
dated reference context and AI commentary cannot change that boundary.
[Receipt contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-backup-evidence.md) and
[technical deep dive](technical-deep-dive.md#recovery-evidence-without-a-restore-engine).
