# Security Boundaries

> Current source orientation: `main@2cb706039724d9ea0bda09cbd3c17698b15ba55c` (October 22, 2026). This documents existing interfaces; it authorizes no model, sensor, service or firewall operation.

The local HUD has real, scoped operator actions. Its safety depends on keeping evidence reads, model advice, configuration, privileged execution and acceptance distinct.

## Controls that matter

- **Metadata core:** typed inputs, fixed heuristics, quotas, source identity and private storage. Packet payloads and payload-derived hashes are outside the core event model.
- **Local requests:** numeric loopback binding, Host/Origin/request checks, scoped tokens where required, and local-user admission. A loopback address alone is not sufficient authority.
- **Private storage:** ownership/path/identity admission, transactional writes and bounded managed capacity. Telemetry-reader APIs do not migrate or create the core audit database.
- **Fixed workflows:** untrusted events, browser fields, filenames, prompts and model text cannot select arbitrary executable paths, shell code, SQL, targets or provider endpoints.
- **Visible failure:** unavailable, unknown, stale and ambiguous outcomes remain explicit. A source alert, model explanation or app badge is not proof of compromise or protection.

## Defaults and enabled workflows

A fresh configuration does not mutate the firewall. The installed launcher can start/reuse the local user HUD service; login autostart is separate. HUD companion jobs and report scheduling have documented local defaults. Saved monitoring choices can resume capture. Explicit support configuration may install fixed packages, start configured services, or invoke OS authorization. These effects must not be described as a universally read-only application.

[Support configuration](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/support-configuration.md) and [companion collection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/companion-automation.md) define the exact scope. The static workflow catalog remains non-executing.

## Temporary defense and recovery

Legacy firewall CLI `--apply` flags refuse before host interaction. The separate HUD containment workflow supports a currently observed public endpoint through preview, operator confirmation and OS approval. It protects local/reserved/allowlisted and observed DNS/remote-access services, uses only its fixed managed nftables table, and gives each element a five-minute kernel timeout. Model proposals never authorize application.

Audit admission precedes requested actions. Failed or ambiguous helper results retain review/release paths; a receipt hash chain is not protection against an owner rewriting the ledger. See [the defense contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/visual-operations-defense.md) and [failure and refusal tests](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/tests/test_defense.py).

Backup/restore uses explicit commands and new destinations. Restoring does not automatically activate the database or complete native recovery acceptance.

## Egress and advice

There is no core telemetry cloud-analytics/SIEM/SOAR upload path. Separately opted-in location requests, support downloads and externally opened companion consoles have their own network behavior. Location providers see this PC’s connection address; peer locations are looked up locally.

The model receives bounded evidence through the literal loopback provider. It can explain and return closed proposals; it cannot turn generated code into execution. The canonical Qwen record remains UNBOUND and [#446](https://github.com/bartytime4life/MEGALODON/issues/446) remains open. Runtime selection is not canonical acceptance.

Read [the full security review](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/SECURITY_REVIEW.md) and [the specification](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/SPECIFICATION.md) for the complete contracts and open controls. This Wiki renovation is documentation and graphics work; it does not operate a model, collector, service or firewall, and is not a security certification.

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
