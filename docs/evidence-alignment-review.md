# Evidence and claim alignment review

Reviewed 2026-09-16 against `main@0e71cd41627fe2d2bffde7c2ddd222b475f73bc1`,
Sites v13/source `463c9d7e411ceaa86666babe1e24426cb88877f1`, the supplied unified
roadmap, and the current Drive coordination, platform, blueprint, project
instructions and integration-lifecycle handoff.

This is a source-grounded consistency audit, not a guarantee that every possible
false claim has been found. It distinguishes false statements, stale observations,
unsupported inferences and clearly labeled proposals. Repeated AI-generated text
is not independent corroboration. No model-based automatic truth detector was
added to the product.

## Findings and corrections

| Finding | Classification and correction | Evidence |
| --- | --- | --- |
| Qwen remove targeted `qwen` while download targeted `qwen2.5:7b` | Incorrect operation identity. Inspect/remove/download now use the same explicitly illustrative tag and literal local provider. A mutable tag is not a pinned digest or approved model. | [PR #243 review](https://github.com/bartytime4life/MEGALODON/pull/243#discussion_r4030579195), `site/dist/lifecycle.js`, [Ollama CLI](https://docs.ollama.com/cli) |
| Zabbix reinstall/remove combined two agents and a server | Incorrect role scope. Require one selected role; no default mutation command. | [Review](https://github.com/bartytime4life/MEGALODON/pull/243#discussion_r4030579202), [APT package-list semantics](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html) |
| Greenbone `down` was called uninstall while image presence meant installed | Inconsistent lifecycle semantics. Show project image inventory, container removal retaining data/images, and image refresh without startup. No full uninstall claim. | [Review](https://github.com/bartytime4life/MEGALODON/pull/243#discussion_r4030579215), [Docker down](https://docs.docker.com/reference/cli/docker/compose/down/), [Docker pull](https://docs.docker.com/reference/cli/docker/compose/pull/) |
| Generic Zeek/OSSEC/Nagios package commands did not identify the installation method | Unsupported universality. Keep diagnostics and installation-specific vendor guidance; omit invented copyable removal/reinstall commands. | Existing acquisition links vs old lifecycle registry; private Zeek build in `README.md` |
| ClamAV/Suricata lifecycle lists included extra daemon/updater packages | Broader effects than the named component. Limit the reference to the scanner/sensor package, retain operator review of dependency/service effects, remove automatic `-y` and configuration purge. | Old Site registry; current single-component commands |
| “Installed” could be inferred from executable/import/image checks | Unsupported inference. Separate self-reported notes, PATH findings, diagnostic scope and actual operational acceptance throughout the interface. | `megalodon/readiness.py`, `docs/tool-readiness.md`, Site parser |
| Drive handoff said manual status was memory-only | False persistence description. Manual notes use browser `localStorage`; readiness imports use page memory. | `loadToolPresence`, `setToolPresence`, `importReadinessFile` in Site |
| HUD contained generated traffic, rates, protocol shares, detections and receipts | Labeled demonstration, not real telemetry. Removed for the real-data-only direction. Disconnected measurements are unavailable, never a fabricated zero or healthy network. | Removed fixture arrays, chart generator and interval; empty-state regression |
| Site “INTACT” and “External egress OFF” resembled host health guarantees | Unsupported scope. Show static Site capabilities and unknown host health. Hosted access/sign-in and vendor links are distinct from local-core operation. | Static manifest, no runtime feed, revised HUD |
| Site offline example used relative input/output paths | Non-executable example under the actual adapter contract. Use explicit absolute placeholders and explain replacement/new-output requirements. | `python -m megalodon.offline --help`, `offline/common.py` |
| README said no model execution while documenting one optional call | Contradiction. Qualify the absent capability as background model execution; correct the Wiki’s unqualified “no CLI” statement and preserve the opt-in bounded advisory API/anomaly command. | `qwen_advisory.py`, `offline/anomaly.py`, README feature matrix |
| Wiki/model wording could imply whole-process containment | Unsupported guarantee. Application refusal is not a sandbox for the separately operated provider. | `docs/model-containment-review.md`, corrected Wiki and Site |
| Capacity was conflated with retention/whole-disk budget | Incorrect scope. Dedicated Suricata logical 512 MiB ceiling is not storage duration, whole-disk use or automatic cleanup. | Consumer contract and corrected Site boundaries |
| Roadmap still listed delivered projection/readiness as future slices | Stale sequence. Mark #239/#241 delivery and #243 lifecycle addition; remove the Wiki’s stale “no dashboard projection” claim and keep operational acceptance separate. | Merged source at the audit pin; `docs/unified-roadmap-currentness.md` |
| Repo/Drive “current” Site receipt still said v10/v11 | Stale synchronization. Refresh the canonical deployment receipt and currentness notes; retain old logs as explicitly historical. | Sites version/deployment readback, `docs/site-source-alignment.md` |
| Drive project instructions described an available explicit firewall apply path | Stale operating instruction. Current apply routes refuse before host inspection/subprocess work. Restoration is future work, not an operator toggle. | `megalodon/firewall.py`, `SECURITY_REVIEW.md` |

## Claims deliberately left unproved

The supplied synthesis's external incident statistics, causal claims and alleged
publisher provenance were not authenticated in this audit and are not repeated
as established facts. Its “five inputs” versus six listed sources and nonexistent
section 16 are editorial defects. Its Q2 follow-up conflicts with its own ban on
model output becoming later model input; Q2 stays proposed. Recommendations for
Apache-2.0 do not grant a license. No license or approval appendix was filled in.

GitHub returned no open issues or PRs at the initial readback, before this audit's
new draft. That is issue lifecycle state, not proof all acceptance work is done.
Native Windows/macOS, installed TShark/Scapy/Suricata/model behavior, provider
confinement, representative detection accuracy and sustained operational capacity
remain separate evidence gaps. This audit does not assert the current branch
protection configuration or authenticate historical external research citations.

## Verification and delivery scope

The current Node suite contains 32 checks, including exact model identity,
single-role package targeting, truthful container labels, absent synthetic
telemetry, startup/navigation and adversarial readiness parsing. Application
initialization uses a DOM stub and is not a rendered browser test. The Python
suite exercises real readiness output against the browser parser. No displayed
install, uninstall, download, scanner or provider command is executed by tests.

The [source-alignment receipt](site-source-alignment.md) records final Site
identity, source, artifact digest, access and rollback. Source parity proves only
matching bytes. The hosted Site cannot inspect the local machine or display a
live feed. Use the local dashboard for existing stored evidence; a future hosted
connection needs a separate reviewed data contract and privacy boundary.
