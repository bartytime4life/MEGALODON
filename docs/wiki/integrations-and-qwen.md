# Integrations and Local AI

> Current source orientation: `main@418fa54474f3f77d0758e94aab5735a516d8c43b` (November 11, 2026, America/Chicago). Older immutable links below retain their historical source snapshots. Source presence, runtime observations and native producer/model acceptance remain separate; see the [current reading](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md#november-11-source-orientation).

## Distinguish planning, presence and data

The active static catalog has twelve entries: Python/SQLite, TShark/Wireshark, Zeek, Suricata, Scapy, nftables, ClamAV, osquery, local Qwen/Ollama, Nmap, Lynis and AIDE. A catalog entry describes a capability; executable/process observations describe presence; admitted evidence requires the selected workflow’s own contract.

The static `capabilities` and `hub-plan` commands execute nothing. The local HUD separately implements fixed support configuration, service-start controls, finite capture, bounded inventory/scan collectors, and completed-report watching. These are real host workflows with explicit scope and authorization, not capabilities granted by a catalog listing.

See [Background tools](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/background-tools.md), [Support configuration](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/support-configuration.md), and [the integration hub contract](../integration-hub.md).

## Sensor evidence remains source-specific

Saved-capture TShark analysis, closed Zeek JSON/TSV import, the strict Suricata alert publication chain and the HUD’s separate background observations have different schemas and acceptance boundaries. An offline importer does not start its producer. A background sensor summary does not become a core fixed-rule finding or establish offline producer qualification.

[#445](https://github.com/bartytime4life/MEGALODON/issues/445) tracks exact Zeek offline producer acceptance. [The IP inspector](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/visual-operations-defense.md) can read bounded recent EVE context without making it part of the strict admitted-detection chain. Packet, flow and alert counts are different units.

The current HUD guide makes this distinction visible: **Review sensor
observations** opens connection context; **Review findings** separately opens
the admitted Findings workspace. Sensor connection-summary mode can contain
usable metadata while packet capture is stopped, so its guidance does not
require packet capture. Refresh and navigation read observations or open views;
they do not start a producer. [Guidance source and tests](technical-deep-dive.md#current-arithmetic-and-view-identity).

## Installed local models in the HUD

Explicit Setup discovery can read the bounded installed-model catalog and save
a freshly matched tag/digest and compute preferences. The separate fixed READY
response diagnostic can load/test that saved model after deliberate operator
action; it takes no caller prompt, sends no telemetry and grants no operational
readiness. Operational generation remains blocked by this release's UNBOUND
fence for every model family. No model-generated executable path, shell command,
destination or scan scope is accepted.

AI is optional for reading facts, coverage and reports. **Setup → Local AI →
Knowledge and automatic review** holds learning, explanation and reference-update
preferences. Disabled learning says **Local learning paused**; saved progress
and reviews remain readable. Reference results belong to the current submitted
query and revision, and saved device reviews belong to the current selection
revision. A late success or failure cannot replace a newer view. Failed support
status reads clear current capture/model summary claims rather than retaining a
previous pass as current evidence. [Intelligence regression tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_intelligence_ui.py)
and [support-status tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_dashboard_support_config_ui.py) cover these presentation contracts.

The provider uses literal loopback. Local model code does not sandbox the separately operated Ollama service, prove its provenance, or grant response authority. Read [model selection](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/local-model-selection.md) and [the original Qwen advisory contract](../local-model-advisory-contract.md).

## Canonical Qwen Airlock is still held

[The canonical record](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/config/model-bindings/qwen.unbound.json) remains **UNBOUND / NOT_RECORDED**. The [current release fence](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/docs/qwen-runtime-unbound.md) has no BOUND path or operator override: enabling AI, selecting another family/tag/digest, or editing binding JSON cannot activate operational generation. Explicit catalog/selection and the fixed response diagnostic are named exceptions, not operational inference acceptance. [#446](https://github.com/bartytime4life/MEGALODON/issues/446) tracks the remaining acceptance evidence.

[Current runtime-gate tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_qwen_runtime_gate.py) and [diagnostic tests](https://github.com/bartytime4life/MEGALODON/blob/418fa54474f3f77d0758e94aab5735a516d8c43b/tests/test_ollama_model_test.py) distinguish these entrypoints. The [October reconciliation](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/qwen-446-zero-effect-reconciliation-2026-10-07.md) and its original sentinel results remain historical; they do not lift the current release fence.

## Local host security and dated reference context

Lynis runs a bounded unprivileged audit; AIDE creates an explicit initial
baseline and compares a fixed readable critical-file scope. A baseline records
what exists, not that the PC is clean. Package installation can enable native
service behavior, including the distribution Lynis timer.

Explicit refresh downloads fixed Spamhaus DROP/IPsum resources. A dated match
is context, not a detection or an automatic block. These results remain separate
from admitted network alerts. Read [host security](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-security.md)
for limits, package side effects, private reports and interpretation.

## Recovery evidence and current technical detail

Setup now includes read-only recovery readiness and separately pinned external
backup/isolated-test receipts. The validator opens no backup and runs no test;
host restoration remains unavailable and `restore_eligible` is false. AIDE,
dated reference context and AI commentary cannot change that boundary.
[Receipt contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-backup-evidence.md) and
[technical deep dive](technical-deep-dive.md#recovery-evidence-without-a-restore-engine).

[PR #663](https://github.com/bartytime4life/MEGALODON/pull/663) admits listener posture before model inventory reads.
This closes that metadata-request ordering gap; it does not sandbox Ollama or
complete #446. [AI authority diagram](technical-deep-dive.md#ai-admission-before-explanation).
