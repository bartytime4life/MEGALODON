# Integrations and Local AI

## Distinguish planning, presence and data

The active catalog has ten entries: Python/SQLite, TShark/Wireshark, Zeek, Suricata, Scapy, nftables, ClamAV, osquery, local Qwen/Ollama, and Nmap. A catalog entry describes a capability; executable/process observations describe presence; admitted evidence requires the selected workflow’s own contract.

The static `capabilities` and `hub-plan` commands execute nothing. The local HUD separately implements fixed support configuration, service-start controls, finite capture, bounded inventory/scan collectors, and completed-report watching. These are real host workflows with explicit scope and authorization, not capabilities granted by a catalog listing.

See [Background tools](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/background-tools.md), [Support configuration](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/support-configuration.md), and [the integration hub contract](../integration-hub.md).

## Sensor evidence remains source-specific

Saved-capture TShark analysis, closed Zeek JSON/TSV import, the strict Suricata alert publication chain and the HUD’s separate background observations have different schemas and acceptance boundaries. An offline importer does not start its producer. A background sensor summary does not become a core fixed-rule finding or establish offline producer qualification.

[#445](https://github.com/bartytime4life/MEGALODON/issues/445) remains open for exact Zeek offline producer acceptance. [The IP inspector](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/visual-operations-defense.md) can read bounded recent EVE context without making it part of the strict admitted-detection chain. Packet, flow and alert counts are different units.

## Installed local models in the HUD

Setup selects an installed local completion model with an exact digest. Provider checks, prompt/output bounds, explicit cancellation and separate last-response/last-attempt status constrain analysis. No model-generated executable path, shell command, destination or scan scope is accepted. Closed proposals require an operator-selected workflow.

The provider uses literal loopback. Local model code does not sandbox the separately operated Ollama service, prove its provenance, or grant response authority. Read [model selection](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/local-model-selection.md) and [the original Qwen advisory contract](../local-model-advisory-contract.md).

## Canonical Qwen Airlock is still held

[The canonical record](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/config/model-bindings/qwen.unbound.json) remains **UNBOUND / NOT_RECORDED**. [#446](https://github.com/bartytime4life/MEGALODON/issues/446) is open. The HUD’s saved runtime model selection is distinct from that owner binding and does not complete native containment or representative evaluation. Disabled/UNBOUND claims must be made per entrypoint; canonical UNBOUND is not a universal runtime gate.

[Scoped sentinel tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_qwen_zero_effect.py) and [the dated reconciliation](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/qwen-446-zero-effect-reconciliation-2026-10-07.md) make those differences inspectable. Working application AI and pending canonical acceptance can coexist; neither should be described as the other.
