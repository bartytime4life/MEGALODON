"""Closed, non-executing integration plans for MEGALODON's companion tools."""

from __future__ import annotations

from typing import Any

from .capabilities import SCHEMA as CAPABILITY_SCHEMA
from .capabilities import catalog


SCHEMA = "megalodon-integration-hub-v1"
HUB_MODE = "static_plan_only"

_WORKFLOWS = (
    {
        "id": "core-metadata",
        "component": "python-sqlite",
        "source_kind": "validated_event_metadata",
        "integration_owner": "megalodon.service",
        "input_contract": "PacketEvent",
        "output_contract": "SQLite event/detection/action audit",
        "entry_point": "megalodon run",
        "launch_policy": "operator_invoked_megalodon",
        "data_boundary": "bounded metadata only; no packet payload or payload-derived hash",
        "action_boundary": "observe-only by default; action states remain explicit",
        "next_gate": "representative replay and retention policy before production use",
    },
    {
        "id": "offline-packet-metadata",
        "component": "wireshark-tshark",
        "source_kind": "packet_metadata",
        "integration_owner": "megalodon.offline.tshark",
        "input_contract": "permitted PCAP/PCAPNG below a private input root",
        "output_contract": "private offline-run-v1 packet reports",
        "entry_point": "python -m megalodon.offline --source tshark",
        "launch_policy": "fixed_argv_bounded_subprocess",
        "data_boundary": "fixed field allowlist; no payload, protocol tree, name lookup, or capture hash",
        "action_boundary": "analysis only; no live capture, firewall, or egress",
        "next_gate": "installed-tool compatibility and external process containment",
    },
    {
        "id": "offline-flow-metadata",
        "component": "zeek",
        "source_kind": "flow_metadata",
        "integration_owner": "megalodon.offline.zeek",
        "input_contract": "version-declared Zeek JSON/TSV conn.log profile",
        "output_contract": "private offline-run-v1 flow reports",
        "entry_point": "python -m megalodon.offline with source zeek-json or zeek-tsv",
        "launch_policy": "import_only_external_producer",
        "data_boundary": "closed conn.log field inventory; flow counts never become packet counts",
        "action_boundary": "MEGALODON never starts Zeek and performs no response or egress",
        "next_gate": "producer-profile compatibility and representative flow fixtures",
    },
    {
        "id": "alert-metadata",
        "component": "suricata",
        "source_kind": "alert_metadata",
        "integration_owner": "contracts/suricata-eve/v1",
        "input_contract": "suricata-eve-alert-input-v1 envelope",
        "output_contract": "contract conformance only",
        "entry_point": None,
        "launch_policy": "no_runtime_importer",
        "data_boundary": "closed alert fields; no payload, file content, unrestricted protocol records, or ruleset updates",
        "action_boundary": "no sensor launch, IPS path, blocking, or producer-reported action attribution",
        "next_gate": "reviewed runtime importer with bounded framing and privacy tests",
    },
    {
        "id": "live-metadata-capture",
        "component": "scapy",
        "source_kind": "packet_metadata",
        "integration_owner": "megalodon.capture",
        "input_contract": "operator-selected interface through the capture extra",
        "output_contract": "validated PacketEvent metadata",
        "entry_point": "megalodon run --source scapy",
        "launch_policy": "explicit_optional_capture",
        "data_boundary": "metadata extraction only; packet crafting and replay injection are absent",
        "action_boundary": "capture authority and privilege are external prerequisites",
        "next_gate": "least-privilege live-capture and backpressure validation",
    },
    {
        "id": "time-limited-response",
        "component": "nftables",
        "source_kind": "validated_action_target",
        "integration_owner": "megalodon.firewall",
        "input_contract": "global non-allowlisted IP plus bounded reason",
        "output_contract": "planned ActionRecord only",
        "entry_point": "megalodon firewall-plan or block",
        "launch_policy": "plan_only_apply_refused",
        "data_boundary": "validated target and inert nftables plan only",
        "action_boundary": "live application is unsupported; no firewall subprocess is reachable",
        "next_gate": "durable intent, terminal outcome, reconciliation, recovery, and disposable-namespace safety tests",
    },
    {
        "id": "manual-file-scan",
        "component": "clamav",
        "source_kind": "file_scan_result",
        "integration_owner": "external_operator",
        "input_contract": "none in MEGALODON",
        "output_contract": "none in MEGALODON",
        "entry_point": None,
        "launch_policy": "separate_manual_tool",
        "data_boundary": "no file content, file hash, quarantine request, or scan result intake",
        "action_boundary": "MEGALODON does not scan, update signatures, remove, or quarantine files",
        "next_gate": "separate versioned result contract, retention decision, and false-positive review",
    },
    {
        "id": "endpoint-inventory",
        "component": "osquery",
        "source_kind": "endpoint_metadata",
        "integration_owner": "not_implemented",
        "input_contract": "none",
        "output_contract": "none",
        "entry_point": None,
        "launch_policy": "proposed_no_execution",
        "data_boundary": "no arbitrary SQL, process environment, command-line dump, or remote enrollment",
        "action_boundary": "no scheduler, daemon, fleet manager, or response integration",
        "next_gate": "closed table/field/query-pack contract and local privacy review",
    },
    {
        "id": "local-ai-advisory",
        "component": "qwen-ollama",
        "source_kind": "completed_metadata_projection",
        "integration_owner": "not_implemented",
        "input_contract": "future explicit privacy-bounded projection of one completed result",
        "output_contract": "future advisory result with provenance and limitations",
        "entry_point": None,
        "launch_policy": "contract_only_no_runtime_provider",
        "data_boundary": "no raw traffic, payload, packet capture, background feed, or Internet access",
        "action_boundary": "model output cannot execute commands, modify the host, or apply a response",
        "next_gate": "reviewed local provider contract, strict timeout, provenance, and adversarial privacy tests",
    },
    {
        "id": "network-inventory-import",
        "component": "nmap",
        "source_kind": "network_inventory_metadata",
        "integration_owner": "not_implemented",
        "input_contract": "future bounded import of an operator-supplied completed Nmap XML report",
        "output_contract": "future source-qualified inventory metadata",
        "entry_point": None,
        "launch_policy": "proposed_import_only_no_scan_launch",
        "data_boundary": "closed host, address, port, protocol, and service field inventory; no scripts or banners",
        "action_boundary": "no scan launch, target selection, NSE execution, or network activity",
        "next_gate": "versioned XML contract, adversarial parser fixtures, privacy review, and explicit size limits",
    },
    {
        "id": "host-integrity-import",
        "component": "ossec",
        "source_kind": "host_integrity_alert_metadata",
        "integration_owner": "not_implemented",
        "input_contract": "future bounded import of operator-supplied completed OSSEC JSON alerts",
        "output_contract": "future source-qualified host integrity findings",
        "entry_point": None,
        "launch_policy": "proposed_import_only_no_daemon",
        "data_boundary": "closed alert field inventory; no file content, process environment, or unrestricted logs",
        "action_boundary": "no agent enrollment, daemon control, configuration change, or active response",
        "next_gate": "versioned alert contract, representative fixtures, redaction review, and size limits",
    },
    {
        "id": "vulnerability-report-import",
        "component": "greenbone",
        "source_kind": "completed_vulnerability_report",
        "integration_owner": "not_implemented",
        "input_contract": "future bounded import of an operator-supplied completed GMP XML report",
        "output_contract": "future source-qualified vulnerability review candidates",
        "entry_point": None,
        "launch_policy": "proposed_report_import_only",
        "data_boundary": "closed completed-report fields; no credentials, feed content, task configuration, or raw responses",
        "action_boundary": "no scanner launch, feed update, target creation, scheduling, or remediation",
        "next_gate": "versioned report contract, entity-expansion defenses, privacy review, and size limits",
    },
    {
        "id": "zabbix-availability-read",
        "component": "zabbix",
        "source_kind": "availability_summary",
        "integration_owner": "not_implemented",
        "input_contract": "none until a bounded read-only endpoint contract and credential policy are reviewed",
        "output_contract": "future source-qualified availability summary",
        "entry_point": None,
        "launch_policy": "proposed_no_connection",
        "data_boundary": "no endpoint, credential, host inventory, event history, or API response is read",
        "action_boundary": "no polling, acknowledgement, configuration change, script, or remote command",
        "next_gate": "read-only API allowlist, credential handling, request budgets, fixtures, and failure-state review",
    },
    {
        "id": "nagios-availability-read",
        "component": "nagios-core",
        "source_kind": "availability_summary",
        "integration_owner": "not_implemented",
        "input_contract": "none until a bounded read-only CGI contract and credential policy are reviewed",
        "output_contract": "future source-qualified availability summary",
        "entry_point": None,
        "launch_policy": "proposed_no_connection",
        "data_boundary": "no CGI endpoint, credential, status archive, host inventory, or response is read",
        "action_boundary": "no polling, acknowledgement, command pipe, configuration change, or remote command",
        "next_gate": "read-only field allowlist, credential handling, request budgets, fixtures, and failure-state review",
    },
)

WORKFLOW_IDS = tuple(item["id"] for item in _WORKFLOWS)


def integration_plan(platform: str | None = None, workflow: str | None = None) -> dict[str, Any]:
    """Return a fresh plan without probing, installing, launching, or configuring tools."""
    capabilities = catalog(platform)
    components = {item["id"]: item for item in capabilities["components"]}
    if workflow is not None and workflow not in WORKFLOW_IDS:
        raise ValueError("unknown integration workflow")

    plans = []
    for item in _WORKFLOWS:
        if workflow is not None and item["id"] != workflow:
            continue
        component = components[item["component"]]
        plans.append(
            {
                "id": item["id"],
                "component": item["component"],
                "software": component["software"],
                "selected_status": component["selected_status"],
                "source_kind": item["source_kind"],
                "integration_owner": item["integration_owner"],
                "input_contract": item["input_contract"],
                "output_contract": item["output_contract"],
                "entry_point": item["entry_point"],
                "launch_policy": item["launch_policy"],
                "data_boundary": item["data_boundary"],
                "action_boundary": item["action_boundary"],
                "next_gate": item["next_gate"],
            }
        )

    return {
        "schema": SCHEMA,
        "capability_schema": CAPABILITY_SCHEMA,
        "selected_platform": capabilities["selected_platform"],
        "hub_mode": HUB_MODE,
        "default_posture": "observe_only",
        "execution_performed": False,
        "network_access_performed": False,
        "host_change_performed": False,
        "action_status": "not_attempted",
        "workflows": plans,
    }
