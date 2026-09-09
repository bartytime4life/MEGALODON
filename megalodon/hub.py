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
