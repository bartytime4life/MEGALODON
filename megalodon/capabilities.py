"""Static capability catalog; never probes, installs, starts, or configures tools."""

from __future__ import annotations

import sys
from typing import Any


SCHEMA = "megalodon-capability-catalog-v1"
PLATFORMS = ("linux", "windows", "other")
STATUSES = frozenset(
    {
        "implemented",
        "optional",
        "evaluation_only",
        "contract_only",
        "manual_only",
        "guest_only",
        "proposed",
        "unsupported",
    }
)

_COMPONENTS = (
    {
        "id": "python-sqlite",
        "software": "Python and SQLite",
        "integration": "core_metadata_runtime",
        "platforms": {
            "linux": "implemented",
            "windows": "evaluation_only",
            "other": "unsupported",
        },
        "boundary": "Windows core execution and ACL/UI behavior remain unverified.",
    },
    {
        "id": "wireshark-tshark",
        "software": "Wireshark and TShark",
        "integration": "offline_packet_metadata",
        "platforms": {
            "linux": "optional",
            "windows": "manual_only",
            "other": "unsupported",
        },
        "boundary": "The MEGALODON TShark adapter is Linux-only; Windows may open saved captures manually.",
    },
    {
        "id": "zeek",
        "software": "Zeek",
        "integration": "offline_connection_metadata",
        "platforms": {
            "linux": "optional",
            "windows": "guest_only",
            "other": "unsupported",
        },
        "boundary": "MEGALODON imports a bounded conn.log profile and never starts Zeek.",
    },
    {
        "id": "suricata",
        "software": "Suricata",
        "integration": "eve_alert_contract",
        "platforms": {
            "linux": "contract_only",
            "windows": "contract_only",
            "other": "unsupported",
        },
        "boundary": "Schema and synthetic fixtures exist; no runtime importer, sensor, ruleset, or IPS path exists.",
    },
    {
        "id": "scapy",
        "software": "Scapy",
        "integration": "optional_live_metadata_capture",
        "platforms": {
            "linux": "optional",
            "windows": "unsupported",
            "other": "unsupported",
        },
        "boundary": "The capture extra is not enabled by default and supplies no packet-crafting feature.",
    },
    {
        "id": "nftables",
        "software": "nftables",
        "integration": "explicit_time_limited_response",
        "platforms": {
            "linux": "optional",
            "windows": "unsupported",
            "other": "unsupported",
        },
        "boundary": "Plans are non-mutating by default; application needs exact confirmation and already-held root.",
    },
    {
        "id": "clamav",
        "software": "ClamAV",
        "integration": "separate_manual_file_scan",
        "platforms": {
            "linux": "manual_only",
            "windows": "manual_only",
            "other": "proposed",
        },
        "boundary": "No file-content intake, quarantine, signature update, daemon, or result importer exists.",
    },
    {
        "id": "osquery",
        "software": "osquery",
        "integration": "future_endpoint_metadata",
        "platforms": {
            "linux": "proposed",
            "windows": "proposed",
            "other": "proposed",
        },
        "boundary": "No query pack, arbitrary SQL, scheduler, remote enrollment, or importer exists.",
    },
)

_EXCLUDED = (
    {
        "id": "npcap",
        "software": "Npcap",
        "reason": "not_an_open_source_baseline_dependency",
        "boundary": "Windows live capture is unsupported; saved-capture analysis does not require Npcap.",
    },
)


def runtime_platform(value: str | None = None) -> str:
    """Collapse host names into the three documented platform profiles."""
    candidate = sys.platform if value is None else value
    if candidate.startswith("linux"):
        return "linux"
    if candidate.startswith("win") or candidate == "cygwin":
        return "windows"
    return "other"


def catalog(platform: str | None = None) -> dict[str, Any]:
    """Return a fresh, deterministic support catalog without inspecting the host."""
    selected = runtime_platform() if platform is None else platform
    if selected not in PLATFORMS:
        raise ValueError("unsupported platform profile")
    components = []
    for item in _COMPONENTS:
        statuses = dict(item["platforms"])
        components.append(
            {
                "id": item["id"],
                "software": item["software"],
                "software_class": "free_or_open_source",
                "integration": item["integration"],
                "selected_status": statuses[selected],
                "platforms": statuses,
                "boundary": item["boundary"],
            }
        )
    return {
        "schema": SCHEMA,
        "selected_platform": selected,
        "catalog_mode": "static_no_host_probe",
        "default_posture": "observe_only",
        "installation_performed": False,
        "network_access_performed": False,
        "components": components,
        "excluded": [dict(item) for item in _EXCLUDED],
    }
