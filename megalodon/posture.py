"""Build a bounded local posture receipt without probing or changing the host."""

from __future__ import annotations

from collections import Counter
from . import __version__
from .capabilities import STATUSES, catalog, runtime_platform
from .reference import ReferenceDataError, load_iana


SCHEMA = "megalodon-local-posture-v1"
LIMITATIONS = (
    "This is package-level boundary evidence, not host-health, deployment, or operational-readiness evidence.",
    "It does not inspect installed tools, permissions, databases, network listeners, captures, services, or firewall state.",
)


def _reference_data_status() -> dict[str, object]:
    try:
        bundle = load_iana()
    except ReferenceDataError as error:
        unavailable = str(error) == "REFERENCE_DATA:RESOURCE_IO"
        return {
            "action_status": "not_attempted",
            "error": "reference bundle unavailable" if unavailable else "reference bundle integrity failure",
            "network_access_performed": False,
            "persistence_status": "not_attempted",
            "status": "unavailable" if unavailable else "integrity_failure",
        }
    return {
        "action_status": "not_attempted",
        "bundle_id": bundle.bundle_id,
        "manifest_sha256": bundle.manifest_sha256,
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "protocol_records": len(bundle.protocols),
        "service_records": len(bundle.services),
        "status": "verified",
    }


def local_posture(platform: str | None = None) -> dict[str, object]:
    """Return fresh bounded evidence without an installation or host probe."""
    selected = runtime_platform() if platform is None else platform
    static_catalog = catalog(selected)
    counts = Counter(item["selected_status"] for item in static_catalog["components"])
    return {
        "action_status": "not_attempted",
        "capability_status_counts": {
            status: counts[status] for status in sorted(STATUSES)
        },
        "declared_posture": "observe_only",
        "host_change_performed": False,
        "host_inspection_performed": False,
        "limitations": list(LIMITATIONS),
        "network_access_performed": False,
        "package_version": __version__,
        "persistence_status": "not_attempted",
        "reference_data": _reference_data_status(),
        "schema": SCHEMA,
        "selected_platform": selected,
        "selection_mode": "runtime_platform" if platform is None else "explicit_static_profile",
    }
