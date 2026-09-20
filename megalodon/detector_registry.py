"""Closed descriptions of the existing rules; never a runtime dispatch table."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .config import DetectionSettings


@dataclass(frozen=True)
class DetectorDefinition:
    rule_id: str
    version: str
    severity: str
    required_fields: tuple[str, ...]
    eligibility: str
    measurement: str
    threshold_setting: str
    window_setting: str | None
    fixtures: tuple[str, ...]


DETECTORS = (
    DetectorDefinition(
        "DNS_TUNNELING", "1.0.0", "CRITICAL",
        ("src_ip", "observed_at", "protocol", "dns_query_length"),
        "protocol is DNS or UDP and dns_query_length is present; no port gate",
        "current event dns_query_length", "dns_query_length", None,
        ("dns-protocol-gates-v1", "threshold-matrix-v1", "cooldown-boundaries-v1",
         "authorized-lookalikes-v1", "source-cap-pressure-v1"),
    ),
    DetectorDefinition(
        "PORT_SCAN", "1.0.0", "MEDIUM",
        ("src_ip", "observed_at", "protocol", "dst_port"),
        "protocol is TCP and dst_port is present; any TCP flags",
        "distinct destination ports per source across destination addresses",
        "port_scan_distinct_ports", "port_scan_window_seconds",
        ("port-distinct-ipv6-v1", "port-repeated-ipv6-v1", "threshold-matrix-v1",
         "cooldown-boundaries-v1", "authorized-lookalikes-v1"),
    ),
    DetectorDefinition(
        "SYN_FLOOD", "1.0.0", "HIGH",
        ("src_ip", "observed_at", "protocol", "tcp_flags", "dst_ip"),
        "protocol is TCP, SYN is present and ACK is absent",
        "qualifying TCP SYN event count per source across destination addresses",
        "syn_flood_threshold", "syn_flood_window_seconds",
        ("syn-window-cutoff-v1", "syn-window-outside-v1", "threshold-matrix-v1",
         "cooldown-boundaries-v1", "ipv6-parity-v1", "authorized-lookalikes-v1"),
    ),
)
RULE_IDS = tuple(item.rule_id for item in DETECTORS)


def registry_document() -> dict[str, object]:
    """Return a detached JSON document, including shared semantics for each rule."""
    rules = []
    for definition in DETECTORS:
        rule = asdict(definition)
        rule["required_fields"] = list(definition.required_fields)
        rule["fixtures"] = list(definition.fixtures)
        rule.update({
            "owner": "MEGALODON maintainers",
            "source_unit": "validated PacketEvent metadata",
            "source_vantage": "not inferred from rule output",
            "threshold_comparison": "greater_than_or_equal",
            "window_boundary": (
                "event-time inclusive cutoff; remove timestamps strictly before cutoff"
                if definition.window_setting else "single event; no sliding window"
            ),
            "cooldown_setting": "alert_cooldown_seconds",
            "cooldown_key": ["rule_id", "src_ip"],
            "cooldown_boundary": "suppress elapsed < cooldown; equality may emit",
        })
        rules.append(rule)
    return {
        "schema": "detector-registry-v1",
        "registry_version": "1.0.0",
        "rules": rules,
        "default_settings": asdict(DetectionSettings()),
        "state": {
            "source_limit_setting": "max_tracked_sources",
            "window_event_limit_setting": "max_events_per_source_window",
            "window_overflow": "discard oldest events; counts can be truncated",
            "source_overflow": "LRU eviction clears windows, cooldown and time watermark",
            "time_order": "nondecreasing per source; at most 60 seconds ahead of detector clock",
            "allowlisted_source": "finding carries source_allowlisted suppression; still counted",
        },
        "change_policy": (
            "Review rule-version changes with behavior, severity or required-input changes; "
            "record effective settings separately. This registry does not configure or dispatch rules."
        ),
        "interpretation": "heuristic findings for review; no maliciousness or accuracy verdict",
        "attack_mapping": {"status": "not_assessed", "validation_evidence": False},
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }


def registry_sha256() -> str:
    """Digest the canonical UTF-8 JSON document (no trailing newline)."""
    data = json.dumps(
        registry_document(), sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
