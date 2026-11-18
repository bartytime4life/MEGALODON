"""One closed catalog of every detector rule a stored finding may carry.

Projection, AI evidence and browser validators are fail-closed: an unknown
``rule_id`` makes them refuse the whole response. They therefore derive their
closed sets from this catalog instead of repeating literal rule lists. The
catalog describes rules; it never configures, dispatches or enables them.
"""

from __future__ import annotations

from dataclasses import dataclass
import json


@dataclass(frozen=True)
class RuleDescription:
    rule_id: str
    layer: str
    severity: str
    measurement_key: str
    unit: str
    windowed: bool
    summary: str
    lookalikes: str
    attack: tuple[str, ...]
    review_category: str
    response_party: str


CORE_LAYER = "core-specification"
THREAT_LAYER = "threat-signals"

RULES: tuple[RuleDescription, ...] = (
    RuleDescription(
        "SYN_FLOOD", CORE_LAYER, "HIGH", "count", "SYN events", True,
        "The recorded SYN_FLOOD rule identifies SYN activity for review.",
        "Legitimate load or authorized testing can produce similar patterns.",
        ("T1498",), "traffic_volume", "source",
    ),
    RuleDescription(
        "PORT_SCAN", CORE_LAYER, "MEDIUM", "distinct_ports", "distinct destination ports", True,
        "The recorded PORT_SCAN rule identifies a port-access pattern for review.",
        "Inventory work and authorized testing can produce similar patterns.",
        ("T1046",), "discovery", "source",
    ),
    RuleDescription(
        "DNS_TUNNELING", CORE_LAYER, "CRITICAL", "dns_query_length", "DNS query length", False,
        "The recorded DNS_TUNNELING rule identifies DNS metadata for review.",
        "A long DNS query can be legitimate; this finding does not prove tunneling.",
        ("T1071.004",), "dns", "source",
    ),
    RuleDescription(
        "BRUTE_FORCE", THREAT_LAYER, "HIGH", "attempts", "connection attempts", True,
        "Repeated connection attempts from one source reached one authentication service.",
        "Reconnecting clients, health checks and configuration tools can retry the same service.",
        ("T1110",), "credential_access", "source",
    ),
    RuleDescription(
        "HOST_SWEEP", THREAT_LAYER, "MEDIUM", "distinct_hosts", "distinct internal hosts", True,
        "One source contacted many distinct internal hosts in a short window.",
        "Inventory scanners, backup agents and network discovery features sweep subnets too.",
        ("T1018", "T1046"), "discovery", "source",
    ),
    RuleDescription(
        "DATA_EXFILTRATION", THREAT_LAYER, "HIGH", "mebibytes", "MiB sent outbound", True,
        "An internal host sent a large volume of reported bytes to one public address.",
        "Cloud backup, file sync, video calls and uploads can send the same volume.",
        ("T1041", "T1048"), "traffic_volume", "destination",
    ),
    RuleDescription(
        "BEACONING", THREAT_LAYER, "MEDIUM", "intervals", "regular intervals", True,
        "Connection starts from one host to one public service repeated at a near-constant interval.",
        "Update checks, telemetry, keep-alives and monitoring agents also poll on a schedule.",
        ("T1071", "T1573"), "command_and_control", "destination",
    ),
    RuleDescription(
        "DECOY_TOUCH", THREAT_LAYER, "CRITICAL", "contacts", "decoy contacts", False,
        "A source contacted a decoy port or unassigned decoy address that no legitimate client uses.",
        "A misconfigured client, a stale DNS record or an operator's own test can touch a decoy.",
        ("T1046", "T1018"), "discovery", "source",
    ),
    RuleDescription(
        "IOC_MATCH", THREAT_LAYER, "HIGH", "matches", "watchlist matches", False,
        "An address in this event matched an operator-supplied watchlist indicator.",
        "Indicator lists go stale; shared hosting and reassigned addresses cause false matches.",
        ("T1071",), "threat_intelligence", "matched",
    ),
    # Appended, never inserted: earlier HUD snapshot exports label by position.
    RuleDescription(
        "DGA_DOMAIN", THREAT_LAYER, "MEDIUM", "signals", "name signals", False,
        "A looked-up domain reads like a machine-generated or encoded name.",
        "CDNs, trackers, ad networks and some cloud services also use random-looking names.",
        ("T1568.002",), "dns", "source",
    ),
    RuleDescription(
        "DNS_TUNNEL_CHURN", THREAT_LAYER, "HIGH", "distinct_subdomains", "distinct subdomains", True,
        "One host queried many distinct subdomains of one domain in a short window.",
        "Some telemetry, anti-spam and CDN services encode data in subdomains on purpose.",
        ("T1071.004", "T1048.003"), "dns", "source",
    ),
)

BY_ID: dict[str, RuleDescription] = {rule.rule_id: rule for rule in RULES}
ALL_RULE_IDS: tuple[str, ...] = tuple(rule.rule_id for rule in RULES)
CORE_RULE_IDS: tuple[str, ...] = tuple(r.rule_id for r in RULES if r.layer == CORE_LAYER)
THREAT_RULE_IDS: tuple[str, ...] = tuple(r.rule_id for r in RULES if r.layer == THREAT_LAYER)
MEASUREMENT_UNITS: dict[str, str] = {rule.rule_id: rule.unit for rule in RULES}
UNWINDOWED_RULES: frozenset[str] = frozenset(r.rule_id for r in RULES if not r.windowed)


def browser_constants() -> str:
    """Return a JS object literal for embedded validators; JSON is valid JS."""
    return json.dumps(
        {
            "rules": list(ALL_RULE_IDS),
            "units": MEASUREMENT_UNITS,
            "unwindowed": sorted(UNWINDOWED_RULES),
            "summaries": {r.rule_id: f"{r.summary} {r.lookalikes}" for r in RULES},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
