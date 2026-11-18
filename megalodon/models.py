"""Typed domain objects. Packet payloads are intentionally not represented."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from .validation import (
    parse_flags,
    parse_dns_name,
    parse_ja3,
    parse_ja4,
    parse_ip,
    parse_mac,
    parse_nonnegative_int,
    parse_port,
    parse_timestamp,
    safe_text,
    SQLITE_INTEGER_MAX,
    ValidationError,
    validate_metadata,
    validate_packet_metadata,
)


@dataclass(frozen=True)
class PacketEvent:
    observed_at: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: frozenset[str] = frozenset()
    dns_query_length: int | None = None
    byte_count: int = 0
    interface: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)
    # Transient and opt-in ([threat_detection] dns_names). Detectors read it in
    # memory; storage never writes it, and only a flagged domain is retained,
    # inside that finding's evidence.
    dns_query_name: str | None = None
    # Transient and opt-in ([threat_detection] tls_fingerprints): one TLS
    # ClientHello's JA3/JA4 fingerprints and server name. Never stored.
    tls_ja3: str | None = None
    tls_ja4: str | None = None
    tls_sni: str | None = None
    # Transient and opt-in ([threat_detection] lan_integrity): an ARP frame's
    # opcode and sender hardware address (src_ip/dst_ip are its sender and
    # target protocol addresses), and a DHCP reply's message type and server
    # identifier. Never stored; only a flagged binding or server is retained.
    arp_opcode: int | None = None
    arp_sender_mac: str | None = None
    dhcp_message_type: int | None = None
    dhcp_server_id: str | None = None
    # The IPv6 counterparts, under the same opt-in: a neighbour-discovery
    # message's type (134 router advertisement, 135 neighbour solicitation,
    # 136 neighbour advertisement), the link-layer address it claims, an
    # advertisement's target address and a router advertisement's router
    # lifetime. A DHCPv6 message's type uses dhcp_message_type. Never stored.
    nd_type: int | None = None
    nd_mac: str | None = None
    nd_target: str | None = None
    ra_router_lifetime: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", parse_timestamp(self.observed_at))
        object.__setattr__(self, "src_ip", parse_ip(self.src_ip))
        object.__setattr__(self, "dst_ip", parse_ip(self.dst_ip))
        protocol = safe_text(self.protocol, "protocol", 32).strip().upper()
        if not protocol:
            raise ValidationError("protocol must not be empty")
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "src_port", parse_port(self.src_port))
        object.__setattr__(self, "dst_port", parse_port(self.dst_port))
        object.__setattr__(self, "tcp_flags", parse_flags(self.tcp_flags))
        if self.dns_query_length is not None:
            object.__setattr__(
                self,
                "dns_query_length",
                parse_nonnegative_int(
                    self.dns_query_length,
                    "dns_query_length",
                    maximum=SQLITE_INTEGER_MAX,
                ),
            )
        object.__setattr__(
            self,
            "byte_count",
            parse_nonnegative_int(
                self.byte_count,
                "byte_count",
                maximum=SQLITE_INTEGER_MAX,
            ),
        )
        if self.interface is not None:
            object.__setattr__(self, "interface", safe_text(self.interface, "interface", 64))
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(validate_packet_metadata(self.metadata)),
        )
        if self.dns_query_name is not None:
            object.__setattr__(self, "dns_query_name", parse_dns_name(self.dns_query_name))
        if self.tls_ja3 is not None:
            object.__setattr__(self, "tls_ja3", parse_ja3(self.tls_ja3))
        if self.tls_ja4 is not None:
            object.__setattr__(self, "tls_ja4", parse_ja4(self.tls_ja4))
        if self.tls_sni is not None:
            object.__setattr__(self, "tls_sni", parse_dns_name(self.tls_sni))
        for name, maximum in (("arp_opcode", 65535), ("dhcp_message_type", 255)):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, parse_nonnegative_int(value, name, maximum=maximum))
        if (self.arp_opcode is None) != (self.arp_sender_mac is None):
            raise ValidationError("arp_opcode and arp_sender_mac must be given together")
        if self.arp_sender_mac is not None:
            object.__setattr__(self, "arp_sender_mac", parse_mac(self.arp_sender_mac))
        if self.dhcp_server_id is not None:
            object.__setattr__(self, "dhcp_server_id", parse_ip(self.dhcp_server_id))
        self._validate_neighbour_discovery()

    def _validate_neighbour_discovery(self) -> None:
        if self.nd_type is None:
            if any(v is not None for v in (self.nd_mac, self.nd_target, self.ra_router_lifetime)):
                raise ValidationError("nd_mac, nd_target and ra_router_lifetime need nd_type")
            return
        kind = parse_nonnegative_int(self.nd_type, "nd_type", maximum=255)
        if kind not in {134, 135, 136}:
            raise ValidationError("nd_type must be 134, 135 or 136")
        if self.protocol != "ICMPV6" or ":" not in self.src_ip:
            raise ValidationError("neighbour discovery fields need an IPv6 ICMPV6 event")
        object.__setattr__(self, "nd_type", kind)
        if self.nd_mac is not None:
            object.__setattr__(self, "nd_mac", parse_mac(self.nd_mac))
        if (kind == 136) != (self.nd_target is not None):
            raise ValidationError("nd_target is given with, and only with, a neighbour advertisement")
        if self.nd_target is not None:
            target = parse_ip(self.nd_target)
            if ":" not in target:
                raise ValidationError("nd_target must be an IPv6 address")
            object.__setattr__(self, "nd_target", target)
        if (kind == 134) != (self.ra_router_lifetime is not None):
            raise ValidationError("ra_router_lifetime is given with, and only with, a router advertisement")
        if self.ra_router_lifetime is not None:
            object.__setattr__(self, "ra_router_lifetime", parse_nonnegative_int(
                self.ra_router_lifetime, "ra_router_lifetime", maximum=65535))

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "PacketEvent":
        return cls(
            observed_at=parse_timestamp(value.get("observed_at", value.get("timestamp"))),
            src_ip=value["src_ip"],
            dst_ip=value["dst_ip"],
            protocol=value.get("protocol", "UNKNOWN"),
            src_port=value.get("src_port"),
            dst_port=value.get("dst_port"),
            tcp_flags=value.get("tcp_flags", ()),
            dns_query_length=value.get("dns_query_length"),
            byte_count=value.get("byte_count", 0),
            interface=value.get("interface"),
            metadata=value.get("metadata"),
            dns_query_name=value.get("dns_query_name"),
            tls_ja3=value.get("tls_ja3"),
            tls_ja4=value.get("tls_ja4"),
            tls_sni=value.get("tls_sni"),
            arp_opcode=value.get("arp_opcode"),
            arp_sender_mac=value.get("arp_sender_mac"),
            dhcp_message_type=value.get("dhcp_message_type"),
            dhcp_server_id=value.get("dhcp_server_id"),
            nd_type=value.get("nd_type"),
            nd_mac=value.get("nd_mac"),
            nd_target=value.get("nd_target"),
            ra_router_lifetime=value.get("ra_router_lifetime"),
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "observed_at": self.observed_at.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": sorted(self.tcp_flags),
            "dns_query_length": self.dns_query_length,
            "byte_count": self.byte_count,
            "interface": self.interface,
            "metadata": dict(self.metadata),
        }
        # Opt-in fields appear only when present, so default output is unchanged.
        for name in ("dns_query_name", "tls_ja3", "tls_ja4", "tls_sni", "arp_opcode",
                     "arp_sender_mac", "dhcp_message_type", "dhcp_server_id", "nd_type", "nd_mac",
                     "nd_target", "ra_router_lifetime"):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result

    @property
    def is_client_hello(self) -> bool:
        return self.tls_ja3 is not None or self.tls_ja4 is not None


@dataclass(frozen=True)
class DetectionResult:
    detected_at: datetime
    rule_id: str
    severity: str
    src_ip: str
    dst_ip: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = "ALERT"
    suppressed_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "detected_at", parse_timestamp(self.detected_at))
        object.__setattr__(self, "src_ip", parse_ip(self.src_ip))
        object.__setattr__(self, "dst_ip", parse_ip(self.dst_ip))
        severity = safe_text(self.severity, "severity", 16).strip().upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValidationError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")
        rule_id = safe_text(self.rule_id, "rule_id", 64).strip()
        message = safe_text(self.message, "message", 512).strip()
        recommendation = safe_text(self.recommendation, "recommendation", 64).strip().upper()
        if not rule_id:
            raise ValidationError("rule_id must not be empty")
        if not message:
            raise ValidationError("message must not be empty")
        if not recommendation:
            raise ValidationError("recommendation must not be empty")
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "rule_id", rule_id)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "evidence", validate_metadata(self.evidence))
        object.__setattr__(self, "recommendation", recommendation)
        if self.suppressed_reason is not None:
            object.__setattr__(
                self,
                "suppressed_reason",
                safe_text(self.suppressed_reason, "suppressed_reason", 256).strip(),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_at": self.detected_at.isoformat(),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "suppressed_reason": self.suppressed_reason,
        }


@dataclass(frozen=True)
class ActionRecord:
    created_at: datetime
    action: str
    target: str
    status: str
    reason: str
    expires_at: datetime | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", parse_timestamp(self.created_at))
        action = safe_text(self.action, "action", 64).strip()
        target = safe_text(self.target, "target", 128).strip()
        status = safe_text(self.status, "status", 32).strip().lower()
        reason = safe_text(self.reason, "reason", 512).strip()
        if not action:
            raise ValidationError("action must not be empty")
        if not target:
            raise ValidationError("target must not be empty")
        if status not in {"not_attempted", "suppressed", "planned", "applied", "failed"}:
            raise ValidationError(
                "status must be not_attempted, suppressed, planned, applied, or failed"
            )
        if not reason:
            raise ValidationError("reason must not be empty")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason", reason)
        if self.expires_at is not None:
            object.__setattr__(self, "expires_at", parse_timestamp(self.expires_at))
        object.__setattr__(self, "details", validate_metadata(self.details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at.isoformat(),
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "details": self.details,
        }
