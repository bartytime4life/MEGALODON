"""Typed domain objects. Packet payloads are intentionally not represented."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .validation import (
    parse_flags,
    parse_ip,
    parse_nonnegative_int,
    parse_port,
    parse_timestamp,
    safe_text,
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
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", parse_timestamp(self.observed_at))
        object.__setattr__(self, "src_ip", parse_ip(self.src_ip))
        object.__setattr__(self, "dst_ip", parse_ip(self.dst_ip))
        object.__setattr__(self, "protocol", str(self.protocol).upper())
        object.__setattr__(self, "src_port", parse_port(self.src_port))
        object.__setattr__(self, "dst_port", parse_port(self.dst_port))
        object.__setattr__(self, "tcp_flags", parse_flags(self.tcp_flags))
        if self.dns_query_length is not None:
            object.__setattr__(
                self,
                "dns_query_length",
                parse_nonnegative_int(self.dns_query_length, "dns_query_length"),
            )
        object.__setattr__(self, "byte_count", parse_nonnegative_int(self.byte_count, "byte_count"))
        if self.interface is not None:
            object.__setattr__(self, "interface", safe_text(self.interface, "interface", 64))

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
            metadata=dict(value.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
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
            "metadata": self.metadata,
        }


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
        object.__setattr__(self, "severity", str(self.severity).upper())
        object.__setattr__(self, "rule_id", safe_text(self.rule_id, "rule_id", 64))
        object.__setattr__(self, "message", safe_text(self.message, "message", 512))

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
