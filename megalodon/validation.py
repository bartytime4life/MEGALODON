"""Input validation and normalization for untrusted network metadata."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any


class ValidationError(ValueError):
    """Raised when an event or policy value is not safe to use."""


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def parse_ip(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("IP address must be a non-empty string")
    candidate = value.strip()
    if "%" in candidate:
        raise ValidationError("IPv6 zone identifiers are not accepted")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError as exc:
        raise ValidationError(f"invalid IP address: {value!r}") from exc


def parse_network(value: str) -> ipaddress._BaseNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"invalid network: {value!r}") from exc


def parse_port(value: Any, *, allow_none: bool = True) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool):
        raise ValidationError("port must be an integer")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid port: {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ValidationError(f"port outside 0..65535: {port}")
    return port


def parse_nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{field_name} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field_name} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValidationError(f"{field_name} must be non-negative")
    return parsed


def parse_timestamp(value: Any) -> datetime:
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        candidate = value.strip().replace("Z", "+00:00")
        try:
            result = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValidationError(f"invalid ISO timestamp: {value!r}") from exc
    else:
        raise ValidationError("timestamp must be an ISO string")
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def parse_flags(value: Any) -> frozenset[str]:
    if value is None or value == "":
        return frozenset()
    if isinstance(value, str):
        raw = value.replace("|", ",").replace(" ", ",").split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = value
    else:
        raise ValidationError("tcp_flags must be a string or sequence")
    flags = {str(item).strip().upper() for item in raw if str(item).strip()}
    allowed = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
    unknown = flags - allowed
    if unknown:
        raise ValidationError(f"unknown TCP flags: {sorted(unknown)}")
    return frozenset(flags)


def safe_text(value: Any, field_name: str, max_length: int = 512) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be text")
    if _CONTROL_CHARS.search(value):
        raise ValidationError(f"{field_name} contains control characters")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} exceeds {max_length} characters")
    return value


def is_global_unicast(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast
