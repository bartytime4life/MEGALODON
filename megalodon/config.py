"""Typed TOML configuration with conservative defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import tomllib

from .validation import ValidationError, parse_network


@dataclass(frozen=True)
class DetectionSettings:
    syn_flood_window_seconds: int = 10
    syn_flood_threshold: int = 100
    port_scan_window_seconds: int = 5
    port_scan_distinct_ports: int = 20
    dns_query_length: int = 50
    alert_cooldown_seconds: int = 30
    max_tracked_sources: int = 4096
    max_events_per_source_window: int = 4096


@dataclass(frozen=True)
class BlockingSettings:
    enabled: bool = False
    dry_run: bool = True
    auto_block: bool = False
    auto_block_min_severity: str = "CRITICAL"
    timeout_seconds: int = 900
    public_only: bool = True
    allowlist: tuple[ipaddress._BaseNetwork, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DashboardSettings:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8787


@dataclass(frozen=True)
class Settings:
    name: str = "MEGALODON"
    db_path: Path = Path("data/megalodon.db")
    log_level: str = "INFO"
    capture_source: str = "sample"
    interface: str = ""
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    blocking: BlockingSettings = field(default_factory=BlockingSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)


DEFAULT_ALLOWLIST = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
)


def _positive(value: object, name: str, minimum: int = 1) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{name} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ValidationError(f"{name} must be >= {minimum}")
    return parsed


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be a TOML boolean")
    return value


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path)
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)

    app = raw.get("app", {})
    capture = raw.get("capture", {})
    detection = raw.get("detection", {})
    blocking = raw.get("blocking", {})
    dashboard = raw.get("dashboard", {})

    allowlist_values = blocking.get("allowlist", list(DEFAULT_ALLOWLIST))
    allowlist = tuple(parse_network(str(item)) for item in allowlist_values)
    severity = str(blocking.get("auto_block_min_severity", "CRITICAL")).upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValidationError("auto_block_min_severity must be LOW, MEDIUM, HIGH, or CRITICAL")
    blocking_enabled = _boolean(blocking.get("enabled", False), "blocking.enabled")
    blocking_dry_run = _boolean(blocking.get("dry_run", True), "blocking.dry_run")
    auto_block = _boolean(blocking.get("auto_block", False), "blocking.auto_block")
    if auto_block and not blocking_dry_run:
        raise ValidationError(
            "automatic firewall application is prohibited; keep blocking.dry_run true "
            "and use the explicit block CLI after review"
        )

    port = _positive(dashboard.get("port", 8787), "dashboard.port")
    if port > 65535:
        raise ValidationError("dashboard.port must be <= 65535")

    return Settings(
        name=str(app.get("name", "MEGALODON")),
        db_path=Path(app.get("db_path", "data/megalodon.db")),
        log_level=str(app.get("log_level", "INFO")).upper(),
        capture_source=str(capture.get("source", "sample")).lower(),
        interface=str(capture.get("interface", "")),
        detection=DetectionSettings(
            syn_flood_window_seconds=_positive(detection.get("syn_flood_window_seconds", 10), "syn_flood_window_seconds"),
            syn_flood_threshold=_positive(detection.get("syn_flood_threshold", 100), "syn_flood_threshold"),
            port_scan_window_seconds=_positive(detection.get("port_scan_window_seconds", 5), "port_scan_window_seconds"),
            port_scan_distinct_ports=_positive(detection.get("port_scan_distinct_ports", 20), "port_scan_distinct_ports"),
            dns_query_length=_positive(detection.get("dns_query_length", 50), "dns_query_length"),
            alert_cooldown_seconds=_positive(detection.get("alert_cooldown_seconds", 30), "alert_cooldown_seconds"),
            max_tracked_sources=_positive(detection.get("max_tracked_sources", 4096), "max_tracked_sources"),
            max_events_per_source_window=_positive(
                detection.get("max_events_per_source_window", 4096),
                "max_events_per_source_window",
            ),
        ),
        blocking=BlockingSettings(
            enabled=blocking_enabled,
            dry_run=blocking_dry_run,
            auto_block=auto_block,
            auto_block_min_severity=severity,
            timeout_seconds=_positive(blocking.get("timeout_seconds", 900), "timeout_seconds"),
            public_only=_boolean(blocking.get("public_only", True), "blocking.public_only"),
            allowlist=allowlist,
        ),
        dashboard=DashboardSettings(
            enabled=_boolean(dashboard.get("enabled", True), "dashboard.enabled"),
            host=str(dashboard.get("host", "127.0.0.1")),
            port=port,
        ),
    )
