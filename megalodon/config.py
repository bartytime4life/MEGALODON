"""Typed TOML configuration with conservative defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import tomllib

from .validation import ValidationError, parse_network, safe_text


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
    refresh_seconds: int = 5
    event_limit: int = 50


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

MAX_DETECTION_WINDOW_SECONDS = 3600
MAX_DETECTION_THRESHOLD = 65536
MAX_DNS_QUERY_LENGTH = 65535
MAX_ALERT_COOLDOWN_SECONDS = 86400
MAX_TRACKED_SOURCES = 65536
MAX_EVENTS_PER_SOURCE_WINDOW = 65536
MAX_BLOCK_TIMEOUT_SECONDS = 604800


def _table(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be a TOML table")
    return value


def _text(
    value: object,
    name: str,
    maximum: int,
    *,
    allow_empty: bool = False,
) -> str:
    parsed = safe_text(value, name, maximum).strip()
    if not parsed and not allow_empty:
        raise ValidationError(f"{name} must not be empty")
    return parsed


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be a TOML boolean")
    return value


def _bounded_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_settings(path: str | Path | None = None) -> Settings:
    if path is None:
        raw: dict[str, object] = {}
    else:
        config_path = Path(path)
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)

    app = _table(raw.get("app", {}), "app")
    capture = _table(raw.get("capture", {}), "capture")
    detection = _table(raw.get("detection", {}), "detection")
    blocking = _table(raw.get("blocking", {}), "blocking")
    dashboard = _table(raw.get("dashboard", {}), "dashboard")

    allowlist_values = blocking.get("allowlist", list(DEFAULT_ALLOWLIST))
    if not isinstance(allowlist_values, list) or not all(
        isinstance(item, str) for item in allowlist_values
    ):
        raise ValidationError("blocking.allowlist must be an array of network strings")
    allowlist = tuple(parse_network(item) for item in allowlist_values)
    severity = _text(
        blocking.get("auto_block_min_severity", "CRITICAL"),
        "blocking.auto_block_min_severity",
        16,
    ).upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValidationError("auto_block_min_severity must be LOW, MEDIUM, HIGH, or CRITICAL")
    blocking_enabled = _boolean(blocking.get("enabled", False), "blocking.enabled")
    blocking_dry_run = _boolean(blocking.get("dry_run", True), "blocking.dry_run")
    auto_block = _boolean(blocking.get("auto_block", False), "blocking.auto_block")
    if auto_block and not blocking_dry_run:
        raise ValidationError(
            "live firewall application is unsupported in this evaluation release; "
            "keep blocking.dry_run true"
        )

    port = _bounded_integer(dashboard.get("port", 8787), "dashboard.port", 1, 65535)
    max_events_per_source_window = _bounded_integer(
        detection.get("max_events_per_source_window", 4096),
        "detection.max_events_per_source_window",
        1,
        MAX_EVENTS_PER_SOURCE_WINDOW,
    )
    syn_flood_threshold = _bounded_integer(
        detection.get("syn_flood_threshold", 100),
        "detection.syn_flood_threshold",
        1,
        MAX_DETECTION_THRESHOLD,
    )
    port_scan_distinct_ports = _bounded_integer(
        detection.get("port_scan_distinct_ports", 20),
        "detection.port_scan_distinct_ports",
        1,
        MAX_DETECTION_THRESHOLD,
    )
    if syn_flood_threshold > max_events_per_source_window:
        raise ValidationError(
            "detection.syn_flood_threshold must not exceed "
            "detection.max_events_per_source_window"
        )
    if port_scan_distinct_ports > max_events_per_source_window:
        raise ValidationError(
            "detection.port_scan_distinct_ports must not exceed "
            "detection.max_events_per_source_window"
        )

    name = _text(app.get("name", "MEGALODON"), "app.name", 64)
    db_path = _text(app.get("db_path", "data/megalodon.db"), "app.db_path", 1024)
    log_level = _text(app.get("log_level", "INFO"), "app.log_level", 16).upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValidationError("app.log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    capture_source = _text(capture.get("source", "sample"), "capture.source", 16).lower()
    if capture_source not in {"sample", "jsonl", "scapy"}:
        raise ValidationError("capture.source must be sample, jsonl, or scapy")

    return Settings(
        name=name,
        db_path=Path(db_path),
        log_level=log_level,
        capture_source=capture_source,
        interface=_text(capture.get("interface", ""), "capture.interface", 64, allow_empty=True),
        detection=DetectionSettings(
            syn_flood_window_seconds=_bounded_integer(
                detection.get("syn_flood_window_seconds", 10),
                "detection.syn_flood_window_seconds",
                1,
                MAX_DETECTION_WINDOW_SECONDS,
            ),
            syn_flood_threshold=syn_flood_threshold,
            port_scan_window_seconds=_bounded_integer(
                detection.get("port_scan_window_seconds", 5),
                "detection.port_scan_window_seconds",
                1,
                MAX_DETECTION_WINDOW_SECONDS,
            ),
            port_scan_distinct_ports=port_scan_distinct_ports,
            dns_query_length=_bounded_integer(
                detection.get("dns_query_length", 50),
                "detection.dns_query_length",
                1,
                MAX_DNS_QUERY_LENGTH,
            ),
            alert_cooldown_seconds=_bounded_integer(
                detection.get("alert_cooldown_seconds", 30),
                "detection.alert_cooldown_seconds",
                1,
                MAX_ALERT_COOLDOWN_SECONDS,
            ),
            max_tracked_sources=_bounded_integer(
                detection.get("max_tracked_sources", 4096),
                "detection.max_tracked_sources",
                1,
                MAX_TRACKED_SOURCES,
            ),
            max_events_per_source_window=max_events_per_source_window,
        ),
        blocking=BlockingSettings(
            enabled=blocking_enabled,
            dry_run=blocking_dry_run,
            auto_block=auto_block,
            auto_block_min_severity=severity,
            timeout_seconds=_bounded_integer(
                blocking.get("timeout_seconds", 900),
                "blocking.timeout_seconds",
                1,
                MAX_BLOCK_TIMEOUT_SECONDS,
            ),
            public_only=_boolean(blocking.get("public_only", True), "blocking.public_only"),
            allowlist=allowlist,
        ),
        dashboard=DashboardSettings(
            enabled=_boolean(dashboard.get("enabled", True), "dashboard.enabled"),
            host=_text(dashboard.get("host", "127.0.0.1"), "dashboard.host", 253),
            port=port,
            refresh_seconds=_bounded_integer(
                dashboard.get("refresh_seconds", 5), "dashboard.refresh_seconds", 2, 300
            ),
            event_limit=_bounded_integer(dashboard.get("event_limit", 50), "dashboard.event_limit", 1, 200),
        ),
    )
