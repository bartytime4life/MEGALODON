"""Bounded threat-signal rules that run beside the core specification detector.

The three core rules (SYN_FLOOD, PORT_SCAN, DNS_TUNNELING) are a published,
corpus-qualified specification and are deliberately left unchanged. This
module adds five review signals a defender expects from a network sensor:

``BRUTE_FORCE``
    Repeated connection attempts from one source to one authentication service
    (SSH, RDP, SMB, databases, mail, directory, remote management, ...).
``HOST_SWEEP``
    One source opening contact with many distinct *internal* hosts: subnet
    discovery and the first step of lateral movement.
``DATA_EXFILTRATION``
    An internal host sending a large reported byte volume to one public address.
``BEACONING``
    Connection starts from an internal host to one public service repeating at
    a near-constant interval, the classic command-and-control heartbeat.
``IOC_MATCH``
    Any source or destination that matches an operator-supplied local watchlist.

Every rule is a heuristic finding for human review, never a malware verdict.
State is bounded by each rule's own threshold plus one global LRU key cap, and
all time arithmetic uses exact integer microseconds. ``prepare`` stages state
behind a closure undo journal so that the service can roll back when the
event's audit bundle does not commit, exactly as the core detector does.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any

from .models import DetectionResult, PacketEvent
from .rule_catalog import BY_ID, THREAT_RULE_IDS


_US = 1_000_000
_MIB = 1024 * 1024
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MISSING = object()

# Fixed in code: an update to reference data can never widen these.
AUTH_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 88: "kerberos", 110: "pop3",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 445: "smb", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2222: "ssh-alt", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 8291: "mikrotik-winbox",
    27017: "mongodb",
}
# Service-discovery chatter that legitimately reaches many hosts.
_SWEEP_EXEMPT_UDP_PORTS = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353, 5355})
# Explicit internal address space. Python's is_private also covers the RFC
# 5737/3849 documentation ranges, which real LANs never use.
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "fc00::/7", "fe80::/10",
))
_LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")


def _microseconds(value: datetime) -> int:
    delta = value.astimezone(timezone.utc) - _UNIX_EPOCH
    return (delta.days * 86_400 + delta.seconds) * _US + delta.microseconds


def _canonical(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    parsed = ipaddress.ip_address(address)
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def is_internal(address: str) -> bool:
    """Private, link-local, unique-local or carrier-grade NAT unicast space."""
    parsed = _canonical(address)
    if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
        return False
    if parsed == _LIMITED_BROADCAST:
        return False
    return any(parsed in network for network in _INTERNAL_NETWORKS
               if network.version == parsed.version)


def is_public(address: str) -> bool:
    parsed = _canonical(address)
    return parsed.is_global and not parsed.is_multicast


def _connection_start(event: PacketEvent) -> bool:
    """A TCP connection-attempt candidate: SYN without ACK, or a flagless flow record."""
    if event.protocol != "TCP":
        return False
    flags = event.tcp_flags
    return not flags or ("SYN" in flags and "ACK" not in flags)


@dataclass(frozen=True)
class ThreatDetectionSettings:
    enabled: bool = True
    brute_force_window_seconds: int = 60
    brute_force_attempts: int = 15
    host_sweep_window_seconds: int = 15
    host_sweep_distinct_hosts: int = 24
    exfiltration_window_seconds: int = 300
    exfiltration_threshold_mib: int = 100
    beacon_min_intervals: int = 8
    beacon_min_interval_seconds: int = 5
    beacon_max_interval_seconds: int = 3600
    beacon_jitter_percent: int = 10
    alert_cooldown_seconds: int = 600
    max_tracked_keys: int = 8192
    watchlist_path: str = ""
    watchlist_severity: str = "HIGH"

    def __post_init__(self) -> None:
        if self.watchlist_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError(
                "threat_detection.watchlist_severity must be LOW, MEDIUM, HIGH or CRITICAL"
            )
        for name, minimum, maximum in (
            ("brute_force_window_seconds", 1, 3600),
            ("brute_force_attempts", 2, 4096),
            ("host_sweep_window_seconds", 1, 3600),
            ("host_sweep_distinct_hosts", 2, 4096),
            ("exfiltration_window_seconds", 1, 3600),
            ("exfiltration_threshold_mib", 1, 65536),
            ("beacon_min_intervals", 3, 256),
            ("beacon_min_interval_seconds", 1, 3600),
            ("beacon_max_interval_seconds", 1, 3600),
            ("beacon_jitter_percent", 0, 50),
            ("alert_cooldown_seconds", 0, 86400),
            ("max_tracked_keys", 16, 1_048_576),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"threat_detection.{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(
                    f"threat_detection.{name} must be between {minimum} and {maximum}"
                )
        if self.beacon_min_interval_seconds > self.beacon_max_interval_seconds:
            raise ValueError(
                "threat_detection.beacon_min_interval_seconds must not exceed "
                "beacon_max_interval_seconds"
            )
        if not isinstance(self.enabled, bool):
            raise ValueError("threat_detection.enabled must be a boolean")
        if not isinstance(self.watchlist_path, str) or len(self.watchlist_path) > 1024:
            raise ValueError("threat_detection.watchlist_path must be text")


class _Journal:
    """Inverse operations recorded while staging; replayed in reverse on rollback."""

    def __init__(self) -> None:
        self.undo: list[Callable[[], None]] = []

    def rollback(self) -> None:
        while self.undo:
            self.undo.pop()()

    # -- primitive mutations, each registering its exact inverse -----------
    def get_or_create(self, mapping: dict, key: Any, factory: Callable[[], Any]) -> Any:
        if key in mapping:
            return mapping[key]
        value = factory()
        mapping[key] = value
        self.undo.append(lambda: mapping.pop(key, None))
        return value

    def append(self, window: deque, item: Any) -> None:
        window.append(item)
        self.undo.append(window.pop)

    def popleft(self, window: deque) -> Any:
        item = window.popleft()
        self.undo.append(lambda: window.appendleft(item))
        return item

    def set_item(self, mapping: dict, key: Any, value: Any) -> None:
        previous = mapping.get(key, _MISSING)
        mapping[key] = value
        if previous is _MISSING:
            self.undo.append(lambda: mapping.pop(key, None))
        else:
            self.undo.append(lambda: mapping.__setitem__(key, previous))

    def snapshot_ordered(self, mapping: OrderedDict) -> None:
        """For small threshold-bounded ordered maps, restore the whole order."""
        saved = list(mapping.items())

        def restore() -> None:
            mapping.clear()
            mapping.update(saved)

        self.undo.append(restore)


@dataclass
class PreparedThreatDetection:
    detector: "ThreatDetector"
    token: object
    results: tuple[DetectionResult, ...]
    journal: _Journal
    touched: tuple[tuple[str, Any], ...]
    _resolved: bool = field(default=False)

    def _check(self) -> None:
        pending = self.detector._pending
        if pending is None or pending[0] is not self.token:
            raise RuntimeError("threat detector preparation token mismatch")

    def commit(self) -> None:
        if self._resolved:
            return
        self._check()
        for item in self.touched:
            self.detector._touch(item)
        self.detector._pending = None
        self._resolved = True

    def rollback(self) -> None:
        if self._resolved:
            return
        self._check()
        self.journal.rollback()
        self.detector._pending = None
        self._resolved = True


class ThreatDetector:
    """Single-threaded; the service serializes prepare and resolve."""

    def __init__(
        self,
        settings: ThreatDetectionSettings | None = None,
        allowlist: tuple[ipaddress._BaseNetwork, ...] = (),
        watchlist: "Watchlist | None" = None,
    ) -> None:
        self.settings = settings or ThreatDetectionSettings()
        self.allowlist = allowlist
        self.watchlist = watchlist
        # rule-scoped state maps; every key is also tracked in one LRU.
        self.brute: dict[tuple[str, str, int], deque[int]] = {}
        self.sweep: dict[str, OrderedDict[str, int]] = {}
        self.exfil: dict[tuple[str, str], deque[list[int]]] = {}
        self.exfil_totals: dict[tuple[str, str], int] = {}
        self.beacon: dict[tuple[str, str, int], deque[int]] = {}
        self.last_emitted: dict[tuple[str, Any], int] = {}
        self.lru: OrderedDict[tuple[str, Any], None] = OrderedDict()
        # (token, journal) while a preparation is unresolved.
        self._pending: tuple[object, _Journal] | None = None

    # ------------------------------------------------------------------ API
    def analyze(self, event: PacketEvent) -> list[DetectionResult]:
        prepared = self.prepare(event)
        prepared.commit()
        return list(prepared.results)

    def prepare(self, event: PacketEvent) -> PreparedThreatDetection:
        if self._pending is not None:
            raise RuntimeError("threat detector preparation already pending")
        token = object()
        journal = _Journal()
        touched: list[tuple[str, Any]] = []
        results: list[DetectionResult] = []
        self._pending = (token, journal)
        try:
            if self.settings.enabled:
                now = _microseconds(event.observed_at)
                src = str(_canonical(event.src_ip))
                dst = str(_canonical(event.dst_ip))
                for rule in (self._ioc, self._brute_force, self._host_sweep,
                             self._exfiltration, self._beaconing):
                    found = rule(event, src, dst, now, journal, touched)
                    if found is not None:
                        results.append(found)
            return PreparedThreatDetection(
                self, token, tuple(results), journal, tuple(touched)
            )
        except BaseException:
            journal.rollback()
            self._pending = None
            raise

    def rollback_pending(self) -> bool:
        """Unwind a preparation whose handle the caller lost (e.g. an interrupt)."""
        if self._pending is None:
            return False
        _, journal = self._pending
        journal.rollback()
        self._pending = None
        return True

    # ---------------------------------------------------------------- rules
    def _ioc(self, event, src, dst, now, journal, touched):
        if self.watchlist is None or not len(self.watchlist):
            return None
        for direction, address in (("source", src), ("destination", dst)):
            hit = self.watchlist.match(address)
            if hit is None:
                continue
            key = ("IOC_MATCH", address)
            if not self._can_emit(key, now, journal):
                return None
            touched.append(key)
            indicator, label = hit
            evidence: dict[str, Any] = {
                "matches": 1,
                "matched_address": address,
                "matched_direction": direction,
                "indicator": indicator,
            }
            if label:
                evidence["indicator_label"] = label
            return self._result(
                event, "IOC_MATCH", address,
                f"{direction.capitalize()} {address} matched watchlist indicator {indicator}",
                evidence, severity=self.watchlist.severity,
            )
        return None

    def _brute_force(self, event, src, dst, now, journal, touched):
        port = event.dst_port
        if port not in AUTH_SERVICES or not _connection_start(event):
            return None
        settings = self.settings
        key = (src, dst, port)
        touched.append(("brute", key))
        window = journal.get_or_create(self.brute, key, deque)
        now = max(now, window[-1]) if window else now
        journal.append(window, now)
        cutoff = now - settings.brute_force_window_seconds * _US
        while window and window[0] < cutoff:
            journal.popleft(window)
        # Only the newest `threshold` attempts are needed to decide.
        while len(window) > settings.brute_force_attempts:
            journal.popleft(window)
        if len(window) < settings.brute_force_attempts:
            return None
        emit_key = ("BRUTE_FORCE", key)
        if not self._can_emit(emit_key, now, journal):
            return None
        touched.append(emit_key)
        service = AUTH_SERVICES[port]
        return self._result(
            event, "BRUTE_FORCE", src,
            f"{len(window)} connection attempts to {service}/{port} on one host "
            f"within {settings.brute_force_window_seconds}s",
            {
                "attempts": len(window),
                "threshold": settings.brute_force_attempts,
                "window_seconds": settings.brute_force_window_seconds,
                "service": service,
                "service_port": port,
            },
        )

    def _host_sweep(self, event, src, dst, now, journal, touched):
        if not is_internal(dst) or src == dst:
            return None
        if event.protocol == "UDP":
            if event.dst_port in _SWEEP_EXEMPT_UDP_PORTS:
                return None
        elif event.protocol not in {"ICMP", "ICMPV6"} and not _connection_start(event):
            return None
        settings = self.settings
        touched.append(("sweep", src))
        hosts = journal.get_or_create(self.sweep, src, OrderedDict)
        journal.snapshot_ordered(hosts)
        if hosts:
            now = max(now, next(reversed(hosts.values())))
        hosts[dst] = now
        hosts.move_to_end(dst)
        cutoff = now - settings.host_sweep_window_seconds * _US
        while hosts and next(iter(hosts.values())) < cutoff:
            hosts.popitem(last=False)
        while len(hosts) > settings.host_sweep_distinct_hosts:
            hosts.popitem(last=False)
        if len(hosts) < settings.host_sweep_distinct_hosts:
            return None
        emit_key = ("HOST_SWEEP", src)
        if not self._can_emit(emit_key, now, journal):
            return None
        touched.append(emit_key)
        return self._result(
            event, "HOST_SWEEP", src,
            f"{len(hosts)} distinct internal hosts contacted within "
            f"{settings.host_sweep_window_seconds}s",
            {
                "distinct_hosts": len(hosts),
                "threshold": settings.host_sweep_distinct_hosts,
                "window_seconds": settings.host_sweep_window_seconds,
            },
        )

    def _exfiltration(self, event, src, dst, now, journal, touched):
        if event.byte_count <= 0 or not is_internal(src) or not is_public(dst):
            return None
        settings = self.settings
        key = (src, dst)
        touched.append(("exfil", key))
        buckets = journal.get_or_create(self.exfil, key, deque)
        total = self.exfil_totals.get(key, 0)
        second = now // _US
        if buckets and buckets[-1][0] >= second:
            # Same (or clamped earlier) second: add to the newest bucket.
            last = buckets[-1]
            previous = last[1]
            last[1] = previous + event.byte_count
            journal.undo.append(lambda: last.__setitem__(1, previous))
            second = last[0]
        else:
            journal.append(buckets, [second, event.byte_count])
        total += event.byte_count
        cutoff = second - settings.exfiltration_window_seconds + 1
        while buckets and buckets[0][0] < cutoff:
            total -= journal.popleft(buckets)[1]
        journal.set_item(self.exfil_totals, key, total)
        if total < settings.exfiltration_threshold_mib * _MIB:
            return None
        emit_key = ("DATA_EXFILTRATION", key)
        if not self._can_emit(emit_key, now, journal):
            return None
        touched.append(emit_key)
        mib = total // _MIB
        return self._result(
            event, "DATA_EXFILTRATION", dst,
            f"{mib} MiB of reported bytes sent from internal {src} to public {dst} "
            f"within {settings.exfiltration_window_seconds}s",
            {
                "mebibytes": mib,
                "bytes": str(total),
                "threshold": settings.exfiltration_threshold_mib,
                "window_seconds": settings.exfiltration_window_seconds,
            },
        )

    def _beaconing(self, event, src, dst, now, journal, touched):
        if event.dst_port is None or not _connection_start(event):
            return None
        if not is_internal(src) or not is_public(dst):
            return None
        settings = self.settings
        key = (src, dst, event.dst_port)
        touched.append(("beacon", key))
        starts = journal.get_or_create(self.beacon, key, deque)
        minimum = settings.beacon_min_interval_seconds * _US
        if starts and now - starts[-1] < minimum:
            # Retransmitted SYNs and parallel sockets belong to the same contact.
            return None
        journal.append(starts, now)
        while len(starts) > settings.beacon_min_intervals + 1:
            journal.popleft(starts)
        if len(starts) <= settings.beacon_min_intervals:
            return None
        ordered = list(starts)
        intervals = sorted(b - a for a, b in zip(ordered, ordered[1:]))
        median = intervals[(len(intervals) - 1) // 2]
        if median > settings.beacon_max_interval_seconds * _US:
            return None
        deviation = max(abs(intervals[0] - median), abs(intervals[-1] - median))
        if deviation * 100 > settings.beacon_jitter_percent * median:
            return None
        emit_key = ("BEACONING", key)
        if not self._can_emit(emit_key, now, journal):
            return None
        touched.append(emit_key)
        median_seconds = max(1, min(3600, median // _US))
        return self._result(
            event, "BEACONING", dst,
            f"{len(intervals) + 1} connection starts to {dst}:{event.dst_port} repeated every "
            f"~{median_seconds}s (max deviation {deviation // 1000} ms)",
            {
                "intervals": len(intervals),
                "threshold": settings.beacon_min_intervals,
                "window_seconds": median_seconds,
                "median_interval_ms": median // 1000,
                "max_deviation_ms": deviation // 1000,
                "jitter_percent": settings.beacon_jitter_percent,
                "service_port": event.dst_port,
            },
        )

    # -------------------------------------------------------------- helpers
    def _can_emit(self, key: tuple[str, Any], now: int, journal: _Journal) -> bool:
        previous = self.last_emitted.get(key)
        cooldown = self.settings.alert_cooldown_seconds * _US
        if previous is not None and now - previous < cooldown:
            return False
        journal.set_item(self.last_emitted, key, now)
        return True

    def _allowlisted(self, address: str) -> bool:
        parsed = _canonical(address)
        return any(parsed in network for network in self.allowlist
                   if network.version == parsed.version)

    def _result(self, event, rule_id, target, message, evidence, *, severity=None):
        description = BY_ID[rule_id]
        evidence = dict(evidence)
        # Record the event's own spelling so it compares equal to src_ip/dst_ip.
        is_source = target == str(_canonical(event.src_ip))
        evidence["response_target"] = event.src_ip if is_source else event.dst_ip
        evidence["detector_layer"] = description.layer
        suppressed = None
        if self._allowlisted(target):
            suppressed = "source_allowlisted" if is_source else "target_allowlisted"
        return DetectionResult(
            detected_at=event.observed_at,
            rule_id=rule_id,
            severity=severity or description.severity,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            message=message,
            evidence=evidence,
            recommendation="ALERT",
            suppressed_reason=suppressed,
        )

    _STATE_MAPS = {"brute": "brute", "sweep": "sweep", "exfil": "exfil", "beacon": "beacon"}

    def _touch(self, item: tuple[str, Any]) -> None:
        lru = self.lru
        lru.pop(item, None)
        lru[item] = None
        while len(lru) > self.settings.max_tracked_keys:
            (kind, key), _ = lru.popitem(last=False)
            if kind in self._STATE_MAPS:
                getattr(self, self._STATE_MAPS[kind]).pop(key, None)
                if kind == "exfil":
                    self.exfil_totals.pop(key, None)
            else:
                self.last_emitted.pop((kind, key), None)

    def state_size(self) -> int:
        return (len(self.brute) + len(self.sweep) + len(self.exfil)
                + len(self.beacon) + len(self.last_emitted))


def registry_document() -> dict[str, object]:
    """Describe the threat-signal layer; never a runtime dispatch table."""
    settings = ThreatDetectionSettings()
    return {
        "schema": "threat-signal-registry-v1",
        "layer": "threat-signals",
        "rules": [
            {
                "rule_id": rule_id,
                "severity": BY_ID[rule_id].severity,
                "measurement": BY_ID[rule_id].unit,
                "summary": BY_ID[rule_id].summary,
                "lookalikes": BY_ID[rule_id].lookalikes,
                "attack": list(BY_ID[rule_id].attack),
                "response_party": BY_ID[rule_id].response_party,
            }
            for rule_id in THREAT_RULE_IDS
        ],
        "default_settings": {
            k: v for k, v in settings.__dict__.items()
            if k not in {"watchlist_path", "watchlist_severity"}
        },
        "auth_services": {str(port): name for port, name in sorted(AUTH_SERVICES.items())},
        "state": {
            "bound": "each key holds at most its rule threshold; one LRU caps all keys",
            "time": "exact integer microseconds; out-of-order times clamp to the key's newest",
            "atomicity": "staged behind an undo journal; rolled back unless the audit bundle commits",
        },
        "interpretation": "heuristic findings for review; no maliciousness or accuracy verdict",
        "network_access_performed": False,
        "action_status": "not_attempted",
    }


# Imported last to avoid a cycle; the watchlist module has no detector imports.
from .watchlist import Watchlist  # noqa: E402
