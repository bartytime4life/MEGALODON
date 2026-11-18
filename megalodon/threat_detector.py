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
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any

from . import domain_signals
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
MAX_DECOY_PORTS = 64
MAX_DECOY_ADDRESSES = 256
MAX_DHCP_SERVERS = 16
MAX_IPV6_ROUTERS = 16
# The replies a client acts on: DHCP OFFER and ACK, DHCPv6 ADVERTISE and REPLY.
_DHCP_REPLIES = frozenset({2, 5})
_DHCPV6_REPLIES = frozenset({2, 7})


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


# Approximate registrable domains without a fetched public-suffix list: the
# last two labels, or three under these common two-label public suffixes.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "com.au", "net.au", "org.au",
    "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "com.br",
    "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.mx", "co.in", "net.in", "org.in",
    "co.za", "com.tr", "com.tw", "com.hk", "co.kr", "com.sg", "com.ar", "co.id", "com.my",
    "com.ph", "com.vn", "co.il", "com.ua", "com.pl", "com.ru",
})


def registrable_domain(name: str) -> str:
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _churn_exempt(name: str) -> bool:
    # Reverse lookups, local service discovery and CDNs generate many names by design.
    if name.endswith((".local", ".arpa", ".lan", ".internal")):
        return True
    return any(name == s or name.endswith("." + s) for s in domain_signals.GENERATED_SUFFIXES)


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
    # Tripwires: ports no real service on this network uses, and unassigned
    # internal addresses. Any contact is a near-certain sign of scanning.
    decoy_ports: tuple[int, ...] = ()
    decoy_addresses: tuple[str, ...] = ()
    # Opt-in: read DNS query names from capture. Off by default because names
    # are a record of every site visited; only a flagged domain is retained.
    dns_names: bool = False
    dns_churn_window_seconds: int = 60
    dns_churn_distinct_subdomains: int = 30
    # Opt-in: read TLS ClientHello JA3/JA4 fingerprints and server names (SNI)
    # from capture. Off by default: server names are a record of sites visited.
    tls_fingerprints: bool = False
    # Opt-in: read ARP sender bindings and DHCP reply server identities from
    # capture, for ARP_SPOOFING and ROGUE_DHCP. Off by default: DHCP options
    # lie past the metadata-only snapshot, so whole packets are captured.
    lan_integrity: bool = False
    arp_rebind_seconds: int = 300
    dhcp_window_seconds: int = 3600
    # The DHCP servers this network should have. Empty: learn them, and flag
    # a second server answering within dhcp_window_seconds. Each address
    # family is checked on its own: DHCPv6 servers are listed by the address
    # their replies come from, usually a link-local fe80:: address.
    dhcp_servers: tuple[str, ...] = ()
    # The same opt-in covers IPv6: neighbour-discovery bindings (NDP_SPOOFING,
    # within arp_rebind_seconds) and router advertisements (ROGUE_IPV6_ROUTER).
    # The routers this network should have, by their link-local address.
    # Empty: learn them, and flag a second router within router_window_seconds.
    ipv6_routers: tuple[str, ...] = ()
    router_window_seconds: int = 3600

    def __post_init__(self) -> None:
        self._validate_decoys()
        servers = self.dhcp_servers
        if (not isinstance(servers, tuple) or len(servers) > MAX_DHCP_SERVERS
                or not all(isinstance(s, str) for s in servers)):
            raise ValueError(f"threat_detection.dhcp_servers must be up to {MAX_DHCP_SERVERS} addresses")
        try:
            canonical = tuple(str(_canonical(s)) for s in servers)
        except ValueError:
            raise ValueError("threat_detection.dhcp_servers contains an invalid address") from None
        if len(set(canonical)) != len(canonical):
            raise ValueError("threat_detection.dhcp_servers must be distinct")
        object.__setattr__(self, "dhcp_servers", canonical)
        routers = self.ipv6_routers
        if (not isinstance(routers, tuple) or len(routers) > MAX_IPV6_ROUTERS
                or not all(isinstance(r, str) for r in routers)):
            raise ValueError(f"threat_detection.ipv6_routers must be up to {MAX_IPV6_ROUTERS} addresses")
        try:
            canonical = tuple(_canonical(r) for r in routers)
        except ValueError:
            raise ValueError("threat_detection.ipv6_routers contains an invalid address") from None
        if any(r.version != 6 for r in canonical):
            raise ValueError("threat_detection.ipv6_routers must be IPv6 addresses")
        if len(set(canonical)) != len(canonical):
            raise ValueError("threat_detection.ipv6_routers must be distinct")
        object.__setattr__(self, "ipv6_routers", tuple(str(r) for r in canonical))
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
            ("dns_churn_window_seconds", 1, 3600),
            ("dns_churn_distinct_subdomains", 2, 4096),
            ("arp_rebind_seconds", 10, 86400),
            ("dhcp_window_seconds", 60, 86400),
            ("router_window_seconds", 60, 86400),
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
        if not isinstance(self.dns_names, bool):
            raise ValueError("threat_detection.dns_names must be a boolean")
        if not isinstance(self.tls_fingerprints, bool):
            raise ValueError("threat_detection.tls_fingerprints must be a boolean")
        if not isinstance(self.lan_integrity, bool):
            raise ValueError("threat_detection.lan_integrity must be a boolean")
        if not isinstance(self.watchlist_path, str) or len(self.watchlist_path) > 1024:
            raise ValueError("threat_detection.watchlist_path must be text")

    def _validate_decoys(self) -> None:
        ports = self.decoy_ports
        if (not isinstance(ports, tuple) or len(ports) > MAX_DECOY_PORTS
                or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535
                       for p in ports)
                or len(set(ports)) != len(ports)):
            raise ValueError(
                f"threat_detection.decoy_ports must be up to {MAX_DECOY_PORTS} distinct ports 1-65535"
            )
        addresses = self.decoy_addresses
        if (not isinstance(addresses, tuple) or len(addresses) > MAX_DECOY_ADDRESSES
                or not all(isinstance(a, str) for a in addresses)):
            raise ValueError(
                f"threat_detection.decoy_addresses must be up to {MAX_DECOY_ADDRESSES} addresses"
            )
        canonical = []
        for text in addresses:
            try:
                parsed = _canonical(text)
            except ValueError:
                raise ValueError("threat_detection.decoy_addresses contains an invalid address") from None
            if (parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback
                    or parsed == _LIMITED_BROADCAST):
                raise ValueError(
                    "threat_detection.decoy_addresses must be unicast, non-loopback addresses"
                )
            canonical.append(str(parsed))
        if len(set(canonical)) != len(canonical):
            raise ValueError("threat_detection.decoy_addresses must be distinct")
        object.__setattr__(self, "decoy_addresses", tuple(canonical))


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
        self._decoy_ports = frozenset(self.settings.decoy_ports)
        self._decoy_addresses = frozenset(self.settings.decoy_addresses)
        # rule-scoped state maps; every key is also tracked in one LRU.
        self.brute: dict[tuple[str, str, int], deque[int]] = {}
        self.sweep: dict[str, OrderedDict[str, int]] = {}
        self.exfil: dict[tuple[str, str], deque[list[int]]] = {}
        self.exfil_totals: dict[tuple[str, str], int] = {}
        self.beacon: dict[tuple[str, str, int], deque[int]] = {}
        self.churn: dict[tuple[str, str], OrderedDict[str, int]] = {}
        # IPv4 address -> (sender MAC, last seen); DHCP server -> last reply seen.
        self.arp: dict[str, tuple[str, int]] = {}
        self.dhcp: OrderedDict[str, int] = OrderedDict()
        self._dhcp_servers = frozenset(self.settings.dhcp_servers)
        # IPv6 address -> (claimed MAC, last seen); router -> last advertisement seen.
        self.nd: dict[str, tuple[str, int]] = {}
        self.routers: OrderedDict[str, int] = OrderedDict()
        self._ipv6_routers = frozenset(self.settings.ipv6_routers)
        self.last_emitted: dict[tuple[str, Any], int] = {}
        self.lru: OrderedDict[tuple[str, Any], None] = OrderedDict()
        # (token, journal) while a preparation is unresolved.
        self._pending: tuple[object, _Journal] | None = None

    def __deepcopy__(self, memo):
        """Copy mutable state only; settings, allowlist and watchlist are immutable
        and may be large (a watchlist holds up to 200 000 indicators)."""
        if self._pending is not None:
            raise RuntimeError("cannot copy a threat detector with a pending preparation")
        clone = ThreatDetector.__new__(ThreatDetector)
        for name, value in self.__dict__.items():
            if name in {"settings", "allowlist", "watchlist", "_decoy_ports", "_decoy_addresses",
                        "_dhcp_servers", "_ipv6_routers"}:
                setattr(clone, name, value)
            else:
                setattr(clone, name, deepcopy(value, memo))
        return clone

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
                rules = [self._decoy, self._ioc, self._brute_force, self._host_sweep,
                         self._exfiltration, self._beaconing]
                if event.arp_opcode is not None:
                    # An ARP frame is not traffic between hosts: only binding
                    # checks, and decoys for ARP scans of unassigned addresses.
                    rules = [self._arp_spoofing] if self.settings.lan_integrity else []
                    if event.arp_opcode == 1:
                        rules.append(self._decoy)
                elif self.settings.lan_integrity and _is_dhcp_reply(event):
                    rules.append(self._rogue_dhcp)
                elif self.settings.lan_integrity and event.nd_type is not None:
                    rules.append(self._ndp_spoofing)
                    if event.nd_type == 134:
                        rules.append(self._rogue_router)
                if self.settings.dns_names and event.dns_query_name:
                    rules += [self._domain_ioc, self._generated_domain, self._dns_churn]
                if self.settings.tls_fingerprints and event.is_client_hello:
                    rules += [self._tls_ioc, self._sni_ioc, self._sni_generated,
                              self._tls_without_sni]
                for rule in rules:
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
    def _decoy(self, event, src, dst, now, journal, touched):
        settings = self.settings
        if dst in self._decoy_addresses and src != dst:
            kind, decoy = "address", dst
        elif (event.dst_port in self._decoy_ports and src not in self._decoy_addresses
              and (event.protocol == "UDP" or _connection_start(event))):
            kind, decoy = "port", str(event.dst_port)
        else:
            return None
        key = ("DECOY_TOUCH", (src, kind, decoy))
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        target = f"decoy address {dst}" if kind == "address" else f"decoy port {decoy}"
        return self._result(
            event, "DECOY_TOUCH", src,
            f"{src} contacted {target}; nothing legitimate should ever reach it",
            {
                "contacts": 1,
                "decoy_kind": kind,
                "decoy": decoy,
                "protocol": event.protocol,
            },
        )

    def _ioc(self, event, src, dst, now, journal, touched):
        if self.watchlist is None or not len(self.watchlist):
            return None
        for direction, address in (("source", src), ("destination", dst)):
            hit = self.watchlist.match(address)
            if hit is None:
                continue
            key = ("IOC_MATCH", address)
            if not self._can_emit(key, now, journal):
                # A cooled-down source must not hide a new destination match.
                continue
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

    # ------------------------------------------------------------ DNS names
    def _domain_ioc(self, event, src, dst, now, journal, touched):
        return self._named_ioc(event, event.dns_query_name, "dns_query", src, now, journal, touched)

    def _sni_ioc(self, event, src, dst, now, journal, touched):
        if event.tls_sni is None:
            return None
        return self._named_ioc(event, event.tls_sni, "tls_sni", src, now, journal, touched)

    def _named_ioc(self, event, name, via, src, now, journal, touched):
        if self.watchlist is None or not self.watchlist.has_domains:
            return None
        hit = self.watchlist.match_domain(name)
        if hit is None:
            return None
        indicator, label = hit
        key = ("IOC_MATCH", ("domain", src, indicator))
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        evidence: dict[str, Any] = {
            "matches": 1, "matched_domain": name, "matched_direction": via,
            "indicator": indicator,
        }
        if label:
            evidence["indicator_label"] = label
        verb = "looked up" if via == "dns_query" else "opened a TLS session to"
        return self._result(
            event, "IOC_MATCH", src,
            f"{src} {verb} {name}, which matches watchlist domain {indicator}",
            evidence, severity=self.watchlist.severity,
        )

    def _generated_domain(self, event, src, dst, now, journal, touched):
        return self._generated_name(event, event.dns_query_name, "dns_query", src, now, journal, touched)

    def _sni_generated(self, event, src, dst, now, journal, touched):
        if event.tls_sni is None:
            return None
        return self._generated_name(event, event.tls_sni, "tls_sni", src, now, journal, touched)

    def _generated_name(self, event, name, via, src, now, journal, touched):
        review = domain_signals.assess(name)
        if review is None or review["level"] != "review":
            return None
        parent = registrable_domain(review["name"])
        key = ("DGA_DOMAIN", (src, parent))
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        signals = [item["id"] for item in review["signals"]]
        verb = "looked up" if via == "dns_query" else "opened a TLS session to"
        return self._result(
            event, "DGA_DOMAIN", src,
            f"{src} {verb} {review['name']}, which reads like a machine-generated or "
            f"encoded name ({', '.join(signals)})",
            {
                "signals": len(signals), "threshold": 2, "domain": review["name"],
                "registrable_domain": parent, "signal_ids": signals, "name_source": via,
            },
        )

    # ------------------------------------------------------ TLS fingerprints
    def _tls_ioc(self, event, src, dst, now, journal, touched):
        if self.watchlist is None or not self.watchlist.has_fingerprints:
            return None
        for kind, value in (("ja3", event.tls_ja3), ("ja4", event.tls_ja4)):
            hit = self.watchlist.match_fingerprint(kind, value)
            if hit is None:
                continue
            indicator, label = hit
            key = ("IOC_MATCH", ("tls", src, indicator))
            touched.append(key)
            if not self._can_emit(key, now, journal):
                continue
            evidence: dict[str, Any] = {
                "matches": 1, "matched_direction": "tls_client", "indicator": indicator,
                "fingerprint_kind": kind, "server": dst,
            }
            if event.tls_sni:
                evidence["server_name"] = event.tls_sni
            if label:
                evidence["indicator_label"] = label
            return self._result(
                event, "IOC_MATCH", src,
                f"{src} opened TLS to {dst} with client fingerprint {indicator}, which is on the watchlist",
                evidence, severity=self.watchlist.severity,
            )
        return None

    def _tls_without_sni(self, event, src, dst, now, journal, touched):
        if event.tls_sni is not None or not is_internal(src) or not is_public(dst):
            return None
        key = ("TLS_WITHOUT_SNI", (src, dst))
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        evidence: dict[str, Any] = {"handshakes": 1, "server": dst,
                                    "service_port": event.dst_port or 0}
        if event.tls_ja3:
            evidence["ja3"] = event.tls_ja3
        if event.tls_ja4:
            evidence["ja4"] = event.tls_ja4
        return self._result(
            event, "TLS_WITHOUT_SNI", dst,
            f"{src} opened TLS directly to public address {dst}:{event.dst_port} without a "
            "server name, as many command-and-control clients do",
            evidence,
        )

    def _arp_spoofing(self, event, src, dst, now, journal, touched):
        """A recently seen IPv4-to-MAC binding replaced by another MAC."""
        parsed = _canonical(src)
        if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast or parsed == _LIMITED_BROADCAST:
            return None  # ARP probes (sender 0.0.0.0) claim nothing.
        return self._rebinding(event, "ARP_SPOOFING", "arp", src, event.arp_sender_mac, now, journal, touched,
                               "as ARP cache poisoning does")

    def _ndp_spoofing(self, event, src, dst, now, journal, touched):
        """A recently seen IPv6-to-MAC binding replaced by another MAC.

        A neighbour advertisement claims its target address; a solicitation or
        router advertisement claims its sender's, through the link-layer
        address option it carries. Messages without one claim nothing."""
        if event.nd_mac is None:
            return None
        address = str(_canonical(event.nd_target)) if event.nd_type == 136 else src
        parsed = _canonical(address)
        if parsed.version != 6 or parsed.is_unspecified or parsed.is_multicast:
            return None  # Duplicate address detection (sender ::) claims nothing.
        return self._rebinding(event, "NDP_SPOOFING", "nd", address, event.nd_mac, now, journal, touched,
                               "as neighbour-discovery spoofing does")

    def _rebinding(self, event, rule_id, kind, address, mac, now, journal, touched, how):
        table = getattr(self, self._STATE_MAPS[kind])
        touched.append((kind, address))
        previous = table.get(address)
        journal.set_item(table, address, (mac, max(now, previous[1]) if previous else now))
        if previous is None or previous[0] == mac:
            return None
        elapsed = max(0, now - previous[1])
        if elapsed > self.settings.arp_rebind_seconds * _US:
            return None  # An old binding: a replaced device or a new address lease.
        key = (rule_id, address)
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        return self._result(
            event, rule_id, address,
            f"{address} was claimed by {mac} {elapsed // _US}s after {previous[0]} answered for it, {how}",
            {
                "rebinds": 1,
                "claimed_address": address,
                "previous_mac": previous[0],
                "new_mac": mac,
                "seconds_since_previous": elapsed // _US,
                "window_seconds": self.settings.arp_rebind_seconds,
            },
        )

    def _unexpected(self, table, identity, expected, window_seconds, now, journal):
        """Record identity as active; the reason it is unexpected and the known set, else None.

        Configured identities of the same address family win; without them, a
        second identity active within the window is unexpected."""
        version = _canonical(identity).version
        expected = sorted(e for e in expected if _canonical(e).version == version)
        journal.snapshot_ordered(table)
        cutoff = now - window_seconds * _US
        while table and next(iter(table.values())) < cutoff:
            table.popitem(last=False)
        others = sorted(k for k in table if k != identity and _canonical(k).version == version)
        table[identity] = max(now, table.get(identity, now))
        table.move_to_end(identity)
        while len(table) > MAX_DHCP_SERVERS:
            table.popitem(last=False)
        if expected:
            return None if identity in expected else ("configured", expected)
        return ("learned", others) if others else None

    def _rogue_dhcp(self, event, src, dst, now, journal, touched):
        """A DHCP OFFER/ACK or DHCPv6 ADVERTISE/REPLY from a server outside the expected or learned set."""
        v6 = event.src_port == 547
        server = str(_canonical(event.dhcp_server_id or src))
        found = self._unexpected(self.dhcp, server, self._dhcp_servers,
                                 self.settings.dhcp_window_seconds, now, journal)
        if found is None:
            return None
        mode, known = found
        label = "DHCPv6" if v6 else "DHCP"
        reason = (f"is not one of the configured {label} servers" if mode == "configured"
                  else f"answered while another {label} server was active")
        key = ("ROGUE_DHCP", server)
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        kind = event.dhcp_message_type
        evidence: dict[str, Any] = {
            "replies": 1,
            "server": server,
            "message_type": ({2: "advertise", 7: "reply"} if v6 else {2: "offer", 5: "ack"})[kind],
            "known_servers": known[:4],
            "configured": mode == "configured",
        }
        if v6:
            evidence["protocol"] = "dhcpv6"
        if event.dhcp_server_id and server != str(_canonical(src)):
            evidence["relay_address"] = src
        return self._result(
            event, "ROGUE_DHCP", src,
            f"{label} server {server} {reason} ({', '.join(known[:4])}); a rogue server can hand out "
            "its own gateway and DNS",
            evidence,
        )

    def _rogue_router(self, event, src, dst, now, journal, touched):
        """An IPv6 router advertisement from a router outside the expected or learned set."""
        found = self._unexpected(self.routers, src, self._ipv6_routers,
                                 self.settings.router_window_seconds, now, journal)
        if found is None:
            return None
        mode, known = found
        reason = ("is not one of the configured IPv6 routers" if mode == "configured"
                  else "advertised while another IPv6 router was active")
        key = ("ROGUE_IPV6_ROUTER", src)
        touched.append(key)
        if not self._can_emit(key, now, journal):
            return None
        lifetime = event.ra_router_lifetime
        effect = ("withdraws its default route" if lifetime == 0
                  else "can make itself the default gateway and hand out its own prefixes and DNS")
        return self._result(
            event, "ROGUE_IPV6_ROUTER", src,
            f"Router {src} {reason} ({', '.join(known[:4])}); a rogue router advertisement {effect}",
            {
                "advertisements": 1,
                "router": src,
                "router_lifetime_seconds": lifetime,
                "router_mac": event.nd_mac,
                "known_routers": known[:4],
                "configured": mode == "configured",
            },
        )

    def _dns_churn(self, event, src, dst, now, journal, touched):
        name = event.dns_query_name
        parent = registrable_domain(name)
        if name == parent or _churn_exempt(name):
            return None
        settings = self.settings
        key = (src, parent)
        touched.append(("churn", key))
        children = journal.get_or_create(self.churn, key, OrderedDict)
        journal.snapshot_ordered(children)
        if children:
            now = max(now, next(reversed(children.values())))
        child = name[: -(len(parent) + 1)]
        children[child] = now
        children.move_to_end(child)
        cutoff = now - settings.dns_churn_window_seconds * _US
        while children and next(iter(children.values())) < cutoff:
            children.popitem(last=False)
        while len(children) > settings.dns_churn_distinct_subdomains:
            children.popitem(last=False)
        if len(children) < settings.dns_churn_distinct_subdomains:
            return None
        emit_key = ("DNS_TUNNEL_CHURN", key)
        if not self._can_emit(emit_key, now, journal):
            return None
        touched.append(emit_key)
        longest = max(len(label) for label in children)
        return self._result(
            event, "DNS_TUNNEL_CHURN", src,
            f"{src} queried {len(children)} distinct subdomains of {parent} within "
            f"{settings.dns_churn_window_seconds}s, as DNS tunnels and exfiltration do",
            {
                "distinct_subdomains": len(children),
                "threshold": settings.dns_churn_distinct_subdomains,
                "window_seconds": settings.dns_churn_window_seconds,
                "registrable_domain": parent,
                "longest_subdomain_chars": longest,
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

    _STATE_MAPS = {"brute": "brute", "sweep": "sweep", "exfil": "exfil", "beacon": "beacon",
                   "churn": "churn", "arp": "arp", "nd": "nd"}

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
        return (len(self.brute) + len(self.sweep) + len(self.exfil) + len(self.beacon)
                + len(self.churn) + len(self.arp) + len(self.dhcp) + len(self.nd) + len(self.routers)
                + len(self.last_emitted))


def _is_dhcp_reply(event: PacketEvent) -> bool:
    """A DHCP OFFER/ACK from port 67, or a DHCPv6 ADVERTISE/REPLY from port 547."""
    if event.dhcp_message_type is None:
        return False
    if event.src_port == 67:
        return event.dhcp_message_type in _DHCP_REPLIES and ":" not in event.src_ip
    if event.src_port == 547:
        return event.dhcp_message_type in _DHCPV6_REPLIES and ":" in event.src_ip
    return False


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
            if k not in {"watchlist_path", "watchlist_severity", "decoy_ports", "decoy_addresses",
                         "dhcp_servers"}
            and not isinstance(v, tuple)
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
