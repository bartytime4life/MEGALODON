"""Bounded, typed detection rules using in-memory sliding windows."""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from datetime import datetime
import ipaddress
from typing import Deque

from .config import DetectionSettings
from .models import DetectionResult, PacketEvent


SEVERITY_RANK = {"LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 40}


class Detector:
    def __init__(self, settings: DetectionSettings, allowlist: tuple[ipaddress._BaseNetwork, ...] = ()):
        self.settings = settings
        self.allowlist = allowlist
        self.syn_windows: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        self.port_windows: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self.last_emitted: dict[tuple[str, str], float] = {}
        self.source_order: OrderedDict[str, None] = OrderedDict()
        if settings.max_tracked_sources < 1:
            raise ValueError("max_tracked_sources must be positive")
        if settings.max_events_per_source_window < 1:
            raise ValueError("max_events_per_source_window must be positive")

    def analyze(self, event: PacketEvent) -> list[DetectionResult]:
        self._touch_source(event.src_ip)
        now = event.observed_at.timestamp()
        results: list[DetectionResult] = []

        if event.protocol == "TCP" and "SYN" in event.tcp_flags and "ACK" not in event.tcp_flags:
            syn_window = self.syn_windows[event.src_ip]
            syn_window.append((now, event.dst_ip))
            self._trim(syn_window, now - self.settings.syn_flood_window_seconds)
            self._cap_window(syn_window)
            if len(syn_window) >= self.settings.syn_flood_threshold and self._can_emit("SYN_FLOOD", event.src_ip, now):
                results.append(
                    self._result(
                        event,
                        "SYN_FLOOD",
                        "HIGH",
                        f"{len(syn_window)} TCP SYN packets from one source in {self.settings.syn_flood_window_seconds}s",
                        {"count": len(syn_window), "window_seconds": self.settings.syn_flood_window_seconds},
                        now,
                    )
                )

        if event.protocol == "TCP" and event.dst_port is not None:
            port_window = self.port_windows[event.src_ip]
            port_window.append((now, event.dst_port))
            self._trim(port_window, now - self.settings.port_scan_window_seconds)
            self._cap_window(port_window)
            distinct_ports = {port for _, port in port_window}
            if (
                len(distinct_ports) >= self.settings.port_scan_distinct_ports
                and self._can_emit("PORT_SCAN", event.src_ip, now)
            ):
                results.append(
                    self._result(
                        event,
                        "PORT_SCAN",
                        "MEDIUM",
                        f"{len(distinct_ports)} destination ports targeted in {self.settings.port_scan_window_seconds}s",
                        {
                            "distinct_ports": len(distinct_ports),
                            "window_seconds": self.settings.port_scan_window_seconds,
                        },
                        now,
                    )
                )

        if (
            event.protocol in {"DNS", "UDP"}
            and event.dns_query_length is not None
            and event.dns_query_length >= self.settings.dns_query_length
            and self._can_emit("DNS_TUNNELING", event.src_ip, now)
        ):
            results.append(
                self._result(
                    event,
                    "DNS_TUNNELING",
                    "CRITICAL",
                    f"DNS query metadata length {event.dns_query_length} exceeds the configured threshold",
                    {"dns_query_length": event.dns_query_length, "threshold": self.settings.dns_query_length},
                    now,
                )
            )

        return results

    def _result(
        self,
        event: PacketEvent,
        rule_id: str,
        severity: str,
        message: str,
        evidence: dict[str, int | str],
        now: float,
    ) -> DetectionResult:
        suppressed_reason = None
        source = ipaddress.ip_address(event.src_ip)
        if any(source in network for network in self.allowlist):
            suppressed_reason = "source_allowlisted"
        return DetectionResult(
            detected_at=event.observed_at,
            rule_id=rule_id,
            severity=severity,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            message=message,
            evidence=evidence,
            recommendation="ALERT",
            suppressed_reason=suppressed_reason,
        )

    def _touch_source(self, source: str) -> None:
        self.source_order.pop(source, None)
        self.source_order[source] = None
        while len(self.source_order) > self.settings.max_tracked_sources:
            evicted, _ = self.source_order.popitem(last=False)
            self.syn_windows.pop(evicted, None)
            self.port_windows.pop(evicted, None)
            for key in tuple(self.last_emitted):
                if key[1] == evicted:
                    del self.last_emitted[key]

    def _cap_window(self, window: Deque[tuple[float, object]]) -> None:
        while len(window) > self.settings.max_events_per_source_window:
            window.popleft()

    def _can_emit(self, rule_id: str, source: str, now: float) -> bool:
        key = (rule_id, source)
        previous = self.last_emitted.get(key)
        if previous is not None and now - previous < self.settings.alert_cooldown_seconds:
            return False
        self.last_emitted[key] = now
        return True

    @staticmethod
    def _trim(window: Deque[tuple[float, object]], cutoff: float) -> None:
        while window and window[0][0] < cutoff:
            window.popleft()
