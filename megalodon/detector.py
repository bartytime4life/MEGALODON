"""Bounded, typed detection rules using in-memory sliding windows."""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Deque

from .config import DetectionSettings
from .models import DetectionResult, PacketEvent
from .validation import ValidationError


SEVERITY_RANK = {"LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 40}
MAX_FUTURE_SKEW_SECONDS = 60
_MISSING = object()


def _decrement_port_count(counts: Counter[int], port: int) -> None:
    current = counts.get(port)
    if current is None or current < 1:
        raise RuntimeError("port window frequency invariant violated")
    if current == 1:
        del counts[port]
    else:
        counts[port] = current - 1


@dataclass
class _WindowUndo:
    mapping: dict[str, Deque]
    source: str
    window: Deque
    original_length: int
    removed: list[tuple[float, object]]
    created: bool
    appended: bool = False

    def rollback(self) -> None:
        if self.appended:
            self.window.pop()
        for item in reversed(self.removed):
            self.window.appendleft(item)
        if len(self.window) != self.original_length:
            raise RuntimeError("window rollback invariant violated")
        if self.created and self.mapping.get(self.source) is self.window:
            self.mapping.pop(self.source, None)


@dataclass
class _PortWindowUndo:
    window_mapping: dict[str, Deque[tuple[float, int]]]
    count_mapping: dict[str, Counter[int]]
    source: str
    window: Deque[tuple[float, int]]
    counts: Counter[int]
    appended_item: tuple[float, int]
    original_length: int
    original_counts: dict[int, object]
    removed: list[tuple[float, int]]
    window_created: bool = False
    counts_created: bool = False
    appended: bool = False

    def rollback(self) -> None:
        if self.appended:
            if self.window.pop() != self.appended_item:
                raise RuntimeError("port window rollback invariant violated")
        for item in reversed(self.removed):
            self.window.appendleft(item)
        if len(self.window) != self.original_length:
            raise RuntimeError("port window rollback invariant violated")
        for port, previous in self.original_counts.items():
            if previous is _MISSING:
                self.counts.pop(port, None)
            else:
                self.counts[port] = previous  # type: ignore[assignment]
        if (
            self.window_created
            and self.window_mapping.get(self.source) is self.window
        ):
            self.window_mapping.pop(self.source, None)
        if (
            self.counts_created
            and self.count_mapping.get(self.source) is self.counts
        ):
            self.count_mapping.pop(self.source, None)


@dataclass
class PreparedDetection:
    """A bounded provisional detector result resolved after storage."""

    detector: "Detector"
    token: object
    source: str
    observed: float
    results: tuple[DetectionResult, ...]
    window_undos: tuple[_WindowUndo | _PortWindowUndo, ...]
    emission_undos: tuple[tuple[tuple[str, str], object], ...]
    _resolved: bool = False

    def commit(self) -> None:
        """Install the staged state once; persistence must happen first."""

        if self._resolved:
            return
        detector = self.detector
        pending = detector._pending
        if (
            pending is None
            or pending[0] is not self.token
            or pending[1] is not self
        ):
            raise RuntimeError("detector preparation token mismatch")
        detector._touch_source(self.source)
        detector.source_high_watermarks[self.source] = self.observed
        detector._pending = None
        self._resolved = True

    def rollback(self) -> None:
        """Undo provisional state when planning or persistence does not commit."""

        if self._resolved:
            return
        pending = self.detector._pending
        if (
            pending is None
            or pending[0] is not self.token
            or pending[1] is not self
        ):
            raise RuntimeError("detector preparation token mismatch")
        for key, previous in reversed(self.emission_undos):
            if previous is _MISSING:
                self.detector.last_emitted.pop(key, None)
            else:
                self.detector.last_emitted[key] = previous  # type: ignore[assignment]
        for undo in reversed(self.window_undos):
            undo.rollback()
        self.detector._pending = None
        self._resolved = True


class Detector:
    def __init__(
        self,
        settings: DetectionSettings,
        allowlist: tuple[ipaddress._BaseNetwork, ...] = (),
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        self.settings = settings
        self.allowlist = allowlist
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.syn_windows: dict[str, Deque[tuple[float, str]]] = defaultdict(deque)
        self.port_windows: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self.port_counts: dict[str, Counter[int]] = defaultdict(Counter)
        self.last_emitted: dict[tuple[str, str], float] = {}
        self.source_high_watermarks: dict[str, float] = {}
        self.source_order: OrderedDict[str, None] = OrderedDict()
        self._pending: tuple[object, PreparedDetection | None] | None = None
        if settings.syn_flood_window_seconds < 1:
            raise ValueError("syn_flood_window_seconds must be positive")
        if settings.port_scan_window_seconds < 1:
            raise ValueError("port_scan_window_seconds must be positive")
        if settings.max_tracked_sources < 1:
            raise ValueError("max_tracked_sources must be positive")
        if settings.max_events_per_source_window < 1:
            raise ValueError("max_events_per_source_window must be positive")

    def analyze(self, event: PacketEvent) -> list[DetectionResult]:
        """Analyze and immediately commit state for compatibility callers."""

        prepared = self.prepare(event)
        prepared.commit()
        return list(prepared.results)

    def prepare(self, event: PacketEvent) -> PreparedDetection:
        """Evaluate with a bounded undo journal; the caller resolves it later.

        Detector instances are intentionally single-threaded. The service
        serializes prepare/resolve and rolls back provisional window/cooldown
        mutations unless the event's complete audit bundle commits.
        """

        if self._pending is not None:
            raise RuntimeError("detector preparation already pending")
        token = object()
        window_undos: list[_WindowUndo | _PortWindowUndo] = []
        emission_undos: list[tuple[tuple[str, str], object]] = []
        results: list[DetectionResult] = []
        source = event.src_ip
        now = event.observed_at.timestamp()

        def can_emit(rule_id: str) -> bool:
            key = (rule_id, source)
            previous = self.last_emitted.get(key, _MISSING)
            if (
                previous is not _MISSING
                and now - previous < self.settings.alert_cooldown_seconds
            ):
                return False
            emission_undos.append((key, previous))
            self.last_emitted[key] = now
            return True

        try:
            self._pending = (token, None)
            self.validate_event_time(event)
            if (
                event.protocol == "TCP"
                and "SYN" in event.tcp_flags
                and "ACK" not in event.tcp_flags
            ):
                syn_window = self._stage_window(
                    self.syn_windows,
                    source,
                    (now, event.dst_ip),
                    now - self.settings.syn_flood_window_seconds,
                    window_undos,
                )
                if len(syn_window) >= self.settings.syn_flood_threshold and can_emit(
                    "SYN_FLOOD"
                ):
                    results.append(
                        self._result(
                            event,
                            "SYN_FLOOD",
                            "HIGH",
                            f"{len(syn_window)} TCP SYN packets from one source in {self.settings.syn_flood_window_seconds}s",
                            {
                                "count": len(syn_window),
                                "window_seconds": self.settings.syn_flood_window_seconds,
                            },
                            now,
                        )
                    )

            if event.protocol == "TCP" and event.dst_port is not None:
                _, port_counts = self._stage_port_window(
                    source,
                    (now, event.dst_port),
                    now - self.settings.port_scan_window_seconds,
                    window_undos,
                )
                distinct_port_count = len(port_counts)
                if (
                    distinct_port_count >= self.settings.port_scan_distinct_ports
                    and can_emit("PORT_SCAN")
                ):
                    results.append(
                        self._result(
                            event,
                            "PORT_SCAN",
                            "MEDIUM",
                            f"{distinct_port_count} destination ports targeted in {self.settings.port_scan_window_seconds}s",
                            {
                                "distinct_ports": distinct_port_count,
                                "window_seconds": self.settings.port_scan_window_seconds,
                            },
                            now,
                        )
                    )

            if (
                event.protocol in {"DNS", "UDP"}
                and event.dns_query_length is not None
                and event.dns_query_length >= self.settings.dns_query_length
                and can_emit("DNS_TUNNELING")
            ):
                results.append(
                    self._result(
                        event,
                        "DNS_TUNNELING",
                        "CRITICAL",
                        f"DNS query metadata length {event.dns_query_length} exceeds the configured threshold",
                        {
                            "dns_query_length": event.dns_query_length,
                            "threshold": self.settings.dns_query_length,
                        },
                        now,
                    )
                )

            prepared = PreparedDetection(
                detector=self,
                token=token,
                source=source,
                observed=now,
                results=tuple(results),
                window_undos=tuple(window_undos),
                emission_undos=tuple(emission_undos),
            )
            self._pending = (token, prepared)
            return prepared
        except BaseException:
            for key, previous in reversed(emission_undos):
                if previous is _MISSING:
                    self.last_emitted.pop(key, None)
                else:
                    self.last_emitted[key] = previous  # type: ignore[assignment]
            for undo in reversed(window_undos):
                undo.rollback()
            if self._pending is not None and self._pending[0] is token:
                self._pending = None
            raise

    @property
    def _pending_token(self) -> object | None:
        return None if self._pending is None else self._pending[0]

    def rollback_pending(self) -> bool:
        """Rollback the detector-owned handle when a caller lost its return value."""

        pending = self._pending
        if pending is None:
            return False
        prepared = pending[1]
        if prepared is None:
            raise RuntimeError("detector preparation handle unavailable")
        prepared.rollback()
        return True

    def _stage_window(
        self,
        mapping: dict[str, Deque],
        source: str,
        item: tuple[float, object],
        cutoff: float,
        undo_log: list[_WindowUndo | _PortWindowUndo],
    ) -> Deque:
        created = source not in mapping
        if created:
            window = deque()
        else:
            window = mapping[source]
        undo = _WindowUndo(
            mapping=mapping,
            source=source,
            window=window,
            original_length=len(window),
            removed=[],
            created=created,
        )
        undo_log.append(undo)
        if created:
            mapping[source] = window
        self._stage_append(undo, item)
        while window and window[0][0] < cutoff:
            self._stage_deque_removal(undo)
        while len(window) > self.settings.max_events_per_source_window:
            self._stage_deque_removal(undo)
        return window

    @staticmethod
    def _stage_append(
        undo: _WindowUndo | _PortWindowUndo, item: tuple[float, object]
    ) -> None:
        before = len(undo.window)
        try:
            undo.window.append(item)
            undo.appended = True
        except BaseException:
            after = len(undo.window)
            if after == before + 1:
                undo.appended = True
            elif after != before:
                raise RuntimeError("window append invariant violated")
            raise

    @staticmethod
    def _stage_deque_removal(undo: _WindowUndo | _PortWindowUndo) -> None:
        item = undo.window[0]
        before_window = len(undo.window)
        before_journal = len(undo.removed)
        try:
            undo.removed.append(item)
            removed = undo.window.popleft()
            if removed != item:
                raise RuntimeError("window removal invariant violated")
        except BaseException:
            after_window = len(undo.window)
            if after_window == before_window:
                while len(undo.removed) > before_journal:
                    undo.removed.pop()
            elif after_window != before_window - 1:
                raise RuntimeError("window removal invariant violated")
            raise

    def _stage_port_window(
        self,
        source: str,
        item: tuple[float, int],
        cutoff: float,
        undo_log: list[_WindowUndo | _PortWindowUndo],
    ) -> tuple[Deque[tuple[float, int]], Counter[int]]:
        window_missing = source not in self.port_windows
        counts_missing = source not in self.port_counts
        window = deque() if window_missing else self.port_windows[source]
        counts = Counter() if counts_missing else self.port_counts[source]
        if counts_missing and len(window) != 0:
            raise RuntimeError("port window frequency invariant violated")
        if window_missing and len(counts) != 0:
            raise RuntimeError("port window frequency invariant violated")

        undo = _PortWindowUndo(
            window_mapping=self.port_windows,
            count_mapping=self.port_counts,
            source=source,
            window=window,
            counts=counts,
            appended_item=item,
            original_length=len(window),
            original_counts={},
            removed=[],
            window_created=window_missing,
            counts_created=counts_missing,
        )
        undo_log.append(undo)
        if window_missing:
            self.port_windows[source] = window
        if counts_missing:
            self.port_counts[source] = counts

        self._stage_append(undo, item)
        self._remember_port_count(undo, item[1])
        counts[item[1]] += 1
        while window and window[0][0] < cutoff:
            self._stage_port_removal(undo)
        while len(window) > self.settings.max_events_per_source_window:
            self._stage_port_removal(undo)
        return window, counts

    @staticmethod
    def _stage_port_removal(undo: _PortWindowUndo) -> None:
        port = undo.window[0][1]
        if undo.counts.get(port, 0) < 1:
            raise RuntimeError("port window frequency invariant violated")
        Detector._stage_deque_removal(undo)
        Detector._remember_port_count(undo, port)
        _decrement_port_count(undo.counts, port)

    @staticmethod
    def _remember_port_count(undo: _PortWindowUndo, port: int) -> None:
        if port not in undo.original_counts:
            undo.original_counts[port] = undo.counts.get(port, _MISSING)

    def validate_event_time(self, event: PacketEvent) -> None:
        """Reject future and per-source reordered records before state changes."""
        observed = event.observed_at.timestamp()
        current = self.clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise RuntimeError("detector clock must be timezone-aware")
        if observed > current.astimezone(timezone.utc).timestamp() + MAX_FUTURE_SKEW_SECONDS:
            raise ValidationError("event timestamp exceeds allowed future skew")
        previous = self.source_high_watermarks.get(event.src_ip)
        if previous is not None and observed < previous:
            raise ValidationError("event timestamp precedes source high watermark")

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
            self.port_counts.pop(evicted, None)
            self.source_high_watermarks.pop(evicted, None)
            for key in tuple(self.last_emitted):
                if key[1] == evicted:
                    del self.last_emitted[key]
