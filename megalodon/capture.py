"""Metadata-only event sources: JSONL, deterministic sample data, and optional Scapy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import queue
import time
from threading import Event, Lock
from typing import Iterable, Iterator, TextIO

from .capabilities import runtime_platform
from .models import PacketEvent
from .validation import ValidationError


class CaptureError(RuntimeError):
    """Raised when an event source cannot be opened or decoded."""


MAX_JSONL_LINE_BYTES = 64 * 1024
MAX_SCAPY_QUEUE_EVENTS = 1024
SCAPY_QUEUE_POLL_SECONDS = 0.25
SCAPY_STARTUP_TIMEOUT_SECONDS = 5.0
SCAPY_SHUTDOWN_TIMEOUT_SECONDS = 2.0
_SCAPY_TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)
_SCAPY_TCP_FLAG_MASK = sum(bit for bit, _ in _SCAPY_TCP_FLAG_BITS)


class _BoundedCaptureQueue:
    """Non-blocking callback queue that fails the stream after first overflow."""

    def __init__(self, maximum: int = MAX_SCAPY_QUEUE_EVENTS):
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
            raise ValueError("capture queue maximum must be a positive integer")
        self._events: queue.Queue[PacketEvent] = queue.Queue(maxsize=maximum)
        self._overflowed = Event()
        self._stats_lock = Lock()
        self._offered = 0
        self._accepted = 0
        self._dropped = 0

    def offer(self, event: PacketEvent) -> bool:
        with self._stats_lock:
            self._offered += 1
            if self._overflowed.is_set():
                self._dropped += 1
                return False
            try:
                self._events.put_nowait(event)
            except queue.Full:
                self._overflowed.set()
                self._dropped += 1
                return False
            self._accepted += 1
            return True

    def take(self) -> PacketEvent | None:
        if self._overflowed.is_set():
            raise self._overflow_error()
        try:
            event = self._events.get(timeout=SCAPY_QUEUE_POLL_SECONDS)
        except queue.Empty:
            if self._overflowed.is_set():
                raise self._overflow_error()
            return None
        if self._overflowed.is_set():
            raise self._overflow_error()
        return event

    def telemetry(self) -> dict[str, int | bool]:
        """Return bounded in-memory queue/drop counters for diagnostics."""
        with self._stats_lock:
            return {
                "capacity": self._events.maxsize,
                "offered": self._offered,
                "accepted": self._accepted,
                "dropped": self._dropped,
                "queued": self._events.qsize(),
                "overflowed": self._overflowed.is_set(),
            }

    def _overflow_error(self) -> CaptureError:
        return CaptureError(
            f"live capture queue exceeded {self._events.maxsize} events; capture stopped"
        )


def _normalize_scapy_tcp_flags(value: object) -> frozenset[str]:
    """Translate Scapy's FlagValue bitmask into PacketEvent flag names."""
    if isinstance(value, bool):
        raise ValidationError("invalid Scapy TCP flag bitmask")
    try:
        bitmask = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationError("invalid Scapy TCP flag bitmask") from exc
    if bitmask < 0 or bitmask & ~_SCAPY_TCP_FLAG_MASK:
        raise ValidationError("unsupported Scapy TCP flag bitmask")
    return frozenset(name for bit, name in _SCAPY_TCP_FLAG_BITS if bitmask & bit)


def _thread_is_alive(sniffer: object) -> bool | None:
    """Return a reliable thread state, or None when the adapter cannot say."""
    thread = getattr(sniffer, "thread", None)
    if thread is None:
        return False
    probe = getattr(thread, "is_alive", None)
    if not callable(probe):
        return None
    try:
        alive = probe()
    except Exception:
        return None
    return alive if isinstance(alive, bool) else None


def _raise_if_sniffer_failed(sniffer: object, message: str) -> None:
    if isinstance(getattr(sniffer, "exception", None), BaseException):
        raise CaptureError(message) from None


def _wait_for_sniffer_start(sniffer: object) -> None:
    deadline = time.monotonic() + SCAPY_STARTUP_TIMEOUT_SECONDS
    while True:
        _raise_if_sniffer_failed(sniffer, "live capture failed during startup")
        running = getattr(sniffer, "running", None)
        if running is True or not isinstance(running, bool):
            return
        if _thread_is_alive(sniffer) is False:
            raise CaptureError("live capture stopped during startup") from None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CaptureError("live capture startup timed out") from None
        time.sleep(min(SCAPY_QUEUE_POLL_SECONDS, remaining))


def _check_sniffer_liveness(sniffer: object) -> None:
    _raise_if_sniffer_failed(sniffer, "live capture failed after startup")
    running = getattr(sniffer, "running", None)
    alive = _thread_is_alive(sniffer)
    if running is False or alive is False:
        raise CaptureError("live capture stopped unexpectedly") from None


def _stop_sniffer_bounded(sniffer: object) -> None:
    """Stop without Scapy's unbounded join, then bound the native thread wait."""
    sniffer.stop(join=False)  # type: ignore[attr-defined]
    thread = getattr(sniffer, "thread", None)
    join = getattr(thread, "join", None)
    if thread is None or not callable(join):
        raise CaptureError(
            "unable to verify live capture shutdown; shutdown is unverified"
        ) from None
    join(SCAPY_SHUTDOWN_TIMEOUT_SECONDS)
    alive = _thread_is_alive(sniffer)
    if alive is True:
        raise CaptureError(
            "unable to stop live capture; shutdown deadline exceeded"
        ) from None
    if alive is not False:
        raise CaptureError(
            "unable to verify live capture shutdown; shutdown is unverified"
        ) from None


def iter_jsonl(
    stream: TextIO,
    *,
    max_line_bytes: int = MAX_JSONL_LINE_BYTES,
) -> Iterator[PacketEvent]:
    if max_line_bytes < 1:
        raise ValueError("max_line_bytes must be positive")
    line_number = 0
    while True:
        line = stream.readline(max_line_bytes + 1)
        if not line:
            break
        line_number += 1
        if len(line) > max_line_bytes or len(line.encode("utf-8")) > max_line_bytes:
            raise CaptureError(
                f"JSONL event at line {line_number} exceeds {max_line_bytes} bytes"
            )
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValidationError("JSONL record must be an object")
            yield PacketEvent.from_mapping(value)
        except (
            json.JSONDecodeError,
            KeyError,
            OverflowError,
            RecursionError,
            TypeError,
            ValidationError,
        ) as exc:
            raise CaptureError(f"invalid JSONL event at line {line_number}") from exc


def iter_sample(*, include_demo_threat: bool = False) -> Iterator[PacketEvent]:
    start = datetime.now(timezone.utc)
    for index in range(12):
        yield PacketEvent(
            observed_at=start + timedelta(milliseconds=index * 100),
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="TCP",
            src_port=50000 + index,
            dst_port=443,
            tcp_flags=frozenset({"ACK"}),
            byte_count=512,
            interface="sample",
        )
    yield PacketEvent(
        observed_at=start + timedelta(seconds=2),
        src_ip="192.0.2.11",
        dst_ip="198.51.100.53",
        protocol="DNS",
        src_port=53000,
        dst_port=53,
        dns_query_length=32,
        byte_count=140,
        interface="sample",
    )
    if include_demo_threat:
        for index in range(100):
            yield PacketEvent(
                observed_at=start + timedelta(seconds=4, milliseconds=index * 10),
                src_ip="8.8.8.8",
                dst_ip="192.0.2.20",
                protocol="TCP",
                src_port=40000 + (index % 1000),
                dst_port=22,
                tcp_flags=frozenset({"SYN"}),
                byte_count=60,
                interface="sample",
            )
        yield PacketEvent(
            observed_at=start + timedelta(seconds=6),
            src_ip="8.8.4.4",
            dst_ip="192.0.2.53",
            protocol="DNS",
            src_port=5353,
            dst_port=53,
            dns_query_length=90,
            byte_count=300,
            interface="sample",
        )


def iter_scapy(interface: str) -> Iterator[PacketEvent]:
    if runtime_platform() != "linux":
        raise CaptureError("live Scapy capture is supported only on Linux")
    if not interface:
        raise CaptureError("a capture interface is required for the scapy source")
    try:
        from scapy.all import AsyncSniffer, DNS, DNSQR, IP, IPv6, TCP, UDP
    except ImportError:
        raise CaptureError("install the optional capture extra: pip install -e '.[capture]'") from None

    events = _BoundedCaptureQueue()

    def callback(packet: object) -> None:
        try:
            if IP in packet:
                network = packet[IP]
                src_ip, dst_ip = network.src, network.dst
            elif IPv6 in packet:
                network = packet[IPv6]
                src_ip, dst_ip = network.src, network.dst
            else:
                return

            protocol = "IP"
            src_port = dst_port = None
            flags: frozenset[str] = frozenset()
            if TCP in packet:
                protocol = "TCP"
                layer = packet[TCP]
                src_port, dst_port = int(layer.sport), int(layer.dport)
                flags = _normalize_scapy_tcp_flags(layer.flags)
            elif UDP in packet:
                protocol = "UDP"
                layer = packet[UDP]
                src_port, dst_port = int(layer.sport), int(layer.dport)

            query_length = None
            if DNS in packet and DNSQR in packet:
                protocol = "DNS"
                query = packet[DNSQR].qname
                query_length = len(query) if query is not None else None

            events.offer(
                PacketEvent(
                    observed_at=datetime.now(timezone.utc),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_flags=flags,
                    dns_query_length=query_length,
                    byte_count=len(packet),
                    interface=interface,
                )
            )
        except (KeyError, TypeError, ValueError, ValidationError):
            # A malformed packet is ignored; raw packet data is never logged.
            return

    sniffer: object | None = None
    primary_error: BaseException | None = None
    try:
        try:
            sniffer = AsyncSniffer(iface=interface, prn=callback, store=False)
            sniffer.start()
        except Exception:  # scapy raises several platform-specific errors
            raise CaptureError("unable to start live capture") from None
        try:
            _wait_for_sniffer_start(sniffer)
        except CaptureError:
            raise
        except Exception:
            raise CaptureError("unable to start live capture") from None

        while True:
            event = events.take()
            if event is not None:
                yield event
                continue
            _check_sniffer_liveness(sniffer)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if sniffer is not None:
            try:
                _stop_sniffer_bounded(sniffer)
            except BaseException as exc:
                if primary_error is not None and not isinstance(primary_error, GeneratorExit):
                    BaseException.add_note(
                        primary_error,
                        "live capture cleanup failed; shutdown is unverified",
                    )
                elif isinstance(exc, CaptureError):
                    raise
                elif isinstance(exc, Exception):
                    raise CaptureError(
                        "unable to stop live capture; shutdown is unverified"
                    ) from None
                else:
                    raise
