"""Metadata-only event sources: JSONL, deterministic sample data, and optional Scapy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import queue
from typing import Iterable, Iterator, TextIO

from .models import PacketEvent
from .validation import ValidationError


class CaptureError(RuntimeError):
    """Raised when an event source cannot be opened or decoded."""


def iter_jsonl(stream: TextIO) -> Iterator[PacketEvent]:
    for line_number, line in enumerate(stream, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValidationError("JSONL record must be an object")
            yield PacketEvent.from_mapping(value)
        except (json.JSONDecodeError, KeyError, TypeError, ValidationError) as exc:
            raise CaptureError(f"invalid JSONL event at line {line_number}: {exc}") from exc


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
    if not interface:
        raise CaptureError("a capture interface is required for the scapy source")
    try:
        from scapy.all import AsyncSniffer, DNS, DNSQR, IP, IPv6, TCP, UDP
    except ImportError as exc:
        raise CaptureError("install the optional capture extra: pip install -e '.[capture]'") from exc

    events: queue.Queue[PacketEvent] = queue.Queue()

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
                flags = frozenset(str(layer.flags).replace(" ", ""))
            elif UDP in packet:
                protocol = "UDP"
                layer = packet[UDP]
                src_port, dst_port = int(layer.sport), int(layer.dport)

            query_length = None
            if DNS in packet and DNSQR in packet:
                protocol = "DNS"
                query = packet[DNSQR].qname
                query_length = len(query) if query is not None else None

            events.put(
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

    sniffer = AsyncSniffer(iface=interface, prn=callback, store=False)
    try:
        sniffer.start()
    except Exception as exc:  # scapy raises several platform-specific errors
        raise CaptureError(f"unable to start capture on {interface!r}: {exc}") from exc
    try:
        while True:
            yield events.get()
    finally:
        sniffer.stop()
