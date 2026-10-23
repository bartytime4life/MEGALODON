"""Build deterministic, synthetic PCAPs for the unexecuted Suricata study.

This module performs no capture, network access, process launch, or host
inspection.  All addresses are RFC 5737 documentation addresses.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
import struct


ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"
CLIENT_IP = ipaddress.IPv4Address("192.0.2.10").packed
SERVER_IP = ipaddress.IPv4Address("192.0.2.20").packed
CLIENT_MAC = bytes.fromhex("020000000010")
SERVER_MAC = bytes.fromhex("020000000020")
CLIENT_PORT = 50000
SERVER_PORT = 443
CLIENT_ISN = 1000
SERVER_ISN = 5000
PCAP_EPOCH = 1_700_000_000
PCRE_CHUNK_BYTES = 512


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_segment(
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        5 << 4,
        flags,
        64240,
        0,
        0,
    )
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", checksum) + header[18:] + payload


def _frame(
    *,
    from_client: bool,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    identification: int,
) -> bytes:
    if from_client:
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_port, dst_port = CLIENT_PORT, SERVER_PORT
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_port, dst_port = SERVER_PORT, CLIENT_PORT

    tcp = _tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        identification,
        0x4000,
        64,
        6,
        0,
        src_ip,
        dst_ip,
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip_header + tcp


def _pcap(frames: list[bytes]) -> bytes:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        output.extend(struct.pack("<IIII", PCAP_EPOCH + index, 0, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def _handshake() -> list[bytes]:
    return [
        _frame(
            from_client=True,
            seq=CLIENT_ISN,
            ack=0,
            flags=0x02,
            identification=1,
        ),
        _frame(
            from_client=False,
            seq=SERVER_ISN,
            ack=CLIENT_ISN + 1,
            flags=0x12,
            identification=2,
        ),
        _frame(
            from_client=True,
            seq=CLIENT_ISN + 1,
            ack=SERVER_ISN + 1,
            flags=0x10,
            identification=3,
        ),
    ]


def _tls_client_hello() -> tuple[bytes, bytes]:
    hostname = b"fragmented.example"
    server_name = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    sni_data = struct.pack("!H", len(server_name)) + server_name
    sni_extension = b"\x00\x00" + struct.pack("!H", len(sni_data)) + sni_data
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(sni_extension))
        + sni_extension
    )
    handshake_header = b"\x01" + len(body).to_bytes(3, "big")
    first = b"\x16\x03\x03\x00\x02" + handshake_header[:2]
    second_payload = handshake_header[2:] + body
    second = b"\x16\x03\x03" + struct.pack("!H", len(second_payload)) + second_payload
    return first, second


def build_fragmented_tls() -> bytes:
    first, second = _tls_client_hello()
    frames = _handshake()
    client_seq = CLIENT_ISN + 1
    frames.append(
        _frame(
            from_client=True,
            seq=client_seq,
            ack=SERVER_ISN + 1,
            flags=0x18,
            payload=first,
            identification=4,
        )
    )
    client_seq += len(first)
    frames.append(
        _frame(
            from_client=True,
            seq=client_seq,
            ack=SERVER_ISN + 1,
            flags=0x18,
            payload=second,
            identification=5,
        )
    )
    client_seq += len(second)
    frames.append(
        _frame(
            from_client=False,
            seq=SERVER_ISN + 1,
            ack=client_seq,
            flags=0x10,
            identification=6,
        )
    )
    return _pcap(frames)


def build_pcre_stream(segment_count: int) -> bytes:
    if segment_count not in {32, 64, 128}:
        raise ValueError("segment_count must be one of 32, 64, or 128")
    frames = _handshake()
    client_seq = CLIENT_ISN + 1
    for index in range(segment_count):
        payload = b"A" * PCRE_CHUNK_BYTES
        if index == segment_count - 1:
            payload = payload[:-2] + b"mc"
        frames.append(
            _frame(
                from_client=True,
                seq=client_seq,
                ack=SERVER_ISN + 1,
                flags=0x18,
                payload=payload,
                identification=4 + index,
            )
        )
        client_seq += len(payload)
    frames.append(
        _frame(
            from_client=False,
            seq=SERVER_ISN + 1,
            ack=client_seq,
            flags=0x10,
            identification=4 + segment_count,
        )
    )
    return _pcap(frames)


def build_all() -> dict[str, bytes]:
    return {
        "fragmented-tls-handshake-header.pcap": build_fragmented_tls(),
        "pcre-stream-32.pcap": build_pcre_stream(32),
        "pcre-stream-64.pcap": build_pcre_stream(64),
        "pcre-stream-128.pcap": build_pcre_stream(128),
    }


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, content in build_all().items():
        (FIXTURES / name).write_bytes(content)


if __name__ == "__main__":
    main()
